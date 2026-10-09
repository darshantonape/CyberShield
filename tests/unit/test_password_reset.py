"""Forgot-password and reset-token security properties.

Asserts what matters, not only the happy path: tokens are random and stored
hashed, single-use, short-lived and superseded by newer requests; the request
form cannot enumerate accounts; a reset revokes every session and the old
password; nothing secret reaches the audit log; and the existing login and
password-change flows are unaffected.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import backend.auth.password_reset as pr
import backend.auth.routes as auth_routes
import backend.auth.service as auth_service
import backend.database.session as db_session
from backend.auth.mailer import DeliveryError, MailSettings, deliver_reset_link
from backend.auth.password_reset import (
    ACCOUNT_MAX_REQUESTS,
    RateLimiter,
    ResetError,
    request_password_reset,
    reset_password,
    reset_token_status,
)
from backend.auth.service import (
    AuthError,
    _hash_token,
    _utcnow,
    authenticate,
    change_password,
    create_user,
    delete_user,
    resolve_session,
    start_session,
)
from backend.database.models import PasswordResetToken, User, UserSession
from backend.database.session import init_db, session_scope

PASSWORD = "Correct-Horse-9"
NEW_PASSWORD = "Brand-New-Pass-1"
LOCAL = "http://127.0.0.1:8000/"


def _settings(**overrides) -> MailSettings:
    base = dict(
        development=True, smtp_host=None, smtp_port=587, smtp_username=None,
        smtp_password=None, smtp_from=None, smtp_security="starttls",
        public_base_url=None,
    )
    base.update(overrides)
    return MailSettings(**base)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "reset.db"
    init_db(path)
    return path


@pytest.fixture
def audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def operator(db: Path, audit: Path):
    return create_user(
        "operator1", PASSWORD, email="op@example.com", db_path=db, audit_path=audit
    )


@pytest.fixture
def links(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture delivered reset URLs instead of printing or sending them."""
    sent: list[str] = []

    def fake_deliver(*, reset_url: str, **_kwargs) -> str:
        sent.append(reset_url)
        return "console"

    monkeypatch.setattr(pr, "deliver_reset_link", fake_deliver)
    return sent


def _token(url: str) -> str:
    return parse_qs(urlparse(url).query)["token"][0]


def _request(identifier: str, db: Path, audit: Path, **kw) -> None:
    request_password_reset(
        identifier, request_base_url=kw.pop("base", LOCAL),
        db_path=db, audit_path=audit, settings=kw.pop("settings", _settings()), **kw,
    )


# ---------------------------------------------------------------------------
# Issuing tokens
# ---------------------------------------------------------------------------


class TestIssue:
    def test_by_email_and_by_username(self, operator, db, audit, links) -> None:
        _request("OP@example.com ", db, audit)
        _request("operator1", db, audit)
        assert len(links) == 2
        assert all(u.startswith("http://127.0.0.1:8000/reset-password?token=") for u in links)

    def test_token_is_random_and_only_its_hash_is_stored(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        _request("operator1", db, audit)
        t1, t2 = _token(links[0]), _token(links[1])
        assert t1 != t2 and len(t1) >= 43
        for value in ("operator1", "op@example.com", PASSWORD):
            assert value not in t1
        with session_scope(db) as s:
            hashes = {r.token_hash for r in s.query(PasswordResetToken).all()}
        assert hashes == {_hash_token(t1), _hash_token(t2)}
        assert t1 not in hashes and t2 not in hashes

    def test_expiry_is_short(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        with session_scope(db) as s:
            row = s.query(PasswordResetToken).one()
            ttl = row.expires_at - row.created_at
        assert timedelta(minutes=1) < ttl <= timedelta(minutes=60)

    def test_unknown_account_issues_nothing_and_does_not_raise(self, operator, db, audit, links) -> None:
        _request("nobody@example.com", db, audit)
        _request("nobody", db, audit)
        _request("", db, audit)
        assert links == []
        with session_scope(db) as s:
            assert s.query(PasswordResetToken).count() == 0

    def test_disabled_account_issues_nothing(self, operator, db, audit, links) -> None:
        with session_scope(db) as s:
            s.get(User, operator.id).is_active = False
        _request("operator1", db, audit)
        assert links == []

    def test_newer_request_supersedes_older_link(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        _request("operator1", db, audit)
        assert reset_token_status(_token(links[0]), db_path=db) == "used"
        assert reset_token_status(_token(links[1]), db_path=db) is None

    def test_per_account_throttle_is_silent(self, operator, db, audit, links) -> None:
        for _ in range(ACCOUNT_MAX_REQUESTS + 2):
            _request("operator1", db, audit)  # never raises
        assert len(links) == ACCOUNT_MAX_REQUESTS

    def test_untrusted_host_header_never_gets_a_link(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit, base="http://attacker.example/")
        assert links == []

    def test_public_base_url_overrides_request_origin(self, operator, db, audit, links) -> None:
        _request(
            "operator1", db, audit, base="http://attacker.example/",
            settings=_settings(public_base_url="https://cybershield.lab"),
        )
        assert links[0].startswith("https://cybershield.lab/reset-password?token=")

    def test_audit_never_contains_token_or_hash(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        token = _token(links[0])
        reset_password(token, NEW_PASSWORD, db_path=db, audit_path=audit)
        text = audit.read_text()
        for secret in (token, _hash_token(token), PASSWORD, NEW_PASSWORD):
            assert secret not in text
        events = [json.loads(line)["action"] for line in text.splitlines() if line]
        assert "auth.password_reset_requested" in events
        assert "auth.password_reset" in events


# ---------------------------------------------------------------------------
# Redeeming tokens
# ---------------------------------------------------------------------------


class TestRedeem:
    def test_reset_changes_password_and_old_one_stops_working(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        reset_password(_token(links[0]), NEW_PASSWORD, db_path=db, audit_path=audit)
        assert authenticate("operator1", NEW_PASSWORD, db_path=db, audit_path=audit) == operator.id
        with pytest.raises(AuthError):
            authenticate("operator1", PASSWORD, db_path=db, audit_path=audit)
        with session_scope(db) as s:
            assert s.get(User, operator.id).password_hash.startswith("$2b$12$")

    def test_token_is_single_use(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        token = _token(links[0])
        reset_password(token, NEW_PASSWORD, db_path=db, audit_path=audit)
        with pytest.raises(ResetError) as exc:
            reset_password(token, "Another-Pass-2", db_path=db, audit_path=audit)
        assert exc.value.reason == "used"
        assert authenticate("operator1", NEW_PASSWORD, db_path=db, audit_path=audit)

    def test_expired_token_is_refused(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        with session_scope(db) as s:
            s.query(PasswordResetToken).one().expires_at = _utcnow() - timedelta(seconds=1)
        with pytest.raises(ResetError) as exc:
            reset_password(_token(links[0]), NEW_PASSWORD, db_path=db, audit_path=audit)
        assert exc.value.reason == "expired"
        assert authenticate("operator1", PASSWORD, db_path=db, audit_path=audit)

    @pytest.mark.parametrize("token", ["", "not-a-token", "x" * 43, "y" * 5000, None])
    def test_invalid_token_is_refused(self, operator, db, audit, token) -> None:
        with pytest.raises(ResetError) as exc:
            reset_password(token, NEW_PASSWORD, db_path=db, audit_path=audit)
        assert exc.value.reason == "invalid"

    def test_weak_password_is_refused_and_token_survives(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        token = _token(links[0])
        with pytest.raises(AuthError) as exc:
            reset_password(token, "short", db_path=db, audit_path=audit)
        assert not isinstance(exc.value, ResetError)
        assert reset_token_status(token, db_path=db) is None

    def test_reset_revokes_every_session(self, operator, db, audit, links) -> None:
        tokens = [start_session(operator.id, db_path=db, audit_path=audit)[0] for _ in range(2)]
        _request("operator1", db, audit)
        revoked = reset_password(_token(links[0]), NEW_PASSWORD, db_path=db, audit_path=audit)
        assert revoked == 2
        assert all(resolve_session(t, db_path=db) is None for t in tokens)

    def test_token_for_disabled_account_is_refused(self, operator, db, audit, links) -> None:
        _request("operator1", db, audit)
        with session_scope(db) as s:
            s.get(User, operator.id).is_active = False
        with pytest.raises(ResetError):
            reset_password(_token(links[0]), NEW_PASSWORD, db_path=db, audit_path=audit)

    def test_deleting_an_account_with_outstanding_tokens_still_works(self, operator, db, audit, links) -> None:
        create_user("operator2", PASSWORD, db_path=db, audit_path=audit)
        _request("operator1", db, audit)
        delete_user("operator1", db_path=db, audit_path=audit)
        with session_scope(db) as s:
            assert s.query(PasswordResetToken).count() == 0

    def test_password_change_still_works(self, operator, db, audit) -> None:
        change_password(operator.id, PASSWORD, NEW_PASSWORD, db_path=db, audit_path=audit)
        assert authenticate("operator1", NEW_PASSWORD, db_path=db, audit_path=audit)


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


class TestDelivery:
    def test_development_mode_prints_link_to_console_only(self, capsys) -> None:
        channel = deliver_reset_link(
            username="op", email=None, reset_url="http://127.0.0.1:8000/reset-password?token=T",
            ttl_minutes=30, settings=_settings(),
        )
        assert channel == "console"
        assert "token=T" in capsys.readouterr().err

    def test_production_without_smtp_discards_link_without_printing_it(self, capsys) -> None:
        channel = deliver_reset_link(
            username="op", email="op@example.com",
            reset_url="http://127.0.0.1:8000/reset-password?token=SECRET",
            ttl_minutes=30, settings=_settings(development=False),
        )
        out = capsys.readouterr()
        assert channel == "none"
        assert "SECRET" not in out.err + out.out

    def test_smtp_failure_is_reported_without_the_token(self) -> None:
        with pytest.raises(DeliveryError) as exc:
            deliver_reset_link(
                username="op", email="op@example.com",
                reset_url="http://x/reset-password?token=SECRET", ttl_minutes=30,
                settings=_settings(
                    development=False, smtp_host="127.0.0.1", smtp_port=1,
                    smtp_from="cybershield@example.com", smtp_security="none",
                ),
            )
        assert "SECRET" not in str(exc.value)


class TestRateLimiter:
    def test_limits_then_recovers(self) -> None:
        limiter = RateLimiter(limit=2, window_seconds=60)
        assert limiter.hit("a") and limiter.hit("a")
        assert not limiter.hit("a")
        assert limiter.blocked("a") and not limiter.blocked("b")
        limiter.window = 0
        assert limiter.hit("a")


# ---------------------------------------------------------------------------
# The complete browser flow, against an isolated database
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(db: Path, audit: Path, links, monkeypatch: pytest.MonkeyPatch):
    """The real app, pointed at a temporary database and audit log.

    Built without the lifespan hook so startup tasks never touch the
    developer's own data.
    """
    monkeypatch.setattr(db_session, "DB_PATH", db)
    monkeypatch.setattr(db_session, "_engine", None)
    monkeypatch.setattr(db_session, "_Session", None)
    monkeypatch.setattr(auth_service, "DATA_DIR", audit.parent)
    monkeypatch.setattr(pr, "load_mail_settings", lambda: _settings())
    auth_routes._forgot_limiter.reset()
    auth_routes._reset_limiter.reset()
    from backend.main import app

    client = TestClient(app, base_url="http://127.0.0.1:8000")
    yield client
    auth_routes._forgot_limiter.reset()
    auth_routes._reset_limiter.reset()


def _login(client: TestClient, password: str):
    return client.post(
        "/login", data={"username": "operator1", "password": password},
        follow_redirects=False,
    )


class TestBrowserFlow:
    def test_complete_flow(self, app_client, operator, links) -> None:
        # Existing session on another device, to prove it is revoked.
        other = start_session(operator.id)[0]

        login = app_client.get("/login")
        assert 'href="/forgot-password"' in login.text and "Forgot Password?" in login.text

        page = app_client.get("/forgot-password")
        assert page.status_code == 200
        assert "Send Reset Link" in page.text and 'href="/login"' in page.text

        sent = app_client.post("/forgot-password", data={"identifier": "op@example.com"})
        assert sent.status_code == 200
        assert "If an account exists with that information" in sent.text
        assert len(links) == 1
        token = _token(links[0])
        assert token not in sent.text

        form = app_client.get(f"/reset-password?token={token}")
        assert form.status_code == 200
        assert "Confirm New Password" in form.text
        assert form.headers["referrer-policy"] == "no-referrer"
        assert form.headers["cache-control"] == "no-store"

        mismatch = app_client.post(
            "/reset-password",
            data={"token": token, "new_password": NEW_PASSWORD, "confirm_password": "Different-1x"},
        )
        assert mismatch.status_code == 400 and "do not match" in mismatch.text

        weak = app_client.post(
            "/reset-password",
            data={"token": token, "new_password": "short", "confirm_password": "short"},
        )
        assert weak.status_code == 400 and "at least 10 characters" in weak.text

        done = app_client.post(
            "/reset-password",
            data={"token": token, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
            follow_redirects=False,
        )
        assert done.status_code == 303
        assert done.headers["location"].startswith("/login?notice=")
        landing = app_client.get(done.headers["location"])
        assert "Your password has been reset successfully" in landing.text

        assert resolve_session(other) is None
        assert _login(app_client, PASSWORD).status_code == 401
        good = _login(app_client, NEW_PASSWORD)
        assert good.status_code == 303 and "cybershield_session" in good.cookies

        reused = app_client.get(f"/reset-password?token={token}")
        assert reused.status_code == 400 and "already been used" in reused.text
        replay = app_client.post(
            "/reset-password",
            data={"token": token, "new_password": "Another-Pass-2", "confirm_password": "Another-Pass-2"},
        )
        assert replay.status_code == 400 and "already been used" in replay.text

    def test_unknown_account_gets_an_identical_response(self, app_client, operator, links) -> None:
        known = app_client.post("/forgot-password", data={"identifier": "operator1"},
                                follow_redirects=False)
        unknown = app_client.post("/forgot-password", data={"identifier": "ghost@example.com"},
                                  follow_redirects=False)
        assert known.status_code == unknown.status_code == 200
        assert known.text == unknown.text
        assert "location" not in known.headers and "location" not in unknown.headers
        assert "ghost" not in unknown.text and "operator1" not in known.text
        assert len(links) == 1

    def test_invalid_and_expired_links_are_refused(self, app_client, operator, links, db) -> None:
        bad = app_client.get("/reset-password?token=nonsense")
        assert bad.status_code == 400 and "invalid" in bad.text
        assert 'name="new_password"' not in bad.text
        assert app_client.get("/reset-password").status_code == 400

        app_client.post("/forgot-password", data={"identifier": "operator1"})
        with session_scope(db) as s:
            s.query(PasswordResetToken).one().expires_at = _utcnow() - timedelta(minutes=1)
        expired = app_client.get(f"/reset-password?token={_token(links[0])}")
        assert expired.status_code == 400 and "expired" in expired.text

    def test_request_form_is_rate_limited_per_address(self, app_client, operator) -> None:
        codes = [
            app_client.post("/forgot-password", data={"identifier": f"x{i}@example.com"}).status_code
            for i in range(6)
        ]
        assert codes[:5] == [200] * 5 and codes[5] == 429

    def test_failed_redemptions_are_rate_limited(self, app_client, operator) -> None:
        data = {"token": "guess", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD}
        codes = [app_client.post("/reset-password", data=data).status_code for _ in range(11)]
        assert codes[:10] == [400] * 10 and codes[10] == 429

    def test_signed_in_operator_is_sent_home_from_forgot_page(self, app_client, operator) -> None:
        _login(app_client, PASSWORD)
        response = app_client.get("/forgot-password", follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/"

    def test_password_change_route_still_keeps_this_session(self, app_client, operator) -> None:
        _login(app_client, PASSWORD)
        response = app_client.post(
            "/profile/password",
            data={"current_password": PASSWORD, "new_password": NEW_PASSWORD,
                  "confirm_password": NEW_PASSWORD},
            follow_redirects=False,
        )
        assert response.status_code == 303 and "message=" in response.headers["location"]
        assert app_client.get("/profile", follow_redirects=False).status_code == 200
