"""Operator self-service profile and account settings.

These assert the security properties, not just the happy path: the username is
immutable (it is the audit attribution key), a password change requires the
current password, no password or hash reaches the audit log, and a password
change or explicit revoke signs out other sessions while keeping this one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.auth.service import (
    AuthError,
    change_password,
    create_user,
    list_active_sessions,
    revoke_other_sessions,
    start_session,
    update_profile,
    _hash_token,
)
from backend.database.models import User, UserSession
from backend.database.session import init_db, session_scope
from backend.main import app


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "profile.db"
    init_db(path)
    return path


@pytest.fixture
def audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def operator(db: Path, audit: Path):
    return create_user(
        "operator1", "Correct-Horse-9", full_name="Original Name",
        db_path=db, audit_path=audit,
    )


# ---------------------------------------------------------------------------
# Edit profile
# ---------------------------------------------------------------------------


class TestUpdateProfile:
    def test_full_name_can_be_changed(self, operator, db, audit) -> None:
        identity = update_profile(
            operator.id, full_name="New Name", db_path=db, audit_path=audit
        )
        assert identity.full_name == "New Name"
        with session_scope(db) as session:
            assert session.get(User, operator.id).full_name == "New Name"

    def test_full_name_can_be_cleared(self, operator, db, audit) -> None:
        identity = update_profile(operator.id, full_name="   ", db_path=db, audit_path=audit)
        assert identity.full_name is None

    def test_username_is_not_changeable(self, operator, db, audit) -> None:
        # There is no parameter to change the username: it is the attribution key.
        update_profile(operator.id, full_name="X", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            assert session.get(User, operator.id).username == "operator1"

    def test_missing_account_raises(self, db, audit) -> None:
        with pytest.raises(AuthError):
            update_profile(9999, full_name="X", db_path=db, audit_path=audit)


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------


class TestChangePassword:
    def test_correct_current_password_changes_it(self, operator, db, audit) -> None:
        change_password(
            operator.id, "Correct-Horse-9", "Brand-New-Pass-1",
            db_path=db, audit_path=audit,
        )
        from backend.auth.service import authenticate

        # Old password no longer works; new one does.
        with pytest.raises(AuthError):
            authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        assert authenticate("operator1", "Brand-New-Pass-1", db_path=db, audit_path=audit)

    def test_wrong_current_password_is_refused(self, operator, db, audit) -> None:
        with pytest.raises(AuthError):
            change_password(
                operator.id, "wrong-current", "Brand-New-Pass-1",
                db_path=db, audit_path=audit,
            )

    def test_weak_new_password_is_refused(self, operator, db, audit) -> None:
        with pytest.raises(AuthError):
            change_password(
                operator.id, "Correct-Horse-9", "short",
                db_path=db, audit_path=audit,
            )

    def test_no_password_or_hash_in_audit(self, operator, db, audit) -> None:
        change_password(
            operator.id, "Correct-Horse-9", "Brand-New-Pass-1",
            db_path=db, audit_path=audit,
        )
        text = audit.read_text()
        assert "Correct-Horse-9" not in text
        assert "Brand-New-Pass-1" not in text
        # And a bcrypt hash prefix must never appear.
        assert "$2b$" not in text
        # The event itself is recorded.
        actions = [json.loads(line)["action"] for line in text.splitlines() if line.strip()]
        assert "auth.password_changed" in actions

    def test_failed_change_is_audited_as_refused(self, operator, db, audit) -> None:
        with pytest.raises(AuthError):
            change_password(
                operator.id, "wrong", "Brand-New-Pass-1", db_path=db, audit_path=audit
            )
        entries = [json.loads(l) for l in audit.read_text().splitlines() if l.strip()]
        refusals = [e for e in entries if e["action"] == "auth.password_change_failed"]
        assert refusals and refusals[-1]["outcome"] == "refused"


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestSessions:
    def test_lists_only_active_sessions_and_flags_current(self, operator, db, audit) -> None:
        token_a, _ = start_session(operator.id, db_path=db, audit_path=audit)
        start_session(operator.id, db_path=db, audit_path=audit)  # a second device

        sessions = list_active_sessions(operator.id, current_token=token_a, db_path=db)
        assert len(sessions) == 2
        current = [s for s in sessions if s["is_current"]]
        assert len(current) == 1
        # No token material is ever exposed.
        for s in sessions:
            assert "token" not in s and "token_hash" not in s

    def test_revoke_others_keeps_current(self, operator, db, audit) -> None:
        keep, _ = start_session(operator.id, db_path=db, audit_path=audit)
        start_session(operator.id, db_path=db, audit_path=audit)
        start_session(operator.id, db_path=db, audit_path=audit)

        revoked = revoke_other_sessions(operator.id, keep, db_path=db, audit_path=audit)
        assert revoked == 2

        remaining = list_active_sessions(operator.id, current_token=keep, db_path=db)
        assert len(remaining) == 1 and remaining[0]["is_current"]

        # The kept session's row is genuinely still valid.
        with session_scope(db) as session:
            row = session.query(UserSession).filter_by(
                token_hash=_hash_token(keep)
            ).one()
            assert row.revoked_at is None

    def test_password_change_then_revoke_others(self, operator, db, audit) -> None:
        keep, _ = start_session(operator.id, db_path=db, audit_path=audit)
        start_session(operator.id, db_path=db, audit_path=audit)
        change_password(
            operator.id, "Correct-Horse-9", "Brand-New-Pass-1",
            db_path=db, audit_path=audit,
        )
        # The route revokes other sessions after a password change; simulate that.
        assert revoke_other_sessions(operator.id, keep, db_path=db, audit_path=audit) == 1


# ---------------------------------------------------------------------------
# The new routes are behind the auth gate
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def anonymous_client():
    with TestClient(app) as client:
        yield client


class TestProfileRoutesGated:
    @pytest.mark.parametrize(
        "method,path",
        [
            ("get", "/profile"),
            ("get", "/settings"),
            ("post", "/profile/edit"),
            ("post", "/profile/password"),
            ("post", "/settings/sessions/revoke-others"),
            ("post", "/settings/delete"),
        ],
    )
    def test_requires_a_session(self, anonymous_client, method: str, path: str) -> None:
        response = getattr(anonymous_client, method)(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
