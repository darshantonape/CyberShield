"""Operator authentication.

These assert the security properties, not the happy path alone: no plaintext
password anywhere, no account enumeration, no usable session after logout, and
no session that outlives its expiry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.auth.service import (
    AuthError,
    authenticate,
    create_user,
    end_session,
    hash_password,
    purge_expired_sessions,
    resolve_session,
    start_session,
    user_count,
    validate_password,
    validate_username,
)
from backend.database.models import User, UserSession
from backend.database.session import init_db, session_scope


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """An isolated database, so tests never touch the operator's own accounts."""
    path = tmp_path / "auth.db"
    init_db(path)
    return path


@pytest.fixture
def audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


class TestPasswordRules:
    @pytest.mark.parametrize(
        "password",
        ["short", "123456789", "aaaaaaaaaa", "ALLUPPERCASE", "!!!!!!!!!!"],
    )
    def test_weak_passwords_are_refused(self, password: str) -> None:
        with pytest.raises(AuthError):
            validate_password(password)

    @pytest.mark.parametrize(
        "password", ["Correct-Horse-9", "labpassword1", "s3cure!!!!x"]
    )
    def test_acceptable_passwords_pass(self, password: str) -> None:
        assert validate_password(password) == password

    def test_overlong_password_is_refused_not_truncated(self) -> None:
        # bcrypt silently ignores bytes past 72; accepting a longer password
        # would mean two different passwords opening the same account.
        with pytest.raises(AuthError):
            validate_password("A1" + "x" * 200)


class TestUsernameRules:
    def test_username_is_normalised_to_lowercase(self) -> None:
        assert validate_username("  OperatorOne  ") == "operatorone"

    @pytest.mark.parametrize("name", ["ab", "-leading", "has space", "sym$bol", "x" * 40])
    def test_invalid_usernames_are_refused(self, name: str) -> None:
        with pytest.raises(AuthError):
            validate_username(name)


class TestHashing:
    def test_hash_is_bcrypt_and_not_the_password(self) -> None:
        digest = hash_password("Correct-Horse-9")
        assert digest.startswith("$2b$")
        assert "Correct-Horse-9" not in digest

    def test_same_password_hashes_differently_each_time(self) -> None:
        # Distinct salts: two operators with the same password must not have
        # matching hashes in the database.
        assert hash_password("Correct-Horse-9") != hash_password("Correct-Horse-9")


class TestAccounts:
    def test_create_then_authenticate(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        assert authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)

    def test_no_plaintext_password_is_stored(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            row = session.query(User).one()
            assert row.password_hash.startswith("$2b$")
            # Nothing anywhere on the row may contain the password.
            for column in row.__table__.columns:
                value = getattr(row, column.name)
                assert "Correct-Horse-9" != value

    def test_password_is_never_written_to_the_audit_log(
        self, db: Path, audit: Path
    ) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with pytest.raises(AuthError):
            authenticate("operator1", "wrong-password-1", db_path=db, audit_path=audit)
        text = audit.read_text()
        assert "Correct-Horse-9" not in text
        assert "wrong-password-1" not in text
        assert "$2b$" not in text

    def test_duplicate_username_is_refused(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with pytest.raises(AuthError, match="already taken"):
            create_user("Operator1", "Another-Pass-9", db_path=db, audit_path=audit)

    def test_wrong_password_is_refused(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with pytest.raises(AuthError):
            authenticate("operator1", "Wrong-Horse-9", db_path=db, audit_path=audit)

    def test_unknown_and_wrong_password_are_indistinguishable(
        self, db: Path, audit: Path
    ) -> None:
        # The login form must not be usable to discover which accounts exist.
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)

        with pytest.raises(AuthError) as wrong:
            authenticate("operator1", "Wrong-Horse-9", db_path=db, audit_path=audit)
        with pytest.raises(AuthError) as missing:
            authenticate("nobody-here", "Wrong-Horse-9", db_path=db, audit_path=audit)

        assert str(wrong.value) == str(missing.value)

    def test_disabled_account_cannot_authenticate(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            session.query(User).one().is_active = False
        with pytest.raises(AuthError, match="disabled"):
            authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)

    def test_failed_logins_are_counted_then_reset(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        for _ in range(3):
            with pytest.raises(AuthError):
                authenticate("operator1", "nope-nope-99", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            assert session.query(User).one().failed_logins == 3

        authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            assert session.query(User).one().failed_logins == 0

    def test_user_count_reflects_accounts(self, db: Path, audit: Path) -> None:
        assert user_count(db) == 0
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        assert user_count(db) == 1


class TestSessions:
    def _login(self, db: Path, audit: Path) -> str:
        user_id = create_user(
            "operator1", "Correct-Horse-9", db_path=db, audit_path=audit
        ).id
        token, _ = start_session(user_id, db_path=db, audit_path=audit)
        return token

    def test_session_resolves_to_the_operator(self, db: Path, audit: Path) -> None:
        token = self._login(db, audit)
        identity = resolve_session(token, db_path=db)
        assert identity is not None
        assert identity.username == "operator1"

    def test_only_the_token_hash_is_stored(self, db: Path, audit: Path) -> None:
        token = self._login(db, audit)
        with session_scope(db) as session:
            stored = session.query(UserSession).one().token_hash
        assert stored != token
        assert len(stored) == 64  # sha256 hex

    def test_unknown_token_resolves_to_nothing(self, db: Path, audit: Path) -> None:
        self._login(db, audit)
        assert resolve_session("not-a-real-token", db_path=db) is None

    def test_missing_token_resolves_to_nothing(self, db: Path) -> None:
        assert resolve_session(None, db_path=db) is None
        assert resolve_session("", db_path=db) is None

    def test_logout_revokes_the_session(self, db: Path, audit: Path) -> None:
        token = self._login(db, audit)
        end_session(token, db_path=db, audit_path=audit)
        assert resolve_session(token, db_path=db) is None

    def test_expired_session_is_refused(self, db: Path, audit: Path) -> None:
        token = self._login(db, audit)
        with session_scope(db) as session:
            session.query(UserSession).one().expires_at = datetime.now(
                timezone.utc
            ) - timedelta(minutes=1)
        assert resolve_session(token, db_path=db) is None

    def test_session_dies_with_a_disabled_account(self, db: Path, audit: Path) -> None:
        token = self._login(db, audit)
        with session_scope(db) as session:
            session.query(User).one().is_active = False
        assert resolve_session(token, db_path=db) is None

    def test_purge_removes_long_expired_sessions_only(
        self, db: Path, audit: Path
    ) -> None:
        token = self._login(db, audit)
        assert purge_expired_sessions(db) == 0
        with session_scope(db) as session:
            session.query(UserSession).one().expires_at = datetime.now(
                timezone.utc
            ) - timedelta(days=3)
        assert purge_expired_sessions(db) == 1
        assert resolve_session(token, db_path=db) is None

    def test_login_event_is_audited_without_the_token(
        self, db: Path, audit: Path
    ) -> None:
        token = self._login(db, audit)
        text = audit.read_text()
        assert "auth.login" in text
        assert token not in text


class TestAccountDeletion:
    """Deleting an account revokes access without rewriting history."""

    def _two_accounts(self, db: Path, audit: Path) -> None:
        create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        create_user("operator2", "Another-Pass-9", db_path=db, audit_path=audit)

    def test_account_and_sessions_are_removed(self, db: Path, audit: Path) -> None:
        from backend.auth.service import delete_user

        self._two_accounts(db, audit)
        identity = authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        token, _ = start_session(identity, db_path=db, audit_path=audit)
        assert resolve_session(token, db_path=db) is not None

        result = delete_user("operator1", db_path=db, audit_path=audit)
        assert result["sessions_revoked"] == 1

        # The session no longer authenticates, and the account cannot log in.
        assert resolve_session(token, db_path=db) is None
        with pytest.raises(AuthError):
            authenticate("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            assert session.query(User).filter_by(username="operator1").one_or_none() is None
            assert session.query(UserSession).count() == 0

    def test_other_accounts_are_untouched(self, db: Path, audit: Path) -> None:
        from backend.auth.service import delete_user

        self._two_accounts(db, audit)
        delete_user("operator1", db_path=db, audit_path=audit)
        assert authenticate("operator2", "Another-Pass-9", db_path=db, audit_path=audit)

    def test_history_is_preserved_and_the_chain_still_verifies(
        self, db: Path, audit: Path
    ) -> None:
        from backend.core.audit import AuditLog

        from backend.auth.service import delete_user

        self._two_accounts(db, audit)
        before = [e for e in AuditLog(audit).entries() if e.actor == "operator1"]
        assert before, "the account should already have audit history"

        delete_user("operator1", db_path=db, audit_path=audit)

        log = AuditLog(audit)
        after = [e for e in log.entries() if e.actor == "operator1"]
        # Every historical entry survives, plus the deletion event itself.
        assert len(after) == len(before) + 1
        assert after[-1].action == "auth.account_deleted"
        # And the hash chain is intact: nothing was rewritten.
        assert log.verify_chain().valid is True

    def test_unknown_account_is_refused(self, db: Path, audit: Path) -> None:
        from backend.auth.service import delete_user

        self._two_accounts(db, audit)
        with pytest.raises(AuthError, match="No account named"):
            delete_user("nobody-here", db_path=db, audit_path=audit)

    def test_the_last_account_cannot_be_deleted(self, db: Path, audit: Path) -> None:
        from backend.auth.service import delete_user

        create_user("only-one", "Correct-Horse-9", db_path=db, audit_path=audit)
        with pytest.raises(AuthError, match="only operator account"):
            delete_user("only-one", db_path=db, audit_path=audit)
        assert user_count(db) == 1


class TestDeletingAnAccountThatOwnsData:
    """The foreign keys are enforced, so owned rows must be dealt with.

    Before this was handled, deleting an account that owned a target or a scan
    raised IntegrityError out of delete_user. /settings/delete catches only
    AuthError, so "delete my account" returned a 500 for every operator who had
    ever used the tool — only an account that had done nothing could be removed.
    """

    def _populated(self, db: Path, audit: Path):
        from backend.core.user_targets import add_user_target
        from backend.database.models import ScanSession

        create_user("keeper", "Correct-Horse-9", db_path=db, audit_path=audit)
        doomed = create_user("doomed", "Another-Pass-9", db_path=db, audit_path=audit)
        add_user_target(
            doomed.id, "192.168.77.5", name="laptop", confirmed=True, db_path=db
        )
        with session_scope(db) as session:
            session.add(
                ScanSession(
                    session_id="owned-scan",
                    target_spec="192.168.77.5/32",
                    profile="lan_service_detect",
                    scan_kind="assessment",
                    status="completed",
                    initiated_by="doomed",
                    user_id=doomed.id,
                )
            )
        return doomed

    def test_an_account_with_targets_and_scans_can_be_deleted(
        self, db: Path, audit: Path
    ) -> None:
        from backend.auth.service import delete_user

        self._populated(db, audit)
        result = delete_user("doomed", db_path=db, audit_path=audit)
        assert result["targets_removed"] == 1
        assert result["records_disowned"] >= 1

    def test_the_scan_survives_with_its_attribution(self, db: Path, audit: Path) -> None:
        from backend.auth.service import delete_user
        from backend.database.models import ScanSession

        self._populated(db, audit)
        delete_user("doomed", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            row = session.query(ScanSession).filter_by(session_id="owned-scan").one()
            assert row.user_id is None, "the row must be disowned, not reassigned"
            assert row.initiated_by == "doomed", "attribution must survive"

    def test_the_authorization_scope_does_not_outlive_the_account(
        self, db: Path, audit: Path
    ) -> None:
        # A target is a standing permission to touch a network. It must not
        # survive the operator who confirmed it.
        from backend.auth.service import delete_user
        from backend.database.models import Target

        self._populated(db, audit)
        delete_user("doomed", db_path=db, audit_path=audit)
        with session_scope(db) as session:
            assert session.query(Target).count() == 0

    def test_the_next_account_does_not_inherit_the_reused_id(
        self, db: Path, audit: Path
    ) -> None:
        # users.id is a SQLite rowid with no AUTOINCREMENT, so the next account
        # created is handed the deleted one's id straight back. Retained rows
        # still pointing at that id would surface inside a stranger's account:
        # every user-scoped query filters on user_id == uid, and it would match.
        from backend.auth.service import delete_user
        from backend.core.user_targets import list_user_targets
        from backend.database.models import ScanSession

        doomed = self._populated(db, audit)
        delete_user("doomed", db_path=db, audit_path=audit)

        newcomer = create_user("newcomer", "Third-Pass-9", db_path=db, audit_path=audit)
        assert newcomer.id == doomed.id, "precondition: SQLite reuses the rowid"

        assert list_user_targets(newcomer.id, db_path=db) == []
        with session_scope(db) as session:
            visible = (
                session.query(ScanSession)
                .filter(ScanSession.user_id == newcomer.id)
                .count()
            )
        assert visible == 0, "the newcomer must not inherit the deleted account's scans"


class TestEmail:
    """Email is validated and unique (multi-tenant identity)."""

    def test_valid_email_is_stored_lowercased(self, db, audit) -> None:
        from backend.database.models import User

        identity = create_user(
            "operator1", "Correct-Horse-9", email="Op@Example.COM",
            db_path=db, audit_path=audit,
        )
        assert identity.email == "op@example.com"
        with session_scope(db) as s:
            assert s.get(User, identity.id).email == "op@example.com"

    def test_duplicate_email_is_refused(self, db, audit) -> None:
        create_user("operator1", "Correct-Horse-9", email="dup@example.com", db_path=db, audit_path=audit)
        with pytest.raises(AuthError):
            create_user("operator2", "Correct-Horse-9", email="DUP@example.com", db_path=db, audit_path=audit)

    @pytest.mark.parametrize("bad", ["notanemail", "no@domain", "@nolocal.com", "spaces in@x.com", ""])
    def test_invalid_email_is_refused(self, db, audit, bad: str) -> None:
        with pytest.raises(AuthError):
            create_user("operator1", "Correct-Horse-9", email=bad, db_path=db, audit_path=audit)

    def test_email_optional_for_legacy_callers(self, db, audit) -> None:
        # create_user without email still works (existing tests, backfilled accts).
        identity = create_user("operator1", "Correct-Horse-9", db_path=db, audit_path=audit)
        assert identity.email is None
