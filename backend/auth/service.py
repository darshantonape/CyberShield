"""Operator accounts and session handling.

Design notes that matter for the write-up:

  * Passwords are hashed with bcrypt (cost 12). There is no column, log line, or
    template that can hold a plaintext password, and `password_hash` is never
    placed in a template context or an audit detail.
  * A browser holds an opaque 256-bit random token; the database stores only its
    SHA-256. A stolen database therefore yields no usable session cookies.
  * Sessions are database rows, so logout is a real revocation rather than the
    client being asked to forget a signed cookie. It also means no additional
    dependency (`itsdangerous` is not installed) and no server-side secret to
    manage.
  * Every authentication event is written to the hash-chained audit log. The
    detail never contains the password, the token, or the token hash.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import bcrypt

from backend.core.audit import AuditLog
from backend.core.config import DATA_DIR
from backend.database.models import (
    DiscoveredHost,
    DiscoveredService,
    Job,
    RemediationAction,
    ScanSession,
    Target,
    User,
    UserSession,
    Vulnerability,
)
from backend.database.session import session_scope

__all__ = [
    "AuthError",
    "SESSION_COOKIE",
    "SESSION_TTL_HOURS",
    "AuthenticatedUser",
    "create_user",
    "authenticate",
    "start_session",
    "resolve_session",
    "end_session",
    "delete_user",
    "update_profile",
    "change_password",
    "list_active_sessions",
    "revoke_other_sessions",
    "user_count",
    "validate_password",
    "validate_username",
]

SESSION_COOKIE = "cybershield_session"
SESSION_TTL_HOURS = 8
BCRYPT_ROUNDS = 12
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128  # bcrypt truncates past 72 bytes; reject rather than silently cut
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32

# A real bcrypt hash at the same cost factor, verified against when the account
# does not exist. Without it, "no such user" would return far faster than
# "wrong password" and the login form would become an account-enumeration
# oracle. The plaintext behind it is fixed and meaningless.
_TIMING_EQUALIZER_HASH = "$2b$12$U7sN82mhDW6F1M2YULOx0e6.P.cdbEEolmLGqGzkdbJMRY1yLXi/6"


class AuthError(Exception):
    """Raised when a credential or account operation is refused.

    The message is written to be shown to the operator directly, so it never
    reveals whether a username exists.
    """


@dataclass(frozen=True)
class AuthenticatedUser:
    """The identity attached to a request. Carries no secret material."""

    id: int
    username: str
    full_name: str | None
    role: str
    session_expires_at: datetime
    email: str | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _audit(audit_path: Path | None = None) -> AuditLog:
    return AuditLog(audit_path or (DATA_DIR / "audit.jsonl"))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Credential rules
# ---------------------------------------------------------------------------


def validate_username(value: str) -> str:
    """Normalise and check a username."""
    username = (value or "").strip().lower()
    if len(username) < MIN_USERNAME_LENGTH:
        raise AuthError(f"Username must be at least {MIN_USERNAME_LENGTH} characters.")
    if len(username) > MAX_USERNAME_LENGTH:
        raise AuthError(f"Username must be at most {MAX_USERNAME_LENGTH} characters.")
    if not all(c.isalnum() or c in "._-" for c in username):
        raise AuthError(
            "Username may contain letters, digits, dot, underscore and hyphen only."
        )
    if not username[0].isalnum():
        raise AuthError("Username must start with a letter or digit.")
    return username


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email(value: str) -> str:
    """Normalise and check an email address.

    Deliberately a shape check, not a deliverability check: a local research
    tool cannot send mail, so the goal is to reject obviously-malformed input
    and keep a consistent, lower-cased unique key — not to prove the mailbox
    exists.
    """
    email = (value or "").strip().lower()
    if not email:
        raise AuthError("An email address is required.")
    if len(email) > 254:
        raise AuthError("Email address is too long.")
    if not _EMAIL_RE.match(email):
        raise AuthError("Enter a valid email address, e.g. name@example.com.")
    return email


def validate_password(value: str) -> str:
    """Check a password against the minimum rules.

    Deliberately short: a length floor and a character-variety floor. Elaborate
    composition rules push operators towards predictable substitutions without
    measurably improving strength.
    """
    password = value or ""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at most {MAX_PASSWORD_LENGTH} bytes.")
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 2:
        raise AuthError(
            "Password must combine at least two of: lowercase, uppercase, "
            "digits, symbols."
        )
    return password


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("ascii")


def _password_matches(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        # A corrupt or non-bcrypt hash must fail closed, not raise.
        return False


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def user_count(db_path: Path | None = None) -> int:
    with session_scope(db_path) as db:
        return db.query(User).count()


def create_user(
    username: str,
    password: str,
    *,
    email: str | None = None,
    full_name: str | None = None,
    role: str = "operator",
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> AuthenticatedUser:
    """Create an account. Raises AuthError if the input, name or email is unusable.

    `email` is optional at this layer so existing callers and tests keep working;
    the signup route passes and requires it. When given it is validated and must
    be unique.
    """
    name = validate_username(username)
    validate_password(password)
    clean_email = validate_email(email) if email is not None else None
    if role not in ("operator", "admin"):
        raise AuthError(f"Unknown role {role!r}.")

    digest = hash_password(password)

    with session_scope(db_path) as db:
        if db.query(User).filter_by(username=name).one_or_none() is not None:
            raise AuthError(f"Username {name!r} is already taken.")
        if clean_email is not None and (
            db.query(User).filter_by(email=clean_email).one_or_none() is not None
        ):
            raise AuthError(f"An account with the email {clean_email!r} already exists.")
        user = User(
            username=name,
            email=clean_email,
            password_hash=digest,
            full_name=(full_name or "").strip() or None,
            role=role,
            is_active=True,
        )
        db.add(user)
        db.flush()
        identity = AuthenticatedUser(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            session_expires_at=_utcnow(),
        )

    _audit(audit_path).record(
        "auth.signup",
        outcome="success",
        actor=name,
        # No password, no hash. Only the facts needed for the trail.
        detail={"username": name, "role": role, "has_email": clean_email is not None},
    )
    return identity


def authenticate(
    username: str,
    password: str,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> int:
    """Verify credentials and return the user id.

    Raises:
        AuthError: on any failure. The message is identical for "no such user"
            and "wrong password" so the form cannot be used to enumerate
            accounts.
    """
    generic = AuthError("Incorrect username or password.")
    name = (username or "").strip().lower()

    # The refusal is raised AFTER the transaction closes. Raising inside
    # `session_scope` rolls the transaction back, which silently discarded the
    # failed-login counter increment — the count stayed at zero no matter how
    # many attempts were made. Caught by test_failed_logins_are_counted_then_reset.
    failure: tuple[AuthError, dict[str, Any]] | None = None
    user_id: int | None = None

    with session_scope(db_path) as db:
        user = db.query(User).filter_by(username=name).one_or_none()

        if user is None:
            # Spend the same time as a real check so the response time does not
            # disclose whether the account exists.
            _password_matches(password, _TIMING_EQUALIZER_HASH)
            failure = (generic, {"username": name, "reason": "no such account"})
        elif not user.is_active:
            failure = (
                AuthError("This account is disabled. Ask an administrator."),
                {"username": name, "reason": "account disabled"},
            )
        elif not _password_matches(password, user.password_hash):
            user.failed_logins = (user.failed_logins or 0) + 1
            failure = (
                generic,
                {
                    "username": name,
                    "reason": "incorrect password",
                    "consecutive_failures": user.failed_logins,
                },
            )
        else:
            user.failed_logins = 0
            user.last_login_at = _utcnow()
            user_id = user.id

    if failure is not None:
        error, detail = failure
        _audit(audit_path).record(
            "auth.login_failed",
            outcome="refused",
            actor=name or "unknown",
            # Contains the username and the reason. Never the password.
            detail=detail,
        )
        raise error

    assert user_id is not None  # exactly one branch above sets one of the two
    return user_id


def start_session(
    user_id: int,
    *,
    user_agent: str | None = None,
    client_host: str | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> tuple[str, datetime]:
    """Open a session and return (cookie token, expiry).

    The raw token is returned to the caller once and never stored.
    """
    token = secrets.token_urlsafe(32)
    expires = _utcnow() + timedelta(hours=SESSION_TTL_HOURS)

    with session_scope(db_path) as db:
        user = db.get(User, user_id)
        if user is None:
            raise AuthError("Account no longer exists.")
        db.add(
            UserSession(
                token_hash=_hash_token(token),
                user_id=user_id,
                expires_at=expires,
                last_seen_at=_utcnow(),
                user_agent=(user_agent or "")[:255] or None,
                client_host=(client_host or "")[:45] or None,
            )
        )
        username = user.username

    _audit(audit_path).record(
        "auth.login",
        outcome="success",
        actor=username,
        detail={
            "username": username,
            "client_host": client_host,
            "session_expires_at": expires.isoformat(timespec="seconds"),
        },
    )
    return token, expires


def resolve_session(
    token: str | None, *, db_path: Path | None = None
) -> AuthenticatedUser | None:
    """Return the identity for a cookie token, or None.

    Fails closed on every abnormal case: missing token, unknown token, revoked
    session, expired session, deleted or disabled account.
    """
    if not token:
        return None

    digest = _hash_token(token)
    now = _utcnow()

    with session_scope(db_path) as db:
        row = db.query(UserSession).filter_by(token_hash=digest).one_or_none()
        if row is None or row.revoked_at is not None:
            return None

        # Rows written before this column was timezone-aware may come back
        # naive; compare in UTC either way rather than raising.
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            return None

        user = db.get(User, row.user_id)
        if user is None or not user.is_active:
            return None

        row.last_seen_at = now
        return AuthenticatedUser(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            session_expires_at=expires,
        )


def end_session(
    token: str | None,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> None:
    """Revoke a session. Silently succeeds if the token is already unusable."""
    if not token:
        return

    digest = _hash_token(token)
    username: str | None = None

    with session_scope(db_path) as db:
        row = db.query(UserSession).filter_by(token_hash=digest).one_or_none()
        if row is None:
            return
        if row.revoked_at is None:
            row.revoked_at = _utcnow()
        user = db.get(User, row.user_id)
        username = user.username if user else None

    if username:
        _audit(audit_path).record(
            "auth.logout", outcome="success", actor=username, detail={"username": username}
        )


def delete_user(
    username: str,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> dict[str, int | str]:
    """Delete an operator account and revoke all of its sessions.

    What is removed: the `users` row, every `user_sessions` row belonging to it
    — those are live credentials and must not outlive the account — and the
    account's own `targets` rows. A private authorization scope is a standing
    permission to touch a network; it must not survive the operator who gave it.

    What is deliberately KEPT: every historical record naming the account.
    Audit entries, `scan_sessions.initiated_by` and
    `remediation_actions.operator` are the record of what was actually done, and
    deleting an account must not rewrite history. The audit log is append-only
    and hash-chained, so removing entries would also break chain verification
    and make the whole log unverifiable. Those columns are plain strings rather
    than foreign keys precisely so attribution survives account deletion.

    Those retained rows are DISOWNED rather than left pointing at the deleted
    id: `user_id` is set to NULL. Two reasons, and both are bugs that were
    observed rather than anticipated.

    First, the foreign keys are enforced (`PRAGMA foreign_keys=ON`), so
    deleting a user who owned any row raised IntegrityError — which the
    /settings/delete route does not catch, so "delete my account" returned a
    500 for every operator who had ever added a target or run a scan. Only an
    account that had done nothing at all could be deleted.

    Second, `users.id` is a SQLite rowid with no AUTOINCREMENT, so the next
    account created after the highest-id one is deleted is handed that same id
    back. Retained rows still pointing at it would have surfaced inside a
    stranger's account as their own scans and findings — every user-scoped
    query filters on `user_id == uid`, and the new user's uid would have
    matched. NULL matches no account, so the history stays in the database and
    in the audit log while belonging to nobody.

    Refuses to delete the last remaining account: an installation with no
    operator cannot be signed into, and the signup page would then let anyone
    who can reach the port create the first account.

    Returns:
        A summary of what was removed, for reporting.

    Raises:
        AuthError: if the account does not exist, or is the only one left.
    """
    name = (username or "").strip().lower()

    with session_scope(db_path) as db:
        user = db.query(User).filter_by(username=name).one_or_none()
        if user is None:
            raise AuthError(f"No account named {name!r}.")

        if db.query(User).count() == 1:
            raise AuthError(
                f"Refusing to delete {name!r}: it is the only operator account. "
                "Create another account first, or the installation would be "
                "left with no way to sign in."
            )

        sessions = db.query(UserSession).filter_by(user_id=user.id).all()
        removed_sessions = len(sessions)
        for row in sessions:
            db.delete(row)

        # The account's own authorization scope goes with the account.
        targets = db.query(Target).filter_by(user_id=user.id).all()
        removed_targets = len(targets)
        for row in targets:
            db.delete(row)

        # Operational history is disowned, not deleted. See the docstring.
        disowned = 0
        for model in (
            ScanSession,
            DiscoveredHost,
            DiscoveredService,
            Vulnerability,
            RemediationAction,
            Job,
        ):
            disowned += (
                db.query(model)
                .filter(model.user_id == user.id)
                .update({model.user_id: None}, synchronize_session=False)
            )

        db.delete(user)

    _audit(audit_path).record(
        "auth.account_deleted",
        outcome="success",
        actor=name,
        detail={
            "username": name,
            "sessions_revoked": removed_sessions,
            "targets_removed": removed_targets,
            "records_disowned": disowned,
            "note": (
                "Account, its sessions and its authorized targets removed. "
                "Historical audit, scan and remediation records naming this "
                "operator are retained but no longer owned by any account: "
                "deleting an account does not rewrite what was done, and does "
                "not hand that history to whoever signs up next."
            ),
        },
    )
    return {
        "username": name,
        "sessions_revoked": removed_sessions,
        "targets_removed": removed_targets,
        "records_disowned": disowned,
    }


def update_profile(
    user_id: int,
    *,
    full_name: str | None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> AuthenticatedUser:
    """Update an operator's own editable profile fields (currently: full name).

    The username is deliberately immutable: it is the attribution key written
    into scan, remediation and audit records, and renaming it would orphan that
    history. The role is not self-editable either.
    """
    clean = (full_name or "").strip()[:128] or None
    with session_scope(db_path) as db:
        user = db.get(User, user_id)
        if user is None:
            raise AuthError("Account no longer exists.")
        changed = user.full_name != clean
        user.full_name = clean
        identity = AuthenticatedUser(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            session_expires_at=_utcnow(),
        )
        username = user.username

    if changed:
        _audit(audit_path).record(
            "profile.updated",
            outcome="success",
            actor=username,
            detail={"username": username, "field": "full_name"},
        )
    return identity


def change_password(
    user_id: int,
    current_password: str,
    new_password: str,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> None:
    """Change an operator's password after verifying the current one.

    Requiring the current password means a hijacked session cannot lock the
    real operator out by silently changing it. The new password is validated
    against the same rules as signup. Neither password, nor the old or new
    hash, is ever written to the audit log.
    """
    # Validate before any DB work; an unusable new password is rejected outright.
    validate_password(new_password)
    new_hash = hash_password(new_password)

    username: str | None = None
    current_ok = False
    with session_scope(db_path) as db:
        user = db.get(User, user_id)
        if user is None:
            raise AuthError("Account no longer exists.")
        username = user.username
        if _password_matches(current_password, user.password_hash):
            user.password_hash = new_hash
            current_ok = True

    if not current_ok:
        # Recorded outside the transaction so the failure is logged even though
        # nothing was written — the same reason authenticate() defers its record.
        _audit(audit_path).record(
            "auth.password_change_failed",
            outcome="refused",
            actor=username or "unknown",
            detail={"username": username, "reason": "current password incorrect"},
        )
        raise AuthError("Your current password is incorrect.")

    _audit(audit_path).record(
        "auth.password_changed",
        outcome="success",
        actor=username,
        detail={"username": username},
    )


def list_active_sessions(
    user_id: int,
    *,
    current_token: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return an operator's non-revoked, unexpired sessions, newest first.

    The current session (matched by the cookie token) is flagged so the UI can
    mark "this device". No token or token hash is ever returned.
    """
    now = _utcnow()
    current_hash = _hash_token(current_token) if current_token else None
    out: list[dict[str, Any]] = []
    with session_scope(db_path) as db:
        rows = (
            db.query(UserSession)
            .filter_by(user_id=user_id)
            .filter(UserSession.revoked_at.is_(None))
            .all()
        )
        for row in rows:
            expires = row.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= now:
                continue
            out.append(
                {
                    "is_current": (
                        current_hash is not None and row.token_hash == current_hash
                    ),
                    "created_at": (
                        row.created_at.isoformat(timespec="seconds")
                        if row.created_at
                        else None
                    ),
                    "last_seen_at": (
                        row.last_seen_at.isoformat(timespec="seconds")
                        if row.last_seen_at
                        else None
                    ),
                    "expires_at": expires.isoformat(timespec="seconds"),
                    "user_agent": row.user_agent,
                    "client_host": row.client_host,
                }
            )
    out.sort(key=lambda s: s["last_seen_at"] or s["created_at"] or "", reverse=True)
    return out


def revoke_other_sessions(
    user_id: int,
    keep_token: str | None,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> int:
    """Revoke every session for this operator except the one holding keep_token.

    Used from account settings to sign other devices out. Returns the count.
    """
    keep_hash = _hash_token(keep_token) if keep_token else None
    username: str | None = None
    revoked = 0
    with session_scope(db_path) as db:
        user = db.get(User, user_id)
        username = user.username if user else None
        rows = (
            db.query(UserSession)
            .filter_by(user_id=user_id)
            .filter(UserSession.revoked_at.is_(None))
            .all()
        )
        for row in rows:
            if keep_hash is not None and row.token_hash == keep_hash:
                continue
            row.revoked_at = _utcnow()
            revoked += 1

    if revoked and username:
        _audit(audit_path).record(
            "auth.sessions_revoked",
            outcome="success",
            actor=username,
            detail={"username": username, "sessions_revoked": revoked},
        )
    return revoked


def purge_expired_sessions(db_path: Path | None = None) -> int:
    """Delete sessions that expired more than a day ago. Returns the count."""
    cutoff = _utcnow() - timedelta(days=1)
    with session_scope(db_path) as db:
        stale = db.query(UserSession).filter(UserSession.expires_at < cutoff).all()
        for row in stale:
            db.delete(row)
        return len(stale)
