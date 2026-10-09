"""Forgot-password: issuing and redeeming single-use reset tokens.

Built on the same primitives as sessions in `backend.auth.service` rather than
a parallel scheme:

  * The token is `secrets.token_urlsafe(32)` — 256 bits from the OS CSPRNG,
    unrelated to the username, user id, password or clock. Only its SHA-256
    (`_hash_token`, the session-token hash) is stored.
  * The new password goes through `validate_password` and `hash_password`, so
    the rules and bcrypt cost are exactly those of signup and password change.
  * A successful reset revokes EVERY session for the account, including any
    the requester might hold. That is stricter than a password change (which
    keeps the current session) on purpose: a reset is what an operator does
    when they think someone else may be signed in as them.

Account enumeration: `request_password_reset` returns nothing and raises
nothing. The route runs it after the response has been produced, so the page,
status code, redirect and response time are identical whether or not the
account exists; throttling of an account is equally silent.
"""

from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from collections import deque
from datetime import timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

from sqlalchemy import update

from backend.auth.mailer import DeliveryError, MailSettings, deliver_reset_link, load_mail_settings
from backend.auth.service import (
    AuthError,
    _audit,
    _hash_token,
    _utcnow,
    hash_password,
    validate_password,
)
from backend.database.models import PasswordResetToken, User, UserSession
from backend.database.session import session_scope

__all__ = [
    "RESET_TTL_MINUTES",
    "ResetError",
    "RateLimiter",
    "request_password_reset",
    "reset_token_status",
    "reset_password",
    "reset_error_message",
]

RESET_TTL_MINUTES = 30
# Per account: at most this many links issued per window. Excess requests are
# accepted and silently not acted on, so the limit cannot reveal the account.
ACCOUNT_MAX_REQUESTS = 3
ACCOUNT_WINDOW_MINUTES = 15
# token_urlsafe(32) is 43 characters; anything far longer is not ours and is
# rejected before hashing.
_MAX_TOKEN_LENGTH = 128


class ResetError(AuthError):
    """A reset was refused. `reason` is one of: invalid, expired, used."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


_MESSAGES = {
    "invalid": "This password reset link is invalid. Request a new one below.",
    "expired": "This password reset link has expired. Request a new one below.",
    "used": "This password reset link has already been used. Request a new one below.",
}


def reset_error_message(reason: str) -> str:
    return _MESSAGES.get(reason, _MESSAGES["invalid"])


class RateLimiter:
    """In-process sliding-window limiter keyed by client address.

    Per-process and in-memory by design: CyberShield runs as a single local
    uvicorn process, and this needs no new dependency or table. It resets on
    restart, which is acceptable for a throttle (the per-account limit, which
    is stored in the database, does not).
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, key: str | None) -> bool:
        """True if the key is at the limit. Does not record an attempt."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.get(key or "unknown")
            if not hits:
                return False
            while hits and now - hits[0] > self.window:
                hits.popleft()
            return len(hits) >= self.limit

    def hit(self, key: str | None) -> bool:
        """Record an attempt. Returns False if the key is over the limit."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key or "unknown", deque())
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            # Keep the map from growing without bound under a spray of addresses.
            if len(self._hits) > 10_000:
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _is_loopback_base(base_url: str) -> bool:
    host = urlparse(base_url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _reset_base_url(request_base_url: str | None, settings: MailSettings) -> str | None:
    """Choose the origin the reset link points at.

    An explicit CYBERSHIELD_PUBLIC_BASE_URL always wins. Otherwise the request's
    own origin is used only when it is loopback: trusting an arbitrary Host
    header would let anyone make CyberShield email a victim a genuine token on
    a link pointing at the attacker's server.
    """
    if settings.public_base_url:
        return settings.public_base_url
    if request_base_url and _is_loopback_base(request_base_url):
        return request_base_url.rstrip("/")
    return None


# ---------------------------------------------------------------------------
# Request a reset
# ---------------------------------------------------------------------------


def request_password_reset(
    identifier: str,
    *,
    request_base_url: str | None,
    client_host: str | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    settings: MailSettings | None = None,
) -> None:
    """Issue and deliver a reset link if `identifier` names an active account.

    `identifier` is an email address or a username. Never raises and returns
    nothing, so no caller can turn it into an enumeration oracle; every outcome
    is recorded in the audit log instead.
    """
    cfg = settings or load_mail_settings()
    ident = (identifier or "").strip().lower()[:254]
    audit = _audit(audit_path)

    if not ident:
        return

    token = secrets.token_urlsafe(32)
    now = _utcnow()
    expires = now + timedelta(minutes=RESET_TTL_MINUTES)
    outcome: str = "no_account"
    username: str | None = None
    email: str | None = None

    try:
        with session_scope(db_path) as db:
            column = User.email if "@" in ident else User.username
            user = db.query(User).filter(column == ident).one_or_none()
            if user is not None and user.is_active:
                username, email = user.username, user.email
                window_start = now - timedelta(minutes=ACCOUNT_WINDOW_MINUTES)
                recent = (
                    db.query(PasswordResetToken)
                    .filter(PasswordResetToken.user_id == user.id)
                    .filter(PasswordResetToken.created_at >= window_start)
                    .count()
                )
                if recent >= ACCOUNT_MAX_REQUESTS:
                    outcome = "throttled"
                else:
                    # Only the newest link works: earlier unused ones are spent.
                    db.execute(
                        update(PasswordResetToken)
                        .where(PasswordResetToken.user_id == user.id)
                        .where(PasswordResetToken.used_at.is_(None))
                        .values(used_at=now)
                    )
                    db.add(
                        PasswordResetToken(
                            token_hash=_hash_token(token),
                            user_id=user.id,
                            created_at=now,
                            expires_at=expires,
                            client_host=(client_host or "")[:45] or None,
                        )
                    )
                    outcome = "issued"
            elif user is not None:
                outcome = "disabled"
    except Exception as exc:  # noqa: BLE001 - must never surface to the requester
        audit.record(
            "auth.password_reset_requested",
            outcome="failure",
            actor="unknown",
            detail={"client_host": client_host, "error": type(exc).__name__},
        )
        return

    if outcome != "issued":
        audit.record(
            "auth.password_reset_requested",
            outcome="refused",
            actor=username or "unknown",
            detail={
                "username": username,
                "client_host": client_host,
                "reason": {
                    "no_account": "no matching account",
                    "disabled": "account disabled",
                    "throttled": "too many reset requests for this account",
                }[outcome],
            },
        )
        return

    base = _reset_base_url(request_base_url, cfg)
    channel = "none"
    error: str | None = None
    if base is None:
        error = (
            "No trusted base URL for the reset link: set CYBERSHIELD_PUBLIC_BASE_URL "
            "when CyberShield is not reached via localhost."
        )
    else:
        url = f"{base}/reset-password?{urlencode({'token': token})}"
        try:
            channel = deliver_reset_link(
                username=username or "",
                email=email,
                reset_url=url,
                ttl_minutes=RESET_TTL_MINUTES,
                settings=cfg,
            )
        except DeliveryError as exc:
            error = str(exc)

    audit.record(
        "auth.password_reset_requested",
        outcome="success" if error is None and channel != "none" else "failure",
        actor=username or "unknown",
        # Never the token, the link, or the token hash.
        detail={
            "username": username,
            "client_host": client_host,
            "delivery": channel,
            "expires_at": expires.isoformat(timespec="seconds"),
            **({"error": error} if error else {}),
        },
    )
    if error:
        print(f"[cybershield] Password reset link not delivered: {error}", flush=True)


# ---------------------------------------------------------------------------
# Redeem a reset
# ---------------------------------------------------------------------------


def _classify(row: PasswordResetToken | None, user: User | None, now) -> str | None:
    if row is None or user is None or not user.is_active:
        return "invalid"
    if row.used_at is not None:
        return "used"
    if _aware(row.expires_at) <= now:
        return "expired"
    return None


def reset_token_status(token: str | None, *, db_path: Path | None = None) -> str | None:
    """Return None if the token is currently redeemable, else the refusal reason.

    Read-only: showing the form does not consume the token.
    """
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return "invalid"
    with session_scope(db_path) as db:
        row = (
            db.query(PasswordResetToken)
            .filter_by(token_hash=_hash_token(token))
            .one_or_none()
        )
        user = db.get(User, row.user_id) if row is not None else None
        return _classify(row, user, _utcnow())


def reset_password(
    token: str | None,
    new_password: str,
    *,
    client_host: str | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> int:
    """Set a new password using a reset token. Returns the sessions revoked.

    Raises:
        AuthError: the new password fails the standard rules (token untouched).
        ResetError: the token is invalid, expired or already used.
    """
    validate_password(new_password)
    new_hash = hash_password(new_password)

    reason: str | None = None
    username: str | None = None
    revoked = 0

    if not token or len(token) > _MAX_TOKEN_LENGTH:
        reason = "invalid"
    else:
        with session_scope(db_path) as db:
            now = _utcnow()
            row = (
                db.query(PasswordResetToken)
                .filter_by(token_hash=_hash_token(token))
                .one_or_none()
            )
            user = db.get(User, row.user_id) if row is not None else None
            reason = _classify(row, user, now)
            if reason is None:
                # Conditional spend: of two concurrent redemptions, exactly one
                # sees rowcount 1. The other is refused as "used".
                spent = db.execute(
                    update(PasswordResetToken)
                    .where(PasswordResetToken.id == row.id)
                    .where(PasswordResetToken.used_at.is_(None))
                    .values(used_at=now)
                ).rowcount
                if spent != 1:
                    reason = "used"
                else:
                    username = user.username
                    user.password_hash = new_hash
                    user.failed_logins = 0
                    # Any other outstanding link for this account dies with it.
                    db.execute(
                        update(PasswordResetToken)
                        .where(PasswordResetToken.user_id == user.id)
                        .where(PasswordResetToken.used_at.is_(None))
                        .values(used_at=now)
                    )
                    revoked = db.execute(
                        update(UserSession)
                        .where(UserSession.user_id == user.id)
                        .where(UserSession.revoked_at.is_(None))
                        .values(revoked_at=now)
                    ).rowcount
            elif user is not None:
                username = user.username

    audit = _audit(audit_path)
    if reason is not None:
        # Recorded after the transaction, as authenticate() does.
        audit.record(
            "auth.password_reset_failed",
            outcome="refused",
            actor=username or "unknown",
            detail={"username": username, "client_host": client_host, "reason": reason},
        )
        raise ResetError(reason, _MESSAGES[reason])

    audit.record(
        "auth.password_reset",
        outcome="success",
        actor=username,
        detail={
            "username": username,
            "client_host": client_host,
            "sessions_revoked": revoked,
        },
    )
    return revoked
