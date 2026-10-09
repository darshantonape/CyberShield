"""Delivery of password-reset links.

CyberShield had no email service before this module, so none is assumed. The
reset link reaches the operator in exactly one of these ways:

  * SMTP, when `CYBERSHIELD_SMTP_HOST` is set. Uses the standard library's
    smtplib; no new dependency. Credentials come only from the environment.
  * The server console, ONLY when `CYBERSHIELD_ENV=development`. The link is
    printed to stderr so a local operator can test the flow without a mail
    server. It is never rendered in a page or returned in a response.
  * Nowhere. With neither configured, the request is recorded and the link is
    discarded; a warning (without the token) says why.

The raw token is never written to the audit log in any mode.
"""

from __future__ import annotations

import os
import smtplib
import ssl
import sys
from dataclasses import dataclass
from email.message import EmailMessage

from backend.core.config import PROJECT_ROOT, _load_dotenv

__all__ = ["DeliveryError", "MailSettings", "load_mail_settings", "deliver_reset_link"]

SMTP_TIMEOUT_SECONDS = 10


class DeliveryError(Exception):
    """The link could not be delivered. The message never contains the token."""


@dataclass(frozen=True)
class MailSettings:
    development: bool
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_from: str | None
    smtp_security: str  # "starttls" | "ssl" | "none"
    public_base_url: str | None


def load_mail_settings() -> MailSettings:
    """Read delivery settings from the environment (and .env, which never wins)."""
    _load_dotenv(PROJECT_ROOT / ".env")

    raw_port = os.environ.get("CYBERSHIELD_SMTP_PORT", "").strip()
    security = os.environ.get("CYBERSHIELD_SMTP_SECURITY", "starttls").strip().lower()
    if security not in ("starttls", "ssl", "none"):
        security = "starttls"
    try:
        port = int(raw_port) if raw_port else (465 if security == "ssl" else 587)
    except ValueError:
        port = 587

    base = os.environ.get("CYBERSHIELD_PUBLIC_BASE_URL", "").strip().rstrip("/") or None

    return MailSettings(
        development=os.environ.get("CYBERSHIELD_ENV", "").strip().lower() == "development",
        smtp_host=os.environ.get("CYBERSHIELD_SMTP_HOST", "").strip() or None,
        smtp_port=port,
        smtp_username=os.environ.get("CYBERSHIELD_SMTP_USERNAME", "").strip() or None,
        smtp_password=os.environ.get("CYBERSHIELD_SMTP_PASSWORD") or None,
        smtp_from=os.environ.get("CYBERSHIELD_SMTP_FROM", "").strip() or None,
        smtp_security=security,
        public_base_url=base,
    )


def _console(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _send_smtp(settings: MailSettings, to_address: str, reset_url: str, ttl_minutes: int) -> None:
    if not settings.smtp_from:
        raise DeliveryError("CYBERSHIELD_SMTP_FROM is not set.")

    message = EmailMessage()
    message["Subject"] = "Reset your CyberShield password"
    message["From"] = settings.smtp_from
    message["To"] = to_address
    message.set_content(
        "A password reset was requested for your CyberShield account.\n\n"
        f"Open this link to choose a new password (valid for {ttl_minutes} minutes, "
        f"single use):\n\n{reset_url}\n\n"
        "If you did not request this, ignore this email. Your password has not "
        "been changed.\n"
    )

    context = ssl.create_default_context()
    try:
        if settings.smtp_security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port,
                timeout=SMTP_TIMEOUT_SECONDS, context=context,
            )
        else:
            client = smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
            )
        with client:
            if settings.smtp_security == "starttls":
                client.starttls(context=context)
            if settings.smtp_username:
                client.login(settings.smtp_username, settings.smtp_password or "")
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        # Class name only: SMTP error text can echo back message content.
        raise DeliveryError(f"SMTP delivery failed ({type(exc).__name__}).") from None


def deliver_reset_link(
    *,
    username: str,
    email: str | None,
    reset_url: str,
    ttl_minutes: int,
    settings: MailSettings | None = None,
) -> str:
    """Deliver a reset link. Returns the channel used: "smtp", "console" or "none".

    Raises:
        DeliveryError: SMTP is configured but sending failed, or the account
            has no email address and there is no development fallback.
    """
    cfg = settings or load_mail_settings()
    channel = "none"

    if cfg.development:
        _console(
            "[cybershield] DEVELOPMENT MODE - password reset link for "
            f"{username!r} (expires in {ttl_minutes} min):\n  {reset_url}"
        )
        channel = "console"

    if cfg.smtp_host:
        if not email:
            if channel == "console":
                return channel
            raise DeliveryError("The account has no email address on file.")
        _send_smtp(cfg, email, reset_url, ttl_minutes)
        return "smtp"

    if channel == "none":
        _console(
            "[cybershield] Password reset requested but no delivery channel is "
            "configured. Set CYBERSHIELD_SMTP_HOST (or CYBERSHIELD_ENV=development "
            "for local testing). The link was discarded."
        )
    return channel
