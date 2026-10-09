"""Per-user authorized scan targets (the multi-tenant scope layer).

The install-wide `config/authorized_targets.yaml` remains the safety ceiling and
the only place a laboratory (remediable) target or a public opt-in can be
defined. This module is the per-operator layer on top of it: each user adds
their own private ranges, stored in the `targets` table and visible only to
them. A user-added target is always assessment-only.

Guard rails, matched to the old config-UI rules so the ceiling is never widened:
  * private IPv4 only (RFC1918 / loopback / link-local) — never a public address;
  * at most a /22 (1024 addresses), so a single form submission cannot authorize
    a sweep of a large network;
  * explicit confirmation required;
  * unique per user.
"""

from __future__ import annotations

from pathlib import Path

from backend.core.scope_admin import AUTHORIZABLE_RANGES, is_authorizable
from backend.core.validation import (
    ValidationError,
    parse_target,
)
from backend.database.models import Target
from backend.database.session import session_scope

__all__ = [
    "UserTargetError",
    "add_user_target",
    "remove_user_target",
    "list_user_targets",
    "user_target_pairs",
]

# Largest range addable from the UI: a /22 is 1024 addresses. Anything broader
# must be a deliberate edit to the config file, not a per-user form submission.
_MIN_PREFIXLEN = 22


class UserTargetError(Exception):
    """Raised when a user target is invalid or cannot be added."""


def add_user_target(
    user_id: int,
    target: str,
    *,
    name: str = "",
    notes: str = "",
    confirmed: bool = False,
    db_path: Path | None = None,
) -> dict[str, str]:
    """Validate and store a private target for one user. Returns a summary dict."""
    if not confirmed:
        raise UserTargetError(
            "You must confirm that you own this target or hold written "
            "permission to assess it."
        )

    candidate = (target or "").strip()
    try:
        parsed = parse_target(candidate)
    except ValidationError as exc:
        raise UserTargetError(f"Invalid target: {exc}") from exc

    if parsed.network.version != 4:
        raise UserTargetError(
            "Only IPv4 targets are supported. IPv6 is not implemented."
        )
    # The explicit allowlist, not IPv4Network.is_private. That property also
    # returns True for the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    # 203.0.113.0/24), the benchmarking range (198.18.0.0/15), 240.0.0.0/4 and
    # 0.0.0.0/8 — so 203.0.113.5, which looks exactly like a routable public
    # address, was accepted here. README and docs/safety-controls.md both state
    # those ranges are refused; this is the check that makes that true. The
    # same list backs the config-file path in scope_admin, so the two cannot
    # drift apart.
    if not is_authorizable(parsed.network):
        allowed = ", ".join(str(r) for r in AUTHORIZABLE_RANGES)
        raise UserTargetError(
            f"{parsed.network} is not a private LAN address range. Only "
            f"{allowed} can be added here. Anything else — including routable "
            "internet addresses and the reserved documentation and benchmarking "
            "ranges — is refused; a public range would require a deliberate, "
            "documented edit to config/authorized_targets.yaml."
        )
    if parsed.network.prefixlen < _MIN_PREFIXLEN:
        raise UserTargetError(
            f"{parsed.network} is larger than a /{_MIN_PREFIXLEN} "
            f"({parsed.network.num_addresses} addresses). Add a /{_MIN_PREFIXLEN} "
            "or smaller so a single scan cannot sweep a large network."
        )

    cidr = str(parsed.network)
    label = (name or "").strip()[:64] or cidr

    with session_scope(db_path) as db:
        existing = (
            db.query(Target).filter_by(user_id=user_id, cidr=cidr).one_or_none()
        )
        if existing is not None:
            raise UserTargetError(f"{cidr} is already in your authorized targets.")
        row = Target(
            user_id=user_id,
            name=label,
            cidr=cidr,
            is_lab=False,  # UI-added targets are never remediable
            notes=(notes or "").strip()[:2000] or None,
            active=True,
        )
        db.add(row)

    return {
        "cidr": cidr,
        "name": label,
        "note": (
            "This target is now authorized for assessment under your account. "
            "Firewall remediation is not available on it — only configured "
            "laboratory targets can be modified."
        ),
    }


def remove_user_target(
    user_id: int, target_id: int, *, db_path: Path | None = None
) -> dict[str, str]:
    """Delete one of the user's own targets. Scoped by user_id, so a user can
    only ever remove their own."""
    with session_scope(db_path) as db:
        row = db.query(Target).filter_by(id=target_id, user_id=user_id).one_or_none()
        if row is None:
            raise UserTargetError("No such target in your account.")
        cidr = row.cidr
        db.delete(row)
    return {"cidr": cidr, "note": f"{cidr} removed from your authorized targets."}


def list_user_targets(user_id: int, *, db_path: Path | None = None) -> list[dict]:
    """Return the user's targets as plain dicts (safe to render), newest first."""
    with session_scope(db_path) as db:
        rows = (
            db.query(Target)
            .filter_by(user_id=user_id, active=True)
            .order_by(Target.id.desc())
            .all()
        )
        return [
            {
                "id": r.id,
                "name": r.name,
                "cidr": r.cidr,
                "is_lab": r.is_lab,
                "notes": r.notes,
                "created_at": r.created_at,
            }
            for r in rows
        ]


def user_target_pairs(
    user_id: int, *, db_path: Path | None = None
) -> tuple[tuple[str, str], ...]:
    """(name, cidr) pairs for the authorization check. Only active targets."""
    with session_scope(db_path) as db:
        rows = db.query(Target).filter_by(user_id=user_id, active=True).all()
        return tuple((r.name, r.cidr) for r in rows)
