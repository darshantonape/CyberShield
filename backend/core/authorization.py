"""Scope gatekeeper.

Every scan and every remediation passes through this module first. It is written
to fail closed: the functions raise on refusal rather than returning False, so
a caller that forgets to check the return value still cannot proceed.

Three distinct questions, deliberately kept separate:

  1. `assert_authorization_signed`  — is the operator authorized at all?
  2. `assert_in_scope`              — is this target one we may *scan*?
  3. `assert_authorized_lab_target` — is this target one we may *modify*?

Scanning permission never implies modification permission.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.core.config import AuthorizedTarget, Config, load_authorization
from backend.core.validation import ParsedTarget, ValidationError, parse_target

__all__ = [
    "AuthorizationDenied",
    "ScopeDecision",
    "assert_authorization_signed",
    "assert_in_scope",
    "assert_authorized_lab_target",
    "check_in_scope",
]


class AuthorizationDenied(Exception):
    """Raised when an action is not permitted by the configured scope.

    Deliberately not a subclass of ValueError: this must never be swallowed by a
    generic input-validation handler.
    """


@dataclass(frozen=True)
class ScopeDecision:
    """Record of a scope check, retained for the audit log."""

    requested: str
    allowed: bool
    reason: str
    authorizing_entry: str | None = None


def assert_authorization_signed() -> None:
    """Refuse to act unless AUTHORIZATION.md is signed and complete."""
    record = load_authorization()
    if not record.is_valid:
        problems = "; ".join(record.problems) or "unknown problem"
        raise AuthorizationDenied(
            f"Refusing to act: {problems} "
            "Sign AUTHORIZATION.md (set signed: true and complete every field) "
            "before running any scan or remediation."
        )


def _matching_user_target(
    parsed: ParsedTarget, user_targets: tuple[tuple[str, str], ...]
) -> tuple[str, str] | None:
    """Return the (name, cidr) of the user target that contains `parsed`, if any.

    `user_targets` are (name, cidr) pairs the authenticated operator added to
    their own account. They are validated as private ranges at add-time, so they
    can only ever narrow-authorize a private address — never widen scope to a
    public one.
    """
    for name, cidr in user_targets:
        try:
            entry = parse_target(cidr)
        except ValidationError:
            continue
        if parsed.network.subnet_of(entry.network):
            return (name, cidr)
    return None


def check_in_scope(
    config: Config,
    address: str,
    *,
    user_targets: tuple[tuple[str, str], ...] = (),
) -> ScopeDecision:
    """Non-raising scope check. Returns a decision record.

    `user_targets` are the authenticated user's own authorized ranges (name,
    cidr). A target is in scope if it falls inside a config range (the install
    ceiling) OR one of the user's own private ranges.

    Use this for reporting and UI. Use `assert_in_scope` on any code path that
    is about to actually touch the network.
    """
    try:
        parsed: ParsedTarget = parse_target(address)
    except ValidationError as exc:
        return ScopeDecision(requested=address, allowed=False, reason=str(exc))

    for entry in config.authorized_targets:
        if parsed.network.subnet_of(entry.target.network):
            return ScopeDecision(
                requested=address,
                allowed=True,
                reason=f"Within authorized range {entry.target} ({entry.name}).",
                authorizing_entry=entry.name,
            )

    match = _matching_user_target(parsed, user_targets)
    if match is not None:
        name, cidr = match
        return ScopeDecision(
            requested=address,
            allowed=True,
            reason=f"Within your authorized target {cidr} ({name}).",
            authorizing_entry=name,
        )

    if not config.authorized_targets and not user_targets:
        return ScopeDecision(
            requested=address,
            allowed=False,
            reason=(
                "There are no targets in scope: your account has no authorized "
                "targets and the install-wide scope is empty. Add a private range "
                "on the Targets page before scanning — CyberShield scans nothing "
                "until a target is added and confirmed."
            ),
        )

    config_ranges = [str(t.target) for t in config.authorized_targets]
    user_ranges = [c for _, c in user_targets]
    ranges = ", ".join(config_ranges + user_ranges) or "(none)"
    return ScopeDecision(
        requested=address,
        allowed=False,
        reason=(
            f"{parsed.network} is not inside any authorized range. "
            f"Authorized ranges: {ranges}."
        ),
    )


def assert_in_scope(
    config: Config,
    address: str,
    *,
    user_targets: tuple[tuple[str, str], ...] = (),
) -> AuthorizedTarget:
    """Assert `address` may be scanned. Returns the authorizing entry.

    `user_targets` are the operator's own authorized ranges (name, cidr); a
    target authorized by one of them yields a synthetic assessment-only entry
    (is_lab=False, no SSH), so it can be scanned but never firewall-modified.

    Raises:
        AuthorizationDenied: if out of scope, malformed, or unauthorized.
    """
    assert_authorization_signed()

    decision = check_in_scope(config, address, user_targets=user_targets)
    if not decision.allowed:
        raise AuthorizationDenied(f"Scan refused for {address!r}: {decision.reason}")

    entry = config.find_authorized_target(address)
    if entry is not None:
        return entry

    # Authorized by one of the user's own targets. Build an assessment-only
    # entry: is_lab is False and there is no SSH channel, so remediation on it is
    # refused by assert_authorized_lab_target while scanning proceeds.
    parsed = parse_target(address)
    match = _matching_user_target(parsed, user_targets)
    if match is not None:
        name, cidr = match
        return AuthorizedTarget(
            name=name,
            target=parse_target(cidr),
            is_lab=False,
            ssh_host=None,
            ssh_port=22,
            ssh_user=None,
            notes="Operator-added target (assessment only).",
        )

    raise AuthorizationDenied(  # pragma: no cover - defensive
        f"Scan refused for {address!r}: scope check passed but no authorizing "
        "entry resolved. This indicates inconsistent configuration."
    )


def assert_authorized_lab_target(config: Config, address: str) -> AuthorizedTarget:
    """Assert `address` may have its firewall state modified.

    Stricter than `assert_in_scope`: remediation is confined to the install-wide
    config scope, and additionally requires `is_lab: true` and a usable SSH
    management channel, because a rule that cannot be rolled back is not a
    reversible action.

    Operator-added targets are deliberately NOT consulted here. A target added
    from the Targets page is assessment-only, and no per-user scope entry can
    ever make it remediable.

    Raises:
        AuthorizationDenied: if the target is not a remediable lab target.
    """
    assert_authorization_signed()

    # Config scope only — see above. Checked here rather than via
    # `assert_in_scope` so the refusal says what is actually wrong. Delegating
    # produced "Scan refused for '192.168.1.25': not inside any authorized
    # range" for a target the operator HAD authorized and had just finished
    # scanning, which reads as though the authorization never registered.
    entry = config.find_authorized_target(address)
    if entry is None:
        ranges = ", ".join(str(t.target) for t in config.authorized_targets) or "(none)"
        raise AuthorizationDenied(
            f"Remediation refused for {address!r}: firewall changes are confined "
            "to laboratory targets declared in config/authorized_targets.yaml, "
            f"and {address} is not in one of them ({ranges}). A target you added "
            "on the Targets page can be scanned and reported on, but never "
            "firewall-modified — promoting one to a laboratory target is a "
            "deliberate file edit that also requires SSH management details."
        )

    if not entry.is_lab:
        raise AuthorizationDenied(
            f"Remediation refused for {address!r}: authorized range "
            f"{entry.target} ({entry.name}) is not flagged 'is_lab: true'. "
            "Assessment is permitted here; firewall modification is not."
        )

    if not entry.ssh_user:
        raise AuthorizationDenied(
            f"Remediation refused for {address!r}: no 'ssh_user' configured for "
            f"{entry.name}. Without SSH access the rule could not be rolled back."
        )

    return entry
