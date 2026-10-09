"""Adding and removing authorized targets from the operator interface.

`config/authorized_targets.yaml` stays the single source of truth for scope.
This module is the only writer, and every write goes through the same rules the
config loader already enforces, plus stricter ones that apply specifically to
UI-originated entries:

  * **Private IPv4 only.** A public/routable range cannot be added here at all.
    `allow_public` exists in the file format but is deliberately unreachable
    from the UI: authorizing an internet-routable range must require editing the
    file by hand and describing it in AUTHORIZATION.md.
  * **Assessment only.** UI-added targets are always `is_lab: false`, so they
    can be scanned but never have their firewall modified. Promoting a target to
    `is_lab: true` requires hand-editing the file with SSH details — a
    remediable target is a deliberate, documented decision, not a checkbox.
  * **Explicit confirmation.** The caller must pass `confirmed=True` and an
    operator name. Both are recorded in the file and in the audit log.
  * **Validated before commit.** The file is rewritten, then re-loaded. If the
    result does not load cleanly, the original content is restored and the call
    fails. A broken scope file would otherwise refuse every scan, including the
    laboratory's.
  * **Never widens silently.** Adding a range that is already covered is
    reported rather than duplicated.

Reachability is irrelevant here. A host is authorized because the operator said
so, never because it answered a probe.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from backend.core.audit import AuditLog
from backend.core.config import (
    CONFIG_DIR,
    DATA_DIR,
    AuthorizedTarget,
    Config,
    ConfigError,
    load_config,
)
from backend.core.validation import ValidationError, parse_target

__all__ = [
    "ScopeError",
    "ScopeChange",
    "TARGETS_FILE",
    "AUTHORIZABLE_RANGES",
    "is_authorizable",
    "add_authorized_target",
    "remove_authorized_target",
    "describe_target_scope",
    "suggest_scope_entries",
]

TARGETS_FILE = CONFIG_DIR / "authorized_targets.yaml"

# Entries written by the UI carry this marker so `remove_authorized_target` can
# refuse to delete a hand-configured laboratory entry by accident.
UI_SOURCE = "operator_ui"

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")

# How wide a single entry may be.
#
# /16 (65,536 addresses) is the ceiling. That admits every range an operator
# realistically owns — a host /32, a home LAN /24, a site /16 such as
# 172.16.0.0/16 — while still refusing 10.0.0.0/8, which is 16.7 million
# addresses and is never a considered decision from a laptop.
#
# This is a guard against a slip of the keyboard, not a security control: the
# security control is that the operator must name and confirm the range at all.
MIN_PREFIX_LENGTH = 16
MAX_ADDRESSES = 65536

# Above this, the UI warns about scan duration. A -Pn service scan probes every
# address whether or not anything is there, so a /16 is hours of work, not
# minutes. Authorizing it is allowed; being surprised by it should not be.
LARGE_RANGE_ADDRESSES = 256

# Ranges the UI may authorize, stated explicitly rather than delegated to
# `IPv4Network.is_private`. That property is broader than "a LAN address": it
# also returns True for the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), the benchmarking range (198.18.0.0/15) and 240.0.0.0/4. None
# of those is a network an operator is assessing from a laptop, and 203.0.113.x
# in particular *looks* like a routable public address — offering to authorize it
# would be misleading. An explicit allowlist fails closed by construction.
AUTHORIZABLE_RANGES: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC 1918
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC 1918
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC 1918
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback — this machine
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
)


def is_authorizable(network: ipaddress.IPv4Network) -> bool:
    """True only for ranges inside the explicit LAN allowlist above.

    Public because the per-user scope path in backend.core.user_targets applies
    the same rule; one allowlist, two callers, no drift.
    """
    return any(network.subnet_of(allowed) for allowed in AUTHORIZABLE_RANGES)


class ScopeError(Exception):
    """Raised when a scope change is refused. The message is operator-facing."""


@dataclass(frozen=True)
class ScopeChange:
    """Record of an accepted scope change, for the audit log and the UI."""

    action: str
    name: str
    cidr: str
    address_count: int
    operator: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "name": self.name,
            "cidr": self.cidr,
            "address_count": self.address_count,
            "operator": self.operator,
            "note": self.note,
        }


def _audit(audit_path: Path | None = None) -> AuditLog:
    return AuditLog(audit_path or (DATA_DIR / "audit.jsonl"))


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_scope_input(raw_target: str) -> ipaddress.IPv4Network:
    """Parse and safety-check a proposed scope entry.

    A bare address becomes a /32 — one host, which is the common case for
    "assess this one authorized laptop".
    """
    try:
        parsed = parse_target(raw_target)
    except ValidationError as exc:
        raise ScopeError(str(exc)) from exc

    network = parsed.network

    if not is_authorizable(network):
        raise ScopeError(
            f"{network} is not a private LAN address range. CyberShield only "
            "authorizes private IPv4 space from this screen: 10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 and 169.254.0.0/16. "
            "Anything else — including routable internet addresses and the "
            "reserved documentation ranges — is refused here."
        )

    if network.prefixlen < MIN_PREFIX_LENGTH or network.num_addresses > MAX_ADDRESSES:
        raise ScopeError(
            f"{network} covers {network.num_addresses:,} addresses. The largest "
            f"range that can be authorized here is /{MIN_PREFIX_LENGTH} "
            f"({MAX_ADDRESSES:,} addresses). Authorize the specific subnet or "
            "host you have permission to assess — a range this wide is almost "
            "always a typo."
        )

    return network


def _validate_name(raw_name: str, network: ipaddress.IPv4Network) -> str:
    name = (raw_name or "").strip()
    if not name:
        # A usable default rather than an error: the label is for reports.
        name = f"lan-{str(network.network_address).replace('.', '-')}"
        if network.num_addresses > 1:
            name += f"-{network.prefixlen}"
    if not _NAME_RE.match(name):
        raise ScopeError(
            "Label may contain letters, digits, spaces, dot, underscore and "
            "hyphen only, and must be at most 48 characters."
        )
    return name


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def _read_raw(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"targets": []}
    loaded = yaml.safe_load(path.read_text()) or {}
    if not isinstance(loaded, dict):
        raise ScopeError(f"{path.name} is malformed: expected a YAML mapping.")
    if loaded.get("targets") is None:
        loaded["targets"] = []
    if not isinstance(loaded["targets"], list):
        raise ScopeError(f"{path.name} is malformed: 'targets' must be a list.")
    return loaded


def _write_validated(path: Path, document: dict[str, Any], header: str) -> None:
    """Write the scope file, then prove it still loads. Restores on failure."""
    original = path.read_text() if path.exists() else None
    rendered = header + yaml.safe_dump(document, sort_keys=False, default_flow_style=False)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered)

    try:
        load_config(path.parent)
    except ConfigError as exc:
        # Never leave the operator with a scope file that refuses every scan,
        # including the laboratory's.
        if original is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(original)
        raise ScopeError(
            f"The change was rejected because the resulting scope file would not "
            f"load: {exc} The previous authorized scope has been restored "
            "unchanged."
        ) from exc


def _file_header() -> str:
    """Preserve the explanatory comment block at the top of the file.

    PyYAML drops comments on round-trip, so the header is re-emitted rather than
    silently lost. The laboratory entry's own `notes` field survives because it
    is data, not a comment.
    """
    return (
        "# CyberShield — Authorized scan scope\n"
        "#\n"
        "# FAIL-CLOSED: a target absent from this file is rejected before Nmap is\n"
        "# invoked. Nothing is authorized by being reachable.\n"
        "#\n"
        "# Field reference\n"
        "#   name          Human label used in reports.\n"
        "#   cidr          IPv4 address or CIDR range. Validated with stdlib `ipaddress`.\n"
        "#   is_lab        true  -> firewall remediation is permitted on this target\n"
        "#                 false -> assessment only; remediation is refused\n"
        "#   ssh_host      Address CyberShield connects to for remediation (is_lab only).\n"
        "#   ssh_port      Management port. Protected from isolation automatically.\n"
        "#   ssh_user      Remote account. Needs sudo for nftables, or CAP_NET_ADMIN.\n"
        "#   notes         Free text recorded in the run manifest.\n"
        "#   source        'operator_ui' for entries added from the Targets page.\n"
        "#\n"
        "# Only private ranges (RFC1918 / loopback / link-local) are accepted unless a\n"
        "# target sets `allow_public: true`, which additionally requires the operator to\n"
        "# have described that scope in AUTHORIZATION.md. `allow_public` cannot be set\n"
        "# from the web interface — it requires editing this file deliberately.\n"
        "#\n"
        "# Entries added from the Targets page are always `is_lab: false`: they may be\n"
        "# scanned, never firewall-modified. Promoting a target to a remediable lab\n"
        "# target is a manual edit, and requires ssh_user.\n"
        "#\n"
        "# This file is rewritten by backend/core/scope_admin.py when a target is added\n"
        "# or removed from the UI. Comments inside the targets list are not preserved.\n"
        "\n"
    )


# ---------------------------------------------------------------------------
# Public operations
# ---------------------------------------------------------------------------


def add_authorized_target(
    raw_target: str,
    *,
    name: str = "",
    notes: str = "",
    operator: str = "operator",
    confirmed: bool = False,
    targets_file: Path | None = None,
    audit_path: Path | None = None,
) -> ScopeChange:
    """Authorize a private IPv4 address or CIDR range for assessment.

    Args:
        raw_target: "192.168.0.176", "192.168.0.176/32" or "192.168.0.0/24".
        confirmed: Must be True. This is the operator's explicit statement that
            they own the target or hold written permission to assess it. It is
            not an override of any safety rule — there is nothing here it could
            override.

    Raises:
        ScopeError: if unconfirmed, malformed, public, too large, or duplicated.
    """
    if not confirmed:
        raise ScopeError(
            "Refused: authorization must be confirmed explicitly. Tick the "
            "confirmation box to state that you own this target or hold written "
            "permission to assess it."
        )

    path = targets_file or TARGETS_FILE
    network = _validate_scope_input(raw_target)
    label = _validate_name(name, network)

    document = _read_raw(path)
    entries: list[dict[str, Any]] = document["targets"]

    for existing in entries:
        if not isinstance(existing, dict):
            continue
        if str(existing.get("name", "")).strip().lower() == label.lower():
            raise ScopeError(
                f"An authorized target named {label!r} already exists. Choose a "
                "different label, or remove the existing entry first."
            )
        try:
            existing_net = parse_target(str(existing.get("cidr", ""))).network
        except ValidationError:
            continue
        if network.subnet_of(existing_net):
            raise ScopeError(
                f"{network} is already inside the authorized range {existing_net} "
                f"({existing.get('name')}). It can be scanned now — no change is "
                "needed."
            )

    entries.append(
        {
            "name": label,
            "cidr": str(network),
            # Never remediable from the UI. See the module docstring.
            "is_lab": False,
            "notes": (notes or "").strip()
            or (
                "Authorized from the CyberShield Targets page for assessment only. "
                "Firewall remediation is refused on this target."
            ),
            "source": UI_SOURCE,
            "authorized_by": operator,
            "authorized_at": _utcnow_iso(),
        }
    )

    _write_validated(path, document, _file_header())

    note = (
        f"{network} is authorized for assessment only. Remediation is "
        "refused on this target."
    )
    if network.num_addresses > LARGE_RANGE_ADDRESSES:
        # Not a refusal — a heads-up. A service scan of this range will take a
        # long time, and the operator should know before starting one.
        note += (
            f" This range covers {network.num_addresses:,} addresses: a "
            "service-detection scan across all of them will take a long time. "
            "Scan a single host (/32) where you can."
        )

    change = ScopeChange(
        action="added",
        name=label,
        cidr=str(network),
        address_count=network.num_addresses,
        operator=operator,
        note=note,
    )
    _audit(audit_path).record(
        "scope.target_authorized",
        outcome="success",
        actor=operator,
        detail={
            "target": str(network),
            "name": label,
            "address_count": network.num_addresses,
            "is_lab": False,
            "confirmed_by": operator,
        },
    )
    return change


def remove_authorized_target(
    name: str,
    *,
    operator: str = "operator",
    targets_file: Path | None = None,
    audit_path: Path | None = None,
) -> ScopeChange:
    """Remove an operator-added target from scope.

    Laboratory entries (`is_lab: true`) and entries not added from the UI are
    refused: they were configured deliberately in the file, and removing one
    from a web form would break the laboratory workflow silently.
    """
    path = targets_file or TARGETS_FILE
    label = (name or "").strip()
    if not label:
        raise ScopeError("No target name supplied.")

    document = _read_raw(path)
    entries: list[dict[str, Any]] = document["targets"]

    match: dict[str, Any] | None = None
    for existing in entries:
        if isinstance(existing, dict) and str(existing.get("name", "")).strip() == label:
            match = existing
            break

    if match is None:
        raise ScopeError(f"No authorized target named {label!r}.")

    if bool(match.get("is_lab")):
        raise ScopeError(
            f"{label!r} is a laboratory target (is_lab: true) and cannot be "
            "removed from the web interface. Edit "
            "config/authorized_targets.yaml directly if that is intended."
        )
    if str(match.get("source", "")) != UI_SOURCE:
        raise ScopeError(
            f"{label!r} was configured in config/authorized_targets.yaml rather "
            "than added here. Remove it from that file directly, so the change "
            "is a deliberate edit."
        )

    entries.remove(match)
    _write_validated(path, document, _file_header())

    cidr = str(match.get("cidr", ""))
    _audit(audit_path).record(
        "scope.target_revoked",
        outcome="success",
        actor=operator,
        detail={"target": cidr, "name": label},
    )
    return ScopeChange(
        action="removed",
        name=label,
        cidr=cidr,
        address_count=0,
        operator=operator,
        note=f"{cidr} is no longer in scope. Scans against it will be refused.",
    )


# ---------------------------------------------------------------------------
# Reporting helpers used by the UI
# ---------------------------------------------------------------------------


def describe_target_scope(
    config: Config, *, targets_file: Path | None = None
) -> list[dict[str, Any]]:
    """Render the authorized scope for display, with its provenance.

    Provenance (`source`, `authorized_by`) is not carried on the loaded
    `AuthorizedTarget`, so it is read back from the YAML. `targets_file` exists
    so this reads the file the supplied config actually came from rather than
    always the project's own — otherwise a config loaded from a test or
    alternate directory would be annotated from the wrong file.
    """
    raw_by_name: dict[str, dict[str, Any]] = {}
    try:
        for entry in _read_raw(targets_file or TARGETS_FILE)["targets"]:
            if isinstance(entry, dict) and entry.get("name"):
                raw_by_name[str(entry["name"]).strip()] = entry
    except (ScopeError, yaml.YAMLError, OSError):
        raw_by_name = {}

    rows: list[dict[str, Any]] = []
    for target in config.authorized_targets:
        raw = raw_by_name.get(target.name, {})
        rows.append(
            {
                "name": target.name,
                "cidr": str(target.target),
                "address_count": target.target.address_count,
                "is_lab": target.is_lab,
                "ssh_port": target.ssh_port,
                "ssh_user": target.ssh_user,
                "notes": target.notes,
                "source": str(raw.get("source", "config_file")),
                "authorized_by": raw.get("authorized_by"),
                "authorized_at": raw.get("authorized_at"),
                # Only UI-added, non-lab entries are removable from the UI.
                "removable": str(raw.get("source", "")) == UI_SOURCE
                and not target.is_lab,
            }
        )
    return rows


def suggest_scope_entries(config: Config) -> list[dict[str, Any]]:
    """Suggest ranges the operator might want to authorize.

    A suggestion is a starting point for a decision, not an authorization. Each
    one still has to be added and confirmed. Ranges already covered by the
    existing scope are marked so the operator is not offered a no-op.
    """
    from backend.core.netinfo import detect_local_interfaces

    suggestions: list[dict[str, Any]] = []
    for interface in detect_local_interfaces():
        for candidate, kind, why in (
            (
                interface.host_cidr,
                "this machine",
                "This machine's own address. Useful only to verify the scanner "
                "against itself.",
            ),
            (
                interface.cidr,
                "whole subnet",
                "Every device on this subnet. Authorize this only if you have "
                "permission to assess all of them.",
            ),
        ):
            already = config.find_authorized_target(candidate) is not None
            suggestions.append(
                {
                    "cidr": candidate,
                    "interface": interface.name,
                    "kind": kind,
                    "is_default_route": interface.is_default_route,
                    "description": f"{interface.description} {why}",
                    "already_authorized": already,
                }
            )
    return suggestions
