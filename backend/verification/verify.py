"""Post-remediation verification (spec §16).

Verification is a real Nmap rescan of the single affected port, before and
after the action. It is evidence, not an assumption: the system never infers
that a rule worked because the command exited zero.

What a successful verification does and does not establish:

    ESTABLISHED  the port's reachability changed from open to filtered/closed
                 **as observed by this scanner, from this vantage point**
    ESTABLISHED  the management channel remained reachable (anti-lockout held)

    NOT ESTABLISHED  that the vulnerability is patched, fixed or removed
    NOT ESTABLISHED  that the service stopped running — it is still listening
    NOT ESTABLISHED  that the port is unreachable from any other vantage point

Wording in reports follows this exactly: "network exposure was reduced", never
"the vulnerability was remediated".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.config import Config
from backend.scanner.pipeline import run_service_detection

__all__ = ["PortObservation", "observe_port", "compare_observations"]

# Nmap port states that mean "a client could establish a connection".
_REACHABLE_STATES = frozenset({"open", "open|filtered"})


@dataclass(frozen=True)
class PortObservation:
    address: str
    port: int
    proto: str
    state: str
    reason: str | None
    observed_at: str
    session_id: str
    raw_xml_path: str
    host_was_up: bool

    @property
    def reachable(self) -> bool:
        return self.state in _REACHABLE_STATES

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "port": self.port,
            "proto": self.proto,
            "state": self.state,
            "reason": self.reason,
            "reachable": self.reachable,
            "host_was_up": self.host_was_up,
            "observed_at": self.observed_at,
            "scan_session_id": self.session_id,
            "raw_xml": self.raw_xml_path,
        }


def observe_port(
    config: Config,
    address: str,
    port: int,
    *,
    proto: str = "tcp",
    label: str = "verification",
    actor: str = "operator",
    user_id: int | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    evidence_dir: Path | None = None,
    raw_dir: Path | None = None,
) -> PortObservation:
    """Rescan one port and record what Nmap reported.

    Goes through the normal scan pipeline, so the observation is scope-checked,
    audited, and leaves raw XML evidence exactly like any other scan. The
    verification rescan is owned by the operator performing the remediation.
    """
    result = run_service_detection(
        config,
        address,
        profile_name="verify_port",
        ports=[port],
        scan_kind=label,
        actor=actor,
        user_id=user_id,
        db_path=db_path,
        audit_path=audit_path,
        evidence_dir=evidence_dir,
        raw_dir=raw_dir,
    )

    host = next((h for h in result.parsed.hosts if h.address == address), None)
    service = None
    if host is not None:
        service = next(
            (s for s in host.services if s.port == port and s.proto == proto), None
        )

    # A host that did not respond is NOT evidence that the port was closed —
    # the whole target may simply be unreachable. Recorded as "unknown".
    state = service.state if service is not None else "unknown"
    reason = service.reason if service is not None else None

    return PortObservation(
        address=address,
        port=port,
        proto=proto,
        state=state,
        reason=reason,
        observed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        session_id=result.session_id,
        raw_xml_path=str(result.raw_xml_path),
        host_was_up=bool(host and host.is_up),
    )


def compare_observations(
    before: PortObservation,
    after: PortObservation,
    *,
    management: PortObservation | None = None,
) -> dict[str, Any]:
    """Compare two observations and state plainly what changed.

    `exposure_reduced` is True only when the port was demonstrably reachable
    beforehand and demonstrably is not afterwards. If the "before" observation
    never showed the port open, there is no reduction to claim — even if the
    "after" scan shows it filtered.
    """
    exposure_reduced = before.reachable and not after.reachable

    findings: list[str] = []
    if exposure_reduced:
        findings.append(
            f"Network exposure was reduced: {before.proto}/{before.port} on "
            f"{before.address} changed from {before.state!r} to {after.state!r} "
            "as observed by this scanner. The service is still running on the "
            "target and the underlying vulnerability is unchanged."
        )
    elif before.reachable and after.reachable:
        findings.append(
            f"No change: {before.proto}/{before.port} is still {after.state!r}. "
            "The isolation did not take effect from this vantage point."
        )
    elif not before.reachable:
        findings.append(
            f"Inconclusive: {before.proto}/{before.port} was already "
            f"{before.state!r} before the action, so no reduction can be "
            "attributed to it."
        )
    else:
        findings.append(
            f"Port state moved from {before.state!r} to {after.state!r}."
        )

    if not after.host_was_up:
        findings.append(
            "WARNING: the host did not respond during the post-action scan. A "
            "port cannot be called filtered when the whole target is "
            "unreachable — this result is not evidence of successful isolation."
        )

    payload: dict[str, Any] = {
        "before": before.to_dict(),
        "after": after.to_dict(),
        "exposure_reduced": exposure_reduced,
        "findings": findings,
        "scope_of_claim": (
            "Reachability observed from this scanner only. Not evidence that "
            "the vulnerability is patched, that the service stopped, or that "
            "the port is unreachable from other vantage points."
        ),
    }

    if management is not None:
        payload["management_channel"] = management.to_dict()
        payload["management_channel_intact"] = management.reachable
        if not management.reachable:
            findings.append(
                f"CRITICAL: the management channel {management.proto}/"
                f"{management.port} is {management.state!r} after the action. "
                "Rollback over SSH may not be possible."
            )

    return payload
