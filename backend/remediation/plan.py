"""Reversible remediation plans.

A plan is built and persisted **before** anything is applied, carrying both the
forward command and its exact inverse. If CyberShield dies between applying a
rule and recording it, the rollback command is already in the database.

Building a plan performs no network I/O and changes nothing. It is safe to call
for a preview.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.core.config import Config
from backend.remediation.backends.base import FirewallBackend
from backend.remediation.backends.dryrun import DryRunBackend
from backend.remediation.backends.nftables import NftablesBackend
from backend.risk.decision import Decision, IsolationRequest, Verdict, evaluate

__all__ = ["RemediationPlan", "PlanError", "build_plan", "get_backend"]


class PlanError(Exception):
    """Raised when a plan cannot be built."""


_BACKENDS: dict[str, type[FirewallBackend]] = {
    "nftables": NftablesBackend,
    "dryrun": DryRunBackend,
    # "ufw" is intentionally absent. The base class documents the contract, but
    # no ufw backend has been written or tested, and registering an untested
    # one would let the system claim a capability it does not have.
}


def get_backend(name: str) -> FirewallBackend:
    try:
        return _BACKENDS[name]()
    except KeyError:
        raise PlanError(
            f"Unknown remediation backend {name!r}. Available: "
            f"{', '.join(sorted(_BACKENDS))}."
        ) from None


@dataclass
class RemediationPlan:
    request_id: str
    target_address: str
    port: int
    proto: str
    backend_name: str
    apply_argv: list[str]
    rollback_argv: list[str]
    rule_tag: str
    decision: Decision
    ssh_host: str
    ssh_port: int
    ssh_user: str
    expires_at: datetime | None = None
    vulnerability_id: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision.verdict is Verdict.ALLOW

    @property
    def is_dry_run(self) -> bool:
        return self.backend_name == "dryrun"

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "target": self.target_address,
            "port": self.port,
            "proto": self.proto,
            "backend": self.backend_name,
            "dry_run": self.is_dry_run,
            "apply_command": " ".join(self.apply_argv),
            "rollback_command": " ".join(self.rollback_argv),
            "rule_tag": self.rule_tag,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "management_channel": f"{self.ssh_user}@{self.ssh_host}:{self.ssh_port}",
            "verdict": self.decision.verdict.value,
            "decision": self.decision.to_dict(),
            "notes": list(self.notes),
            "effect": (
                "Reduces network exposure of this port from the scanner's vantage "
                "point. It does NOT patch, fix, or remove the underlying "
                "vulnerability, and the service continues running on the target."
            ),
        }


def build_plan(
    config: Config,
    request: IsolationRequest,
    *,
    vulnerability_id: int | None = None,
) -> RemediationPlan:
    """Evaluate the request and build a reversible plan.

    A plan is produced even when the verdict is DENY or REVIEW_REQUIRED, so the
    operator can see exactly what *would* have run and why it was refused. Only
    the executor consults `decision.verdict`, and it refuses anything but ALLOW.
    """
    decision = evaluate(config, request)

    entry = config.find_authorized_target(request.target_address)
    if entry is None:
        # Out of scope: the decision already records the refusal. There is no
        # management channel to describe, so the plan is a record, not a
        # runnable action.
        ssh_host, ssh_port, ssh_user = request.target_address, 0, ""
    else:
        ssh_host = entry.ssh_host or request.target_address
        ssh_port = entry.ssh_port
        ssh_user = entry.ssh_user or ""

    backend = get_backend(config.settings.remediation_backend)

    try:
        apply_argv = backend.apply_argv(request.port, request.proto)
        rollback_argv = backend.rollback_argv(request.port, request.proto)
    except Exception as exc:  # noqa: BLE001 - surfaced as a plan-level failure
        raise PlanError(
            f"Backend {backend.name!r} cannot express this action: {exc}"
        ) from exc

    request_id = uuid.uuid4().hex[:16]
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=config.settings.remediation_ttl_minutes
    )

    notes: list[str] = []
    if backend.executes is False:
        notes.append(
            "Dry run: these commands will NOT be sent to the target. Set "
            "CYBERSHIELD_REMEDIATION_BACKEND=nftables to enable live enforcement."
        )
    notes.append(
        f"The rule auto-reverts after {config.settings.remediation_ttl_minutes} "
        "minutes if not rolled back sooner."
    )

    return RemediationPlan(
        request_id=request_id,
        target_address=request.target_address,
        port=request.port,
        proto=request.proto,
        backend_name=backend.name,
        apply_argv=apply_argv,
        rollback_argv=rollback_argv,
        rule_tag=f"cybershield:{request_id}",
        decision=decision,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        expires_at=expires_at,
        vulnerability_id=vulnerability_id,
        notes=notes,
    )
