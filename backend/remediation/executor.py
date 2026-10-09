"""Applying, verifying and rolling back isolation actions.

Ordering here is the safety design, not an implementation detail:

    1. refuse anything the decision engine did not return ALLOW for
    2. persist the record, INCLUDING the rollback command, before acting
    3. observe the port (pre-action evidence)
    4. prepare the target and apply the rule
    5. record the outcome
    6. observe again, and observe the management channel
    7. arm a TTL revert

Step 2 precedes step 4 so that a crash between them still leaves the exact
rollback command in the database. Step 6 checks the management channel because
a successful isolation that locks CyberShield out is a failure.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.audit import AuditLog
from backend.core.authorization import assert_authorized_lab_target
from backend.core.config import DATA_DIR, EXPERIMENTS_DIR, Config
from backend.database.models import RemediationAction
from backend.database.session import session_scope
from backend.remediation.backends.base import BackendError
from backend.remediation.plan import RemediationPlan, get_backend
from backend.remediation.ssh_adapter import SshError, SshTarget, connect
from backend.risk.decision import Verdict
from backend.verification.verify import compare_observations, observe_port

__all__ = ["ExecutionError", "RemediationOutcome", "apply_plan", "rollback", "TtlWatchdog"]


class ExecutionError(Exception):
    """Raised when an action is refused or cannot be completed."""


REMEDIATION_EVIDENCE_DIR = EXPERIMENTS_DIR / "remediation"


def _audit(audit_path: Path | None) -> AuditLog:
    return AuditLog(audit_path or (DATA_DIR / "audit.jsonl"))


def _write_evidence(
    request_id: str, payload: dict[str, Any], evidence_dir: Path | None = None
) -> Path:
    """Persist a remediation record under experiments/ (spec §21).

    Written per request_id and updated in place, so applying then rolling back
    leaves ONE file describing the whole lifecycle rather than two partial ones.
    """
    directory = (evidence_dir or REMEDIATION_EVIDENCE_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{request_id}.json"

    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except json.JSONDecodeError:
            existing = {}

    existing.update(payload)
    existing["recorded_at"] = _utcnow().isoformat(timespec="seconds")
    path.write_text(json.dumps(existing, indent=2, sort_keys=True, default=str))
    return path


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RemediationOutcome:
    request_id: str
    state: str
    plan: RemediationPlan
    verification: dict[str, Any] = field(default_factory=dict)
    target_firewall_state: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def exposure_reduced(self) -> bool:
        return bool(self.verification.get("exposure_reduced"))

    def summary(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "state": self.state,
            "target": self.plan.target_address,
            "port": self.plan.port,
            "backend": self.plan.backend_name,
            "dry_run": self.plan.is_dry_run,
            "exposure_reduced": self.exposure_reduced,
            "management_channel_intact": self.verification.get(
                "management_channel_intact"
            ),
            "error": self.error,
        }


def _persist_plan(
    plan: RemediationPlan, db_path: Path | None, actor: str = "operator",
    user_id: int | None = None,
) -> None:
    """Write the record — with its rollback command — before anything runs.

    `actor` is stored so the database row carries the same attribution as the
    audit log. Without it the row fell back to the column default and every
    action read as "operator" regardless of who approved it, while the audit
    entries named the real account — two records of the same event disagreeing.
    """
    with session_scope(db_path) as db:
        db.add(
            RemediationAction(
                request_id=plan.request_id,
                operator=actor,
                user_id=user_id,
                vulnerability_id=plan.vulnerability_id,
                target_address=plan.target_address,
                port=plan.port,
                proto=plan.proto,
                backend=plan.backend_name,
                action="isolate_port",
                apply_argv=plan.apply_argv,
                rollback_argv=plan.rollback_argv,
                rule_tag=plan.rule_tag,
                state="planned",
                decision=plan.decision.to_dict(),
                expires_at=plan.expires_at,
            )
        )


def _update(request_id: str, db_path: Path | None, **fields: Any) -> None:
    with session_scope(db_path) as db:
        row = (
            db.query(RemediationAction).filter_by(request_id=request_id).one_or_none()
        )
        if row is None:
            return
        for key, value in fields.items():
            setattr(row, key, value)


def _ssh_target(config: Config, plan: RemediationPlan) -> SshTarget:
    return SshTarget(
        host=plan.ssh_host,
        port=plan.ssh_port,
        username=plan.ssh_user,
        key_path=config.settings.ssh_key_path,
    )


def apply_plan(
    config: Config,
    plan: RemediationPlan,
    *,
    confirmed: bool,
    actor: str = "operator",
    user_id: int | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    evidence_dir: Path | None = None,
    raw_dir: Path | None = None,
    watchdog: "TtlWatchdog | None" = None,
) -> RemediationOutcome:
    """Apply an isolation plan after explicit human confirmation.

    Args:
        confirmed: Must be True. There is no code path that applies a rule
            without it, and it is not defaulted — an omission is a refusal.
    """
    audit = _audit(audit_path)
    outcome = RemediationOutcome(request_id=plan.request_id, state="planned", plan=plan)

    # --- Refusals, before anything is written or sent --------------------
    if not confirmed:
        outcome.state = "refused"
        outcome.error = "Not confirmed by an operator."
        audit.record(
            "remediation.refused",
            outcome="refused",
            actor=actor,
            detail={"request_id": plan.request_id, "reason": outcome.error},
        )
        raise ExecutionError(
            "Refusing to apply: explicit operator confirmation is required."
        )

    if plan.decision.verdict is not Verdict.ALLOW:
        outcome.state = "refused"
        outcome.error = (
            f"Decision engine returned {plan.decision.verdict.value}: "
            f"{plan.decision.blocking_reason}"
        )
        audit.record(
            "remediation.refused",
            outcome="refused",
            actor=actor,
            detail={
                "request_id": plan.request_id,
                "verdict": plan.decision.verdict.value,
                "reason": plan.decision.blocking_reason,
                "decision": plan.decision.to_dict(),
            },
        )
        raise ExecutionError(outcome.error)

    # Re-assert scope at execution time. The config could have been edited
    # between planning and applying, and this is the last chance to catch it.
    assert_authorized_lab_target(config, plan.target_address)

    # --- Record before acting -------------------------------------------
    _persist_plan(plan, db_path, actor=actor, user_id=user_id)
    audit.record(
        "remediation.plan",
        outcome="success",
        actor=actor,
        detail=plan.to_dict(),
    )

    # --- Pre-action evidence ---------------------------------------------
    before = observe_port(
        config, plan.target_address, plan.port, proto=plan.proto,
        label="verification_before", actor=actor,
        user_id=user_id,
        db_path=db_path, audit_path=audit_path,
        evidence_dir=evidence_dir, raw_dir=raw_dir,
    )
    _update(plan.request_id, db_path, before_state=before.to_dict())

    backend = get_backend(plan.backend_name)

    # --- Dry run stops here ----------------------------------------------
    if not backend.executes:
        outcome.state = "planned"
        outcome.steps = backend.ensure_prepared(None)  # type: ignore[arg-type]
        outcome.verification = {
            "before": before.to_dict(),
            "after": None,
            "exposure_reduced": False,
            "findings": [
                "Dry run: no command was sent to the target and no firewall "
                "state was changed. No exposure reduction has occurred."
            ],
        }
        _update(plan.request_id, db_path, state="planned")
        audit.record(
            "remediation.dryrun",
            outcome="success",
            actor=actor,
            detail={"request_id": plan.request_id, "would_run": plan.apply_argv},
        )
        return outcome

    # --- Apply -------------------------------------------------------------
    try:
        with connect(_ssh_target(config, plan)) as session:
            outcome.steps.extend(backend.ensure_prepared(session))

            result = session.run(plan.apply_argv)
            outcome.steps.append(result.summary())
            if not result.ok:
                raise BackendError(
                    f"Apply command exited {result.exit_status}: {result.stderr.strip()}"
                )

            state = backend.read_state(session, plan.port, plan.proto)
            outcome.target_firewall_state = state.to_dict()

    except (SshError, BackendError) as exc:
        outcome.state = "failed"
        outcome.error = str(exc)
        _update(plan.request_id, db_path, state="failed", error=str(exc))
        audit.record(
            "remediation.apply",
            outcome="failure",
            actor=actor,
            detail={"request_id": plan.request_id, "error": str(exc)},
        )
        raise ExecutionError(f"Isolation failed: {exc}") from exc

    applied_at = _utcnow()
    outcome.state = "applied"
    _update(plan.request_id, db_path, state="applied", applied_at=applied_at)
    audit.record(
        "remediation.apply",
        outcome="success",
        actor=actor,
        detail={
            "request_id": plan.request_id,
            "target": plan.target_address,
            "port": plan.port,
            "command": " ".join(plan.apply_argv),
            "rollback_command": " ".join(plan.rollback_argv),
            "target_firewall_state": outcome.target_firewall_state,
            "expires_at": plan.expires_at.isoformat() if plan.expires_at else None,
        },
    )

    # --- Post-action evidence ---------------------------------------------
    after = observe_port(
        config, plan.target_address, plan.port, proto=plan.proto,
        label="verification_after", actor=actor,
        user_id=user_id,
        db_path=db_path, audit_path=audit_path,
        evidence_dir=evidence_dir, raw_dir=raw_dir,
    )
    management = observe_port(
        config, plan.target_address, plan.ssh_port, proto="tcp",
        label="verification_management", actor=actor,
        user_id=user_id,
        db_path=db_path, audit_path=audit_path,
        evidence_dir=evidence_dir, raw_dir=raw_dir,
    )

    outcome.verification = compare_observations(before, after, management=management)
    _update(
        plan.request_id, db_path,
        after_state=after.to_dict(),
        exposure_reduced=outcome.verification["exposure_reduced"],
        management_channel_intact=outcome.verification.get("management_channel_intact"),
    )
    audit.record(
        "remediation.verify",
        outcome="success" if outcome.exposure_reduced else "failure",
        actor=actor,
        detail={"request_id": plan.request_id, "verification": outcome.verification},
    )

    # --- Anti-lockout: act on a lost management channel immediately ---------
    #
    # If the post-action check says the SSH port stopped answering, the target
    # is in the one state this design must never leave it in: a rule applied,
    # and no way to remove it except waiting for the TTL. Attempt the rollback
    # NOW, while a channel may still exist — the observation is an Nmap probe
    # and can be wrong, so trying costs little and not trying could cost the
    # rollback entirely.
    #
    # Deliberately narrower than "roll back whenever verification fails". An
    # applied rule that did not reduce exposure leaves the target in a safe
    # state, and auto-reverting it would destroy the evidence of why it did not
    # work; that case is flagged loudly and left to the operator, with the TTL
    # watchdog as the backstop.
    if outcome.verification.get("management_channel_intact") is False:
        audit.record(
            "remediation.lockout_risk",
            outcome="failure",
            actor=actor,
            detail={
                "request_id": plan.request_id,
                "target": plan.target_address,
                "management_port": plan.ssh_port,
                "action": "attempting automatic rollback",
            },
        )
        try:
            rollback(
                config,
                plan.request_id,
                actor=actor,
                user_id=user_id,
                db_path=db_path,
                audit_path=audit_path,
                evidence_dir=evidence_dir,
                raw_dir=raw_dir,
            )
            outcome.state = "rolled_back"
            outcome.error = (
                "The management channel did not answer after the rule was "
                "applied, so the rule was automatically rolled back."
            )
        except Exception as exc:  # noqa: BLE001 - must not mask the outcome
            outcome.error = (
                "The management channel did not answer after the rule was "
                f"applied, and the automatic rollback also failed: {exc}. The "
                "rule remains applied until the TTL watchdog reverts it at "
                f"{plan.expires_at.isoformat() if plan.expires_at else 'its expiry'}."
            )
            audit.record(
                "remediation.lockout_risk",
                outcome="failure",
                actor=actor,
                detail={
                    "request_id": plan.request_id,
                    "target": plan.target_address,
                    "automatic_rollback_error": f"{type(exc).__name__}: {exc}",
                },
            )
        if watchdog is not None and outcome.state == "rolled_back":
            watchdog.cancel(plan.request_id)

    _write_evidence(
        plan.request_id,
        {
            "request_id": plan.request_id,
            "plan": plan.to_dict(),
            "apply": {
                "state": outcome.state,
                "applied_at": applied_at.isoformat(),
                "steps": outcome.steps,
                "target_firewall_state": outcome.target_firewall_state,
            },
            "verification": outcome.verification,
        },
        evidence_dir,
    )

    if watchdog is not None and plan.expires_at is not None:
        watchdog.arm(config, plan, db_path=db_path, audit_path=audit_path)

    return outcome


def rollback(
    config: Config,
    request_id: str,
    *,
    actor: str = "operator",
    user_id: int | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    evidence_dir: Path | None = None,
    raw_dir: Path | None = None,
    reason: str = "operator request",
) -> dict[str, Any]:
    """Revert an applied isolation and verify the port is reachable again."""
    audit = _audit(audit_path)

    with session_scope(db_path) as db:
        row = (
            db.query(RemediationAction).filter_by(request_id=request_id).one_or_none()
        )
        if row is None:
            raise ExecutionError(f"No remediation action {request_id!r}.")
        if row.state == "rolled_back":
            return {
                "request_id": request_id,
                "state": "rolled_back",
                "note": "Already rolled back; nothing to do.",
            }
        if row.state != "applied":
            raise ExecutionError(
                f"Action {request_id!r} is {row.state!r}; only an applied action "
                "can be rolled back."
            )
        snapshot = {
            "target_address": row.target_address,
            "port": row.port,
            "proto": row.proto,
            "backend": row.backend,
            "rollback_argv": list(row.rollback_argv or []),
        }

    entry = assert_authorized_lab_target(config, snapshot["target_address"])
    backend = get_backend(snapshot["backend"])

    try:
        with connect(
            SshTarget(
                host=entry.ssh_host or snapshot["target_address"],
                port=entry.ssh_port,
                username=entry.ssh_user or "root",
                key_path=config.settings.ssh_key_path,
            )
        ) as session:
            result = session.run(snapshot["rollback_argv"])
            if not result.ok:
                raise BackendError(
                    f"Rollback command exited {result.exit_status}: "
                    f"{result.stderr.strip()}"
                )
            state = backend.read_state(session, snapshot["port"], snapshot["proto"])
    except (SshError, BackendError) as exc:
        _update(request_id, db_path, error=f"rollback failed: {exc}")
        audit.record(
            "remediation.rollback",
            outcome="failure",
            actor=actor,
            detail={"request_id": request_id, "error": str(exc)},
        )
        raise ExecutionError(f"Rollback failed: {exc}") from exc

    _update(request_id, db_path, state="rolled_back", rolled_back_at=_utcnow())

    restored = observe_port(
        config, snapshot["target_address"], snapshot["port"], proto=snapshot["proto"],
        label="verification_rollback", actor=actor,
        user_id=user_id,
        db_path=db_path, audit_path=audit_path,
        evidence_dir=evidence_dir, raw_dir=raw_dir,
    )
    rollback_verified = restored.reachable
    _update(
        request_id, db_path,
        rollback_state=restored.to_dict(),
        rollback_verified=rollback_verified,
    )

    payload = {
        "request_id": request_id,
        "state": "rolled_back",
        "reason": reason,
        "command": " ".join(snapshot["rollback_argv"]),
        "target_firewall_state": state.to_dict(),
        "restored_state": restored.to_dict(),
        "rollback_verified": rollback_verified,
        "note": (
            "Port reachability restored."
            if rollback_verified
            else "Rule removed, but the port is still not reachable — investigate "
            "before assuming the target is back to its prior state."
        ),
    }
    audit.record(
        "remediation.rollback",
        outcome="success" if rollback_verified else "failure",
        actor=actor,
        detail=payload,
    )
    _write_evidence(request_id, {"rollback": payload}, evidence_dir)
    return payload


class TtlWatchdog:
    """Auto-reverts applied rules once their TTL expires.

    A rule that outlives its window is the failure this guards against: an
    operator walks away, and a lab service stays isolated indefinitely with no
    record of why. Timers are in-process, so `sweep_expired` must also run at
    startup to catch actions that outlived the process.
    """

    def __init__(self) -> None:
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def arm(
        self,
        config: Config,
        plan: RemediationPlan,
        *,
        db_path: Path | None = None,
        audit_path: Path | None = None,
    ) -> None:
        if plan.expires_at is None:
            return
        delay = max((plan.expires_at - _utcnow()).total_seconds(), 1.0)

        def fire() -> None:
            try:
                rollback(
                    config, plan.request_id,
                    actor="ttl-watchdog",
                    db_path=db_path, audit_path=audit_path,
                    reason="TTL expired",
                )
            except ExecutionError:
                # Already rolled back, or the target is gone. Either way the
                # rule is not left silently applied without a record.
                pass
            finally:
                with self._lock:
                    self._timers.pop(plan.request_id, None)

        timer = threading.Timer(delay, fire)
        timer.daemon = True
        with self._lock:
            self._timers[plan.request_id] = timer
        timer.start()

    def cancel(self, request_id: str) -> None:
        with self._lock:
            timer = self._timers.pop(request_id, None)
        if timer is not None:
            timer.cancel()

    def shutdown(self) -> None:
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()
        for timer in timers:
            timer.cancel()


def sweep_expired(
    config: Config,
    *,
    db_path: Path | None = None,
    audit_path: Path | None = None,
) -> list[str]:
    """Roll back any applied action whose TTL has already passed.

    Run at startup: in-process timers do not survive a restart, so without this
    a rule applied before a crash would stay in place indefinitely.
    """
    now = _utcnow()
    with session_scope(db_path) as db:
        rows = (
            db.query(RemediationAction)
            .filter(RemediationAction.state == "applied")
            .all()
        )
        expired = [
            r.request_id
            for r in rows
            if r.expires_at is not None and r.expires_at.replace(tzinfo=timezone.utc) <= now
        ]

    reverted: list[str] = []
    for request_id in expired:
        try:
            rollback(
                config, request_id, actor="ttl-sweep",
                db_path=db_path, audit_path=audit_path,
                reason="TTL expired while CyberShield was not running",
            )
            reverted.append(request_id)
        except ExecutionError:
            continue
    return reverted
