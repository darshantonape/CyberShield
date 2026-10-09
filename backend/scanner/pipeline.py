"""Scan orchestration: authorize -> run -> parse -> persist -> record evidence.

Two entry points share this path:

    run_discovery()          host discovery only (spec §7.1)
    run_service_detection()  ports, services and versions (spec §7.2-7.4)

Ordering here is deliberate. Authorization is the first thing that happens and
is not delegated to the runner, so there is exactly one visible place where the
decision "may we touch this target" is made.

Every scan writes two artifacts:
    data/raw/<session>_<profile>_<ts>.xml   raw Nmap evidence, unmodified
    experiments/scans/<session>.json        normalized result + run manifest
"""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.audit import AuditLog
from backend.core.authorization import assert_in_scope
from backend.core.config import DATA_DIR, EXPERIMENTS_DIR, Config
from backend.core.validation import parse_target
from backend.database.models import DiscoveredHost, DiscoveredService, ScanSession
from backend.database.session import session_scope
from backend.scanner.nmap_parser import NmapParseError, ParsedScan, parse_nmap_xml
from backend.scanner.nmap_runner import NmapError, get_nmap_version, run_nmap
from backend.scanner.reachability import Reachability, assess_scan

__all__ = [
    "ScanError",
    "ScanResult",
    "run_discovery",
    "run_service_detection",
]


class ScanError(Exception):
    """A scan that started but could not produce usable results.

    Distinct from AuthorizationDenied (never started) and from a scan that ran
    and found nothing. Raised only after the failure has been persisted as a
    `failed` scan row and written to the audit log, so the trail exists even
    though there are no results.
    """


SCANS_EVIDENCE_DIR = EXPERIMENTS_DIR / "scans"


@dataclass
class ScanResult:
    session_id: str
    target_spec: str
    profile: str
    scan_kind: str
    parsed: ParsedScan
    raw_xml_path: Path
    evidence_path: Path
    duration_seconds: float
    db_session_id: int
    # Whether the target actually answered. An authorized target that answered
    # nothing is UNREACHABLE, which is not the same as having no findings.
    reachability: Reachability | None = None
    status: str = "completed"

    @property
    def hosts_up(self) -> int:
        return len(self.parsed.hosts_up)

    @property
    def open_services(self) -> int:
        return self.parsed.total_open_services

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target_spec,
            "profile": self.profile,
            "hosts_discovered": len(self.parsed.hosts),
            "hosts_up": self.hosts_up,
            "open_services": self.open_services,
            "duration_seconds": round(self.duration_seconds, 2),
            "status": self.status,
            "reachability": (
                self.reachability.state if self.reachability else "unknown"
            ),
            "reachability_note": self.reachability.note if self.reachability else None,
            "results_complete": self.parsed.is_complete,
            "raw_xml": str(self.raw_xml_path),
            "evidence": str(self.evidence_path),
        }


def _audit_log() -> AuditLog:
    return AuditLog(DATA_DIR / "audit.jsonl")


def _persist(
    result_scan: ParsedScan,
    *,
    session_id: str,
    target_spec: str,
    profile: str,
    scan_kind: str,
    nmap_version: str | None,
    nmap_argv: list[str],
    config_hash: str | None,
    raw_xml_path: Path,
    duration_seconds: float,
    reachability: Reachability,
    status: str,
    actor: str,
    user_id: int | None = None,
    db_path: Path | None = None,
) -> int:
    """Write the scan and its results to the database. Returns the row id.

    `user_id` is the owning operator, stamped onto the scan and denormalised
    onto every host and service so the read paths can filter by owner directly.
    """
    with session_scope(db_path) as db:
        row = ScanSession(
            session_id=session_id,
            target_spec=target_spec,
            profile=profile,
            scan_kind=scan_kind,
            status=status,
            finished_at=datetime.now(timezone.utc),
            duration_seconds=duration_seconds,
            nmap_version=nmap_version,
            nmap_argv=nmap_argv,
            config_hash=config_hash,
            raw_xml_path=str(raw_xml_path),
            initiated_by=actor,
            user_id=user_id,
            hosts_up=len(result_scan.hosts_up),
            open_services=result_scan.total_open_services,
            reachability=reachability.state,
            reachability_note=reachability.note,
        )
        db.add(row)
        db.flush()

        for host in result_scan.hosts:
            host_row = DiscoveredHost(
                session_id=row.id,
                user_id=user_id,
                address=host.address,
                hostname=host.hostname,
                state=host.state,
                mac_address=host.mac_address,
            )
            db.add(host_row)
            db.flush()

            for service in host.services:
                db.add(
                    DiscoveredService(
                        host_id=host_row.id,
                        user_id=user_id,
                        port=service.port,
                        proto=service.proto,
                        state=service.state,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        extra_info=service.extra_info,
                        nmap_confidence=service.confidence,
                        nmap_cpes=list(service.cpes) or None,
                        version_confidence=service.version_confidence,
                        identification_status=service.identification_status,
                    )
                )

        return row.id


def _persist_failure(
    *,
    session_id: str,
    target_spec: str,
    profile: str,
    scan_kind: str,
    error: str,
    actor: str,
    user_id: int | None = None,
    raw_xml_path: Path | None = None,
    nmap_argv: list[str] | None = None,
    duration_seconds: float | None = None,
    db_path: Path | None = None,
) -> int | None:
    """Record a scan that failed, with no results attached.

    Deliberately writes NO host, service, signature or vulnerability rows. A
    failed scan must be visibly failed: the alternative — dropping it — leaves
    the operator with a target that appears never to have been scanned, and the
    alternative to that — recording it as completed with no findings — would be
    a fabricated clean result.

    A failure here must never mask the original error, so any database problem
    is reported and swallowed rather than replacing the exception in flight.
    """
    try:
        with session_scope(db_path) as db:
            row = ScanSession(
                session_id=session_id,
                target_spec=target_spec,
                profile=profile,
                scan_kind=scan_kind,
                status="failed",
                finished_at=datetime.now(timezone.utc),
                duration_seconds=duration_seconds,
                nmap_argv=nmap_argv,
                raw_xml_path=str(raw_xml_path) if raw_xml_path else None,
                error=error[:4000],
                initiated_by=actor,
                user_id=user_id,
                hosts_up=None,
                open_services=None,
                reachability="unknown",
                reachability_note=(
                    "The scan failed before results could be read. Nothing is "
                    "known about this target's services or vulnerabilities."
                ),
            )
            db.add(row)
            db.flush()
            return row.id
    except Exception as exc:  # noqa: BLE001 - must not mask the scan failure
        print(f"warning: could not record failed scan {session_id}: {exc}")
        return None


def _write_evidence(
    result_scan: ParsedScan,
    *,
    session_id: str,
    target_spec: str,
    profile: str,
    scan_kind: str,
    nmap_version: str | None,
    nmap_argv: list[str],
    config_hash: str | None,
    raw_xml_path: Path,
    duration_seconds: float,
    reachability: Reachability | None = None,
    evidence_dir: Path | None = None,
) -> Path:
    """Write the reproducibility manifest plus normalized results (spec §23)."""
    directory = evidence_dir or SCANS_EVIDENCE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{session_id}.json"

    # Copy the raw Nmap XML alongside the normalized results. data/ is
    # gitignored working state, but the raw output is the primary evidence for
    # every claim in the write-up and has to be retained and versioned with it.
    try:
        raw_copy_dir = (directory.parent / "raw")
        raw_copy_dir.mkdir(parents=True, exist_ok=True)
        if raw_xml_path.exists():
            shutil.copy2(raw_xml_path, raw_copy_dir / raw_xml_path.name)
    except OSError as exc:  # evidence copy must never abort a completed scan
        print(f"warning: could not copy raw XML into experiments/raw: {exc}")

    payload = {
        "manifest": {
            "session_id": session_id,
            "target": target_spec,
            "profile": profile,
            "scan_kind": scan_kind,
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "nmap_version": nmap_version,
            "nmap_argv": nmap_argv,
            "config_hash": config_hash,
            "raw_xml_path": str(raw_xml_path),
            "duration_seconds": round(duration_seconds, 3),
        },
        "results": result_scan.to_dict(),
        "counts": {
            "hosts_total": len(result_scan.hosts),
            "hosts_up": len(result_scan.hosts_up),
            "open_services": result_scan.total_open_services,
        },
        # Recorded in the evidence file so a reader of the research output can
        # tell "scanned and found nothing exposed" from "never answered".
        "reachability": reachability.to_dict() if reachability else None,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _execute(
    config: Config,
    target_spec: str,
    *,
    profile_name: str,
    scan_kind: str,
    ports: list[int] | None = None,
    actor: str = "operator",
    user_id: int | None = None,
    authorized_user_targets: tuple[tuple[str, str], ...] = (),
    evidence_dir: Path | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    raw_dir: Path | None = None,
) -> ScanResult:
    session_id = uuid.uuid4().hex[:16]
    audit = AuditLog(audit_path) if audit_path else _audit_log()

    # --- Authorization first, before anything touches the network -----------
    try:
        entry = assert_in_scope(config, target_spec, user_targets=authorized_user_targets)
    except Exception as exc:
        audit.record(
            "scan.refused",
            outcome="refused",
            actor=actor,
            detail={"target": target_spec, "profile": profile_name, "reason": str(exc)},
        )
        raise

    target = parse_target(target_spec)

    audit.record(
        "scan.start",
        outcome="pending",
        actor=actor,
        detail={
            "session_id": session_id,
            "target": str(target.network),
            "profile": profile_name,
            "scan_kind": scan_kind,
            "authorized_by": entry.name,
        },
    )

    # --- Run Nmap ---------------------------------------------------------
    try:
        execution = run_nmap(
            config,
            profile_name,
            target,
            session_id=session_id,
            ports=ports,
            raw_dir=raw_dir,
        )
    except NmapError as exc:
        # Nmap could not run, or produced nothing at all. Record the attempt as
        # a failed scan so it appears in the history with its reason, rather
        # than vanishing and leaving the operator with no trace. No host,
        # service, or vulnerability row is created — a failure must never
        # manufacture findings.
        _persist_failure(
            session_id=session_id,
            target_spec=str(target.network),
            profile=profile_name,
            scan_kind=scan_kind,
            error=str(exc),
            actor=actor,
            user_id=user_id,
            db_path=db_path,
        )
        audit.record(
            "scan.failed",
            outcome="failure",
            actor=actor,
            detail={
                "session_id": session_id,
                "target": str(target.network),
                "stage": "nmap_execution",
                "error": str(exc),
            },
        )
        raise ScanError(str(exc)) from exc

    # --- Parse ------------------------------------------------------------
    # Truncated output is repaired where possible and flagged; output that
    # cannot be parsed at all is a failure, never an empty result set.
    try:
        parsed = parse_nmap_xml(execution.xml_text)
    except NmapParseError as exc:
        message = (
            f"{exc} Raw output retained at {execution.raw_xml_path}."
        )
        _persist_failure(
            session_id=session_id,
            target_spec=str(target.network),
            profile=profile_name,
            scan_kind=scan_kind,
            error=message,
            actor=actor,
            user_id=user_id,
            raw_xml_path=execution.raw_xml_path,
            nmap_argv=list(execution.argv),
            duration_seconds=execution.duration_seconds,
            db_path=db_path,
        )
        audit.record(
            "scan.failed",
            outcome="failure",
            actor=actor,
            detail={
                "session_id": session_id,
                "target": str(target.network),
                "stage": "xml_parsing",
                "error": message,
                "raw_xml_path": str(execution.raw_xml_path),
            },
        )
        raise ScanError(message) from exc

    nmap_version = parsed.nmap_version or get_nmap_version()
    argv = list(execution.argv)

    # --- Reachability -----------------------------------------------------
    # Derived from the results, not from authorization. "-Pn" makes Nmap report
    # every address as up, so the profile's own flags decide how host state is
    # interpreted.
    used_pn = "-Pn" in argv
    reachability = assess_scan(parsed, target_spec=str(target.network), used_pn=used_pn)

    if not parsed.is_complete:
        status = "completed_with_timeouts"
    elif not reachability.is_reachable:
        # A distinct status: the scan ran correctly and the target said nothing.
        # Reported as unreachable everywhere, never as a clean host.
        status = "completed_unreachable"
    else:
        status = "completed"

    db_id = _persist(
        parsed,
        session_id=session_id,
        target_spec=str(target.network),
        profile=profile_name,
        scan_kind=scan_kind,
        nmap_version=nmap_version,
        nmap_argv=argv,
        config_hash=config.config_hash,
        raw_xml_path=execution.raw_xml_path,
        duration_seconds=execution.duration_seconds,
        reachability=reachability,
        status=status,
        actor=actor,
        user_id=user_id,
        db_path=db_path,
    )

    evidence_path = _write_evidence(
        parsed,
        session_id=session_id,
        target_spec=str(target.network),
        profile=profile_name,
        scan_kind=scan_kind,
        nmap_version=nmap_version,
        nmap_argv=argv,
        config_hash=config.config_hash,
        raw_xml_path=execution.raw_xml_path,
        duration_seconds=execution.duration_seconds,
        reachability=reachability,
        evidence_dir=evidence_dir,
    )

    audit.record(
        "scan.finish",
        # A truncated scan is not a success, and neither is a target that never
        # answered. Recorded as distinct outcomes so the audit trail cannot be
        # read as evidence of an exhaustive sweep or of a clean host.
        outcome=(
            "success"
            if parsed.is_complete and reachability.is_reachable
            else "partial"
        ),
        actor=actor,
        detail={
            "session_id": session_id,
            "target": str(target.network),
            "hosts_total": len(parsed.hosts),
            "hosts_up": len(parsed.hosts_up),
            "open_services": parsed.total_open_services,
            "results_complete": parsed.is_complete,
            "recovered_from_truncation": parsed.recovered_from_truncation,
            "hosts_timed_out": [h.address for h in parsed.hosts_timed_out],
            "reachability": reachability.state,
            "status": status,
            "duration_seconds": round(execution.duration_seconds, 3),
            "raw_xml_path": str(execution.raw_xml_path),
        },
    )

    return ScanResult(
        session_id=session_id,
        target_spec=str(target.network),
        profile=profile_name,
        scan_kind=scan_kind,
        parsed=parsed,
        raw_xml_path=execution.raw_xml_path,
        evidence_path=evidence_path,
        duration_seconds=execution.duration_seconds,
        db_session_id=db_id,
        reachability=reachability,
        status=status,
    )


# Profiles that perform host discovery only. `run_discovery` accepts a profile
# name so the LAN probe set can be chosen, but only from this set: a profile
# that also scans ports would silently turn a "discovery" request into a full
# service scan, and the scan_kind recorded in the database would be wrong.
DISCOVERY_PROFILES = frozenset({"discovery", "lan_discovery"})


def run_discovery(
    config: Config,
    target_spec: str,
    *,
    profile_name: str | None = None,
    actor: str = "operator",
    user_id: int | None = None,
    authorized_user_targets: tuple[tuple[str, str], ...] = (),
    evidence_dir: Path | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    raw_dir: Path | None = None,
) -> ScanResult:
    """Host discovery only. No ports are scanned (spec §7.1)."""
    chosen = profile_name or "discovery"
    if chosen not in DISCOVERY_PROFILES:
        raise ScanError(
            f"{chosen!r} is not a host-discovery profile. Discovery accepts one "
            f"of: {', '.join(sorted(DISCOVERY_PROFILES))}. Use a service "
            "detection scan for port and version detection."
        )
    return _execute(
        config,
        target_spec,
        profile_name=chosen,
        scan_kind="discovery",
        actor=actor,
        user_id=user_id,
        authorized_user_targets=authorized_user_targets,
        evidence_dir=evidence_dir,
        db_path=db_path,
        audit_path=audit_path,
        raw_dir=raw_dir,
    )


def run_service_detection(
    config: Config,
    target_spec: str,
    *,
    profile_name: str | None = None,
    ports: list[int] | None = None,
    scan_kind: str = "assessment",
    actor: str = "operator",
    user_id: int | None = None,
    authorized_user_targets: tuple[tuple[str, str], ...] = (),
    correlate_after: bool = False,
    evidence_dir: Path | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    raw_dir: Path | None = None,
) -> ScanResult:
    """Port, service and version detection (spec §7.2-7.4).

    Args:
        correlate_after: Run CVE correlation immediately after the scan. Off by
            default because correlation needs the NVD API and a scan must be
            able to complete and be recorded without network access to NVD. A
            correlation failure never invalidates the scan results.
    """
    result = _execute(
        config,
        target_spec,
        profile_name=profile_name or config.default_profile,
        scan_kind=scan_kind,
        ports=ports,
        actor=actor,
        user_id=user_id,
        authorized_user_targets=authorized_user_targets,
        evidence_dir=evidence_dir,
        db_path=db_path,
        audit_path=audit_path,
        raw_dir=raw_dir,
    )

    if correlate_after and result.open_services:
        # Imported here rather than at module scope: the correlation pipeline is
        # a consumer of scan results, and a top-level import would invert that.
        from backend.nvd.pipeline import run_correlation

        try:
            run_correlation(
                config,
                result.session_id,
                actor=actor,
                user_id=user_id,
                db_path=db_path,
                audit_path=audit_path,
            )
        except Exception as exc:  # noqa: BLE001 - recorded, never fatal
            # The scan itself succeeded and its results are stored. Correlation
            # failing means "no CVE lookup happened", which the UI reports as
            # such — it must never be shown as "no vulnerabilities found".
            audit = AuditLog(audit_path) if audit_path else _audit_log()
            audit.record(
                "correlation.failed",
                outcome="failure",
                actor=actor,
                detail={
                    "session_id": result.session_id,
                    "error": f"{type(exc).__name__}: {exc}",
                    "note": (
                        "The scan results are unaffected. No CVE candidates were "
                        "recorded because the lookup did not run."
                    ),
                },
            )

    return result
