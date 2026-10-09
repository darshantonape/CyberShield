"""Correlation run: take a completed scan and produce CVE candidates.

Reads `discovered_services` for a scan session, correlates each open service
against NVD, and writes `software_signatures`, `cve_records` and
`vulnerabilities`, plus a reproducibility manifest under
`experiments/reports/<session>_correlation.json`.

Only **open** services are correlated. A closed or filtered port exposes
nothing, so correlating it would inflate the finding count with services that
are not reachable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.audit import AuditLog
from backend.core.config import DATA_DIR, EXPERIMENTS_DIR, Config
from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    ScanSession,
    SoftwareSignature,
    Vulnerability,
)
from backend.database.session import session_scope
from backend.nvd.client import NvdClient
from backend.nvd.correlate import CorrelationResult, correlate_service
from backend.scanner.nmap_parser import ParsedService

__all__ = ["CorrelationRunResult", "run_correlation"]

REPORTS_DIR = EXPERIMENTS_DIR / "reports"


@dataclass
class CorrelationRunResult:
    session_id: str
    services_considered: int = 0
    services_correlated: int = 0
    services_undetermined: int = 0
    signatures_created: int = 0
    candidates_created: int = 0
    flagged_probable_false_positives: int = 0
    queries_made: int = 0
    duration_seconds: float = 0.0
    evidence_path: Path | None = None
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "services_considered": self.services_considered,
            "services_correlated": self.services_correlated,
            "services_undetermined": self.services_undetermined,
            "signatures_created": self.signatures_created,
            "cve_candidates": self.candidates_created,
            "flagged_probable_false_positives": self.flagged_probable_false_positives,
            "nvd_queries": self.queries_made,
            "duration_seconds": round(self.duration_seconds, 2),
            "evidence": str(self.evidence_path) if self.evidence_path else None,
            "errors": self.errors,
        }


def _to_parsed_service(row: DiscoveredService) -> ParsedService:
    """Rebuild the parser's view of a service from its stored row."""
    return ParsedService(
        port=row.port,
        proto=row.proto,
        state=row.state,
        service_name=row.service_name,
        product=row.product,
        version=row.version,
        extra_info=row.extra_info,
        confidence=row.nmap_confidence,
        # Stored rows do not retain Nmap's match method; "probed" is the
        # neutral assumption because a "table" guess would have produced no
        # product string, and a product-less service is skipped anyway.
        method="probed" if row.product else "table",
        cpes=tuple(row.nmap_cpes or ()),
    )


def _persist(
    db, service_row: DiscoveredService, result: CorrelationResult,
    *, user_id: int | None = None,
) -> tuple[int, int, int]:
    """Write signatures, CVE records and candidates. Returns counts.

    `user_id` (the owning operator of the scan) is stamped onto each
    Vulnerability so the vulnerabilities list can be filtered by owner.
    """
    signature_ids: dict[str, int] = {}

    for candidate in result.normalization.candidates:
        signature = SoftwareSignature(
            service_id=service_row.id,
            vendor=candidate.vendor,
            product=candidate.product,
            version=candidate.version,
            part=candidate.part,
            cpe23=candidate.cpe23,
            mapping_source=candidate.mapping_source,
            confidence=candidate.confidence,
            notes=candidate.notes or None,
        )
        db.add(signature)
        db.flush()
        if candidate.cpe23:
            signature_ids[candidate.cpe23] = signature.id

    # Keep the service's derived fields in step with normalization.
    service_row.version_confidence = result.normalization.version_confidence
    service_row.identification_status = result.normalization.identification_status

    flagged = 0
    created = 0

    for candidate in result.candidates:
        record = db.get(CveRecord, candidate.cve_id)
        if record is None:
            record = CveRecord(
                cve_id=candidate.cve_id,
                published=candidate.published,
                last_modified=candidate.last_modified,
                vuln_status=candidate.raw.get("vulnStatus"),
                description=candidate.description,
                cvss_version=candidate.severity.version,
                base_score=candidate.severity.base_score,
                base_severity=candidate.severity.base_severity,
                vector_string=candidate.severity.vector_string,
                all_metrics=candidate.severity.all_metrics,
                cwe_ids=candidate.cwe_ids or None,
                reference_urls=[
                    r.get("url")
                    for r in (candidate.raw.get("references") or [])[:10]
                    if r.get("url")
                ]
                or None,
                raw_json=candidate.raw or None,
            )
            db.add(record)
            db.flush()

        exists = (
            db.query(Vulnerability)
            .filter_by(service_id=service_row.id, cve_id=candidate.cve_id)
            .one_or_none()
        )
        if exists is not None:
            continue

        is_flagged = candidate.evidence.get("vulnerable_match_count") == 0
        if is_flagged:
            flagged += 1

        db.add(
            Vulnerability(
                service_id=service_row.id,
                user_id=user_id,
                cve_id=candidate.cve_id,
                signature_id=signature_ids.get(candidate.matched_cpe or ""),
                matching_method=candidate.matching_method,
                confidence=candidate.confidence,
                detected_product=candidate.detected_product,
                detected_version=candidate.detected_version,
                status="candidate",
                evidence=candidate.evidence or None,
                caveats=candidate.caveats or None,
                nvd_reference=candidate.nvd_reference,
            )
        )
        created += 1

    return len(result.normalization.candidates), created, flagged


def run_correlation(
    config: Config,
    session_id: str,
    *,
    client: NvdClient | None = None,
    actor: str = "operator",
    user_id: int | None = None,
    db_path: Path | None = None,
    audit_path: Path | None = None,
    evidence_dir: Path | None = None,
) -> CorrelationRunResult:
    """Correlate every open service from a completed scan session."""
    started = datetime.now(timezone.utc)
    audit = AuditLog(audit_path or (DATA_DIR / "audit.jsonl"))
    nvd = client or NvdClient(api_key=config.settings.nvd_api_key)

    result = CorrelationRunResult(session_id=session_id)
    per_service: list[dict[str, Any]] = []

    audit.record(
        "correlation.start",
        outcome="pending",
        actor=actor,
        detail={"session_id": session_id},
    )

    # Transaction boundaries matter here more than anywhere else in the system.
    #
    # This used to run inside ONE session_scope that stayed open across every
    # correlate_service() call — and each of those makes live HTTPS requests to
    # NVD, rate-limited to 5 requests per 30 seconds without an API key. A
    # twelve-service laboratory scan therefore held SQLite's write lock for
    # minutes. Every other request in the process touches the database (the auth
    # middleware alone stamps user_sessions.last_seen_at), so the whole console
    # returned 500 "database is locked" for the duration of a correlation run.
    #
    # The work is now split: one short read transaction to decide what to
    # correlate, the network calls outside any transaction at all, and one short
    # write transaction per service. A correlation run no longer blocks the UI,
    # and a crash mid-run leaves the services already correlated persisted
    # rather than rolling all of them back.
    with session_scope(db_path) as db:
        scan = db.query(ScanSession).filter_by(session_id=session_id).one_or_none()
        if scan is None:
            raise ValueError(f"No scan session {session_id!r}.")

        # Vulnerabilities belong to the scan's owner, whoever triggered the
        # correlation. An explicit user_id (from the scan pipeline) wins; the
        # scan's own owner is the fallback.
        owner_id = user_id if user_id is not None else scan.user_id

        host_ids = [h.id for h in db.query(DiscoveredHost).filter_by(session_id=scan.id).all()]
        services = (
            db.query(DiscoveredService)
            .filter(DiscoveredService.host_id.in_(host_ids))
            .filter(DiscoveredService.state == "open")
            .all()
            if host_ids
            else []
        )
        result.services_considered = len(services)
        # Detached snapshots: the parser's view plus what the evidence file
        # needs. Nothing below holds an ORM row across a network call.
        pending = [
            (row.id, row.port, row.product, row.version, _to_parsed_service(row))
            for row in services
        ]

    for service_id, port, product, version, parsed in pending:
        # Outside every transaction: this is the slow, network-bound part.
        try:
            correlation = correlate_service(nvd, parsed)
        except Exception as exc:  # noqa: BLE001 - recorded per service
            result.errors.append(f"port {port}: {type(exc).__name__}: {exc}")
            continue

        result.queries_made += correlation.queries_made
        result.errors.extend(correlation.errors)

        with session_scope(db_path) as db:
            row = db.get(DiscoveredService, service_id)
            if row is None:  # deleted under us; nothing to attach findings to
                continue
            signatures, created, flagged = _persist(db, row, correlation, user_id=owner_id)
        result.signatures_created += signatures
        result.candidates_created += created
        result.flagged_probable_false_positives += flagged

        if correlation.candidates:
            result.services_correlated += 1
        if not correlation.normalization.candidates:
            result.services_undetermined += 1

        per_service.append(
            {
                "port": port,
                "product": product,
                "version": version,
                **correlation.to_dict(),
            }
        )

    result.duration_seconds = (datetime.now(timezone.utc) - started).total_seconds()

    directory = evidence_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    evidence_path = directory / f"{session_id}_correlation.json"
    evidence_path.write_text(
        json.dumps(
            {
                "manifest": {
                    "session_id": session_id,
                    "recorded_at": started.isoformat(timespec="seconds"),
                    "config_hash": config.config_hash,
                    "nvd_client": nvd.stats() if hasattr(nvd, "stats") else None,
                    "duration_seconds": round(result.duration_seconds, 3),
                },
                "summary": result.summary(),
                "services": per_service,
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
    )
    result.evidence_path = evidence_path

    audit.record(
        "correlation.finish",
        outcome="success" if not result.errors else "failure",
        actor=actor,
        detail=result.summary(),
    )
    return result
