"""Assemble a per-scan assessment report from stored evidence.

Everything here is read-only: it reads the database (and, for the "was this
scan correlated?" signal, the correlation evidence file) and returns a plain
data structure. It writes nothing and touches no network.

The report deliberately mirrors what the rest of the system already refuses to
overstate:

  * A CVE row is a *candidate*, never a confirmed vulnerability.
  * "version unknown" is *undetermined*, never clean.
  * A failed / unreachable / partial / uncorrelated scan is never summarised as
    "no vulnerabilities found".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from backend.core.config import EXPERIMENTS_DIR, Config, ConfigError, load_config
from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    RemediationAction,
    ScanSession,
    Vulnerability,
)
from backend.database.session import session_scope

__all__ = [
    "Report",
    "ReportSummary",
    "SummaryState",
    "build_report",
    "list_reportable_scans",
]

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
REPORTS_EVIDENCE_DIR = EXPERIMENTS_DIR / "reports"


class SummaryState(str, Enum):
    """The one-line verdict class for a report. None of these is 'clean' unless
    the scan actually produced sufficient evidence to say so, and even then the
    wording stays 'no candidates', not 'not vulnerable'."""

    FAILED = "failed"                    # scan errored; nothing known
    UNREACHABLE = "unreachable"          # authorized but nothing answered
    PARTIAL = "partial"                  # timed out / truncated; incomplete
    IN_PROGRESS = "in_progress"          # not finished
    NO_OPEN_SERVICES = "no_open_services"  # reachable, exposed nothing probed
    NOT_CORRELATED = "not_correlated"    # services found, NVD lookup not run
    UNDETERMINED = "undetermined"        # correlated, but versions unidentified
    CANDIDATES = "candidates"            # CVE candidates present, need review
    NO_CANDIDATES = "no_candidates"      # correlated, none returned (≠ clean)


# ---------------------------------------------------------------------------
# Recommendation text (report-local; a recommendation, never an automated act)
# ---------------------------------------------------------------------------

_PORT_ADVICE: dict[int, str] = {
    21: "FTP transmits credentials in cleartext. Replace with SFTP or restrict the "
        "port to trusted hosts.",
    23: "Telnet is cleartext and unauthenticated in transit. Disable it and use SSH.",
    139: "NetBIOS/SMB should not be exposed beyond a trusted segment.",
    445: "SMB should not be exposed beyond a trusted segment.",
    3306: "Database ports should not be network-exposed. Bind to localhost or "
          "restrict by source address.",
    5432: "Database ports should not be network-exposed. Bind to localhost or "
          "restrict by source address.",
    6379: "Redis is unauthenticated by default and should never be reachable from a "
          "general network. Bind to localhost and set requirepass.",
    11211: "Memcached is unauthenticated and a known amplification vector. Bind to "
           "localhost.",
    27017: "MongoDB should not be network-exposed. Bind to localhost and enable "
           "authentication.",
    3389: "RDP is a common attack target. Restrict by source and require NLA.",
    5900: "VNC is frequently weakly authenticated. Tunnel it over SSH instead.",
}

_DEFAULT_ADVICE = (
    "Review whether this service needs to be reachable from this network at all. "
    "Where the vendor has published a fixed version, apply it — CyberShield does "
    "not patch software. For an eligible laboratory target, controlled network "
    "isolation is available on the Remediation page."
)


def _recommendation(port: int, product: str | None, version: str | None) -> str:
    base = _PORT_ADVICE.get(port, _DEFAULT_ADVICE)
    if product and version:
        return (
            f"{base} Detected {product} {version}: confirm against the vendor's "
            "advisory whether this specific build is affected before acting."
        )
    if product:
        return (
            f"{base} Detected {product} with no version string: the CVE match is "
            "weaker, not absent."
        )
    return base


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ReportVuln:
    cve_id: str
    severity: str | None
    base_score: float | None
    cvss_version: str | None
    vector_string: str | None
    confidence: str
    matching_method: str
    status: str
    detected_product: str | None
    detected_version: str | None
    probable_false_positive: bool
    description: str | None
    cwe_ids: list[str]
    nvd_reference: str | None
    caveats: list[str]

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ReportService:
    port: int
    proto: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    version_confidence: str
    identification_status: str
    nmap_confidence: int | None
    policy: str | None
    recommendation: str
    vulnerabilities: list[ReportVuln] = field(default_factory=list)

    @property
    def max_severity(self) -> str | None:
        scored = [v.severity for v in self.vulnerabilities if v.severity in SEVERITY_ORDER]
        return max(scored, key=lambda s: SEVERITY_ORDER[s]) if scored else None

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        d["max_severity"] = self.max_severity
        return d


@dataclass
class ReportHost:
    address: str
    hostname: str | None
    state: str
    services: list[ReportService] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["services"] = [s.to_dict() for s in self.services]
        return d


@dataclass
class ReportRemediation:
    request_id: str
    target: str
    port: int
    proto: str
    backend: str
    state: str
    is_dry_run: bool
    exposure_reduced: bool | None
    rollback_verified: bool | None
    management_channel_intact: bool | None
    before_state: str | None
    after_state: str | None
    applied_at: str | None
    rolled_back_at: str | None
    verification_findings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ReportSummary:
    state: SummaryState
    headline: str
    detail: str
    total_candidates: int
    reviewed_candidates: int
    flagged_false_positives: int
    undetermined_services: int
    severity_counts: dict[str, int]

    @property
    def is_clean_claim(self) -> bool:
        """True only for the states that legitimately mean 'nothing was found in a
        scan that could have found it'. Used by tests to guard the honesty rule:
        the insufficient-evidence states must never report this as True."""
        return self.state == SummaryState.NO_CANDIDATES

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["state"] = self.state.value
        return d


@dataclass
class Report:
    session_id: str
    target: str
    scan_kind: str
    profile: str
    status: str
    reachability: str | None
    reachability_note: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    nmap_version: str | None
    nmap_argv: list[str]
    config_hash: str | None
    operator: str | None
    raw_xml_path: str | None
    generated_at: datetime
    correlation_ran: bool
    hosts: list[ReportHost]
    remediations: list[ReportRemediation]
    summary: ReportSummary
    counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "scan_kind": self.scan_kind,
            "profile": self.profile,
            "status": self.status,
            "reachability": self.reachability,
            "reachability_note": self.reachability_note,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "nmap_version": self.nmap_version,
            "nmap_argv": self.nmap_argv,
            "config_hash": self.config_hash,
            "operator": self.operator,
            "raw_xml_path": self.raw_xml_path,
            "generated_at": self.generated_at.isoformat(),
            "correlation_ran": self.correlation_ran,
            "hosts": [h.to_dict() for h in self.hosts],
            "remediations": [r.to_dict() for r in self.remediations],
            "summary": self.summary.to_dict(),
            "counts": self.counts,
        }


# ---------------------------------------------------------------------------
# Summary (the honesty-critical part)
# ---------------------------------------------------------------------------


def summarise(
    *,
    status: str,
    reachability: str | None,
    open_service_count: int,
    correlation_ran: bool,
    total_candidates: int,
    flagged_false_positives: int,
    undetermined_services: int,
    severity_counts: dict[str, int],
    reviewed_candidates: int,
) -> ReportSummary:
    """Derive the overall security verdict without ever overstating it.

    The ordering of the branches is the whole point: a scan that could not
    gather evidence is reported as such and short-circuits before any branch
    that could read as "clean".
    """
    def make(state: SummaryState, headline: str, detail: str) -> ReportSummary:
        return ReportSummary(
            state=state,
            headline=headline,
            detail=detail,
            total_candidates=total_candidates,
            reviewed_candidates=reviewed_candidates,
            flagged_false_positives=flagged_false_positives,
            undetermined_services=undetermined_services,
            severity_counts=severity_counts,
        )

    if status == "failed":
        return make(
            SummaryState.FAILED,
            "Scan failed — no conclusion can be drawn",
            "The scan did not complete and produced no host, service or "
            "vulnerability data. Nothing is known about this target. This is not "
            "a clean result; re-run the scan.",
        )

    if status == "pending" or status not in {
        "completed", "completed_with_timeouts", "completed_unreachable",
    }:
        return make(
            SummaryState.IN_PROGRESS,
            "Scan incomplete",
            "This scan has not finished, so no findings can be reported yet.",
        )

    if status == "completed_unreachable" or reachability == "unreachable":
        return make(
            SummaryState.UNREACHABLE,
            "Target unreachable — insufficient evidence",
            "The scan ran correctly but the target answered no probe. Nothing "
            "could be observed about its services or vulnerabilities. A zero "
            "count here means the target was not examined — NOT that it is clean.",
        )

    if status == "completed_with_timeouts":
        return make(
            SummaryState.PARTIAL,
            "Partial results — incomplete evidence",
            "One or more hosts timed out or Nmap output was truncated, so the "
            "port and service list is incomplete. An absent finding is not "
            "evidence of absence; re-run with a longer host timeout before "
            "drawing conclusions.",
        )

    # From here the scan completed and the target was reachable.
    if open_service_count == 0:
        return make(
            SummaryState.NO_OPEN_SERVICES,
            "Reachable, but no probed port was open",
            "The target answered but exposed none of the ports this profile "
            "probes. That is not the same as having no vulnerabilities — only "
            "the probed ports were examined.",
        )

    if not correlation_ran:
        return make(
            SummaryState.NOT_CORRELATED,
            "Services detected — CVE correlation not yet run",
            "Open services were detected but have not been correlated against "
            "NVD, so no CVE candidates exist yet. This is NOT a clean result. "
            "Run correlation from the scan page to check these services.",
        )

    if total_candidates > 0:
        crit = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        headline = f"{total_candidates} CVE candidate(s) require review"
        emphasis = ""
        if crit or high:
            emphasis = f" including {crit} critical and {high} high-severity"
        return make(
            SummaryState.CANDIDATES,
            headline,
            f"Correlation returned {total_candidates} CVE candidate(s){emphasis}. "
            "Each is a candidate only: a version string resembling a CVE's "
            "affected software is not proof of vulnerability or exploitability, "
            "and no exploitation was attempted. "
            f"{flagged_false_positives} are flagged as probable false positives.",
        )

    if undetermined_services > 0:
        return make(
            SummaryState.UNDETERMINED,
            "No CVE candidates — but some services are undetermined",
            f"NVD returned no candidates, but {undetermined_services} open "
            "service(s) could not be version-identified, so they are "
            "UNDETERMINED, not clean. Absence of a version is not absence of a "
            "vulnerability.",
        )

    return make(
        SummaryState.NO_CANDIDATES,
        "No CVE candidates returned for the identified services",
        "Correlation ran and NVD returned no CVE candidates for the identified "
        "services. This is not proof the services are free of vulnerabilities: "
        "NVD coverage is incomplete, only the probed ports were examined, and no "
        "exploitation was attempted.",
    )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _correlation_ran(session_id: str, service_ids: list[int], db) -> bool:
    """Did CVE correlation run for this scan?

    Two independent signals, either sufficient: a Vulnerability row for one of
    these services (correlation ran and matched), or the correlation evidence
    file the pipeline writes (correlation ran, possibly matching nothing). The
    file covers the "ran and returned zero" case that leaves no DB rows.
    """
    if service_ids:
        exists = (
            db.query(Vulnerability.id)
            .filter(Vulnerability.service_id.in_(service_ids))
            .first()
        )
        if exists is not None:
            return True
    return (REPORTS_EVIDENCE_DIR / f"{session_id}_correlation.json").exists()


def build_report(
    session_id: str,
    *,
    user_id: int | None = None,
    config: Config | None = None,
    db_path: Path | None = None,
) -> Report | None:
    """Assemble the report for one scan session, or None if it does not exist.

    When `user_id` is given, a scan owned by a different user is treated as
    non-existent, so a report cannot be read by changing the id in the URL.
    """
    if config is None:
        try:
            config = load_config()
        except ConfigError:
            config = None

    with session_scope(db_path) as db:
        scan = db.query(ScanSession).filter_by(session_id=session_id).one_or_none()
        if scan is None:
            return None
        if user_id is not None and scan.user_id != user_id:
            return None

        host_rows = (
            db.query(DiscoveredHost)
            .filter_by(session_id=scan.id)
            .order_by(DiscoveredHost.address)
            .all()
        )
        host_addresses = {h.address for h in host_rows}
        all_service_ids: list[int] = []
        hosts: list[ReportHost] = []

        severity_counts: dict[str, int] = {}
        total_candidates = 0
        reviewed_candidates = 0
        flagged_fp = 0
        undetermined_services = 0
        open_service_count = 0

        for host in host_rows:
            service_rows = (
                db.query(DiscoveredService)
                .filter_by(host_id=host.id)
                .order_by(DiscoveredService.port)
                .all()
            )
            report_services: list[ReportService] = []
            for svc in service_rows:
                all_service_ids.append(svc.id)
                if svc.state == "open":
                    open_service_count += 1
                    if svc.identification_status == "undetermined":
                        undetermined_services += 1

                policy = None
                if config is not None:
                    try:
                        policy = config.policy_for(svc.port, svc.proto).policy
                    except Exception:  # noqa: BLE001 - policy is decorative here
                        policy = None

                vuln_rows = (
                    db.query(Vulnerability)
                    .filter_by(service_id=svc.id)
                    .order_by(Vulnerability.id)
                    .all()
                )
                report_vulns: list[ReportVuln] = []
                for v in vuln_rows:
                    cve = db.get(CveRecord, v.cve_id)
                    is_fp = (v.evidence or {}).get("vulnerable_match_count") == 0
                    total_candidates += 1
                    if is_fp:
                        flagged_fp += 1
                    if v.status and v.status != "candidate":
                        reviewed_candidates += 1
                    sev = cve.base_severity if cve else None
                    if sev in SEVERITY_ORDER:
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    report_vulns.append(
                        ReportVuln(
                            cve_id=v.cve_id,
                            severity=sev,
                            base_score=cve.base_score if cve else None,
                            cvss_version=cve.cvss_version if cve else None,
                            vector_string=cve.vector_string if cve else None,
                            confidence=v.confidence,
                            matching_method=v.matching_method,
                            status=v.status,
                            detected_product=v.detected_product,
                            detected_version=v.detected_version,
                            probable_false_positive=is_fp,
                            description=cve.description if cve else None,
                            cwe_ids=list(cve.cwe_ids or []) if cve else [],
                            nvd_reference=v.nvd_reference,
                            caveats=list(v.caveats or []),
                        )
                    )
                # Most severe candidate first within a service.
                report_vulns.sort(
                    key=lambda rv: -SEVERITY_ORDER.get(rv.severity or "", -1)
                )
                report_services.append(
                    ReportService(
                        port=svc.port,
                        proto=svc.proto,
                        state=svc.state,
                        service_name=svc.service_name,
                        product=svc.product,
                        version=svc.version,
                        version_confidence=svc.version_confidence,
                        identification_status=svc.identification_status,
                        nmap_confidence=svc.nmap_confidence,
                        policy=policy,
                        recommendation=_recommendation(svc.port, svc.product, svc.version),
                        vulnerabilities=report_vulns,
                    )
                )
            hosts.append(
                ReportHost(
                    address=host.address,
                    hostname=host.hostname,
                    state=host.state,
                    services=report_services,
                )
            )

        correlation_ran = _correlation_ran(session_id, all_service_ids, db)

        # Remediation actions against any host in this scan.
        remediations: list[ReportRemediation] = []
        if host_addresses:
            rem_rows = (
                db.query(RemediationAction)
                .filter(RemediationAction.target_address.in_(host_addresses))
                .order_by(RemediationAction.id.desc())
                .all()
            )
            for r in rem_rows:
                verification = (r.after_state or {})
                findings: list[str] = []
                # Rebuild a plain-language verification line from stored evidence.
                before = (r.before_state or {}).get("state")
                after = (r.after_state or {}).get("state")
                if before or after:
                    findings.append(
                        f"Port {r.proto}/{r.port}: {before or '—'} → {after or '—'} "
                        "(observed by this scanner only)."
                    )
                if r.exposure_reduced:
                    findings.append("Network exposure was reduced. Service still runs; not patched.")
                elif r.exposure_reduced is False and r.state == "applied":
                    findings.append("No exposure reduction observed from this vantage point.")
                if r.management_channel_intact is False:
                    findings.append("WARNING: management channel did not answer after the action.")
                remediations.append(
                    ReportRemediation(
                        request_id=r.request_id,
                        target=r.target_address,
                        port=r.port,
                        proto=r.proto,
                        backend=r.backend,
                        state=r.state,
                        is_dry_run=r.backend == "dryrun",
                        exposure_reduced=r.exposure_reduced,
                        rollback_verified=r.rollback_verified,
                        management_channel_intact=r.management_channel_intact,
                        before_state=before,
                        after_state=after,
                        applied_at=r.applied_at.isoformat() if r.applied_at else None,
                        rolled_back_at=r.rolled_back_at.isoformat() if r.rolled_back_at else None,
                        verification_findings=findings,
                    )
                )

        summary = summarise(
            status=scan.status,
            reachability=scan.reachability,
            open_service_count=open_service_count,
            correlation_ran=correlation_ran,
            total_candidates=total_candidates,
            flagged_false_positives=flagged_fp,
            undetermined_services=undetermined_services,
            severity_counts=severity_counts,
            reviewed_candidates=reviewed_candidates,
        )

        counts = {
            "hosts": len(hosts),
            "hosts_up": scan.hosts_up if scan.hosts_up is not None else sum(
                1 for h in hosts if h.state == "up"
            ),
            "open_services": open_service_count,
            "candidates": total_candidates,
            "flagged_false_positives": flagged_fp,
            "undetermined_services": undetermined_services,
            "remediations": len(remediations),
        }

        return Report(
            session_id=scan.session_id,
            target=scan.target_spec,
            scan_kind=scan.scan_kind,
            profile=scan.profile,
            status=scan.status,
            reachability=scan.reachability,
            reachability_note=scan.reachability_note,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            duration_seconds=scan.duration_seconds,
            nmap_version=scan.nmap_version,
            nmap_argv=list(scan.nmap_argv or []),
            config_hash=scan.config_hash,
            operator=scan.initiated_by,
            raw_xml_path=scan.raw_xml_path,
            generated_at=datetime.now(timezone.utc),
            correlation_ran=correlation_ran,
            hosts=hosts,
            remediations=remediations,
            summary=summary,
            counts=counts,
        )


def list_reportable_scans(
    *, user_id: int | None = None, limit: int = 100, db_path: Path | None = None
) -> list[dict[str, Any]]:
    """List assessment scans a report can be generated for, newest first.

    Scoped to `user_id` when given, so each operator sees only their own scans.
    """
    with session_scope(db_path) as db:
        query = db.query(ScanSession).filter_by(scan_kind="assessment")
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        rows = (
            query
            .order_by(ScanSession.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "session_id": r.session_id,
                "target": r.target_spec,
                "status": r.status,
                "reachability": r.reachability,
                "hosts_up": r.hosts_up,
                "open_services": r.open_services,
                "started_at": r.started_at,
            }
            for r in rows
        ]
