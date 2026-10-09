"""Assessment report assembly.

The load-bearing assertions here are the honesty ones: a scan that could not
gather sufficient evidence must never be summarised as a clean result. Every
insufficient-evidence state (failed, unreachable, partial, no-open-services,
not-correlated, undetermined) is checked to NOT read as clean, and only a
completed+reachable+correlated scan with zero returned candidates is allowed to
say "no candidates" — and even then not "not vulnerable".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    ScanSession,
    Vulnerability,
)
from backend.database.session import init_db, session_scope
from backend.reports.builder import SummaryState, build_report, summarise
from backend.reports.pdf import render_pdf


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "reports.db"
    init_db(path)
    return path


# ---------------------------------------------------------------------------
# The honesty guarantee, tested directly on summarise()
# ---------------------------------------------------------------------------


def _summary(**over):
    base = dict(
        status="completed", reachability="reachable", open_service_count=3,
        correlation_ran=True, total_candidates=0, flagged_false_positives=0,
        undetermined_services=0, severity_counts={}, reviewed_candidates=0,
    )
    base.update(over)
    return summarise(**base)


class TestNeverFalselyClean:
    def test_failed_scan_is_not_clean(self) -> None:
        s = _summary(status="failed")
        assert s.state == SummaryState.FAILED
        assert not s.is_clean_claim
        assert "not a clean result" in s.detail.lower()

    def test_unreachable_is_not_clean(self) -> None:
        s = _summary(status="completed_unreachable", reachability="unreachable")
        assert s.state == SummaryState.UNREACHABLE
        assert not s.is_clean_claim
        assert "not that it is clean" in s.detail.lower()

    def test_reachability_flag_alone_forces_unreachable(self) -> None:
        # Even if status looks completed, an unreachable verdict wins.
        s = _summary(status="completed", reachability="unreachable")
        assert s.state == SummaryState.UNREACHABLE

    def test_partial_is_not_clean(self) -> None:
        s = _summary(status="completed_with_timeouts")
        assert s.state == SummaryState.PARTIAL
        assert not s.is_clean_claim

    def test_in_progress_is_not_clean(self) -> None:
        s = _summary(status="pending")
        assert s.state == SummaryState.IN_PROGRESS
        assert not s.is_clean_claim

    def test_no_open_services_is_not_clean(self) -> None:
        s = _summary(open_service_count=0)
        assert s.state == SummaryState.NO_OPEN_SERVICES
        assert not s.is_clean_claim

    def test_uncorrelated_is_not_clean(self) -> None:
        s = _summary(correlation_ran=False, open_service_count=5)
        assert s.state == SummaryState.NOT_CORRELATED
        assert not s.is_clean_claim
        assert "not a clean result" in s.detail.lower()

    def test_undetermined_services_are_not_clean(self) -> None:
        s = _summary(total_candidates=0, undetermined_services=2)
        assert s.state == SummaryState.UNDETERMINED
        assert not s.is_clean_claim

    def test_candidates_present(self) -> None:
        s = _summary(total_candidates=4, severity_counts={"HIGH": 2, "MEDIUM": 2})
        assert s.state == SummaryState.CANDIDATES
        assert not s.is_clean_claim
        assert "candidate" in s.headline.lower()

    def test_only_fully_correlated_zero_is_the_no_candidates_state(self) -> None:
        s = _summary(total_candidates=0, undetermined_services=0, correlation_ran=True)
        assert s.state == SummaryState.NO_CANDIDATES
        assert s.is_clean_claim  # the ONLY state permitted to be "clean-ish"
        # ...but the wording still refuses to claim the target is not vulnerable.
        assert "not proof" in s.detail.lower()


# ---------------------------------------------------------------------------
# End-to-end assembly against a real (temp) database
# ---------------------------------------------------------------------------


def _seed_completed_scan(db: Path, *, with_cve: bool) -> str:
    with session_scope(db) as s:
        scan = ScanSession(
            session_id="rep123", target_spec="192.168.56.10/32", profile="service_detect",
            scan_kind="assessment", status="completed", reachability="reachable",
            hosts_up=1, open_services=1, initiated_by="tester",
        )
        s.add(scan)
        s.flush()
        host = DiscoveredHost(session_id=scan.id, address="192.168.56.10", state="up")
        s.add(host)
        s.flush()
        svc = DiscoveredService(
            host_id=host.id, port=21, proto="tcp", state="open",
            service_name="ftp", product="vsftpd", version="2.3.4",
            version_confidence="known", identification_status="identified",
        )
        s.add(svc)
        s.flush()
        if with_cve:
            s.add(CveRecord(
                cve_id="CVE-2011-2523", base_score=10.0, base_severity="CRITICAL",
                cvss_version="2.0", description="vsftpd backdoor",
            ))
            s.add(Vulnerability(
                service_id=svc.id, cve_id="CVE-2011-2523", matching_method="cpe_exact",
                confidence="HIGH", detected_product="vsftpd", detected_version="2.3.4",
                status="candidate", evidence={"vulnerable_match_count": 1},
            ))
    return "rep123"


class TestBuildReport:
    def test_missing_session_returns_none(self, db) -> None:
        assert build_report("nope", config=None, db_path=db) is None

    def test_assembles_hosts_services_and_candidates(self, db) -> None:
        _seed_completed_scan(db, with_cve=True)
        report = build_report("rep123", config=None, db_path=db)
        assert report is not None
        assert report.target == "192.168.56.10/32"
        assert report.counts["hosts"] == 1
        assert report.counts["open_services"] == 1
        assert report.counts["candidates"] == 1
        assert report.correlation_ran is True
        assert report.summary.state == SummaryState.CANDIDATES

        service = report.hosts[0].services[0]
        assert service.port == 21
        assert service.recommendation  # a recommendation is always present
        vuln = service.vulnerabilities[0]
        assert vuln.cve_id == "CVE-2011-2523"
        assert vuln.severity == "CRITICAL"
        assert vuln.base_score == 10.0
        assert vuln.cvss_version == "2.0"

    def test_completed_but_uncorrelated_is_not_correlated(self, db) -> None:
        _seed_completed_scan(db, with_cve=False)
        report = build_report("rep123", config=None, db_path=db)
        assert report.correlation_ran is False
        assert report.summary.state == SummaryState.NOT_CORRELATED
        assert not report.summary.is_clean_claim

    def test_to_dict_is_serialisable(self, db) -> None:
        _seed_completed_scan(db, with_cve=True)
        report = build_report("rep123", config=None, db_path=db)
        import json

        json.dumps(report.to_dict())  # must not raise


class TestPdf:
    def test_pdf_renders_bytes(self, db) -> None:
        _seed_completed_scan(db, with_cve=True)
        report = build_report("rep123", config=None, db_path=db)
        pdf = render_pdf(report)
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 1000

    def test_pdf_renders_for_failed_scan(self, db) -> None:
        with session_scope(db) as s:
            s.add(ScanSession(
                session_id="fail1", target_spec="10.0.0.5/32", profile="service_detect",
                scan_kind="assessment", status="failed", reachability="unknown",
                error="nmap not found",
            ))
        report = build_report("fail1", config=None, db_path=db)
        assert report.summary.state == SummaryState.FAILED
        pdf = render_pdf(report)
        assert pdf.startswith(b"%PDF")
