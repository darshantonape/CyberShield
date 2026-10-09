"""What a scan does when it cannot produce results.

The property under test: a scan that fails is *visibly* failed. It must not
vanish, and it must not be recorded as a scan that ran and found nothing —
because every count downstream would then read zero for a target that was never
examined.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.core.audit import AuditLog
from backend.core.config import load_config
from backend.database.models import (
    DiscoveredHost,
    DiscoveredService,
    ScanSession,
    Vulnerability,
)
from backend.database.session import init_db, session_scope
from backend.scanner import pipeline
from backend.scanner.nmap_runner import NmapError
from backend.scanner.pipeline import ScanError, run_discovery, run_service_detection


class _FakeExecution:
    """Stand-in for NmapExecution carrying whatever XML the test needs."""

    argv = ("nmap", "-sT", "-sV", "192.168.56.10/32")
    returncode = 0
    duration_seconds = 0.5
    timed_out = False
    stderr = ""

    def __init__(self, xml_text: str, raw_path: Path) -> None:
        self.xml_text = xml_text
        self.raw_xml_path = raw_path
        raw_path.write_text(xml_text)


@pytest.fixture
def workspace(tmp_path: Path, config_dir: Path, signed_authorization):
    """An isolated database, audit log and evidence directory."""
    db = tmp_path / "scan.db"
    init_db(db)
    return {
        "config": load_config(config_dir),
        "db": db,
        "audit": tmp_path / "audit.jsonl",
        "evidence": tmp_path / "evidence",
        "raw": tmp_path / "raw",
        "tmp": tmp_path,
    }


def _counts(db: Path) -> dict[str, int]:
    with session_scope(db) as session:
        return {
            "scans": session.query(ScanSession).count(),
            "hosts": session.query(DiscoveredHost).count(),
            "services": session.query(DiscoveredService).count(),
            "vulns": session.query(Vulnerability).count(),
        }


class TestUnparseableOutput:
    """Nmap ran, but its output cannot be read even after repair."""

    @pytest.fixture(autouse=True)
    def _patch_nmap(self, monkeypatch, workspace):
        broken = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
            '<?xml-stylesheet href="file:///opt/homebrew/share/nmap'
        )
        execution = _FakeExecution(broken, workspace["tmp"] / "broken.xml")
        monkeypatch.setattr(pipeline, "run_nmap", lambda *a, **k: execution)

    def test_scan_error_is_raised(self, workspace) -> None:
        with pytest.raises(ScanError, match="could not be recovered"):
            run_service_detection(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
            )

    def test_failure_is_recorded_as_a_failed_scan(self, workspace) -> None:
        with pytest.raises(ScanError):
            run_service_detection(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
                actor="tester",
            )

        with session_scope(workspace["db"]) as session:
            row = session.query(ScanSession).one()
            assert row.status == "failed"
            assert row.initiated_by == "tester"
            assert row.error and "could not be recovered" in row.error
            # Not "reachable" and not "unreachable": the scan never got far
            # enough to learn either.
            assert row.reachability == "unknown"
            assert row.hosts_up is None
            assert row.open_services is None
            assert "Nothing is known" in (row.reachability_note or "")

    def test_no_findings_are_fabricated(self, workspace) -> None:
        with pytest.raises(ScanError):
            run_service_detection(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
            )
        counts = _counts(workspace["db"])
        assert counts["scans"] == 1
        # The whole point: a failure must produce no evidence of anything.
        assert counts["hosts"] == 0
        assert counts["services"] == 0
        assert counts["vulns"] == 0

    def test_audit_trail_survives_the_failure(self, workspace) -> None:
        with pytest.raises(ScanError):
            run_service_detection(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
            )
        log = AuditLog(workspace["audit"])
        actions = [e.action for e in log.entries()]
        assert actions == ["scan.start", "scan.failed"]

        failed = log.entries()[-1]
        assert failed.outcome == "failure"
        assert failed.detail["stage"] == "xml_parsing"
        assert "raw_xml_path" in failed.detail
        # The chain must still verify: a failed scan is part of the record.
        assert log.verify_chain().valid is True


class TestNmapCouldNotRun:
    """Nmap itself failed — missing binary, no output at all."""

    @pytest.fixture(autouse=True)
    def _patch_nmap(self, monkeypatch):
        def explode(*_args, **_kwargs):
            raise NmapError("Executable 'nmap' not found on PATH.")

        monkeypatch.setattr(pipeline, "run_nmap", explode)

    def test_recorded_as_failed_with_the_reason(self, workspace) -> None:
        with pytest.raises(ScanError, match="not found on PATH"):
            run_discovery(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
            )

        with session_scope(workspace["db"]) as session:
            row = session.query(ScanSession).one()
            assert row.status == "failed"
            assert "not found on PATH" in (row.error or "")

        log = AuditLog(workspace["audit"])
        assert log.entries()[-1].detail["stage"] == "nmap_execution"
        assert log.verify_chain().valid is True

    def test_still_no_findings(self, workspace) -> None:
        with pytest.raises(ScanError):
            run_discovery(
                workspace["config"],
                "192.168.56.10",
                db_path=workspace["db"],
                audit_path=workspace["audit"],
                evidence_dir=workspace["evidence"],
            )
        counts = _counts(workspace["db"])
        assert (counts["hosts"], counts["services"], counts["vulns"]) == (0, 0, 0)


class TestUnreachableTarget:
    """Nmap ran fine and the target said nothing."""

    @pytest.fixture(autouse=True)
    def _patch_nmap(self, monkeypatch, workspace):
        # A -Pn scan of an absent host: reported up, every port filtered.
        xml = (
            '<?xml version="1.0"?><nmaprun version="7.991" args="nmap -Pn">'
            "<host><status state=\"up\" reason=\"user-set\"/>"
            '<address addr="192.168.56.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="filtered" reason="no-response"/></port>'
            '<port protocol="tcp" portid="445">'
            '<state state="filtered" reason="no-response"/></port>'
            "</ports></host>"
            '<runstats><finished elapsed="4.1" exit="success"/></runstats>'
            "</nmaprun>"
        )
        execution = _FakeExecution(xml, workspace["tmp"] / "unreachable.xml")
        execution.argv = ("nmap", "-sT", "-sV", "-Pn", "192.168.56.10/32")
        monkeypatch.setattr(pipeline, "run_nmap", lambda *a, **k: execution)

    def test_status_says_unreachable_not_completed(self, workspace) -> None:
        result = run_service_detection(
            workspace["config"],
            "192.168.56.10",
            db_path=workspace["db"],
            audit_path=workspace["audit"],
            evidence_dir=workspace["evidence"],
        )
        assert result.status == "completed_unreachable"
        assert result.reachability is not None
        assert result.reachability.state == "unreachable"

        with session_scope(workspace["db"]) as session:
            row = session.query(ScanSession).one()
            assert row.status == "completed_unreachable"
            assert row.reachability == "unreachable"
            assert row.open_services == 0

    def test_the_note_refuses_to_call_it_clean(self, workspace) -> None:
        result = run_service_detection(
            workspace["config"],
            "192.168.56.10",
            db_path=workspace["db"],
            audit_path=workspace["audit"],
            evidence_dir=workspace["evidence"],
        )
        note = result.reachability.note
        assert "NOT a clean result" in note or "Nothing was learned" in note
        assert result.reachability.possible_causes

    def test_audit_outcome_is_partial_not_success(self, workspace) -> None:
        run_service_detection(
            workspace["config"],
            "192.168.56.10",
            db_path=workspace["db"],
            audit_path=workspace["audit"],
            evidence_dir=workspace["evidence"],
        )
        finish = AuditLog(workspace["audit"]).entries()[-1]
        assert finish.action == "scan.finish"
        # A target that never answered is not a successful assessment.
        assert finish.outcome == "partial"
        assert finish.detail["reachability"] == "unreachable"
