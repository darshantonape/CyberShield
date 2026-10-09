"""End-to-end scan pipeline against real listeners on loopback.

Runs actual Nmap. Excluded from the default test run; execute with:

    pytest tests/integration -m integration

Scope for these tests is 127.0.0.0/8 only. No external host is contacted.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from backend.core.audit import AuditLog
from backend.core.authorization import AuthorizationDenied
from backend.core.config import load_config
from backend.database.session import init_db, session_scope
from backend.database.models import DiscoveredHost, DiscoveredService, ScanSession
from backend.scanner.pipeline import run_discovery, run_service_detection
from tests.conftest import write_config_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("signed_authorization")]

LOOPBACK_TARGETS = """
targets:
  - name: loopback-lab
    cidr: 127.0.0.0/8
    is_lab: true
    ssh_port: 22
    ssh_user: labadmin
    notes: "Loopback only. Integration testing."
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def listener():
    """A real HTTP listener on loopback, so version detection has something to find."""
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait for the socket to accept rather than sleeping a fixed interval.
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        process.terminate()
        pytest.fail(f"listener on port {port} never came up")

    yield port
    process.terminate()
    process.wait(timeout=10)


@pytest.fixture
def lab(tmp_path: Path):
    """Isolated config, database, audit log and evidence directory."""
    config_dir = write_config_dir(
        tmp_path / "config", **{"authorized_targets.yaml": LOOPBACK_TARGETS}
    )
    db_path = tmp_path / "test.db"
    init_db(db_path)
    return {
        "config": load_config(config_dir),
        "db_path": db_path,
        "audit_path": tmp_path / "audit.jsonl",
        "evidence_dir": tmp_path / "evidence",
        "raw_dir": tmp_path / "raw",
    }


def run_scan(lab, target, **kwargs):
    return run_service_detection(
        lab["config"],
        target,
        db_path=lab["db_path"],
        audit_path=lab["audit_path"],
        evidence_dir=lab["evidence_dir"],
        raw_dir=lab["raw_dir"],
        **kwargs,
    )


class TestServiceDetection:
    def test_detects_a_real_listener(self, lab, listener) -> None:
        result = run_scan(lab, "127.0.0.1", ports=[listener])

        assert result.hosts_up == 1
        assert result.open_services == 1

        service = result.parsed.hosts[0].open_services[0]
        assert service.port == listener
        assert service.state == "open"
        # Nmap identifies Python's http.server; assert on what it actually
        # reports rather than pinning an exact banner string.
        assert service.service_name == "http"
        assert service.product is not None
        assert service.version_confidence == "known"
        assert service.identification_status == "identified"

    def test_closed_port_is_reported_as_closed(self, lab) -> None:
        closed = free_port()  # bound then released, so nothing is listening
        result = run_scan(lab, "127.0.0.1", ports=[closed])
        service = result.parsed.hosts[0].services[0]
        assert service.state in ("closed", "filtered")
        assert not service.is_open
        assert result.open_services == 0


class TestEvidence:
    def test_raw_xml_is_written_and_parseable(self, lab, listener) -> None:
        result = run_scan(lab, "127.0.0.1", ports=[listener])
        assert result.raw_xml_path.exists()
        content = result.raw_xml_path.read_text()
        assert content.startswith("<?xml")
        assert "<nmaprun" in content

    def test_evidence_manifest_supports_reproduction(self, lab, listener) -> None:
        import json

        result = run_scan(lab, "127.0.0.1", ports=[listener])
        payload = json.loads(result.evidence_path.read_text())

        manifest = payload["manifest"]
        # Everything needed to re-run and explain the result later.
        assert manifest["nmap_version"]
        assert manifest["config_hash"]
        assert manifest["target"] == "127.0.0.1/32"
        assert manifest["duration_seconds"] > 0
        assert "-oX" in manifest["nmap_argv"]
        assert payload["counts"]["open_services"] == 1

    def test_no_fabricated_counts(self, lab) -> None:
        closed = free_port()
        result = run_scan(lab, "127.0.0.1", ports=[closed])
        import json

        payload = json.loads(result.evidence_path.read_text())
        assert payload["counts"]["open_services"] == 0


class TestPersistence:
    def test_results_are_written_to_the_database(self, lab, listener) -> None:
        result = run_scan(lab, "127.0.0.1", ports=[listener])

        with session_scope(lab["db_path"]) as db:
            session = db.get(ScanSession, result.db_session_id)
            assert session is not None
            assert session.status == "completed"
            assert session.nmap_version is not None
            assert session.raw_xml_path == str(result.raw_xml_path)

            hosts = db.query(DiscoveredHost).filter_by(session_id=session.id).all()
            assert len(hosts) == 1
            assert hosts[0].address == "127.0.0.1"

            services = db.query(DiscoveredService).filter_by(host_id=hosts[0].id).all()
            assert len(services) == 1
            assert services[0].port == listener
            assert services[0].version_confidence == "known"


class TestAuditTrail:
    def test_scan_is_logged_and_chain_verifies(self, lab, listener) -> None:
        run_scan(lab, "127.0.0.1", ports=[listener])

        log = AuditLog(lab["audit_path"])
        actions = [e.action for e in log.entries()]
        assert "scan.start" in actions
        assert "scan.finish" in actions
        assert log.verify_chain().valid

    def test_refused_scan_is_logged_and_nothing_runs(self, lab) -> None:
        with pytest.raises(AuthorizationDenied):
            run_scan(lab, "8.8.8.8")

        log = AuditLog(lab["audit_path"])
        entries = log.entries()
        assert [e.action for e in entries] == ["scan.refused"]
        assert entries[0].outcome == "refused"
        # Critically: no scan.start, so Nmap was never invoked.
        assert not any(e.action == "scan.start" for e in entries)


class TestHostDiscovery:
    def test_discovery_finds_loopback(self, lab) -> None:
        result = run_discovery(
            lab["config"],
            "127.0.0.1",
            db_path=lab["db_path"],
            audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"],
            raw_dir=lab["raw_dir"],
        )
        assert result.hosts_up == 1
        assert result.parsed.hosts[0].address == "127.0.0.1"
        # -sn scans no ports.
        assert result.open_services == 0
