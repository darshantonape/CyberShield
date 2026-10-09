"""End-to-end scan -> correlate against loopback and the live NVD API.

Excluded from the default run. Execute with:

    pytest tests/integration -m integration

Contacts services.nvd.nist.gov (read-only, public) and scans 127.0.0.1 only.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from backend.core.config import load_config
from backend.database.models import SoftwareSignature, Vulnerability
from backend.database.session import init_db, session_scope
from backend.nvd.client import NvdClient
from backend.nvd.pipeline import run_correlation
from backend.scanner.pipeline import run_service_detection
from tests.conftest import write_config_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("signed_authorization")]

LOOPBACK_TARGETS = """
targets:
  - name: loopback-lab
    cidr: 127.0.0.0/8
    is_lab: true
    ssh_port: 22
    ssh_user: labadmin
"""


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def listener():
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        process.terminate()
        pytest.fail("listener never came up")
    yield port
    process.terminate()
    process.wait(timeout=10)


@pytest.fixture
def lab(tmp_path: Path):
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


class TestScanThenCorrelate:
    def test_full_pipeline_produces_signatures_and_evidence(self, lab, listener) -> None:
        scan = run_service_detection(
            lab["config"],
            "127.0.0.1",
            ports=[listener],
            db_path=lab["db_path"],
            audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"],
            raw_dir=lab["raw_dir"],
        )
        assert scan.open_services == 1

        # Reuse the project cache so repeated runs stay within NVD rate limits.
        client = NvdClient(cache_dir=Path("data/nvd_cache"))
        result = run_correlation(
            lab["config"],
            scan.session_id,
            client=client,
            db_path=lab["db_path"],
            audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"],
        )

        assert result.services_considered == 1
        # Nmap identifies Python's http.server and emits a CPE for it, so a
        # signature must be produced regardless of whether NVD has CVEs for it.
        assert result.signatures_created >= 1

        with session_scope(lab["db_path"]) as db:
            signatures = db.query(SoftwareSignature).all()
            assert signatures
            assert all(s.confidence in {"HIGH", "MEDIUM", "LOW"} for s in signatures)
            assert all(s.mapping_source in {"nmap_cpe", "curated_map"} for s in signatures)

    def test_correlation_evidence_is_reproducible(self, lab, listener) -> None:
        scan = run_service_detection(
            lab["config"], "127.0.0.1", ports=[listener],
            db_path=lab["db_path"], audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"], raw_dir=lab["raw_dir"],
        )
        result = run_correlation(
            lab["config"], scan.session_id,
            client=NvdClient(cache_dir=Path("data/nvd_cache")),
            db_path=lab["db_path"], audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"],
        )

        payload = json.loads(result.evidence_path.read_text())
        assert payload["manifest"]["config_hash"]
        assert payload["manifest"]["nvd_client"]["cache"] is not None
        assert payload["summary"]["services_considered"] == 1
        # Per-service normalization is recorded so a finding can be traced back
        # to the raw banner it came from.
        assert payload["services"][0]["normalization"]["candidates"]

    def test_every_stored_candidate_has_method_confidence_and_caveats(
        self, lab, listener
    ) -> None:
        scan = run_service_detection(
            lab["config"], "127.0.0.1", ports=[listener],
            db_path=lab["db_path"], audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"], raw_dir=lab["raw_dir"],
        )
        run_correlation(
            lab["config"], scan.session_id,
            client=NvdClient(cache_dir=Path("data/nvd_cache")),
            db_path=lab["db_path"], audit_path=lab["audit_path"],
            evidence_dir=lab["evidence_dir"],
        )

        with session_scope(lab["db_path"]) as db:
            for vuln in db.query(Vulnerability).all():
                assert vuln.matching_method in {"cpe_exact", "keyword"}
                assert vuln.confidence in {"HIGH", "MEDIUM", "LOW"}
                # Nothing may be stored as confirmed.
                assert vuln.status == "candidate"
                assert vuln.caveats
                assert any("not proof" in c for c in vuln.caveats)


class TestLiveNvdBehaviour:
    """Documents measured NVD behaviour the correlation design depends on."""

    def test_cpe_query_outperforms_keyword_for_apache(self) -> None:
        client = NvdClient(cache_dir=Path("data/nvd_cache"))
        by_cpe = client.search_by_cpe(
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        )
        by_keyword = client.search_by_keyword("Apache httpd 2.4.49")

        # The measurement that makes CPE the primary path.
        assert by_cpe.total_results > by_keyword.total_results
        assert by_cpe.total_results > 50
        assert any(c.get("id") == "CVE-2021-41773" for c in by_cpe.cves)

    def test_vsftpd_backdoor_cve_is_found_by_cpe(self) -> None:
        client = NvdClient(cache_dir=Path("data/nvd_cache"))
        response = client.search_by_cpe(
            "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"
        )
        assert any(c.get("id") == "CVE-2011-2523" for c in response.cves)
