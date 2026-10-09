"""Per-user data isolation (the multi-tenant guarantee).

The brief's core requirement: a new user's world is empty, and one user can
never read another's scans, hosts, services, vulnerabilities, remediation
actions, targets, reports or audit trail — including by changing an id in a URL.

Part 1 tests the ownership at the query/service layer against an isolated
database. Part 2 tests the actual HTTP routes (IDOR) against the app, seeding
two real accounts and cleaning them up.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.auth.service import AuthenticatedUser, create_user
from backend.core.authorization import check_in_scope
from backend.core.config import load_config
from backend.core.user_targets import (
    add_user_target,
    list_user_targets,
    user_target_pairs,
)
from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    RemediationAction,
    ScanSession,
    User,
    Vulnerability,
)
from backend.database.session import init_db, session_scope
from backend.main import app
from backend.reports.builder import build_report, list_reportable_scans


# ---------------------------------------------------------------------------
# Part 1 — ownership at the query/service layer (isolated DB)
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "iso.db"
    init_db(path)
    return path


def _seed_scan_for(db: Path, user_id: int, session_id: str) -> None:
    with session_scope(db) as s:
        scan = ScanSession(
            session_id=session_id, target_spec="192.168.56.10/32",
            profile="service_detect", scan_kind="assessment", status="completed",
            reachability="reachable", hosts_up=1, open_services=1, user_id=user_id,
        )
        s.add(scan); s.flush()
        host = DiscoveredHost(session_id=scan.id, user_id=user_id, address="192.168.56.10", state="up")
        s.add(host); s.flush()
        svc = DiscoveredService(
            host_id=host.id, user_id=user_id, port=21, proto="tcp", state="open",
            service_name="ftp", product="vsftpd", version="2.3.4",
            version_confidence="known", identification_status="identified",
        )
        s.add(svc); s.flush()
        if s.get(CveRecord, "CVE-2011-2523") is None:
            s.add(CveRecord(cve_id="CVE-2011-2523", base_score=9.8, base_severity="CRITICAL", cvss_version="3.1"))
        s.add(Vulnerability(
            service_id=svc.id, user_id=user_id, cve_id="CVE-2011-2523",
            matching_method="cpe_exact", confidence="HIGH", status="candidate",
            evidence={"vulnerable_match_count": 1},
        ))
        s.add(RemediationAction(
            request_id=f"rem-{session_id}", user_id=user_id, target_address="192.168.56.10",
            port=21, proto="tcp", backend="dryrun", apply_argv=[], rollback_argv=[],
            rule_tag="t", state="planned",
        ))


class TestQueryLevelIsolation:
    def test_new_user_owns_nothing(self, db) -> None:
        a = create_user("alice", "Correct-Horse-9", email="alice@example.com", db_path=db)
        b = create_user("bob", "Correct-Horse-9", email="bob@example.com", db_path=db)
        _seed_scan_for(db, a.id, "scanA")

        with session_scope(db) as s:
            # Everything belongs to A; B sees nothing.
            for model in (ScanSession, DiscoveredHost, DiscoveredService, Vulnerability, RemediationAction):
                assert s.query(model).filter_by(user_id=a.id).count() >= 1
                assert s.query(model).filter_by(user_id=b.id).count() == 0

    def test_reports_are_owner_scoped(self, db) -> None:
        a = create_user("alice", "Correct-Horse-9", email="a@example.com", db_path=db)
        b = create_user("bob", "Correct-Horse-9", email="b@example.com", db_path=db)
        _seed_scan_for(db, a.id, "scanA")

        # A can build and list; B cannot even by knowing the session id.
        assert build_report("scanA", user_id=a.id, config=None, db_path=db) is not None
        assert build_report("scanA", user_id=b.id, config=None, db_path=db) is None
        assert len(list_reportable_scans(user_id=a.id, db_path=db)) == 1
        assert list_reportable_scans(user_id=b.id, db_path=db) == []

    def test_targets_are_per_user(self, db) -> None:
        a = create_user("alice", "Correct-Horse-9", email="a@example.com", db_path=db)
        b = create_user("bob", "Correct-Horse-9", email="b@example.com", db_path=db)

        add_user_target(a.id, "192.168.1.0/24", name="a-net", confirmed=True, db_path=db)
        assert len(list_user_targets(a.id, db_path=db)) == 1
        assert list_user_targets(b.id, db_path=db) == []  # B sees none of A's targets
        assert user_target_pairs(b.id, db_path=db) == ()

    def test_scope_check_respects_only_own_targets(self, db) -> None:
        config = load_config()
        a_targets = (("a-net", "192.168.1.0/24"),)
        # A authorized for an address in their range; B (no targets) is refused.
        assert check_in_scope(config, "192.168.1.50", user_targets=a_targets).allowed
        assert not check_in_scope(config, "192.168.1.50", user_targets=()).allowed

    def test_public_range_cannot_be_added(self, db) -> None:
        from backend.core.user_targets import UserTargetError

        a = create_user("alice", "Correct-Horse-9", email="a@example.com", db_path=db)
        with pytest.raises(UserTargetError):
            add_user_target(a.id, "8.8.8.0/24", confirmed=True, db_path=db)


# ---------------------------------------------------------------------------
# Part 2 — IDOR at the HTTP layer (real app, two seeded accounts)
# ---------------------------------------------------------------------------


@pytest.fixture
def two_accounts():
    """Create two real accounts in the app DB with a scan owned by A; clean up."""
    import uuid

    suffix = uuid.uuid4().hex[:8]
    a = create_user(f"isoA{suffix}", "Correct-Horse-9", email=f"a{suffix}@ex.com")
    b = create_user(f"isoB{suffix}", "Correct-Horse-9", email=f"b{suffix}@ex.com")
    session_id = f"isoscan{suffix}"
    with session_scope() as s:
        scan = ScanSession(
            session_id=session_id, target_spec="192.168.56.77/32", profile="service_detect",
            scan_kind="assessment", status="completed", reachability="reachable",
            hosts_up=1, open_services=0, user_id=a.id,
        )
        s.add(scan)
    try:
        yield {"a": a, "b": b, "session_id": session_id}
    finally:
        from backend.database.models import Job, Target

        with session_scope() as s:
            row = s.query(ScanSession).filter_by(session_id=session_id).one_or_none()
            if row is not None:
                s.delete(row)
            for u in (a, b):
                for tgt in s.query(Target).filter_by(user_id=u.id):
                    s.delete(tgt)
                for job in s.query(Job).filter_by(user_id=u.id):
                    s.delete(job)
                acc = s.get(User, u.id)
                if acc is not None:
                    for sess in acc.sessions:
                        s.delete(sess)
                    s.delete(acc)


def _client_as(identity: AuthenticatedUser) -> TestClient:
    from backend.auth import middleware

    middleware.resolve_session = lambda token, **kwargs: identity
    return TestClient(app, cookies={"cybershield_session": "stub"})


class TestHttpIdorIsolation:
    def test_b_cannot_open_a_scan_by_id(self, two_accounts) -> None:
        from backend.auth import middleware

        original = middleware.resolve_session
        try:
            sid = two_accounts["session_id"]
            # A sees the scan...
            with _client_as(two_accounts["a"]) as ca:
                assert two_accounts["session_id"] in ca.get(f"/scans/{sid}").text
            # ...B, changing the id in the URL, does not.
            with _client_as(two_accounts["b"]) as cb:
                body = cb.get(f"/scans/{sid}").text
                assert "No scan with that session id" in body
                assert "192.168.56.77" not in body
        finally:
            middleware.resolve_session = original

    def test_b_cannot_download_a_report(self, two_accounts) -> None:
        from backend.auth import middleware

        original = middleware.resolve_session
        try:
            sid = two_accounts["session_id"]
            with _client_as(two_accounts["a"]) as ca:
                assert ca.get(f"/reports/{sid}/pdf").headers["content-type"] == "application/pdf"
            with _client_as(two_accounts["b"]) as cb:
                # B gets the "no such report" HTML page, never A's PDF.
                resp = cb.get(f"/reports/{sid}/pdf")
                assert resp.headers["content-type"].startswith("text/html")
        finally:
            middleware.resolve_session = original

    def test_b_dashboard_excludes_a_scans(self, two_accounts) -> None:
        from backend.auth import middleware

        original = middleware.resolve_session
        try:
            with _client_as(two_accounts["b"]) as cb:
                assert "192.168.56.77" not in cb.get("/").text
        finally:
            middleware.resolve_session = original


class TestApiTargetAndJobIsolation:
    """The two isolation fixes: /api/targets is per-user, and jobs are owned."""

    def test_api_targets_are_per_user(self, two_accounts) -> None:
        from backend.auth import middleware

        original = middleware.resolve_session
        try:
            with _client_as(two_accounts["a"]) as ca:
                r = ca.post("/api/targets", json={
                    "target": "192.168.77.0/24", "name": "a-lan", "confirm": True,
                })
                assert r.status_code == 201
                mine = ca.get("/api/targets").json()
                assert any(t["cidr"] == "192.168.77.0/24" for t in mine["your_targets"])
            # B must not see A's target in their own list.
            with _client_as(two_accounts["b"]) as cb:
                theirs = cb.get("/api/targets").json()
                assert all(t["cidr"] != "192.168.77.0/24" for t in theirs["your_targets"])
                # And B cannot delete A's target by name.
                assert cb.delete("/api/targets/a-lan").status_code == 404
        finally:
            middleware.resolve_session = original

    def test_api_targets_still_reject_public(self, two_accounts) -> None:
        from backend.auth import middleware

        original = middleware.resolve_session
        try:
            with _client_as(two_accounts["a"]) as ca:
                r = ca.post("/api/targets", json={"target": "8.8.8.0/24", "confirm": True})
                assert r.status_code == 400  # public range still refused (safety intact)
        finally:
            middleware.resolve_session = original

    def test_job_status_is_owner_scoped(self, two_accounts) -> None:
        from backend.auth import middleware
        from backend.database.models import Job

        original = middleware.resolve_session
        job_id = f"job-{two_accounts['session_id']}"
        with session_scope() as s:
            s.add(Job(job_id=job_id, user_id=two_accounts["a"].id, kind="scan.discovery", state="completed"))
        try:
            with _client_as(two_accounts["a"]) as ca:
                assert ca.get(f"/api/jobs/{job_id}").status_code == 200
            with _client_as(two_accounts["b"]) as cb:
                # B knows the id but does not own it → indistinguishable from missing.
                assert cb.get(f"/api/jobs/{job_id}").status_code == 404
        finally:
            middleware.resolve_session = original
