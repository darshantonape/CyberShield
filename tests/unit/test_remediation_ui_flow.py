"""The browser flow for remediation: review, confirm, execute, result.

The properties under test are about the *route layer*, which is where a UI
convenience could quietly weaken an otherwise sound safety model:

  * a non-ALLOW verdict is explained and offers no approval control
  * approval needs two independent confirmations, neither defaulted
  * a missing confirmation is refused AND audited
  * the review page writes nothing and sends nothing
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.auth.service import AuthenticatedUser
from backend.database.models import (
    CveRecord,
    DiscoveredHost,
    DiscoveredService,
    RemediationAction,
    ScanSession,
    User,
    Vulnerability,
)
from backend.database.session import session_scope
from backend.main import app


def _data_owner() -> AuthenticatedUser:
    """The operator that owns the developer DB's data (earliest account)."""
    with session_scope() as db:
        row = db.query(User).order_by(User.id.asc()).first()
        uid = row.id if row else 1
        username = row.username if row else "flow-test-operator"
    return AuthenticatedUser(
        id=uid, username=username, full_name="Flow Test", role="operator",
        session_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


OPERATOR = _data_owner()

# A deterministic remediation candidate owned by the stub operator, seeded so
# the candidates-table and result-page assertions do not depend on whatever the
# developer's latest live scan happened to find. Cleaned up after the module.
_SEED_MARKER = "flowtest-192.168.64.12"


@pytest.fixture(scope="module", autouse=True)
def _seed_candidate():
    ids: dict[str, int] = {}
    with session_scope() as db:
        scan = ScanSession(
            session_id="flowtestseed01", target_spec="192.168.64.12/32",
            profile="service_detect", scan_kind="assessment", status="completed",
            reachability="reachable", hosts_up=1, open_services=1,
            initiated_by=OPERATOR.username, user_id=OPERATOR.id,
        )
        db.add(scan); db.flush()
        host = DiscoveredHost(
            session_id=scan.id, user_id=OPERATOR.id,
            address="192.168.64.12", state="up",
        )
        db.add(host); db.flush()
        svc = DiscoveredService(
            host_id=host.id, user_id=OPERATOR.id, port=21, proto="tcp", state="open",
            service_name="ftp", product="vsftpd", version="2.3.4",
            version_confidence="known", identification_status="identified",
        )
        db.add(svc); db.flush()
        if db.get(CveRecord, "CVE-2011-2523") is None:
            db.add(CveRecord(
                cve_id="CVE-2011-2523", base_score=9.8, base_severity="CRITICAL",
                cvss_version="3.1", description="seed",
            ))
        db.add(Vulnerability(
            service_id=svc.id, user_id=OPERATOR.id, cve_id="CVE-2011-2523",
            matching_method="cpe_exact", confidence="HIGH",
            detected_product="vsftpd", detected_version="2.3.4",
            status="candidate", evidence={"vulnerable_match_count": 1},
        ))
        db.flush()
        # Record the high-water mark so teardown removes only rows created during
        # this module — never a pre-existing remediation action of the operator's.
        max_rem = db.query(RemediationAction.id).order_by(RemediationAction.id.desc()).first()
        ids = {"scan": scan.id, "max_rem": (max_rem[0] if max_rem else 0)}
    yield
    with session_scope() as db:
        scan = db.get(ScanSession, ids["scan"])
        if scan is not None:
            db.delete(scan)  # cascade drops host/service/vuln
        for row in (
            db.query(RemediationAction)
            .filter(RemediationAction.id > ids["max_rem"])
            .all()
        ):
            db.delete(row)


@pytest.fixture(scope="module")
def client(_seed_candidate):
    """Signed-in client. Session resolution is stubbed so the test does not
    create an account or a login event in the developer's own database."""
    from backend.auth import middleware

    original = middleware.resolve_session
    middleware.resolve_session = lambda token, **kwargs: OPERATOR
    with TestClient(app, cookies={"cybershield_session": "stub"}) as test_client:
        try:
            yield test_client
        finally:
            middleware.resolve_session = original


def _action_count() -> int:
    with session_scope() as db:
        return db.query(RemediationAction).count()


class TestReviewPage:
    def test_unknown_candidate_is_explained_not_crashed(self, client) -> None:
        response = client.get("/remediation/review?target=10.99.99.99&port=1234")
        assert response.status_code == 200
        assert "No such remediation candidate" in response.text

    def test_review_page_writes_no_action_row(self, client) -> None:
        before = _action_count()
        client.get("/remediation/review?target=192.168.64.12&port=21")
        # Loading a review must not persist a plan or touch a target.
        assert _action_count() == before

    def test_review_page_is_reachable_only_when_signed_in(self) -> None:
        with TestClient(app) as anon:
            response = anon.get(
                "/remediation/review?target=192.168.64.12&port=21",
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert response.headers["location"].startswith("/login")


class TestConfirmationIsMandatory:
    """Both confirmations are required, and neither has a default."""

    @pytest.mark.parametrize(
        "payload",
        [
            # No confirmation at all.
            {"target": "192.168.64.12", "port": "21"},
            # Button submitted, acknowledgement box not ticked.
            {"target": "192.168.64.12", "port": "21", "confirm": "yes"},
            # Box ticked but confirm absent — e.g. a hand-crafted post.
            {"target": "192.168.64.12", "port": "21", "acknowledge": "yes"},
            # Both present but not the required value.
            {
                "target": "192.168.64.12",
                "port": "21",
                "confirm": "no",
                "acknowledge": "no",
            },
        ],
    )
    def test_partial_confirmation_is_refused(self, client, payload: dict) -> None:
        before = _action_count()
        response = client.post(
            "/remediation/apply", data=payload, follow_redirects=False
        )
        assert response.status_code == 303
        location = response.headers["location"]
        # Sent back to the review page with the refusal, and nothing executed.
        assert "/remediation/review" in location
        assert "error=" in location
        assert _action_count() == before, "a refused apply must persist nothing"

    def test_refusal_is_audited(self, client) -> None:
        from backend.core.audit import AuditLog
        from backend.core.config import DATA_DIR

        log = AuditLog(DATA_DIR / "audit.jsonl")
        before = len(log.entries())

        client.post(
            "/remediation/apply",
            data={"target": "192.168.64.12", "port": "21", "confirm": "yes"},
            follow_redirects=False,
        )

        entries = log.entries()
        assert len(entries) > before, "a refusal must leave an audit entry"
        latest = entries[-1]
        assert latest.action == "remediation.refused"
        assert latest.outcome == "refused"
        assert latest.actor == OPERATOR.username
        assert "confirmation" in latest.detail["reason"].lower()


class TestResultPage:
    def test_unknown_request_id_does_not_500(self, client) -> None:
        # 404 is the right status for an action that does not exist; the point
        # of this test is that the page renders its empty state, not that it
        # claims 200.
        response = client.get("/remediation/action/does-not-exist")
        assert response.status_code == 404
        assert "No remediation action with that request id" in response.text
        assert "Traceback" not in response.text

    def test_result_page_never_calls_isolation_a_patch(self, client) -> None:
        # Any existing action row is fine; the wording must hold for all of them.
        with session_scope() as db:
            # Scoped to the viewing operator, because the page is. Unscoped,
            # this picked the newest action in the database regardless of owner,
            # so the page correctly rendered its "not found" state and the
            # wording assertions below had nothing to match.
            row = (
                db.query(RemediationAction)
                .filter(RemediationAction.user_id == OPERATOR.id)
                .order_by(RemediationAction.id.desc())
                .first()
            )
        if row is None:
            pytest.skip("no remediation action recorded")

        body = client.get(f"/remediation/action/{row.request_id}").text
        flat = " ".join(body.split())
        assert "does not patch" in flat or "not a patch" in flat
        assert "vantage point" in flat


class TestCandidatesTable:
    def test_no_single_click_apply_control_exists(self, client) -> None:
        # Approval must go through the review page. A form posting straight to
        # /remediation/apply from the candidates table would bypass the review
        # step and the acknowledgement.
        body = client.get("/remediation").text
        assert 'action="/remediation/apply"' not in body
        assert "/remediation/review?target=" in body


class TestAttribution:
    """The database row and the audit log must name the same operator.

    They disagreed: audit entries carried the signed-in username while the
    remediation_actions row fell back to its column default, so every action
    read as "operator" no matter who approved it.
    """

    def test_action_row_records_the_approving_operator(
        self, tmp_path, monkeypatch, signed_authorization
    ) -> None:
        from backend.core.audit import AuditLog
        from backend.core.config import load_config
        from backend.database.session import init_db
        from backend.remediation import executor as executor_module
        from backend.remediation.executor import apply_plan
        from backend.remediation.plan import build_plan
        from backend.risk.decision import IsolationRequest
        from backend.verification.verify import PortObservation
        from tests.conftest import write_config_dir

        config_dir = write_config_dir(tmp_path / "config")
        db = tmp_path / "attrib.db"
        audit = tmp_path / "audit.jsonl"
        init_db(db)

        # Dry-run backend: this test is about attribution and must never send a
        # command to anything.
        monkeypatch.setenv("CYBERSHIELD_REMEDIATION_BACKEND", "dryrun")
        config = load_config(config_dir)
        assert config.settings.remediation_backend == "dryrun"

        # Stub the verification rescan so no Nmap process is started. The
        # observation content is irrelevant here.
        def fake_observe(_config, address, port, **kwargs):
            return PortObservation(
                address=address, port=port, proto="tcp", state="open",
                reason="syn-ack", observed_at="2026-09-01T00:00:00Z",
                session_id="stub", raw_xml_path="/dev/null", host_was_up=True,
            )

        monkeypatch.setattr(executor_module, "observe_port", fake_observe)

        plan = build_plan(
            config,
            IsolationRequest(
                target_address="192.168.56.10",
                port=21,
                max_severity="HIGH",
                max_confidence="HIGH",
            ),
        )
        assert plan.allowed, plan.decision.blocking_reason

        apply_plan(
            config,
            plan,
            confirmed=True,
            actor="specific-operator",
            db_path=db,
            audit_path=audit,
            evidence_dir=tmp_path / "ev",
        )

        with session_scope(db) as session:
            row = session.query(RemediationAction).one()
            assert row.operator == "specific-operator"

        # And the audit log agrees — one operator, named consistently.
        assert {e.actor for e in AuditLog(audit).entries()} == {"specific-operator"}


class TestAntiLockoutRollback:
    """A lost management channel must trigger an immediate rollback attempt.

    This is the one post-action state the design must never leave a target in:
    a rule applied with no way to remove it except waiting for the TTL.
    """

    def _run(self, tmp_path, monkeypatch, mgmt_state: str):
        from backend.core.config import load_config
        from backend.database.session import init_db
        from backend.remediation import executor as executor_module
        from backend.remediation.executor import apply_plan
        from backend.remediation.plan import build_plan
        from backend.risk.decision import IsolationRequest
        from backend.verification.verify import PortObservation
        from tests.conftest import write_config_dir

        config_dir = write_config_dir(tmp_path / "config")
        db = tmp_path / "lockout.db"
        audit = tmp_path / "audit.jsonl"
        init_db(db)

        # The anti-lockout path only exists for an executing backend: a dry run
        # applies nothing, so it cannot lock anyone out. So the nftables backend
        # is selected and the SSH session is replaced with a stub — no host is
        # contacted and no command leaves this process.
        monkeypatch.setenv("CYBERSHIELD_REMEDIATION_BACKEND", "nftables")
        config = load_config(config_dir)

        import contextlib

        from backend.remediation.backends.base import PortState
        from backend.remediation.ssh_adapter import SshResult

        class _StubSession:
            def run(self, argv, timeout=30.0):
                return SshResult(
                    argv=tuple(argv), command=" ".join(argv),
                    exit_status=0, stdout="", stderr="",
                )

        @contextlib.contextmanager
        def fake_connect(_target):
            yield _StubSession()

        monkeypatch.setattr(executor_module, "connect", fake_connect)

        # The backend's own prepare/read_state talk to the stub session, which
        # reports success for every command.
        from backend.remediation.backends import nftables as nft_module

        monkeypatch.setattr(
            nft_module.NftablesBackend, "ensure_prepared", lambda self, session: []
        )
        monkeypatch.setattr(
            nft_module.NftablesBackend,
            "read_state",
            lambda self, session, port, proto="tcp": PortState(
                port=port, proto=proto, blocked=True, raw="elements = { 21 }"
            ),
        )

        def fake_observe(_config, address, port, *, label="", **kwargs):
            # The management probe is the one that reports the failure.
            state = mgmt_state if label == "verification_management" else "open"
            return PortObservation(
                address=address, port=port, proto="tcp", state=state,
                reason="probe", observed_at="2026-09-01T00:00:00Z",
                session_id="stub", raw_xml_path="/dev/null",
                host_was_up=state != "filtered",
            )

        monkeypatch.setattr(executor_module, "observe_port", fake_observe)

        plan = build_plan(
            config,
            IsolationRequest(
                target_address="192.168.56.10", port=21,
                max_severity="HIGH", max_confidence="HIGH",
            ),
        )
        outcome = apply_plan(
            config, plan, confirmed=True, actor="tester",
            db_path=db, audit_path=audit, evidence_dir=tmp_path / "ev",
        )
        return outcome, audit

    def test_lost_channel_triggers_rollback_and_is_audited(
        self, tmp_path, monkeypatch, signed_authorization
    ) -> None:
        from backend.core.audit import AuditLog

        outcome, audit = self._run(tmp_path, monkeypatch, mgmt_state="filtered")

        actions = [e.action for e in AuditLog(audit).entries()]
        assert "remediation.lockout_risk" in actions
        assert outcome.error and "management channel" in outcome.error.lower()
        # The chain must still verify across the whole incident.
        assert AuditLog(audit).verify_chain().valid is True

    def test_intact_channel_does_not_trigger_rollback(
        self, tmp_path, monkeypatch, signed_authorization
    ) -> None:
        from backend.core.audit import AuditLog

        outcome, audit = self._run(tmp_path, monkeypatch, mgmt_state="open")

        actions = [e.action for e in AuditLog(audit).entries()]
        assert "remediation.lockout_risk" not in actions
        assert outcome.error is None
