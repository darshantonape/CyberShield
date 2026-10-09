"""Dashboard rendering (spec §18).

These assert on the honesty properties of the UI, not on styling: a reader must
not be able to mistake a candidate for a confirmed vulnerability, a dry run for
a real action, or a truncated scan for a clean one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.auth.service import AuthenticatedUser
from backend.database.models import User
from backend.database.session import session_scope
from backend.main import app


def _data_owner() -> AuthenticatedUser:
    """The operator that owns the developer DB's data.

    These page-content tests read the real database, so the stubbed viewer must
    be the account that owns that data — the earliest account, which the
    multi-tenant migration backfilled all legacy rows to. Falls back to a
    synthetic id when the DB has no users (a fresh checkout), where the pages
    simply render their empty states.
    """
    with session_scope() as db:
        row = db.query(User).order_by(User.id.asc()).first()
        uid = row.id if row else 1
        username = row.username if row else "test-operator"
    return AuthenticatedUser(
        id=uid,
        username=username,
        full_name="Test Operator",
        role="operator",
        session_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


TEST_OPERATOR = _data_owner()


@pytest.fixture(scope="module")
def anonymous_client():
    """A client with no session. Used to prove the auth gate refuses."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def client(request):
    """A client that appears signed in.

    Session resolution is stubbed rather than a real account being created:
    these tests assert on page content, and they must not write an operator
    account or a login event into the developer's own database and audit log.
    The gate itself is tested separately, unstubbed, in TestAuthenticationGate.
    """
    from backend.auth import middleware

    original = middleware.resolve_session
    middleware.resolve_session = lambda token, **kwargs: TEST_OPERATOR
    # The middleware only calls resolve_session when a cookie is present.
    with TestClient(app, cookies={"cybershield_session": "stub"}) as test_client:
        try:
            yield test_client
        finally:
            middleware.resolve_session = original


class TestAuthenticationGate:
    """Unauthenticated access must be refused, not merely undocumented."""

    @pytest.mark.parametrize(
        "path",
        ["/scans", "/vulnerabilities", "/remediation", "/audit", "/targets", "/profile", "/settings", "/reports"],
    )
    def test_pages_redirect_to_login(self, anonymous_client, path: str) -> None:
        response = anonymous_client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")

    def test_landing_is_public_and_leaks_no_data(self, anonymous_client) -> None:
        # "/" is the public landing for a visitor: 200, and it must not expose
        # any scope, finding or dashboard figure to an anonymous request.
        response = anonymous_client.get("/", follow_redirects=False)
        assert response.status_code == 200
        body = response.text
        assert "CyberShield" in body and "Create account" in body
        # No dashboard content for an anonymous visitor.
        assert "Security overview" not in body
        assert "Hosts discovered" not in body

    @pytest.mark.parametrize(
        "path", ["/api/scans", "/api/vulnerabilities", "/api/audit", "/api/targets"]
    )
    def test_api_returns_401(self, anonymous_client, path: str) -> None:
        # JSON, not a login page: a script must get a machine-readable answer.
        response = anonymous_client.get(path)
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_scan_cannot_be_started_without_a_session(self, anonymous_client) -> None:
        response = anonymous_client.post(
            "/api/scans", json={"target": "192.168.64.12", "kind": "discovery"}
        )
        assert response.status_code == 401

    def test_login_page_is_reachable(self, anonymous_client) -> None:
        assert anonymous_client.get("/login").status_code == 200

    def test_health_is_public(self, anonymous_client) -> None:
        assert anonymous_client.get("/api/health").status_code == 200


class TestPagesRender:
    @pytest.mark.parametrize(
        "path", ["/", "/scans", "/vulnerabilities", "/remediation", "/audit"]
    )
    def test_page_returns_html(self, client, path: str) -> None:
        response = client.get(path)
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_unknown_scan_does_not_500(self, client) -> None:
        # 404 is the right answer (it is also what another operator's scan id
        # returns, so the two are indistinguishable); the point of this test is
        # that the page renders its empty state instead of raising.
        assert client.get("/scans/does-not-exist").status_code == 404

    def test_unknown_vulnerability_does_not_500(self, client) -> None:
        assert client.get("/vulnerabilities/999999").status_code == 404

    def test_api_routes_still_win(self, client) -> None:
        # The dashboard router must not shadow the JSON API.
        assert client.get("/api/health").json()["status"] == "ok"


class TestSafetyBanner:
    def test_every_page_states_the_enforcement_mode(self, client) -> None:
        for path in ["/", "/scans", "/vulnerabilities", "/remediation", "/audit"]:
            body = client.get(path).text
            assert (
                "Dry-run mode" in body
                or "LIVE ENFORCEMENT ARMED" in body
                or "is not signed" in body
            ), path

    def test_footer_states_the_core_limitations(self, client) -> None:
        body = client.get("/").text
        assert "candidates requiring review" in body
        assert "does not patch software" in body


class TestNoOverclaiming:
    def test_vulnerabilities_page_says_candidate(self, client) -> None:
        body = client.get("/vulnerabilities").text
        assert "CVE candidate" in body
        assert "not proof" in body

    def test_remediation_page_distinguishes_isolation_from_patching(self, client) -> None:
        body = client.get("/remediation").text
        assert "not patching" in body
        # The phrase wraps across lines in the rendered HTML, so normalise
        # whitespace before asserting on it.
        flat = " ".join(body.split())
        assert "underlying vulnerability remains present on the target" in flat

    def test_remediation_page_lists_protected_ports(self, client) -> None:
        body = client.get("/remediation").text
        assert "never isolatable" in body
        # The guarantee must be stated where an operator will see it.
        assert "no <code>force</code> parameter" in body or "force" in body

    def test_empty_vulnerability_list_is_not_called_clean(self, client) -> None:
        # Filter to something that cannot match, and check the wording.
        body = client.get("/vulnerabilities?severity=NONE").text
        assert "not evidence that the services are free" in body


class TestDashboardScoping:
    """Counts must be scoped to one assessment scan.

    Two bugs of this shape were found by reading the rendered page:
    host/service counts included single-port verification rescans (12 hosts and
    18 services for a lab with 4 and 12), and CVE counts included every
    correlation run (556 candidates and 28 flagged for a run that produced 278
    and 14). Both would have been reported as experimental results.
    """

    def test_counts_come_from_one_assessment_scan(self, client) -> None:
        import re

        from backend.database.models import (
            DiscoveredHost,
            DiscoveredService,
            ScanSession,
            Vulnerability,
        )
        from backend.database.session import session_scope

        body = client.get("/").text
        tiles = [int(n) for n in re.findall(r'<div class="n">(\d+)</div>', body)]
        if not tiles:
            pytest.skip("dashboard rendered no tiles")
        hosts, services, candidates = tiles[0], tiles[1], tiles[2]

        with session_scope() as db:
            # Scoped to the viewing operator, because the dashboard is. Without
            # the user_id filter this picked the newest assessment scan in the
            # database regardless of who owns it, and the test failed the moment
            # a second account ran a scan — comparing one operator's page
            # against another operator's data.
            latest = (
                db.query(ScanSession)
                .filter_by(scan_kind="assessment", user_id=TEST_OPERATOR.id)
                .order_by(ScanSession.id.desc())
                .first()
            )
            if latest is None:
                pytest.skip("no assessment scan recorded for the viewing operator")

            host_ids = [
                h.id for h in db.query(DiscoveredHost).filter_by(session_id=latest.id)
            ]
            expected_hosts = len(host_ids)
            expected_services = (
                db.query(DiscoveredService)
                .filter(
                    DiscoveredService.host_id.in_(host_ids),
                    DiscoveredService.state == "open",
                )
                .count()
            )
            service_ids = [
                s.id
                for s in db.query(DiscoveredService).filter(
                    DiscoveredService.host_id.in_(host_ids)
                )
            ]
            expected_candidates = (
                db.query(Vulnerability)
                .filter(Vulnerability.service_id.in_(service_ids))
                .count()
            )
            total_hosts = (
                db.query(DiscoveredHost)
                .filter(DiscoveredHost.user_id == TEST_OPERATOR.id)
                .count()
            )
            total_candidates = (
                db.query(Vulnerability)
                .filter(Vulnerability.user_id == TEST_OPERATOR.id)
                .count()
            )

        assert hosts == expected_hosts
        assert services == expected_services
        assert candidates == expected_candidates

        # And specifically NOT the unscoped totals, when they differ.
        if total_hosts != expected_hosts:
            assert hosts != total_hosts
        if total_candidates != expected_candidates:
            assert candidates != total_candidates

    def test_page_states_which_scan_the_counts_come_from(self, client) -> None:
        body = client.get("/").text
        flat = " ".join(body.split())
        assert "Host and service counts are from the latest" in flat


class TestAuditPage:
    def test_reports_chain_verification(self, client) -> None:
        body = client.get("/audit").text
        assert "Hash chain verified" in body or "AUDIT CHAIN BROKEN" in body

    def test_states_the_chains_limitation(self, client) -> None:
        # Tamper-evident is not tamper-proof, and the UI must say so.
        body = client.get("/audit").text
        assert "does not <em>prevent</em>" in body


class TestFormSafety:
    def test_apply_without_confirmation_is_refused(self, client) -> None:
        response = client.post(
            "/remediation/apply",
            data={"target": "192.168.64.12", "port": "21", "confirm": "no"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "confirmation+is+required" in response.headers["location"].replace(
            "%20", "+"
        ) or "confirmation is required" in response.headers["location"]

    def test_out_of_scope_scan_is_refused_by_the_form(self, client) -> None:
        response = client.post(
            "/scans",
            data={"target": "8.8.8.8", "kind": "service_detect"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "error=" in response.headers["location"]


class TestRevokeTargetByCidr:
    """DELETE /api/targets/{identifier} promises "by its name or CIDR".

    A CIDR contains a slash, and a plain FastAPI path parameter matches one
    segment only — so DELETE /api/targets/192.168.1.77/32 matched no route and
    returned 404, in both raw and percent-encoded form. Half the documented
    contract silently did not work.
    """

    def test_the_route_accepts_a_slash_in_the_identifier(self) -> None:
        from backend.main import app

        route = next(
            r for r in app.routes
            if getattr(r, "path", "") == "/api/targets/{identifier:path}"
        )
        assert "DELETE" in route.methods

    def test_a_cidr_reaches_the_handler_rather_than_404ing(self, client) -> None:
        # The viewing operator does not own this range, so the correct answer is
        # a 404 FROM THE HANDLER ("No target ... in your account") rather than a
        # routing miss. The body is what distinguishes the two.
        response = client.delete("/api/targets/203.0.113.99/32")
        assert response.status_code == 404
        assert "in your account" in response.json()["detail"]

    def test_an_unmatched_name_still_reaches_the_handler(self, client) -> None:
        response = client.delete("/api/targets/no-such-target-name")
        assert response.status_code == 404
        assert "in your account" in response.json()["detail"]


class TestMissingObjectsReturn404:
    """A page for an object that does not exist must say so in its status.

    These pages all render an empty state rather than raising, which is right —
    but they returned HTTP 200 while doing it, so a script (or a link checker)
    could not tell "here is the scan" from "there is no such scan". The same
    response is what another operator's object id produces, so the two stay
    indistinguishable, which is the property that matters for isolation.
    """

    def test_unknown_scan(self, client) -> None:
        assert client.get("/scans/no-such-session").status_code == 404

    def test_unknown_vulnerability(self, client) -> None:
        assert client.get("/vulnerabilities/987654").status_code == 404

    def test_unknown_report(self, client) -> None:
        assert client.get("/reports/no-such-session").status_code == 404

    def test_unknown_report_pdf(self, client) -> None:
        assert client.get("/reports/no-such-session/pdf").status_code == 404

    def test_unknown_remediation_action(self, client) -> None:
        assert client.get("/remediation/action/no-such-request").status_code == 404

    def test_the_empty_state_still_renders_rather_than_raising(self, client) -> None:
        body = client.get("/scans/no-such-session").text
        assert "Traceback" not in body
        assert "<html" in body.lower()
