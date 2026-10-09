"""CVSS resolution and CVE correlation (spec §9, §10, §11, §25).

Runs entirely offline against `tests/unit/fixtures/nvd_*.json`, which are REAL
NVD REST API 2.0 responses captured on 2026-08-30 — not hand-written JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.normalization.normalizer import SignatureCandidate
from backend.nvd.cache import NvdCache
from backend.nvd.client import NvdError, NvdResponse
from backend.nvd.correlate import check_applicability, correlate_service
from backend.nvd.severity import resolve_severity, severity_band
from backend.scanner.nmap_parser import ParsedService

FIXTURES = Path(__file__).parent / "fixtures"


def load_cves(name: str) -> list[dict]:
    payload = json.loads((FIXTURES / name).read_text())
    return [v["cve"] for v in payload["vulnerabilities"]]


def find(cves: list[dict], cve_id: str) -> dict:
    return next(c for c in cves if c["id"] == cve_id)


class FakeClient:
    """Serves captured NVD responses; records the queries made."""

    def __init__(self, by_cpe: dict[str, list[dict]] | None = None,
                 by_keyword: dict[str, list[dict]] | None = None) -> None:
        self.by_cpe = by_cpe or {}
        self.by_keyword = by_keyword or {}
        self.cpe_queries: list[str] = []
        self.keyword_queries: list[str] = []

    def search_by_cpe(self, cpe23: str, **_) -> NvdResponse:
        self.cpe_queries.append(cpe23)
        cves = self.by_cpe.get(cpe23, [])
        return NvdResponse(cves=cves, total_results=len(cves), query={"cpeName": cpe23})

    def search_by_keyword(self, keyword: str, **_) -> NvdResponse:
        self.keyword_queries.append(keyword)
        cves = self.by_keyword.get(keyword, [])
        return NvdResponse(cves=cves, total_results=len(cves), query={"keywordSearch": keyword})


def service(**kwargs) -> ParsedService:
    params = {"port": 21, "proto": "tcp", "state": "open", "method": "probed", "confidence": 10}
    params.update(kwargs)
    return ParsedService(**params)


# ---------------------------------------------------------------------------
# CVSS (spec §10)
# ---------------------------------------------------------------------------


class TestSeverityResolution:
    def test_prefers_v31_when_available(self) -> None:
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2021-41773")
        resolved = resolve_severity(cve)
        assert resolved.version == "3.1"
        assert resolved.base_score == 9.8
        assert resolved.base_severity == "CRITICAL"
        assert not resolved.severity_derived

    def test_v2_only_cve_derives_its_band(self) -> None:
        # NVD returns baseSeverity: null for CVSS v2, so the band must be
        # computed from the score and flagged as derived.
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2009-0796")
        resolved = resolve_severity(cve)
        assert resolved.version == "2.0"
        assert resolved.base_score is not None
        assert resolved.base_severity in {"LOW", "MEDIUM", "HIGH"}
        assert resolved.severity_derived

    def test_all_metrics_are_retained(self) -> None:
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2021-41773")
        assert resolve_severity(cve).all_metrics is not None

    def test_absent_metrics_yield_no_score(self) -> None:
        # No score is ever invented.
        resolved = resolve_severity({"id": "CVE-0000-0000"})
        assert resolved.base_score is None
        assert resolved.base_severity is None
        assert not resolved.has_score


class TestSeverityBands:
    @pytest.mark.parametrize(
        "score,expected",
        [(0.0, "NONE"), (3.9, "LOW"), (5.0, "MEDIUM"), (7.5, "HIGH"), (9.8, "CRITICAL")],
    )
    def test_v3_bands(self, score: float, expected: str) -> None:
        assert severity_band(score, "3.1") == expected

    @pytest.mark.parametrize("score,expected", [(3.9, "LOW"), (5.0, "MEDIUM"), (9.8, "HIGH")])
    def test_v2_has_no_critical_band(self, score: float, expected: str) -> None:
        # Applying v3 bands to a v2 score would inflate 9.8 to CRITICAL.
        assert severity_band(score, "2.0") == expected

    def test_none_score_gives_none(self) -> None:
        assert severity_band(None, "3.1") is None


# ---------------------------------------------------------------------------
# Applicability — the false-positive filter
# ---------------------------------------------------------------------------


class TestApplicabilityCheck:
    @pytest.fixture
    def apache_signature(self) -> SignatureCandidate:
        return SignatureCandidate(
            vendor="apache",
            product="http_server",
            version="2.4.49",
            cpe23="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            confidence="HIGH",
        )

    def test_genuine_match_is_confirmed(self, apache_signature) -> None:
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2021-41773")
        applies, evidence = check_applicability(cve, apache_signature)
        assert applies
        assert evidence["vulnerable_match_count"] >= 1

    def test_unrelated_product_is_rejected(self, apache_signature) -> None:
        # NVD returns CVE-2007-4723 for the Apache 2.4.49 CPE, but its
        # configuration names ragnarok_online_control_panel.
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2007-4723")
        applies, evidence = check_applicability(cve, apache_signature)
        assert not applies
        others = evidence["other_products_in_configuration"]
        assert any("ragnarok" in o for o in others)

    def test_apache_module_cve_is_rejected(self, apache_signature) -> None:
        # mod_authnz_external is not http_server.
        cve = find(load_cves("nvd_apache_2.4.49.json"), "CVE-2011-2688")
        applies, _ = check_applicability(cve, apache_signature)
        assert not applies

    def test_cve_without_configurations_cannot_be_confirmed(self, apache_signature) -> None:
        applies, evidence = check_applicability({"id": "CVE-0000-0000"}, apache_signature)
        assert not applies
        assert evidence["no_configuration_data"]


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


class TestCpeCorrelation:
    def test_vsftpd_matches_the_expected_cves(self) -> None:
        cves = load_cves("nvd_vsftpd_2.3.4.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*": cves}
        )
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))

        ids = {c.cve_id for c in result.candidates}
        assert "CVE-2011-2523" in ids  # the vsftpd 2.3.4 backdoor
        assert all(c.matching_method == "cpe_exact" for c in result.candidates)
        assert result.max_confidence == "HIGH"

    def test_flagged_false_positives_are_downgraded(self) -> None:
        cves = load_cves("nvd_apache_2.4.49.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*": cves}
        )
        result = correlate_service(
            client, service(port=8080, product="Apache httpd", version="2.4.49 ((Ubuntu))")
        )

        by_id = {c.cve_id: c for c in result.candidates}
        assert by_id["CVE-2021-41773"].confidence == "HIGH"
        # Mis-attributed CVEs are kept but demoted and explained.
        assert by_id["CVE-2007-4723"].confidence == "LOW"
        assert any("mis-attribution" in c for c in by_id["CVE-2007-4723"].caveats)

    def test_every_candidate_carries_the_core_caveat(self) -> None:
        cves = load_cves("nvd_vsftpd_2.3.4.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*": cves}
        )
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))
        for candidate in result.candidates:
            assert any("not proof" in c for c in candidate.caveats)

    def test_results_are_ranked_by_confidence_then_severity(self) -> None:
        cves = load_cves("nvd_apache_2.4.49.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*": cves}
        )
        result = correlate_service(
            client, service(port=8080, product="Apache httpd", version="2.4.49")
        )
        ranks = [{"LOW": 1, "MEDIUM": 2, "HIGH": 3}[c.confidence] for c in result.candidates]
        assert ranks == sorted(ranks, reverse=True)

    def test_max_severity_feeds_the_decision_engine(self) -> None:
        cves = load_cves("nvd_vsftpd_2.3.4.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*": cves}
        )
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))
        assert result.max_severity in {"HIGH", "CRITICAL"}


class TestKeywordFallback:
    def test_keyword_is_used_only_when_cpe_returns_nothing(self) -> None:
        client = FakeClient(by_cpe={}, by_keyword={"vsftpd 2.3.4": load_cves("nvd_vsftpd_2.3.4.json")})
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))

        assert client.cpe_queries, "the CPE path must be attempted first"
        assert client.keyword_queries == ["vsftpd 2.3.4"]
        assert all(c.matching_method == "keyword" for c in result.candidates)

    def test_keyword_results_are_always_low_confidence(self) -> None:
        client = FakeClient(by_cpe={}, by_keyword={"vsftpd 2.3.4": load_cves("nvd_vsftpd_2.3.4.json")})
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))
        assert all(c.confidence == "LOW" for c in result.candidates)
        assert result.max_confidence == "LOW"

    def test_keyword_candidates_state_the_under_reporting(self) -> None:
        client = FakeClient(by_cpe={}, by_keyword={"vsftpd 2.3.4": load_cves("nvd_vsftpd_2.3.4.json")})
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))
        assert any("under-report" in c for c in result.candidates[0].caveats)

    def test_no_keyword_search_when_cpe_succeeded(self) -> None:
        cves = load_cves("nvd_vsftpd_2.3.4.json")
        client = FakeClient(
            by_cpe={"cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*": cves}
        )
        correlate_service(client, service(product="vsftpd", version="2.3.4"))
        assert client.keyword_queries == []


class TestNoResultsIsNotClean:
    def test_empty_result_says_so_explicitly(self) -> None:
        client = FakeClient(by_cpe={}, by_keyword={})
        result = correlate_service(client, service(product="vsftpd", version="2.3.4"))
        assert result.candidates == []
        assert any("not the same as the service being free" in c for c in result.caveats)

    def test_unidentified_service_makes_no_queries(self) -> None:
        client = FakeClient()
        result = correlate_service(client, service(product=None, method="table", confidence=3))
        assert result.candidates == []
        assert client.cpe_queries == []
        assert result.max_severity is None
        assert result.max_confidence is None


class TestClientGuards:
    def test_search_by_cpe_rejects_a_2_2_uri(self) -> None:
        from backend.nvd.client import NvdClient

        client = NvdClient(offline=True)
        with pytest.raises(NvdError, match="2.3"):
            client.search_by_cpe("cpe:/a:apache:http_server:2.4.49")

    def test_offline_miss_raises_rather_than_returning_empty(self, tmp_path) -> None:
        # An empty result would be indistinguishable from "no vulnerabilities".
        from backend.nvd.client import NvdClient

        client = NvdClient(offline=True, cache_dir=tmp_path)
        with pytest.raises(NvdError, match="Offline mode"):
            client.search_by_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")


class TestCache:
    def test_round_trip(self, tmp_path) -> None:
        cache = NvdCache(tmp_path)
        params = {"cpeName": "cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"}
        cache.put(params, {"totalResults": 3, "vulnerabilities": []})
        entry = cache.get(params)
        assert entry is not None
        assert entry.payload["totalResults"] == 3
        assert entry.query == params

    def test_expired_entry_is_a_miss(self, tmp_path) -> None:
        cache = NvdCache(tmp_path, ttl_seconds=0)
        cache.put({"q": "x"}, {"totalResults": 1})
        assert cache.get({"q": "x"}) is None

    def test_corrupt_entry_is_a_miss_not_a_crash(self, tmp_path) -> None:
        cache = NvdCache(tmp_path)
        params = {"q": "x"}
        (tmp_path / f"{NvdCache.key_for(params)}.json").write_text("{not json")
        assert cache.get(params) is None

    def test_hit_rate_is_tracked(self, tmp_path) -> None:
        cache = NvdCache(tmp_path)
        cache.put({"q": "x"}, {"ok": True})
        cache.get({"q": "x"})
        cache.get({"q": "missing"})
        assert cache.stats()["hits"] == 1
        assert cache.stats()["misses"] == 1


class TestWildcardCpeIsNotQueried:
    """A CPE with no concrete version must never reach NVD.

    Measured against the live API on 2026-09-20: a `cpeName` whose version
    component is `*` returns HTTP 404 whether or not the product exists
    (`encode:uvicorn` and `apache:http_server` both 404), while the same
    product with a concrete version returns 200. Querying one is therefore a
    guaranteed failure, and it was being recorded as a correlation error — which
    made the audit log record `correlation.finish` as outcome="failure" for a
    run that had completed normally.
    """

    def _service(self, product, version):
        from backend.scanner.nmap_parser import ParsedService

        return ParsedService(
            port=8000, proto="tcp", state="open", service_name="http",
            product=product, version=version, method="probed",
        )

    def test_a_versionless_service_makes_no_cpe_call(self) -> None:
        from backend.nvd.correlate import correlate_service

        class Recorder:
            def __init__(self): self.cpe_calls = []; self.keyword_calls = []
            def search_by_cpe(self, cpe23, **kw):
                self.cpe_calls.append(cpe23)
                raise AssertionError("a wildcard CPE must not be queried")
            def search_by_keyword(self, keyword, **kw):
                from backend.nvd.client import NvdResponse
                self.keyword_calls.append(keyword)
                return NvdResponse(cves=[], total_results=0, from_cache=False,
                                   query={"keywordSearch": keyword}, elapsed_seconds=0.0)

        client = Recorder()
        result = correlate_service(client, self._service("Apache httpd", None))
        assert client.cpe_calls == []
        assert result.errors == [], "a normal version-less service is not an error"

    def test_the_reason_is_stated_rather_than_silently_skipped(self) -> None:
        from backend.nvd.client import NvdResponse
        from backend.nvd.correlate import correlate_service

        class Quiet:
            def search_by_cpe(self, cpe23, **kw):
                raise AssertionError("should not be called")
            def search_by_keyword(self, keyword, **kw):
                return NvdResponse(cves=[], total_results=0, from_cache=False,
                                   query={}, elapsed_seconds=0.0)

        result = correlate_service(Quiet(), self._service("Apache httpd", None))
        joined = " ".join(result.caveats).lower()
        assert "no version" in joined
        assert "undetermined" in joined, "must never read as clean"

    def test_a_versioned_service_is_still_queried_by_cpe(self) -> None:
        from backend.nvd.client import NvdResponse
        from backend.nvd.correlate import correlate_service

        class Recorder:
            def __init__(self): self.cpe_calls = []
            def search_by_cpe(self, cpe23, **kw):
                self.cpe_calls.append(cpe23)
                return NvdResponse(cves=[], total_results=0, from_cache=False,
                                   query={"cpeName": cpe23}, elapsed_seconds=0.0)
            def search_by_keyword(self, keyword, **kw):
                return NvdResponse(cves=[], total_results=0, from_cache=False,
                                   query={}, elapsed_seconds=0.0)

        client = Recorder()
        correlate_service(client, self._service("Apache httpd", "2.4.49"))
        assert client.cpe_calls, "the primary CPE path must still run"
        assert all(":2.4.49:" in c for c in client.cpe_calls)
