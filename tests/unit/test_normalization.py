"""Software normalization: CPE handling, version cleaning, signatures (spec §8, §25)."""

from __future__ import annotations

import pytest

from backend.normalization.cpe import (
    ANY,
    CpeError,
    CpeParts,
    cpe22_to_cpe23,
    is_valid_cpe23,
    parse_cpe,
    parse_cpe22,
    parse_cpe23,
)
from backend.normalization.normalizer import normalize_service
from backend.normalization.product_map import PRODUCT_MAP, lookup_product
from backend.normalization.version import normalize_version
from backend.scanner.nmap_parser import ParsedService


def service(**kwargs) -> ParsedService:
    params = {
        "port": 21,
        "proto": "tcp",
        "state": "open",
        "method": "probed",
        "confidence": 10,
    }
    params.update(kwargs)
    return ParsedService(**params)


# ---------------------------------------------------------------------------
# CPE
# ---------------------------------------------------------------------------


class TestCpeConversion:
    def test_nmap_2_2_uri_converts_to_2_3(self) -> None:
        # This conversion is mandatory: NVD returns nothing for a 2.2 URI.
        assert (
            cpe22_to_cpe23("cpe:/a:apache:http_server:2.4.49")
            == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        )

    def test_real_nmap_cpe_from_the_fixture_converts(self) -> None:
        assert (
            cpe22_to_cpe23("cpe:/a:python:simplehttpserver:0.6")
            == "cpe:2.3:a:python:simplehttpserver:0.6:*:*:*:*:*:*:*"
        )

    def test_omitted_trailing_components_become_any(self) -> None:
        parts = parse_cpe22("cpe:/a:vsftpd_project:vsftpd")
        assert parts.version == ANY
        assert parts.update == ANY
        assert not parts.has_version

    def test_operating_system_part_is_preserved(self) -> None:
        assert parse_cpe22("cpe:/o:linux:linux_kernel:5.4").part == "o"

    def test_round_trip_2_3(self) -> None:
        original = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        assert parse_cpe23(original).to_cpe23() == original

    def test_parse_cpe_dispatches_on_prefix(self) -> None:
        assert parse_cpe("cpe:/a:apache:http_server:2.4.49").vendor == "apache"
        assert parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").vendor == "apache"


class TestCpeValidation:
    @pytest.mark.parametrize(
        "value",
        [
            "",
            "not-a-cpe",
            "cpe:2.3:a:apache",  # too few components
            "cpe:/x:vendor:product",  # invalid part
        ],
    )
    def test_malformed_is_rejected(self, value: str) -> None:
        with pytest.raises(CpeError):
            parse_cpe(value)

    def test_invalid_part_letter_is_rejected(self) -> None:
        with pytest.raises(CpeError, match="part"):
            CpeParts(part="z", vendor="v", product="p")

    def test_is_valid_cpe23(self) -> None:
        assert is_valid_cpe23("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        assert not is_valid_cpe23("cpe:/a:apache:http_server:2.4.49")


class TestCpeVersionSemantics:
    def test_any_and_na_are_not_versions(self) -> None:
        # A wildcard must never be mistaken for a detected version.
        assert not CpeParts(vendor="v", product="p", version=ANY).has_version
        assert not CpeParts(vendor="v", product="p", version="-").has_version
        assert CpeParts(vendor="v", product="p", version="2.3.4").has_version

    def test_with_version_none_resets_to_any(self) -> None:
        parts = CpeParts(vendor="v", product="p", version="1.0").with_version(None)
        assert parts.version == ANY


# ---------------------------------------------------------------------------
# Version cleaning
# ---------------------------------------------------------------------------


class TestVersionNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("2.3.4", "2.3.4"),
            ("2.4.49 ((Ubuntu))", "2.4.49"),  # real Apache banner
            ("5.7.44-log", "5.7.44"),  # real MySQL banner
            ("1.18.0 (Ubuntu)", "1.18.0"),
            ("7.2p2 Ubuntu 4ubuntu2.10", "7.2p2"),  # OpenSSH keeps its qualifier
            ("0.6", "0.6"),
            ("  3.0.3  ", "3.0.3"),
        ],
    )
    def test_extracts_upstream_version(self, raw: str, expected: str) -> None:
        assert normalize_version(raw).version == expected

    @pytest.mark.parametrize("raw", [None, "", "   ", "unknown", "abc"])
    def test_absent_version_stays_none(self, raw) -> None:
        # The core rule: never invent a version.
        result = normalize_version(raw)
        assert result.version is None
        assert result.confidence == "unknown"
        assert not result.is_known

    def test_change_is_recorded_for_audit(self) -> None:
        result = normalize_version("5.7.44-log")
        assert result.changed
        assert result.raw == "5.7.44-log"
        assert "5.7.44" in (result.note or "")

    def test_unchanged_version_is_not_flagged(self) -> None:
        assert not normalize_version("2.3.4").changed


# ---------------------------------------------------------------------------
# Product map
# ---------------------------------------------------------------------------


class TestProductMap:
    @pytest.mark.parametrize(
        "product,vendor,name",
        [
            ("vsftpd", "vsftpd_project", "vsftpd"),
            ("Apache httpd", "apache", "http_server"),
            ("OpenSSH", "openbsd", "openssh"),
            ("Samba smbd", "samba", "samba"),
            ("Apache Tomcat", "apache", "tomcat"),
        ],
    )
    def test_verified_mappings(self, product: str, vendor: str, name: str) -> None:
        mapping = lookup_product(product)
        assert mapping is not None
        assert (mapping.vendor, mapping.product) == (vendor, name)

    def test_nginx_vendor_is_the_verified_one(self) -> None:
        # Verified against NVD: igor_sysoev, NOT f5 or nginx:nginx.
        mapping = lookup_product("nginx")
        assert mapping is not None
        assert mapping.vendor == "igor_sysoev"

    def test_ambiguous_products_retain_alternates(self) -> None:
        # MySQL 5.7.44: oracle:mysql -> 12 CVEs, mysql:mysql -> 2. Both real.
        mysql = lookup_product("MySQL")
        assert mysql is not None
        assert len(mysql.candidates()) == 2
        assert ("oracle", "mysql") in mysql.candidates()
        assert ("mysql", "mysql") in mysql.candidates()

    def test_redis_uses_the_vendor_that_actually_carries_cves(self) -> None:
        # The CPE dictionary ranks redislabs/pivotal_software higher, but for
        # 5.0.14 both return 0 CVEs while redis:redis returns 21.
        redis = lookup_product("Redis key-value store")
        assert redis is not None
        assert redis.vendor == "redis"

    def test_case_and_alias_handling(self) -> None:
        assert lookup_product("APACHE HTTPD") is not None
        assert lookup_product("Apache HTTP Server") is not None
        assert lookup_product("  vsftpd  ") is not None

    def test_unmapped_product_returns_none(self) -> None:
        # Not an error: the caller must surface it, never treat it as clean.
        assert lookup_product("Totally Unknown Daemon 9000") is None
        assert lookup_product(None) is None

    def test_every_entry_has_a_valid_part(self) -> None:
        for mapping in PRODUCT_MAP.values():
            assert mapping.part in {"a", "o", "h"}


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class TestNormalizer:
    def test_apache_banner_normalizes_end_to_end(self) -> None:
        result = normalize_service(
            service(product="Apache httpd", version="2.4.49 ((Ubuntu))")
        )
        best = result.candidates[0]
        assert (best.vendor, best.product, best.version) == ("apache", "http_server", "2.4.49")
        assert best.cpe23 == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        assert best.confidence == "HIGH"
        assert result.version_confidence == "known"

    def test_nmap_cpe_is_preferred_and_gains_the_version(self) -> None:
        # Nmap's CPE often omits the version even when the banner had one.
        result = normalize_service(
            service(product="vsftpd", version="2.3.4", cpes=("cpe:/a:vsftpd_project:vsftpd",))
        )
        best = result.candidates[0]
        assert best.mapping_source == "nmap_cpe"
        assert best.version == "2.3.4"

    def test_ambiguous_vendor_produces_multiple_candidates(self) -> None:
        result = normalize_service(service(product="MySQL", version="5.7.44-log"))
        pairs = {(c.vendor, c.product) for c in result.candidates}
        assert ("oracle", "mysql") in pairs
        assert ("mysql", "mysql") in pairs
        # Ambiguity caps confidence.
        assert all(c.confidence in ("MEDIUM", "LOW") for c in result.candidates)

    def test_missing_version_drops_confidence_to_low(self) -> None:
        result = normalize_service(service(product="vsftpd", version=None))
        assert all(c.confidence == "LOW" for c in result.candidates)
        assert result.version_confidence == "unknown"
        assert any("over-report" in c for c in result.caveats)

    def test_table_method_is_low_confidence(self) -> None:
        # Guessed from the port number with no banner evidence.
        result = normalize_service(
            service(product="vsftpd", version="2.3.4", method="table", confidence=3)
        )
        assert all(c.confidence == "LOW" for c in result.candidates)
        assert any("port number alone" in c for c in result.caveats)

    def test_low_nmap_confidence_caps_at_medium(self) -> None:
        result = normalize_service(
            service(product="vsftpd", version="2.3.4", method="probed", confidence=4)
        )
        assert result.best_confidence == "MEDIUM"
        assert any("4/10" in c for c in result.caveats)

    def test_no_product_yields_no_candidates(self) -> None:
        result = normalize_service(service(product=None, version=None))
        assert result.candidates == []
        assert result.identification_status == "undetermined"
        # Explicitly not "clean".
        assert any("not the same as having no vulnerabilities" in c for c in result.caveats)

    def test_unmapped_product_is_reported_not_hidden(self) -> None:
        result = normalize_service(service(product="Weird Daemon", version="1.0"))
        assert any("not in the curated map" in c for c in result.caveats)

    def test_os_cpes_from_nmap_are_ignored(self) -> None:
        result = normalize_service(
            service(product="vsftpd", version="2.3.4", cpes=("cpe:/o:linux:linux_kernel",))
        )
        assert all(c.part == "a" for c in result.candidates)

    def test_unparseable_nmap_cpe_is_noted_not_fatal(self) -> None:
        result = normalize_service(
            service(product="vsftpd", version="2.3.4", cpes=("garbage",))
        )
        # Falls back to the curated map rather than raising.
        assert result.candidates
        assert any("unparseable" in c for c in result.caveats)
