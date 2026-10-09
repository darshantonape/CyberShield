"""Target and port validation (spec §25)."""

from __future__ import annotations

import pytest

from backend.core.validation import (
    ValidationError,
    is_private_network,
    parse_target,
    validate_hostname,
    validate_port,
    validate_proto,
)


class TestParseTarget:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("192.168.1.10", "192.168.1.10/32"),
            ("192.168.1.0/24", "192.168.1.0/24"),
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("  172.16.0.1  ", "172.16.0.1/32"),
            # Non-zero host bits are normalised rather than rejected.
            ("192.168.1.5/24", "192.168.1.0/24"),
        ],
    )
    def test_accepts_valid_ipv4(self, value: str, expected: str) -> None:
        assert str(parse_target(value).network) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "not-an-ip",
            "999.1.1.1",
            "192.168.1.1/33",
            "192.168.1",
            "192.168.1.1-192.168.1.5",
        ],
    )
    def test_rejects_malformed(self, value: str) -> None:
        with pytest.raises(ValidationError):
            parse_target(value)

    def test_rejects_hostnames(self) -> None:
        # Hostnames are refused so scope checks cannot be defeated by DNS
        # resolving to a different address than the one that was authorized.
        with pytest.raises(ValidationError):
            parse_target("scanme.nmap.org")

    def test_rejects_ipv6_explicitly(self) -> None:
        with pytest.raises(ValidationError, match="IPv6"):
            parse_target("2001:db8::1")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError):
            parse_target(12345)  # type: ignore[arg-type]

    def test_single_host_flag(self) -> None:
        assert parse_target("192.168.1.1").is_single_host
        assert not parse_target("192.168.1.0/24").is_single_host


class TestPrivateNetwork:
    @pytest.mark.parametrize(
        "value", ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.1"]
    )
    def test_private_ranges(self, value: str) -> None:
        assert is_private_network(parse_target(value).network)

    @pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1/32", "45.33.32.156"])
    def test_public_ranges(self, value: str) -> None:
        assert not is_private_network(parse_target(value).network)

    def test_range_spanning_public_space_is_not_private(self) -> None:
        # is_private evaluates the whole range, not just its first address.
        assert not is_private_network(parse_target("0.0.0.0/0").network)


class TestValidatePort:
    @pytest.mark.parametrize("value,expected", [(1, 1), (22, 22), (65535, 65535), ("8080", 8080)])
    def test_accepts_valid(self, value: object, expected: int) -> None:
        assert validate_port(value) == expected

    @pytest.mark.parametrize("value", [0, -1, 65536, 99999, "", "abc", "80.5", None, 3.5])
    def test_rejects_invalid(self, value: object) -> None:
        with pytest.raises(ValidationError):
            validate_port(value)

    def test_rejects_booleans(self) -> None:
        # isinstance(True, int) is True in Python, so without an explicit guard
        # validate_port(True) would silently return port 1.
        with pytest.raises(ValidationError, match="boolean"):
            validate_port(True)


class TestValidateProto:
    @pytest.mark.parametrize("value,expected", [("tcp", "tcp"), ("TCP", "tcp"), (" udp ", "udp")])
    def test_accepts_valid(self, value: str, expected: str) -> None:
        assert validate_proto(value) == expected

    @pytest.mark.parametrize("value", ["icmp", "sctp", "", "tcp6"])
    def test_rejects_unsupported(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_proto(value)


class TestValidateHostname:
    @pytest.mark.parametrize("value", ["192.168.1.1", "lab-target", "target.lab.local"])
    def test_accepts_valid(self, value: str) -> None:
        assert validate_hostname(value) == value

    @pytest.mark.parametrize("value", ["", "-bad", "bad-", "has space", "a" * 300])
    def test_rejects_invalid(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_hostname(value)
