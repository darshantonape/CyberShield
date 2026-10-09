"""Reachability assessment.

The failure being guarded against: an authorized target that is asleep or
firewalled produces a scan with no hosts and no services, and every count
downstream then reads zero — indistinguishable from a host that was examined and
found clean. These tests assert that case is classified UNREACHABLE and says so.
"""

from __future__ import annotations

from backend.scanner.nmap_parser import ParsedHost, ParsedScan, ParsedService
from backend.scanner.reachability import (
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    assess_scan,
)


def _service(port: int, state: str) -> ParsedService:
    return ParsedService(port=port, proto="tcp", state=state)


def _host(address: str, state: str, services=()) -> ParsedHost:
    return ParsedHost(address=address, state=state, services=tuple(services))


class TestUnreachable:
    def test_no_hosts_at_all_is_unreachable(self) -> None:
        result = assess_scan(
            ParsedScan(hosts=()), target_spec="192.168.0.176/32", used_pn=False
        )
        assert result.state == UNREACHABLE
        assert result.open_ports == 0

    def test_pn_scan_with_only_filtered_ports_is_unreachable(self) -> None:
        # The Windows-firewall case: -Pn reports the host "up" regardless, and
        # every probed port comes back filtered. Nothing was actually learned.
        scan = ParsedScan(
            hosts=(
                _host(
                    "192.168.0.176",
                    "up",
                    [_service(445, "filtered"), _service(3389, "filtered")],
                ),
            )
        )
        result = assess_scan(scan, target_spec="192.168.0.176/32", used_pn=True)
        assert result.state == UNREACHABLE

    def test_unreachable_result_is_not_described_as_clean(self) -> None:
        result = assess_scan(
            ParsedScan(hosts=()), target_spec="192.168.0.176/32", used_pn=False
        )
        note = result.note.lower()
        assert "unreachable" in note
        assert "clean" not in note.replace("not a clean", "")
        assert "no conclusion" in note or "not a clean" in note

    def test_unreachable_result_lists_causes_to_check(self) -> None:
        result = assess_scan(
            ParsedScan(hosts=()), target_spec="192.168.0.176/32", used_pn=True
        )
        causes = " ".join(result.possible_causes).lower()
        # The ordinary LAN causes an operator needs to rule out.
        assert "firewall" in causes
        assert "isolation" in causes
        assert "asleep" in causes or "powered off" in causes
        assert "subnet" in causes


class TestReachable:
    def test_an_open_port_is_reachable(self) -> None:
        scan = ParsedScan(
            hosts=(_host("192.168.64.12", "up", [_service(21, "open")]),)
        )
        result = assess_scan(scan, target_spec="192.168.64.12/32", used_pn=False)
        assert result.state == REACHABLE
        assert result.open_ports == 1

    def test_a_closed_port_still_proves_reachability(self) -> None:
        # A closed port means a RST came back: packets reached the host. That is
        # reachable-with-nothing-exposed, which is a real and different finding
        # from "no answer at all".
        scan = ParsedScan(
            hosts=(_host("192.168.1.50", "up", [_service(22, "closed")]),)
        )
        result = assess_scan(scan, target_spec="192.168.1.50/32", used_pn=True)
        assert result.state == REACHABLE
        assert result.open_ports == 0
        assert "not the same as having no" in result.note

    def test_discovery_only_scan_with_a_host_up_is_reachable(self) -> None:
        scan = ParsedScan(hosts=(_host("192.168.64.11", "up"),))
        result = assess_scan(scan, target_spec="192.168.64.8/29", used_pn=False)
        assert result.state == REACHABLE
        assert "No ports were scanned" in result.note


class TestTruncation:
    def test_recovered_scan_reachability_is_unknown(self) -> None:
        # A repaired, truncated scan cannot support a reachability claim either
        # way, so it must not be asserted.
        scan = ParsedScan(
            hosts=(_host("192.168.1.50", "up", [_service(80, "open")]),),
            recovered_from_truncation=True,
            recovery_notes=("closed unterminated element(s): nmaprun",),
        )
        result = assess_scan(scan, target_spec="192.168.1.50/32", used_pn=True)
        assert result.state == UNKNOWN
        assert "truncated" in result.note


class TestCollapsedExtraPorts:
    """Nmap collapses uninteresting ports instead of listing them.

    A host that refuses every probed port emits no <port> elements at all —
    only <extraports state="closed" count="44"/>. Reading only the <port>
    elements made that host indistinguishable from one that answered nothing,
    so a laptop sitting on the LAN with its ports shut was reported "authorized
    but UNREACHABLE — every probed port was filtered". Observed against
    192.168.10.4 on 2026-09-20.
    """

    def test_all_ports_closed_via_extraports_is_reachable(self) -> None:
        host = ParsedHost(
            address="192.168.10.4",
            state="up",
            services=(),
            extra_ports=(("closed", 44),),
        )
        result = assess_scan(
            ParsedScan(hosts=(host,)), target_spec="192.168.10.4/32", used_pn=True
        )
        assert result.state == REACHABLE
        assert result.open_ports == 0
        assert result.hosts_responding == 1
        # And it must still refuse to read as a clean bill of health.
        assert "not the same as having no" in result.note

    def test_all_ports_filtered_via_extraports_is_still_unreachable(self) -> None:
        # The opposite case, and the one that must NOT be softened: filtered is
        # the absence of an answer, so it proves nothing about the host.
        host = ParsedHost(
            address="192.168.1.25",
            state="up",
            services=(),
            extra_ports=(("filtered", 44),),
        )
        result = assess_scan(
            ParsedScan(hosts=(host,)), target_spec="192.168.1.25/32", used_pn=True
        )
        assert result.state == UNREACHABLE
        assert result.hosts_responding == 0
        assert "NOT a clean result" in result.note

    def test_extraports_are_not_expanded_into_services(self) -> None:
        # The summary is a count, not evidence about any particular port.
        # Materialising 44 synthetic "closed" services would corrupt every
        # service count downstream.
        host = ParsedHost(
            address="192.168.10.4", state="up", services=(), extra_ports=(("closed", 44),)
        )
        assert host.services == ()
        assert host.closed_port_count == 44
        assert host.responded is True
