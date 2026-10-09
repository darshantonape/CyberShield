"""Nmap XML parsing (spec §7, §25).

Two kinds of input are used:

  * `tests/unit/fixtures/*.xml` — REAL Nmap 7.991 output, captured by scanning
    local listeners on this machine. Authentic evidence of the parser's input.
  * Inline XML strings — clearly synthetic, used only to exercise edge cases
    (host down, missing service block, aborted scan) that are awkward to
    reproduce on demand. These are test data, never research results.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.scanner.nmap_parser import NmapParseError, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


class TestRealServiceDetectionOutput:
    """Against genuine Nmap output from two Python http.server listeners."""

    @pytest.fixture
    def scan(self):
        return parse_nmap_xml(load("nmap_service_detect.xml"))

    def test_reads_run_metadata(self, scan) -> None:
        assert scan.nmap_version == "7.991"
        assert scan.exit_status == "success"
        assert scan.elapsed_seconds is not None and scan.elapsed_seconds > 0

    def test_finds_the_host(self, scan) -> None:
        assert len(scan.hosts) == 1
        host = scan.hosts[0]
        assert host.address == "127.0.0.1"
        assert host.state == "up"
        assert host.is_up

    def test_parses_open_and_closed_ports(self, scan) -> None:
        services = {s.port: s for s in scan.hosts[0].services}
        assert set(services) == {18080, 18081, 18082}
        assert services[18080].state == "open"
        assert services[18082].state == "closed"
        assert not services[18082].is_open

    def test_extracts_product_and_version(self, scan) -> None:
        service = next(s for s in scan.hosts[0].services if s.port == 18080)
        assert service.service_name == "http"
        assert service.product == "SimpleHTTPServer"
        assert service.version == "0.6"
        assert service.extra_info == "Python 3.13.15"

    def test_records_nmap_confidence_and_method(self, scan) -> None:
        service = next(s for s in scan.hosts[0].services if s.port == 18080)
        assert service.confidence == 10
        # "probed" means banner-confirmed, as opposed to a port-number guess.
        assert service.method == "probed"

    def test_captures_cpe_in_nmaps_own_format(self, scan) -> None:
        # Nmap emits CPE 2.2 URI form (cpe:/a:...), not 2.3 (cpe:2.3:a:...).
        # Stored verbatim; conversion is the normalizer's job, not the parser's.
        service = next(s for s in scan.hosts[0].services if s.port == 18080)
        assert service.cpes == ("cpe:/a:python:simplehttpserver:0.6",)

    def test_identification_status_and_version_confidence(self, scan) -> None:
        identified = next(s for s in scan.hosts[0].services if s.port == 18080)
        assert identified.identification_status == "identified"
        assert identified.version_confidence == "known"

        # A closed port carries no service block at all.
        closed = next(s for s in scan.hosts[0].services if s.port == 18082)
        assert closed.identification_status == "undetermined"
        assert closed.version_confidence == "unknown"

    def test_open_services_helper(self, scan) -> None:
        assert len(scan.hosts[0].open_services) == 2
        assert scan.total_open_services == 2

    def test_services_are_sorted(self, scan) -> None:
        ports = [s.port for s in scan.hosts[0].services]
        assert ports == sorted(ports)


class TestRealDiscoveryOutput:
    def test_host_discovery_finds_host_without_ports(self) -> None:
        scan = parse_nmap_xml(load("nmap_discovery.xml"))
        assert len(scan.hosts) == 1
        host = scan.hosts[0]
        assert host.address == "127.0.0.1"
        assert host.is_up
        # -sn scans no ports, so the absence of services here means "not looked
        # at", not "nothing listening".
        assert host.services == ()
        assert scan.total_open_services == 0


class TestNoInvention:
    """The parser must never fill in what Nmap did not report."""

    def test_missing_version_stays_unknown(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="21"><state state="open"/>
        <service name="ftp" product="vsftpd" method="probed" conf="10"/>
        </port></ports></host></nmaprun>"""
        service = parse_nmap_xml(xml).hosts[0].services[0]
        assert service.product == "vsftpd"
        assert service.version is None
        assert service.version_confidence == "unknown"
        assert service.identification_status == "product_only"

    def test_table_method_is_preserved_as_a_guess(self) -> None:
        # method="table" means Nmap guessed from the port number alone. That
        # must remain visible; it is not evidence about what is running.
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="21"><state state="open"/>
        <service name="ftp" method="table" conf="3"/>
        </port></ports></host></nmaprun>"""
        service = parse_nmap_xml(xml).hosts[0].services[0]
        assert service.method == "table"
        assert service.confidence == 3
        assert service.product is None
        assert service.identification_status == "undetermined"

    def test_filtered_port_is_not_treated_as_open(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="21">
        <state state="filtered" reason="no-response"/></port></ports></host></nmaprun>"""
        service = parse_nmap_xml(xml).hosts[0].services[0]
        assert service.state == "filtered"
        assert not service.is_open

    def test_empty_attributes_become_none_not_empty_strings(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/><address addr="192.168.56.10" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="21"><state state="open"/>
        <service name="ftp" product="" version="  " method="probed"/>
        </port></ports></host></nmaprun>"""
        service = parse_nmap_xml(xml).hosts[0].services[0]
        assert service.product is None
        assert service.version is None


class TestHostStates:
    def test_down_host_is_reported_not_dropped(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="down"/><address addr="192.168.56.99" addrtype="ipv4"/>
        </host></nmaprun>"""
        scan = parse_nmap_xml(xml)
        assert len(scan.hosts) == 1
        assert not scan.hosts[0].is_up
        assert scan.hosts_up == ()

    def test_mac_address_and_hostname_are_captured(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/>
        <address addr="192.168.56.10" addrtype="ipv4"/>
        <address addr="08:00:27:AA:BB:CC" addrtype="mac" vendor="Oracle"/>
        <hostnames><hostname name="lab-target" type="PTR"/></hostnames>
        </host></nmaprun>"""
        host = parse_nmap_xml(xml).hosts[0]
        assert host.address == "192.168.56.10"
        assert host.mac_address == "08:00:27:AA:BB:CC"
        assert host.vendor == "Oracle"
        assert host.hostname == "lab-target"

    def test_host_without_ip_address_is_skipped(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <host><status state="up"/></host></nmaprun>"""
        assert parse_nmap_xml(xml).hosts == ()


class TestMalformedInput:
    def test_empty_input_raises(self) -> None:
        with pytest.raises(NmapParseError, match="no XML"):
            parse_nmap_xml("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(NmapParseError):
            parse_nmap_xml("   \n  ")

    def test_truncated_xml_is_recovered_but_marked_incomplete(self) -> None:
        # Nmap streams -oX as it scans, so a killed run leaves unclosed tags.
        # The surviving evidence is kept, but the result must never claim to be
        # complete and must not invent a host from a half-written element.
        result = parse_nmap_xml("<nmaprun><host>")
        assert result.recovered_from_truncation is True
        assert result.is_complete is False
        assert result.recovery_notes
        assert result.hosts == ()

    def test_unrecoverable_xml_raises(self) -> None:
        # Cut inside the DOCTYPE/prologue, before <nmaprun> is even opened.
        # There is nothing to salvage, so this must fail loudly rather than
        # return an empty scan that would read as "nothing found".
        with pytest.raises(NmapParseError, match="could not be recovered"):
            parse_nmap_xml(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE nmaprun>\n<?xml-stylesheet href="file:///usr'
            )

    def test_recovery_never_invents_a_port(self) -> None:
        # A <port> element cut mid-attribute must be dropped whole. Half of a
        # port element cannot be trusted to say what state the port was in.
        xml = (
            '<?xml version="1.0"?><nmaprun version="7.991"><host>'
            '<status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="open" reason="syn-ack"/></port>'
            '<port protocol="tcp" portid="80'
        )
        result = parse_nmap_xml(xml)
        assert result.recovered_from_truncation is True
        assert result.is_complete is False
        ports = [s.port for s in result.hosts[0].services]
        assert ports == [22], "the truncated port must not appear at all"

    def test_wrong_root_element_raises(self) -> None:
        with pytest.raises(NmapParseError, match="nmaprun"):
            parse_nmap_xml("<?xml version='1.0'?><html><body/></html>")

    def test_xxe_entity_is_refused(self) -> None:
        # Banners and hostnames come from the scanned host, so Nmap XML is
        # attacker-influenced. defusedxml must reject entity declarations.
        xml = """<?xml version="1.0"?>
        <!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <nmaprun version="7.991"><host><status state="up"/>
        <address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>"""
        with pytest.raises(NmapParseError):
            parse_nmap_xml(xml)

    def test_aborted_scan_surfaces_its_error(self) -> None:
        xml = """<?xml version="1.0"?><nmaprun version="7.991">
        <runstats><finished elapsed="0.5" exit="error"
        errormsg="Failed to resolve target"/></runstats></nmaprun>"""
        scan = parse_nmap_xml(xml)
        assert scan.exit_status == "error"
        assert scan.error_message == "Failed to resolve target"


class TestSerialisation:
    def test_scan_serialises_for_evidence(self) -> None:
        scan = parse_nmap_xml(load("nmap_service_detect.xml"))
        payload = scan.to_dict()
        assert payload["nmap_version"] == "7.991"
        service = payload["hosts"][0]["services"][0]
        assert {"port", "state", "product", "version", "cpes"} <= set(service)


class TestCollapsedExtraPorts:
    """`<extraports>` carries the ports Nmap chose not to list individually.

    Real Nmap output for a host that refused all 44 probed ports contains no
    <port> elements whatsoever — just the collapsed summary. Ignoring it lost
    the only evidence that the host answered at all. Shape taken from
    data/raw/47faa8f01a1d42f2_lan_service_detect_20260920T050507Z.xml.
    """

    ALL_CLOSED = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.991">
      <host>
        <status state="up" reason="user-set"/>
        <address addr="192.168.10.4" addrtype="ipv4"/>
        <ports>
          <extraports state="closed" count="44">
            <extrareasons reason="conn-refused" count="44"/>
          </extraports>
        </ports>
      </host>
      <runstats><finished exit="success"/></runstats>
    </nmaprun>"""

    def test_extraports_are_recorded(self) -> None:
        host = parse_nmap_xml(self.ALL_CLOSED).hosts[0]
        assert host.extra_port_counts == {"closed": 44}
        assert host.closed_port_count == 44
        assert host.responded is True

    def test_no_synthetic_services_are_invented(self) -> None:
        # The summary says 44 ports are closed; it says nothing about WHICH,
        # so no ParsedService may be created from it.
        host = parse_nmap_xml(self.ALL_CLOSED).hosts[0]
        assert host.services == ()
        assert host.open_services == ()

    def test_filtered_extraports_do_not_count_as_an_answer(self) -> None:
        xml = self.ALL_CLOSED.replace('state="closed"', 'state="filtered"')
        host = parse_nmap_xml(xml).hosts[0]
        assert host.extra_port_counts == {"filtered": 44}
        assert host.closed_port_count == 0
        assert host.responded is False

    def test_a_host_with_no_ports_block_still_parses(self) -> None:
        xml = self.ALL_CLOSED.replace(
            """<ports>
          <extraports state="closed" count="44">
            <extrareasons reason="conn-refused" count="44"/>
          </extraports>
        </ports>""",
            "",
        )
        host = parse_nmap_xml(xml).hosts[0]
        assert host.extra_ports == ()
        assert host.responded is False
