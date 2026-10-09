"""Operator-facing error explanations.

Two properties matter: the message tells the operator what to do next, and the
original technical text is never thrown away.
"""

from __future__ import annotations

from backend.core.errors import explain, scope_refusal


class TestScopeRefusal:
    def test_out_of_scope_message_says_how_to_fix_it(self) -> None:
        # The original message was "192.168.0.176/32 is not inside any
        # authorized range." — accurate and useless.
        friendly = scope_refusal(
            "192.168.0.176/32",
            "192.168.0.176/32 is not inside any authorized range. "
            "Authorized ranges: 192.168.64.8/29.",
            ["192.168.64.8/29"],
        )
        assert friendly.title == "Target not authorized"
        assert "192.168.0.176" in friendly.message
        assert "outside the currently authorized" in friendly.message
        # The actionable part.
        assert "Targets page" in friendly.hint
        assert "192.168.64.8/29" in friendly.message

    def test_technical_detail_is_retained(self) -> None:
        original = "192.168.0.176/32 is not inside any authorized range."
        friendly = scope_refusal("192.168.0.176/32", original, [])
        assert friendly.technical == original

    def test_empty_scope_gets_its_own_explanation(self) -> None:
        friendly = scope_refusal(
            "192.168.1.5",
            "config/authorized_targets.yaml defines no targets. CyberShield "
            "ships with an empty scope.",
        )
        assert friendly.title == "No authorized scope"
        assert "intended default" in friendly.message

    def test_ipv6_gets_its_own_explanation(self) -> None:
        friendly = scope_refusal(
            "fe80::1", "'fe80::1' looks like IPv6. This implementation supports IPv4 only."
        )
        assert "IPv4" in friendly.title
        assert "192.168" in friendly.hint

    def test_malformed_address_explains_why_names_are_refused(self) -> None:
        friendly = scope_refusal(
            "my-laptop", "'my-laptop' is not a valid IPv4 address or CIDR range: x"
        )
        assert friendly.title == "Invalid target"
        assert "DNS" in friendly.message


class TestExplain:
    def test_missing_nmap(self) -> None:
        friendly = explain("Executable 'nmap' not found on PATH.")
        assert "not installed" in friendly.title
        assert "brew install nmap" in friendly.hint

    def test_unsigned_authorization(self) -> None:
        friendly = explain("Refusing to act: AUTHORIZATION.md is not signed.")
        assert friendly.title == "Authorization not signed"
        assert "signed: true" in friendly.hint

    def test_malformed_xml(self) -> None:
        friendly = explain("Nmap XML is not well-formed: no element found")
        assert "Unreadable Nmap output" == friendly.title
        assert "data/raw" in friendly.hint

    def test_unrecoverable_xml_is_distinguished(self) -> None:
        friendly = explain(
            "Nmap XML is not well-formed and could not be recovered: bad token"
        )
        assert "no findings were recorded" in friendly.message.lower()

    def test_timeout(self) -> None:
        friendly = explain("Nmap timed out after 600s and produced no XML.")
        assert friendly.title == "Scan timed out"
        assert "prove" in friendly.message or "truncated" in friendly.message

    def test_nvd_failure_does_not_imply_no_vulnerabilities(self) -> None:
        friendly = explain("NVD request failed: connection refused")
        assert "means nothing was looked up" in friendly.message

    def test_ssh_failure_states_nothing_changed(self) -> None:
        friendly = explain("SSH command failed on 192.168.64.12: timed out")
        assert "Nothing was changed on the target" in friendly.message

    def test_protected_port_states_there_is_no_override(self) -> None:
        friendly = explain("tcp/22 is a protected port and can never be isolated")
        assert "no override" in friendly.hint.lower()

    def test_unknown_error_keeps_the_exception_type(self) -> None:
        friendly = explain(RuntimeError("something specific broke"))
        assert "something specific broke" in friendly.message
        assert "RuntimeError" in friendly.technical
        assert "Nothing was changed" in friendly.hint

    def test_flat_rendering_is_one_line(self) -> None:
        friendly = explain("Executable 'nmap' not found on PATH.")
        assert "\n" not in friendly.flat()
