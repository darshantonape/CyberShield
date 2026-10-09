"""Nmap command construction (spec §7).

These tests assert on the argv the runner builds. Nothing here executes Nmap;
the live-execution tests are in tests/integration/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.core.config import ScanProfile
from backend.core.validation import parse_target
from backend.scanner.nmap_runner import NmapError, build_argv

OUT = Path("/tmp/cybershield-test/out.xml")


def profile(*args: str, name: str = "test") -> ScanProfile:
    return ScanProfile(name=name, description="", args=tuple(args), timeout_seconds=600)


class TestArgvConstruction:
    def test_profile_args_are_preserved_in_order(self) -> None:
        argv = build_argv(profile("-sT", "-sV", "-n"), parse_target("192.168.56.10"), OUT)
        assert argv[0] == "nmap"
        assert argv[1:4] == ["-sT", "-sV", "-n"]

    def test_output_path_is_set_by_the_runner(self) -> None:
        argv = build_argv(profile("-sT"), parse_target("192.168.56.10"), OUT)
        assert argv[-3:-1] == ["-oX", str(OUT)]

    def test_target_is_the_final_single_argument(self) -> None:
        argv = build_argv(profile("-sT"), parse_target("192.168.56.0/24"), OUT)
        assert argv[-1] == "192.168.56.0/24"

    def test_single_host_is_rendered_as_slash_32(self) -> None:
        # Uniform CIDR output; Nmap accepts /32 for a single address.
        argv = build_argv(profile("-sT"), parse_target("192.168.56.10"), OUT)
        assert argv[-1] == "192.168.56.10/32"

    def test_every_element_is_a_separate_argument(self) -> None:
        # No element may contain a space: that would mean two flags were
        # concatenated into one string, the shape shell injection needs.
        argv = build_argv(profile("-sT", "-sV"), parse_target("192.168.56.10"), OUT)
        assert all(" " not in a for a in argv if a != str(OUT))


class TestPortInjection:
    def test_explicit_ports_become_one_p_argument(self) -> None:
        argv = build_argv(profile("-sT"), parse_target("192.168.56.10"), OUT, ports=[21, 80])
        index = argv.index("-p")
        assert argv[index + 1] == "21,80"

    def test_ports_are_range_checked(self) -> None:
        from backend.core.validation import ValidationError

        with pytest.raises(ValidationError):
            build_argv(profile("-sT"), parse_target("192.168.56.10"), OUT, ports=[70000])

    def test_injection_attempt_via_ports_is_rejected(self) -> None:
        # A string port carrying extra flags must never reach the command line.
        from backend.core.validation import ValidationError

        with pytest.raises(ValidationError):
            build_argv(
                profile("-sT"),
                parse_target("192.168.56.10"),
                OUT,
                ports=["21 --script=exploit"],  # type: ignore[list-item]
            )

    def test_empty_port_list_is_rejected(self) -> None:
        with pytest.raises(NmapError, match="empty"):
            build_argv(profile("-sT"), parse_target("192.168.56.10"), OUT, ports=[])

    def test_no_p_flag_when_ports_not_given(self) -> None:
        argv = build_argv(profile("-sT", "--top-ports", "1000"), parse_target("10.0.0.1"), OUT)
        assert "-p" not in argv
        # Profile port selection is untouched when no explicit list is supplied.
        assert "--top-ports" in argv


class TestPortSelectionConflict:
    """Nmap given both --top-ports and -p scans NOTHING, silently and with
    exit="success". A verification rescan built that way would be
    indistinguishable from a successful isolation, so the profile's own port
    selection must be stripped whenever an explicit list is supplied."""

    def test_top_ports_is_stripped_when_explicit_ports_given(self) -> None:
        argv = build_argv(
            profile("-sT", "-sV", "--top-ports", "1000"),
            parse_target("192.168.56.10"),
            OUT,
            ports=[21],
        )
        assert "--top-ports" not in argv
        assert "1000" not in argv  # its value must go too
        assert argv[argv.index("-p") + 1] == "21"
        # Non-port arguments survive.
        assert "-sT" in argv and "-sV" in argv

    def test_equals_form_of_top_ports_is_stripped(self) -> None:
        argv = build_argv(
            profile("-sT", "--top-ports=1000"), parse_target("192.168.56.10"), OUT, ports=[21]
        )
        assert not any(a.startswith("--top-ports") for a in argv)
        assert "-sT" in argv

    @pytest.mark.parametrize("flag", ["-F", "-p-"])
    def test_other_port_selection_flags_are_stripped(self, flag: str) -> None:
        argv = build_argv(
            profile("-sT", flag), parse_target("192.168.56.10"), OUT, ports=[21]
        )
        assert flag not in argv

    def test_exclude_ports_and_value_are_stripped(self) -> None:
        argv = build_argv(
            profile("-sT", "--exclude-ports", "9999"),
            parse_target("192.168.56.10"),
            OUT,
            ports=[21],
        )
        assert "--exclude-ports" not in argv
        assert "9999" not in argv

    def test_exactly_one_port_selection_remains(self) -> None:
        argv = build_argv(
            profile("-sT", "-sV", "--top-ports", "1000", "-F"),
            parse_target("192.168.56.10"),
            OUT,
            ports=[21, 8080],
        )
        selectors = [
            a for a in argv if a in {"-p", "-F", "-p-"} or a.startswith("--top-ports")
        ]
        assert selectors == ["-p"]

    def test_shipped_service_detect_profile_survives_stripping(self) -> None:
        # The real profile uses --top-ports, so this is the exact combination
        # that failed in the live pipeline.
        from backend.core.config import CONFIG_DIR, load_config

        shipped = load_config(CONFIG_DIR)
        argv = build_argv(
            shipped.scan_profiles["service_detect"],
            parse_target("192.168.56.10"),
            OUT,
            ports=[21],
        )
        assert not any(a.startswith("--top-ports") for a in argv)
        assert argv[argv.index("-p") + 1] == "21"
        assert "-sV" in argv


class TestRunnerControlledArguments:
    @pytest.mark.parametrize("arg", ["-oX", "-oN", "-oG", "-oA", "-iL"])
    def test_profile_cannot_set_runner_owned_arguments(self, arg: str) -> None:
        with pytest.raises(NmapError, match="controlled by the runner"):
            build_argv(profile("-sT", arg), parse_target("192.168.56.10"), OUT)

    def test_profile_may_declare_an_explicit_port_set(self) -> None:
        # --top-ports is unusable here: Nmap excludes 6379/tcp even at
        # --top-ports 2000, so profiles must be able to enumerate ports.
        argv = build_argv(
            profile("-sT", "-p", "21,6379,8080"), parse_target("192.168.56.10"), OUT
        )
        assert argv[argv.index("-p") + 1] == "21,6379,8080"

    def test_caller_ports_override_a_profile_port_set(self) -> None:
        argv = build_argv(
            profile("-sT", "-p", "21,6379,8080"),
            parse_target("192.168.56.10"),
            OUT,
            ports=[21],
        )
        # Exactly one -p, carrying the caller's list.
        assert argv.count("-p") == 1
        assert argv[argv.index("-p") + 1] == "21"

    def test_equals_form_is_also_caught(self) -> None:
        with pytest.raises(NmapError, match="controlled by the runner"):
            build_argv(profile("-sT", "-oX=/tmp/evil.xml"), parse_target("10.0.0.1"), OUT)


class TestProfileSafetyAtConfigLoad:
    """Intrusive options are rejected when the profile is loaded, not at run time."""

    def test_aggressive_timing_is_rejected(self, tmp_path) -> None:
        from backend.core.config import ConfigError, load_config
        from tests.conftest import write_config_dir

        bad = """
profiles:
  service_detect:
    args: ["-sT", "-T5"]
    timeout_seconds: 600
default_profile: service_detect
global_max_timeout_seconds: 7200
"""
        directory = write_config_dir(tmp_path / "config", **{"scan_profiles.yaml": bad})
        with pytest.raises(ConfigError, match="forbidden"):
            load_config(directory)

    @pytest.mark.parametrize("category", ["vuln", "exploit", "brute", "dos"])
    def test_intrusive_nse_categories_are_rejected(self, tmp_path, category: str) -> None:
        from backend.core.config import ConfigError, load_config
        from tests.conftest import write_config_dir

        bad = f"""
profiles:
  service_detect:
    args: ["-sT", "--script={category}"]
    timeout_seconds: 600
default_profile: service_detect
global_max_timeout_seconds: 7200
"""
        directory = write_config_dir(tmp_path / "config", **{"scan_profiles.yaml": bad})
        with pytest.raises(ConfigError, match=category):
            load_config(directory)

    def test_timeout_above_global_cap_is_rejected(self, tmp_path) -> None:
        from backend.core.config import ConfigError, load_config
        from tests.conftest import write_config_dir

        bad = """
profiles:
  service_detect:
    args: ["-sT"]
    timeout_seconds: 99999
default_profile: service_detect
global_max_timeout_seconds: 7200
"""
        directory = write_config_dir(tmp_path / "config", **{"scan_profiles.yaml": bad})
        with pytest.raises(ConfigError, match="exceeds"):
            load_config(directory)


class TestShippedProfiles:
    """The profiles actually shipped in config/ must be safe and unprivileged."""

    @pytest.fixture
    def shipped(self):
        from backend.core.config import CONFIG_DIR, load_config

        return load_config(CONFIG_DIR)

    def test_all_profiles_load(self, shipped) -> None:
        assert "discovery" in shipped.scan_profiles
        assert "service_detect" in shipped.scan_profiles
        assert "verify_port" in shipped.scan_profiles

    def test_no_profile_uses_a_root_only_scan_type(self, shipped) -> None:
        # -sS/-sU/-sA need raw sockets. Assessment must run without root.
        for prof in shipped.scan_profiles.values():
            assert "-sS" not in prof.args, prof.name
            assert "-sU" not in prof.args, prof.name

    def test_no_profile_uses_root_only_host_probes(self, shipped) -> None:
        for prof in shipped.scan_profiles.values():
            assert "-PR" not in prof.args, prof.name
            assert "-PE" not in prof.args, prof.name

    def test_no_profile_requests_scripts(self, shipped) -> None:
        for prof in shipped.scan_profiles.values():
            assert not any(a.startswith("--script") for a in prof.args), prof.name
