"""Management-channel status reporting.

The properties that matter: no key material escapes, and the channel test
cannot be pointed at an arbitrary host.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.core.authorization import AuthorizationDenied
from backend.core.config import load_config
from backend.remediation.ssh_status import PROBE_ARGV, describe_channels, probe_channel


@pytest.fixture
def config_with_key(tmp_path: Path, config_dir: Path, monkeypatch):
    """Config whose SSH key exists on disk with sane permissions."""
    key = tmp_path / "lab_key"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n")
    key.chmod(0o600)
    monkeypatch.setenv("CYBERSHIELD_SSH_KEY_PATH", str(key))
    return load_config(config_dir), key


class TestDescribeChannels:
    def test_lab_and_non_lab_are_distinguished(self, config_with_key) -> None:
        config, _ = config_with_key
        rows = {c.name: c for c in describe_channels(config)}

        assert rows["lab-net"].is_lab is True
        assert rows["lab-net"].user == "labadmin"
        assert rows["lab-net"].configured is True

        assert rows["assessment-only-net"].is_lab is False
        assert rows["assessment-only-net"].configured is False
        assert any("assessment-only" in p for p in rows["assessment-only-net"].problems)

    def test_no_key_material_is_returned(self, config_with_key) -> None:
        config, key = config_with_key
        payload = str([c.to_dict() for c in describe_channels(config)])
        # The path is reported; the contents never are.
        assert str(key) in payload
        assert "SECRETKEYMATERIAL" not in payload
        assert "BEGIN OPENSSH PRIVATE KEY" not in payload

    def test_missing_key_is_reported_as_a_problem(self, config_dir, monkeypatch) -> None:
        monkeypatch.setenv("CYBERSHIELD_SSH_KEY_PATH", "/nonexistent/key")
        config = load_config(config_dir)
        lab = next(c for c in describe_channels(config) if c.is_lab)
        assert lab.key_present is False
        assert lab.configured is False
        assert any("does not exist" in p for p in lab.problems)

    def test_world_readable_key_is_flagged(self, tmp_path, config_dir, monkeypatch) -> None:
        key = tmp_path / "loose_key"
        key.write_text("x")
        key.chmod(0o644)
        monkeypatch.setenv("CYBERSHIELD_SSH_KEY_PATH", str(key))
        config = load_config(config_dir)
        lab = next(c for c in describe_channels(config) if c.is_lab)
        assert lab.key_too_open is True
        assert lab.configured is False
        assert any("chmod 600" in p for p in lab.problems)


class TestChannelTestIsScoped:
    """The test action reuses the remediation gate; it cannot roam."""

    def test_out_of_scope_address_is_refused(
        self, config_with_key, signed_authorization, tmp_path
    ) -> None:
        config, _ = config_with_key
        with pytest.raises(AuthorizationDenied):
            probe_channel(config, "8.8.8.8", audit_path=tmp_path / "a.jsonl")

    def test_in_scope_but_non_lab_address_is_refused(
        self, config_with_key, signed_authorization, tmp_path
    ) -> None:
        config, _ = config_with_key
        # 10.10.0.0/24 is authorized for assessment only.
        with pytest.raises(AuthorizationDenied, match="is_lab"):
            probe_channel(config, "10.10.0.5", audit_path=tmp_path / "a.jsonl")

    def test_probe_command_is_a_fixed_literal(self) -> None:
        # No parameter feeds this, so nothing operator-supplied can be run.
        assert PROBE_ARGV == ["true"]

    def test_unreachable_lab_host_reports_failure_and_audits(
        self, config_with_key, signed_authorization, tmp_path
    ) -> None:
        from backend.core.audit import AuditLog

        config, _ = config_with_key
        audit = tmp_path / "a.jsonl"
        # 192.168.56.10 is an authorized lab address with nothing listening.
        status = probe_channel(config, "192.168.56.10", actor="tester", audit_path=audit)

        assert status.reachable is False
        assert status.detail
        # The failure names host/port/user, never the key.
        assert "SECRETKEYMATERIAL" not in status.detail

        entries = AuditLog(audit).entries()
        assert entries[-1].action == "ssh.test"
        assert entries[-1].outcome == "failure"
        assert entries[-1].actor == "tester"
        assert "SECRETKEYMATERIAL" not in audit.read_text()


class TestFailureModesAreDistinguished:
    """success / auth failure / timeout / connection failure must be separable.

    They were distinguishable only by paramiko's message text, which is not a
    stable interface — a version bump could silently change what the operator
    sees and what a test matches on. `SshError.kind` classifies by exception
    TYPE instead. Types confirmed against the live laboratory on 2026-09-20.
    """

    import pytest as _pytest

    def _target(self, tmp_path):
        from backend.remediation.ssh_adapter import SshTarget

        key = tmp_path / "id_ed25519"
        key.write_text("not a real key")
        key.chmod(0o600)
        return SshTarget(host="192.0.2.10", port=22, username="root", key_path=key)

    @_pytest.mark.parametrize(
        "exc,expected",
        [
            (__import__("paramiko").AuthenticationException("Authentication failed."), "auth"),
            (__import__("socket").timeout("timed out"), "timeout"),
            (TimeoutError("timed out"), "timeout"),
            (__import__("paramiko").SSHException("Timed out opening banner"), "timeout"),
            (__import__("paramiko").ssh_exception.NoValidConnectionsError(
                {("192.0.2.10", 22): OSError("refused")}), "connect"),
            (OSError("no route to host"), "connect"),
        ],
    )
    def test_each_failure_is_classified(self, tmp_path, monkeypatch, exc, expected) -> None:
        import paramiko

        from backend.remediation.ssh_adapter import SshError, connect

        def boom(*args, **kwargs):
            raise exc

        monkeypatch.setattr(paramiko.SSHClient, "connect", boom)
        with self._pytest.raises(SshError) as caught:
            with connect(self._target(tmp_path)):
                pass
        assert caught.value.kind == expected

    def test_a_missing_key_is_a_configuration_problem_not_a_network_one(self, tmp_path) -> None:
        from backend.remediation.ssh_adapter import SshError, SshTarget, connect

        target = SshTarget(
            host="192.0.2.10", port=22, username="root", key_path=tmp_path / "absent"
        )
        with self._pytest.raises(SshError) as caught:
            with connect(target):
                pass
        assert caught.value.kind == "config"

    def test_no_key_configured_is_a_configuration_problem(self) -> None:
        from backend.remediation.ssh_adapter import SshError, SshTarget, connect

        target = SshTarget(host="192.0.2.10", port=22, username="root", key_path=None)
        with self._pytest.raises(SshError) as caught:
            with connect(target):
                pass
        assert caught.value.kind == "config"
        assert "Password authentication is not supported" in str(caught.value)

    def test_the_classification_never_carries_key_material(self, tmp_path, monkeypatch) -> None:
        import paramiko

        from backend.remediation.ssh_adapter import SshError, connect

        key = tmp_path / "id_ed25519"
        key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETMATERIAL\n")
        key.chmod(0o600)
        from backend.remediation.ssh_adapter import SshTarget

        def boom(*args, **kwargs):
            raise paramiko.AuthenticationException("Authentication failed.")

        monkeypatch.setattr(paramiko.SSHClient, "connect", boom)
        with self._pytest.raises(SshError) as caught:
            with connect(SshTarget(host="192.0.2.10", port=22, username="root", key_path=key)):
                pass
        assert "SECRETMATERIAL" not in str(caught.value)
        assert "BEGIN OPENSSH" not in str(caught.value)


class TestNoArbitraryCommandCanBeRun:
    """The probe runs one fixed literal. There is no parameter for a command."""

    def test_probe_argv_is_a_fixed_harmless_literal(self) -> None:
        from backend.remediation.ssh_status import PROBE_ARGV

        assert PROBE_ARGV == ["true"]

    def test_probe_channel_takes_no_command_parameter(self) -> None:
        import inspect

        from backend.remediation.ssh_status import probe_channel

        params = set(inspect.signature(probe_channel).parameters)
        assert params == {"config", "address", "actor", "audit_path"}
        assert not params & {"command", "argv", "cmd", "shell"}

    def test_a_command_string_is_refused_by_the_session(self) -> None:
        import pytest

        from backend.remediation.ssh_adapter import SshError, SshSession, SshTarget

        session = SshSession(client=None, target=SshTarget(host="192.0.2.10"))
        with pytest.raises(SshError, match="not a string"):
            session.run("nft flush ruleset; rm -rf /")

    def test_nul_bytes_are_refused_by_the_session(self) -> None:
        import pytest

        from backend.remediation.ssh_adapter import SshError, SshSession, SshTarget

        session = SshSession(client=None, target=SshTarget(host="192.0.2.10"))
        with pytest.raises(SshError, match="NUL"):
            session.run(["true", "a\x00b"])
