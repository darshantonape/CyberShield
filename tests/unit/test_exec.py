"""Safe command execution (spec §6, command-injection resistance)."""

from __future__ import annotations

import pytest

from backend.core.exec import CommandError, resolve_executable, run_command


class TestArgumentSafety:
    def test_rejects_a_single_string_command(self) -> None:
        # The shape that invites shell injection.
        with pytest.raises(CommandError, match="not a single string"):
            run_command("echo hello", timeout_seconds=5)  # type: ignore[arg-type]

    def test_rejects_empty_argv(self) -> None:
        with pytest.raises(CommandError, match="empty"):
            run_command([], timeout_seconds=5)

    def test_rejects_non_string_arguments(self) -> None:
        with pytest.raises(CommandError, match="strings"):
            run_command(["echo", 42], timeout_seconds=5)  # type: ignore[list-item]

    def test_rejects_nul_bytes(self) -> None:
        with pytest.raises(CommandError, match="NUL"):
            run_command(["echo", "a\x00b"], timeout_seconds=5)

    def test_shell_metacharacters_are_inert(self) -> None:
        # With shell=False these are literal text, not a command separator.
        result = run_command(["echo", "hello; rm -rf /"], timeout_seconds=10)
        assert result.ok
        assert result.stdout.strip() == "hello; rm -rf /"

    def test_backticks_and_expansion_are_inert(self) -> None:
        payload = "$(whoami) `id` && echo pwned"
        result = run_command(["echo", payload], timeout_seconds=10)
        assert result.stdout.strip() == payload


class TestTimeout:
    def test_timeout_is_mandatory_and_positive(self) -> None:
        with pytest.raises(CommandError, match="positive integer"):
            run_command(["echo", "x"], timeout_seconds=0)
        with pytest.raises(CommandError, match="positive integer"):
            run_command(["echo", "x"], timeout_seconds=-5)

    def test_timeout_is_enforced(self) -> None:
        result = run_command(["sleep", "10"], timeout_seconds=1)
        assert result.timed_out
        assert not result.ok


class TestResults:
    def test_captures_stdout(self) -> None:
        result = run_command(["echo", "captured"], timeout_seconds=10)
        assert result.ok
        assert "captured" in result.stdout

    def test_captures_nonzero_exit_without_raising(self) -> None:
        # A non-zero exit is data for the caller, not an exception.
        result = run_command(["false"], timeout_seconds=10)
        assert result.returncode != 0
        assert not result.ok

    def test_records_absolute_executable_path(self) -> None:
        result = run_command(["echo", "x"], timeout_seconds=10)
        assert result.argv[0].startswith("/")

    def test_summary_is_serialisable(self) -> None:
        summary = run_command(["echo", "x"], timeout_seconds=10).summary()
        assert summary["returncode"] == 0
        assert summary["timed_out"] is False


class TestResolveExecutable:
    def test_resolves_on_path(self) -> None:
        assert resolve_executable("echo").startswith("/")

    def test_missing_executable_raises(self) -> None:
        with pytest.raises(CommandError, match="not found"):
            resolve_executable("definitely-not-a-real-binary-xyz")

    def test_missing_nmap_message_is_actionable(self) -> None:
        try:
            resolve_executable("nmap")
        except CommandError as exc:
            assert "brew install nmap" in str(exc)
