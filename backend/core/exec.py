"""The single subprocess entry point for the whole system.

Rules enforced here, so no caller has to remember them:

  * argv arrays only — `shell=False` is hardcoded and cannot be overridden
  * every command carries a mandatory timeout
  * stdout and stderr are always captured and returned
  * the executable is resolved to an absolute path before execution
  * the invocation and its outcome are returned as a structured record

Nothing in CyberShield calls `subprocess` directly. That keeps the audit story
simple: every external process the tool runs came through `run_command`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

__all__ = [
    "CommandError",
    "CommandResult",
    "run_command",
    "resolve_executable",
]


class CommandError(Exception):
    """Raised when a command cannot be constructed or executed at all.

    A command that runs and exits non-zero is NOT an error here — that is a
    normal `CommandResult` with `returncode != 0`, which callers interpret.
    """


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    # Populated by callers that need the raw output preserved on disk.
    artifact_path: Path | None = field(default=None)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def command_string(self) -> str:
        """Human-readable rendering **for logs and reports only**.

        This is never executed. Execution always uses the argv tuple.
        """
        return " ".join(self.argv)

    def summary(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
        }


def resolve_executable(name: str) -> str:
    """Resolve a program name to an absolute path.

    Resolving up front means the audit log records exactly which binary ran, and
    a missing tool fails with a clear message instead of an opaque OSError.
    """
    if not name or not isinstance(name, str):
        raise CommandError(f"Invalid executable name: {name!r}")

    candidate = Path(name)
    if candidate.is_absolute():
        if not candidate.exists():
            raise CommandError(f"Executable not found: {name}")
        return str(candidate)

    found = shutil.which(name)
    if not found:
        raise CommandError(
            f"Executable {name!r} not found on PATH. "
            f"If this is nmap, install it with: brew install nmap"
        )
    return found


def run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command safely and return a structured result.

    Args:
        argv: Program and arguments as separate list items. A single string is
            rejected — that is the shape that invites shell-injection bugs.
        timeout_seconds: Required. Must be positive.

    Raises:
        CommandError: if argv is malformed or the program cannot be launched.
    """
    if isinstance(argv, (str, bytes)):
        raise CommandError(
            "argv must be a sequence of separate arguments, not a single string. "
            "Passing a string is how shell-injection bugs happen."
        )

    args = list(argv)
    if not args:
        raise CommandError("argv is empty.")

    if not all(isinstance(a, str) for a in args):
        bad = [a for a in args if not isinstance(a, str)]
        raise CommandError(f"All arguments must be strings. Offending values: {bad!r}")

    # NUL bytes terminate C strings and can truncate an argument mid-way,
    # changing the command's meaning.
    for arg in args:
        if "\x00" in arg:
            raise CommandError("Arguments must not contain NUL bytes.")

    if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
        raise CommandError(f"timeout_seconds must be a positive integer, got {timeout_seconds!r}")

    args[0] = resolve_executable(args[0])

    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - shell=False, argv validated above
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(cwd) if cwd else None,
            env=env,
            input=input_text,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=tuple(args),
            returncode=-1,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr),
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except OSError as exc:
        raise CommandError(f"Failed to execute {args[0]!r}: {exc}") from exc

    return CommandResult(
        argv=tuple(args),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration_seconds=time.monotonic() - started,
        timed_out=False,
    )


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
