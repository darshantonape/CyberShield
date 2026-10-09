"""SSH management channel to authorized laboratory targets.

The only way CyberShield reaches a target to change firewall state. There is
deliberately no local-execution path anywhere in this package: the macOS host
cannot be a remediation target because no code exists that could make it one.

Key-based authentication only. Passwords are never accepted, never prompted
for, and never stored — a lab target with a guessable password is a liability
even on an isolated network.

Commands are built from validated integers and fixed literals by the firewall
backends, then quoted with `shlex.quote` before transport. SSH necessarily
transports a command *string*, so quoting is the boundary that argv arrays
provide locally; the argv form is retained for the audit record.
"""

from __future__ import annotations

import shlex
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import paramiko

from backend.core.validation import validate_hostname, validate_port

__all__ = ["SshError", "SshResult", "SshTarget", "SshSession", "connect"]


class SshError(Exception):
    """Raised when the management channel cannot be established or used.

    `kind` classifies WHY, so the operator interface and the audit record can
    distinguish the cases without matching on paramiko's wording, which is not
    a stable interface. The message text is unchanged by this classification.

        "auth"      the key was rejected — wrong key, wrong user, key not
                    installed on the target
        "timeout"   the target accepted nothing within the timeout
        "connect"   no connection could be made — refused, no route, host down
        "config"    CyberShield's own configuration is incomplete (no key
                    configured, key file missing). Nothing was contacted.
        "command"   the channel opened but the command could not be run
    """

    def __init__(self, message: str, *, kind: str = "connect") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class SshTarget:
    host: str
    port: int = 22
    username: str = "root"
    key_path: Path | None = None
    timeout: float = 15.0

    def validated(self) -> "SshTarget":
        return SshTarget(
            host=validate_hostname(self.host),
            port=validate_port(self.port),
            username=self.username,
            key_path=self.key_path,
            timeout=self.timeout,
        )


@dataclass(frozen=True)
class SshResult:
    argv: tuple[str, ...]
    command: str
    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0

    def summary(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "exit_status": self.exit_status,
            "stdout": self.stdout.strip()[:2000],
            "stderr": self.stderr.strip()[:2000],
        }


class SshSession:
    """An open SSH connection to one authorized target."""

    def __init__(self, client: paramiko.SSHClient, target: SshTarget) -> None:
        self._client = client
        self.target = target

    def run(self, argv: Sequence[str], *, timeout: float = 30.0) -> SshResult:
        """Run one command given as an argv sequence.

        Raises:
            SshError: on transport failure. A non-zero exit status is returned
                in the result, not raised — callers interpret it.
        """
        if isinstance(argv, (str, bytes)):
            raise SshError(
                "argv must be a sequence of separate arguments, not a string."
            )
        args = list(argv)
        if not args:
            raise SshError("argv is empty.")
        if not all(isinstance(a, str) for a in args):
            raise SshError(f"All arguments must be strings, got {args!r}")
        for arg in args:
            if "\x00" in arg:
                raise SshError("Arguments must not contain NUL bytes.")

        command = " ".join(shlex.quote(a) for a in args)

        try:
            _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            status = stdout.channel.recv_exit_status()
        except Exception as exc:  # noqa: BLE001 - paramiko raises many types
            raise SshError(
                f"SSH command failed on {self.target.host}: {exc}", kind="command"
            ) from exc

        return SshResult(
            argv=tuple(args),
            command=command,
            exit_status=status,
            stdout=out,
            stderr=err,
        )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 - closing must never raise
            pass


def _classify(exc: BaseException) -> str:
    """Map a paramiko/socket exception to an SshError kind.

    Classified by exception TYPE, not message text: paramiko's wording differs
    between versions and platforms, and an operator-facing state should not
    depend on it. Observed against the laboratory on 2026-09-20 — a wrong
    username raises AuthenticationException, a closed port and an unroutable
    address both raise NoValidConnectionsError.
    """
    if isinstance(exc, paramiko.AuthenticationException):
        return "auth"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    # paramiko reports a banner or negotiation timeout as a plain SSHException;
    # its message is the only signal available for that one case.
    if isinstance(exc, paramiko.SSHException) and "timed out" in str(exc).lower():
        return "timeout"
    return "connect"


@contextmanager
def connect(target: SshTarget) -> Iterator[SshSession]:
    """Open a key-authenticated SSH session to an authorized target."""
    checked = target.validated()

    if checked.key_path is None:
        raise SshError(
            "No SSH key configured. Set CYBERSHIELD_SSH_KEY_PATH in .env. "
            "Password authentication is not supported.",
            kind="config",
        )
    key_file = Path(checked.key_path).expanduser()
    if not key_file.exists():
        raise SshError(f"SSH key not found: {key_file}", kind="config")

    client = paramiko.SSHClient()
    # AutoAddPolicy is acceptable ONLY because targets are ephemeral lab
    # containers on an isolated network whose host keys are regenerated on every
    # rebuild. It would be wrong on a durable host, where a changed key should
    # abort the connection. Recorded as a limitation in docs.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=checked.host,
            port=checked.port,
            username=checked.username,
            key_filename=str(key_file),
            timeout=checked.timeout,
            auth_timeout=checked.timeout,
            banner_timeout=checked.timeout,
            allow_agent=False,
            look_for_keys=False,  # only the configured key, never ambient ones
        )
    except Exception as exc:  # noqa: BLE001
        client.close()
        raise SshError(
            f"Could not open the management channel to "
            f"{checked.username}@{checked.host}:{checked.port}: {exc}",
            kind=_classify(exc),
        ) from exc

    session = SshSession(client, checked)
    try:
        yield session
    finally:
        session.close()
