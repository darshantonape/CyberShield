"""Firewall backend interface.

A backend translates "isolate tcp/21 on this target" into concrete commands,
and — critically — into an exact inverse that is known *before* the forward
command runs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from backend.remediation.ssh_adapter import SshSession

__all__ = ["FirewallBackend", "BackendError", "PortState"]


class BackendError(Exception):
    """Raised when a firewall operation cannot be performed on the target."""


@dataclass(frozen=True)
class PortState:
    """What the backend believes about a port, read back from the target."""

    port: int
    proto: str
    blocked: bool
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "proto": self.proto,
            "blocked_by_cybershield": self.blocked,
            "raw": self.raw.strip()[:1000],
        }


class FirewallBackend(ABC):
    """Contract every backend must satisfy."""

    #: Identifier stored on the remediation record.
    name: str = "abstract"
    #: False for dry-run, which renders commands but changes nothing.
    executes: bool = True

    @abstractmethod
    def ensure_prepared(self, session: SshSession) -> list[dict[str, Any]]:
        """Idempotently create the structures CyberShield owns on the target."""

    @abstractmethod
    def apply_argv(self, port: int, proto: str) -> list[str]:
        """Command that isolates the port."""

    @abstractmethod
    def rollback_argv(self, port: int, proto: str) -> list[str]:
        """Exact inverse of `apply_argv`. Must be derivable without running it."""

    @abstractmethod
    def read_state(self, session: SshSession, port: int, proto: str) -> PortState:
        """Read back whether CyberShield is currently blocking this port."""
