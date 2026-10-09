"""Dry-run backend — the default.

Renders exactly the commands the nftables backend would run, and executes none
of them. Live enforcement has to be turned on deliberately by setting
CYBERSHIELD_REMEDIATION_BACKEND, so a misconfigured or exploratory run cannot
change a target's firewall state by accident.

It subclasses NftablesBackend rather than reimplementing the command strings:
if the two diverged, a dry-run preview would stop predicting what a live run
would actually do, which is the only reason the preview is worth anything.
"""

from __future__ import annotations

from typing import Any

from backend.core.validation import validate_port
from backend.remediation.backends.base import PortState
from backend.remediation.backends.nftables import NftablesBackend
from backend.remediation.ssh_adapter import SshSession

__all__ = ["DryRunBackend"]


class DryRunBackend(NftablesBackend):
    name = "dryrun"
    executes = False

    def ensure_prepared(self, session: SshSession) -> list[dict[str, Any]]:
        """Report what preparation would run. Contacts nothing."""
        return [
            {"dry_run": True, "would_run": argv}
            for argv in (
                ["nft", "add", "table", "inet", "cybershield"],
                ["nft", "add", "set", "inet", "cybershield", "blocked_tcp",
                 "{ type inet_service ; }"],
                ["nft", "add", "chain", "inet", "cybershield", "input",
                 "{ type filter hook input priority 0 ; policy accept ; }"],
                ["nft", "add", "rule", "inet", "cybershield", "input",
                 "tcp", "dport", "@blocked_tcp", "drop"],
            )
        ]

    def read_state(self, session: SshSession, port: int, proto: str = "tcp") -> PortState:
        """Always reports 'not blocked': dry run never changes anything.

        Reported honestly rather than echoing the requested state back, so a
        dry-run verification cannot be mistaken for evidence of isolation.
        """
        return PortState(
            port=validate_port(port),
            proto=proto,
            blocked=False,
            raw="dry-run: target not contacted; no firewall state was read or changed",
        )
