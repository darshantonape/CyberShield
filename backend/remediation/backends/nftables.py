"""nftables backend.

Design: CyberShield owns exactly one table, one chain, one rule and one named
set on the target:

    table inet cybershield {
        set blocked_tcp { type inet_service ; }
        chain input {
            type filter hook input priority 0 ; policy accept ;
            tcp dport @blocked_tcp drop
        }
    }

Isolation adds a port to the set; rollback removes it:

    apply     nft add element    inet cybershield blocked_tcp { 21 }
    rollback  nft delete element inet cybershield blocked_tcp { 21 }

Why a set rather than one rule per port:

  * **Exact inverse, known in advance.** nftables can only delete a rule by
    handle, and handles are assigned at insertion time — so a rule-per-port
    design cannot state its own rollback command before applying it. Set
    elements delete by value, so the inverse is derivable up front, which is
    what makes "rollback stored before apply" achievable rather than aspirational.
  * **Per-port rollback.** Reverting one isolation never disturbs another.
  * **Isolation from pre-existing rules.** Everything lives in a table named
    `cybershield`; no rule outside it is ever read or modified.

The chain policy is `accept`, so the structure blocks nothing until a port is
explicitly added to the set.
"""

from __future__ import annotations

from typing import Any

from backend.core.validation import validate_port, validate_proto
from backend.remediation.backends.base import BackendError, FirewallBackend, PortState
from backend.remediation.ssh_adapter import SshSession

__all__ = ["NftablesBackend", "TABLE", "CHAIN", "SET_TCP"]

TABLE = "cybershield"
CHAIN = "input"
SET_TCP = "blocked_tcp"


class NftablesBackend(FirewallBackend):
    name = "nftables"
    executes = True

    # -- command construction ------------------------------------------------
    # Every element below is a fixed literal or a validated integer, so no
    # caller-controlled text can reach the target's shell.

    def _set_for(self, proto: str) -> str:
        if proto != "tcp":
            raise BackendError(
                f"Only TCP isolation is implemented; got {proto!r}. "
                "The decision engine refuses non-TCP before reaching here."
            )
        return SET_TCP

    def apply_argv(self, port: int, proto: str = "tcp") -> list[str]:
        checked = validate_port(port)
        set_name = self._set_for(validate_proto(proto))
        return ["nft", "add", "element", "inet", TABLE, set_name, f"{{ {checked} }}"]

    def rollback_argv(self, port: int, proto: str = "tcp") -> list[str]:
        checked = validate_port(port)
        set_name = self._set_for(validate_proto(proto))
        return ["nft", "delete", "element", "inet", TABLE, set_name, f"{{ {checked} }}"]

    def list_set_argv(self, proto: str = "tcp") -> list[str]:
        return ["nft", "list", "set", "inet", TABLE, self._set_for(validate_proto(proto))]

    # -- target preparation --------------------------------------------------

    def ensure_prepared(self, session: SshSession) -> list[dict[str, Any]]:
        """Create table, set, chain and the single drop rule, idempotently.

        Safe to call repeatedly: `add` is a no-op when the object exists, and
        the drop rule is only appended when the chain does not already
        reference the set.
        """
        steps: list[dict[str, Any]] = []

        for argv in (
            ["nft", "add", "table", "inet", TABLE],
            ["nft", "add", "set", "inet", TABLE, SET_TCP, "{ type inet_service ; }"],
            [
                "nft", "add", "chain", "inet", TABLE, CHAIN,
                "{ type filter hook input priority 0 ; policy accept ; }",
            ],
        ):
            result = session.run(argv)
            steps.append(result.summary())
            if not result.ok:
                raise BackendError(
                    f"Failed preparing the target: {' '.join(argv)} exited "
                    f"{result.exit_status}: {result.stderr.strip()}"
                )

        # Append the drop rule only if it is not already present, otherwise a
        # repeated prepare would stack duplicate rules.
        listing = session.run(["nft", "list", "chain", "inet", TABLE, CHAIN])
        steps.append(listing.summary())
        if f"@{SET_TCP}" not in listing.stdout:
            argv = [
                "nft", "add", "rule", "inet", TABLE, CHAIN,
                "tcp", "dport", f"@{SET_TCP}", "drop",
            ]
            result = session.run(argv)
            steps.append(result.summary())
            if not result.ok:
                raise BackendError(
                    f"Failed installing the drop rule: exited {result.exit_status}: "
                    f"{result.stderr.strip()}"
                )

        return steps

    # -- state read-back -----------------------------------------------------

    def read_state(self, session: SshSession, port: int, proto: str = "tcp") -> PortState:
        """Ask the target whether this port is currently in the blocked set.

        This is the target's own view of its firewall, independent of the
        rescan. The two are cross-checked during verification: a rule present
        but a port still reachable means the isolation did not take effect.
        """
        checked = validate_port(port)
        result = session.run(self.list_set_argv(proto))
        if not result.ok:
            # A missing set means nothing has ever been blocked here.
            return PortState(port=checked, proto=proto, blocked=False, raw=result.stderr)

        elements = _parse_set_elements(result.stdout)
        return PortState(
            port=checked, proto=proto, blocked=checked in elements, raw=result.stdout
        )


def _parse_set_elements(listing: str) -> set[int]:
    """Extract integer elements from `nft list set` output.

    Output looks like:
        table inet cybershield {
            set blocked_tcp {
                type inet_service
                elements = { 21, 3306 }
            }
        }
    """
    marker = "elements"
    if marker not in listing:
        return set()

    tail = listing.split(marker, 1)[1]
    start = tail.find("{")
    end = tail.find("}", start)
    if start == -1 or end == -1:
        return set()

    found: set[int] = set()
    for token in tail[start + 1 : end].split(","):
        token = token.strip()
        if token.isdigit():
            found.add(int(token))
    return found
