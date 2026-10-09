"""Reachability assessment, kept strictly separate from authorization.

Three states, and the difference between them is the whole point of this module:

    NOT_AUTHORIZED       out of scope. Never probed, whatever its state.
    AUTHORIZED_UNREACHABLE  in scope, but nothing answered.
    AUTHORIZED_REACHABLE    in scope, and something answered.

The failure this prevents: a scan of an authorized-but-offline laptop completes
in two seconds, stores no hosts and no services, and every downstream page then
reads "0 open services, 0 vulnerabilities" — which looks exactly like a clean
bill of health for a machine that was never actually examined. An unreachable
target is therefore recorded as UNREACHABLE and labelled as such everywhere.

Nothing here grants permission. Reachability is measured only for targets that
were already authorized, and a reachable host that is out of scope stays
refused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from backend.scanner.nmap_parser import ParsedScan

__all__ = [
    "REACHABLE",
    "UNREACHABLE",
    "UNKNOWN",
    "Reachability",
    "assess_scan",
    "LAN_UNREACHABLE_CAUSES",
]

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNKNOWN = "unknown"

# Shown to the operator whenever an authorized target does not answer. These are
# the ordinary causes on a real Wi-Fi network, in rough order of likelihood.
# Presented as possibilities to check, never as a diagnosis: CyberShield cannot
# tell a firewalled host from an absent one from the outside.
LAN_UNREACHABLE_CAUSES: tuple[str, ...] = (
    "The device is asleep, powered off, or has left the network.",
    "A host firewall is dropping inbound connections — this is the default on "
    "Windows, and common on macOS. The device is online but answers nothing.",
    "The Wi-Fi access point has client isolation (AP isolation) enabled, which "
    "blocks all device-to-device traffic regardless of firewalls.",
    "ICMP is filtered. CyberShield never relies on ping alone, but a device that "
    "also refuses TCP will look identical to an absent one.",
    "The address is on a different subnet from this machine, so packets never "
    "reach it. Check the Targets page for the subnet this machine is on.",
    "The device has a new address — DHCP leases move. Re-check its current IP.",
    "Nothing is listening on any port this profile probes. The device is "
    "reachable but exposes no service the scan looks for.",
)


@dataclass(frozen=True)
class Reachability:
    """Verdict for one scan's target, derived from the Nmap results."""

    state: str
    hosts_up: int
    hosts_responding: int
    open_ports: int
    note: str
    possible_causes: tuple[str, ...] = field(default=())

    @property
    def is_reachable(self) -> bool:
        return self.state == REACHABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "hosts_up": self.hosts_up,
            "hosts_responding": self.hosts_responding,
            "open_ports": self.open_ports,
            "note": self.note,
            "possible_causes": list(self.possible_causes),
        }


def assess_scan(parsed: ParsedScan, *, target_spec: str, used_pn: bool) -> Reachability:
    """Decide whether the scanned target actually answered.

    Args:
        used_pn: True when the profile passed `-Pn`. This changes the meaning of
            Nmap's host state completely: with `-Pn`, EVERY address is reported
            "up" whether or not anything is there, so host state carries no
            information and only port evidence counts.
    """
    hosts_up = len(parsed.hosts_up)
    open_ports = parsed.total_open_services

    # A host that answered any probe — with SYN/ACK (open) or RST (closed) —
    # produced evidence that packets reached it. "filtered" is the absence of
    # an answer, so it does not count.
    #
    # ParsedHost.responded reads BOTH the explicit <port> elements and the
    # <extraports> summary. That second half matters: Nmap collapses ports
    # sharing one uninteresting state into a single count and emits no <port>
    # element for them, so a host that refused all 44 probed ports arrives here
    # with an empty `services` tuple — identical, without extraports, to a host
    # that never answered at all.
    responding = sum(1 for host in parsed.hosts if host.responded)
    closed_ports = sum(host.closed_port_count for host in parsed.hosts)

    if parsed.recovered_from_truncation:
        return Reachability(
            state=UNKNOWN,
            hosts_up=hosts_up,
            hosts_responding=responding,
            open_ports=open_ports,
            note=(
                f"Nmap output for {target_spec} was truncated and only partially "
                "recovered, so reachability cannot be stated. Re-run the scan."
            ),
        )

    if open_ports or responding:
        detail = f"{open_ports} open port(s)" if open_ports else "no open ports"
        closed_note = (
            f" {closed_ports} probed port(s) answered with a refusal, which is "
            "how the host proved it is there."
            if not open_ports and closed_ports
            else ""
        )
        return Reachability(
            state=REACHABLE,
            hosts_up=hosts_up,
            hosts_responding=responding,
            open_ports=open_ports,
            note=(
                f"{target_spec} answered: {responding} host(s) responded to a TCP "
                f"probe, {detail} found."
                + closed_note
                + (
                    ""
                    if open_ports
                    else " The host is reachable but exposes none of the ports this "
                    "profile probes. That is not the same as having no "
                    "vulnerabilities."
                )
            ),
        )

    if used_pn and not responding:
        return Reachability(
            state=UNREACHABLE,
            hosts_up=hosts_up,
            hosts_responding=0,
            open_ports=0,
            note=(
                f"{target_spec} is authorized but did not answer any probe. Host "
                "discovery was skipped (-Pn) and every probed port was filtered, "
                "so no packet was acknowledged. Nothing was learned about this "
                "target — this is NOT a clean result."
            ),
            possible_causes=LAN_UNREACHABLE_CAUSES,
        )

    if hosts_up and not responding:
        # Discovery-only scans land here: the host answered a ping probe but no
        # ports were scanned.
        return Reachability(
            state=REACHABLE,
            hosts_up=hosts_up,
            hosts_responding=hosts_up,
            open_ports=0,
            note=(
                f"{hosts_up} host(s) in {target_spec} answered host discovery. No "
                "ports were scanned by this profile, so nothing is known about "
                "their exposed services yet."
            ),
        )

    return Reachability(
        state=UNREACHABLE,
        hosts_up=0,
        hosts_responding=0,
        open_ports=0,
        note=(
            f"{target_spec} is authorized but unreachable: no host in the range "
            "answered any probe. No conclusion can be drawn about its services "
            "or its vulnerabilities."
        ),
        possible_causes=LAN_UNREACHABLE_CAUSES,
    )
