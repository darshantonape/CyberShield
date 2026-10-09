"""Local network interface discovery.

Purpose: show the operator which private subnet this machine is actually on, so
they can authorize the right range instead of guessing. Different Wi-Fi networks
use different subnets — 192.168.0.0/24, 192.168.1.0/24, 10.0.0.0/24 — so no
subnet is ever hardcoded or assumed.

This module only *reports*. It authorizes nothing. Detecting a subnet has no
effect on scope: the operator must still add a range explicitly and confirm it
(see `backend.core.scope_admin`). A reachable network is not an authorized one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from backend.core.exec import CommandError, run_command

__all__ = ["LocalInterface", "detect_local_interfaces", "default_interface_name"]

# macOS `ifconfig` output. Windows/Linux hosts are out of scope for this project
# (the tool is developed and run on macOS), but the parser degrades to an empty
# list rather than raising if the format is unrecognised.
# The flags value is HEX and not always digits-only ('flags=8a63<UP,...>' on a
# bridge interface). A \d+ pattern silently fails to match those headers, and
# the following `inet` line is then attributed to the previous interface — which
# mislabelled the lab bridge as the VM's ethernet device.
_IFACE_HEADER = re.compile(
    r"^(?P<name>[a-zA-Z0-9._]+):\s+flags=(?P<flags>[0-9a-fA-F]+)<(?P<names>[^>]*)>"
)
_INET_LINE = re.compile(
    r"^\s+inet (?P<addr>\d+\.\d+\.\d+\.\d+)"
    r"(?:\s+netmask\s+(?P<mask>0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+))?"
)

# Interfaces that are never a useful scan vantage point. awdl/llw are Apple
# peer-to-peer links, utun* are VPN tunnels, and bridge/vmenet carry the local
# virtualisation networks (the lab bridge is offered separately, by name).
_UNINTERESTING_PREFIXES = ("awdl", "llw", "utun", "gif", "stf", "ap")


@dataclass(frozen=True)
class LocalInterface:
    """One IPv4 address configured on a local interface."""

    name: str
    address: str
    netmask: str
    cidr: str
    is_private: bool
    is_loopback: bool
    is_default_route: bool
    description: str

    @property
    def host_cidr(self) -> str:
        """The interface's own address as a /32."""
        return f"{self.address}/32"

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.name,
            "address": self.address,
            "netmask": self.netmask,
            "cidr": self.cidr,
            "is_private": self.is_private,
            "is_loopback": self.is_loopback,
            "is_default_route": self.is_default_route,
            "description": self.description,
        }


def _mask_to_prefix(mask: str | None) -> int:
    """Convert a netmask to a prefix length. Defaults to /24 when absent.

    macOS renders the mask in hex (`netmask 0xffffff00`); other platforms use
    dotted quad. Both are handled.
    """
    if not mask:
        return 24
    try:
        if mask.startswith("0x"):
            value = int(mask, 16)
            return bin(value).count("1")
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except (ValueError, ipaddress.AddressValueError):
        return 24


def default_interface_name() -> str | None:
    """Interface carrying the default route, e.g. 'en0'. None if undetermined."""
    try:
        result = run_command(["route", "-n", "get", "default"], timeout_seconds=10)
    except CommandError:
        return None
    if not result.ok:
        return None
    match = re.search(r"^\s*interface:\s*(\S+)", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def _describe(name: str, network: ipaddress.IPv4Network, is_default: bool) -> str:
    if network.is_loopback:
        return "Loopback — this machine only."
    if is_default:
        return (
            "Primary network for this machine (default route). This is the "
            "Wi-Fi or Ethernet LAN your other devices are on."
        )
    if name.startswith("bridge") or name.startswith("vmenet"):
        return "Virtualisation bridge — the local VM/container network."
    return "Additional local interface."


def detect_local_interfaces(*, include_loopback: bool = False) -> list[LocalInterface]:
    """List private IPv4 addresses configured on this machine.

    Public addresses are excluded: this list feeds a UI that suggests ranges to
    authorize, and suggesting a routable range would be exactly the wrong thing
    to put in front of an operator.

    Returns an empty list rather than raising if `ifconfig` is unavailable, so a
    detection failure degrades to "type the range yourself".
    """
    try:
        result = run_command(["ifconfig"], timeout_seconds=15)
    except CommandError:
        return []
    if not result.ok:
        return []

    default_iface = default_interface_name()

    interfaces: list[LocalInterface] = []
    current: str | None = None
    is_up = False

    for line in result.stdout.splitlines():
        header = _IFACE_HEADER.match(line)
        if header:
            current = header.group("name")
            is_up = "UP" in header.group("names").split(",")
            continue

        if current is None or not is_up:
            continue
        if current.startswith(_UNINTERESTING_PREFIXES):
            continue

        inet = _INET_LINE.match(line)
        if not inet:
            continue

        address = inet.group("addr")
        prefix = _mask_to_prefix(inet.group("mask"))
        try:
            network = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
        except ValueError:
            continue

        if not network.is_private:
            continue
        if network.is_loopback and not include_loopback:
            continue

        interfaces.append(
            LocalInterface(
                name=current,
                address=address,
                netmask=str(network.netmask),
                cidr=str(network),
                is_private=True,
                is_loopback=network.is_loopback,
                is_default_route=current == default_iface,
                description=_describe(current, network, current == default_iface),
            )
        )

    # Default route first: that is the LAN the operator almost always means.
    interfaces.sort(key=lambda i: (not i.is_default_route, i.name))
    return interfaces
