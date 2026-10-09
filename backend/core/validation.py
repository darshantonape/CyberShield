"""Input validation for network targets and ports.

Every externally supplied value crosses this module before it reaches Nmap, SSH,
or the database. Validators raise `ValidationError` rather than returning a
sentinel, so a caller that forgets to check the result still fails closed.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

__all__ = [
    "ValidationError",
    "ParsedTarget",
    "parse_target",
    "validate_port",
    "validate_proto",
    "is_private_network",
    "validate_hostname",
]

MIN_PORT = 1
MAX_PORT = 65535

VALID_PROTOCOLS = frozenset({"tcp", "udp"})

# RFC 1123 hostname label rules. Used only for SSH hosts, never for scan targets
# (scan targets must be numeric so scope checks cannot be defeated by DNS).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


class ValidationError(ValueError):
    """Raised when supplied input is not a safe, well-formed network value."""


@dataclass(frozen=True)
class ParsedTarget:
    """A validated scan target.

    `network` is always a network object; a bare address becomes a /32 so that
    containment checks are uniform.
    """

    raw: str
    network: ipaddress.IPv4Network

    @property
    def is_single_host(self) -> bool:
        return self.network.num_addresses == 1

    @property
    def address_count(self) -> int:
        return self.network.num_addresses

    def __str__(self) -> str:
        return str(self.network)


def parse_target(value: str) -> ParsedTarget:
    """Parse an IPv4 address or CIDR range into a validated target.

    Hostnames are rejected deliberately. Allowing DNS names would mean the scope
    check runs against a name while Nmap resolves it to some other address, so a
    target could drift out of the authorized range between check and use.

    IPv6 is rejected as out of scope for this implementation rather than being
    silently mishandled.
    """
    if not isinstance(value, str):
        raise ValidationError(f"Target must be a string, got {type(value).__name__}.")

    candidate = value.strip()
    if not candidate:
        raise ValidationError("Target is empty.")

    if ":" in candidate:
        raise ValidationError(
            f"{candidate!r} looks like IPv6. This implementation supports IPv4 only."
        )

    try:
        # strict=False so 10.0.0.5/24 is accepted and normalised to 10.0.0.0/24
        # rather than raising over a non-zero host part.
        network = ipaddress.IPv4Network(candidate, strict=False)
    except ValueError as exc:
        raise ValidationError(
            f"{candidate!r} is not a valid IPv4 address or CIDR range: {exc}"
        ) from exc

    return ParsedTarget(raw=candidate, network=network)


def is_private_network(network: ipaddress.IPv4Network) -> bool:
    """True if every address in `network` is non-routable on the public internet.

    `IPv4Network.is_private` already covers RFC1918, loopback, and link-local,
    and evaluates the whole range rather than just its first address.
    """
    return network.is_private


def validate_port(value: object) -> int:
    """Coerce and range-check a TCP/UDP port number.

    Booleans are rejected explicitly: `isinstance(True, int)` is True in Python,
    so without this check `validate_port(True)` would quietly return port 1.
    """
    if isinstance(value, bool):
        raise ValidationError("Port must be an integer, not a boolean.")

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped.isdigit():
            raise ValidationError(f"Port {value!r} is not a positive integer.")
        port = int(stripped)
    elif isinstance(value, int):
        port = value
    else:
        raise ValidationError(f"Port must be an integer, got {type(value).__name__}.")

    if not MIN_PORT <= port <= MAX_PORT:
        raise ValidationError(f"Port {port} is outside the valid range {MIN_PORT}-{MAX_PORT}.")

    return port


def validate_proto(value: str) -> str:
    """Normalise and check a transport protocol name."""
    if not isinstance(value, str):
        raise ValidationError(f"Protocol must be a string, got {type(value).__name__}.")

    proto = value.strip().lower()
    if proto not in VALID_PROTOCOLS:
        raise ValidationError(
            f"Protocol {value!r} is not supported. Expected one of {sorted(VALID_PROTOCOLS)}."
        )
    return proto


def validate_hostname(value: str) -> str:
    """Validate an SSH destination: an IPv4 literal or an RFC1123 hostname.

    Used only for the management channel, where the operator has named the host
    directly in the config file.
    """
    if not isinstance(value, str):
        raise ValidationError(f"Hostname must be a string, got {type(value).__name__}.")

    host = value.strip()
    if not host:
        raise ValidationError("Hostname is empty.")

    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(host):
        raise ValidationError(f"{host!r} is not a valid IPv4 address or hostname.")

    return host
