"""Nmap XML output parser.

Parsed with `defusedxml`, not the stdlib parser: Nmap XML is attacker-influenced
input (banners and hostnames come from the scanned host), so entity-expansion
and external-entity attacks are a real consideration even in a lab.

The parser reports what Nmap said and nothing more. It never fills in a missing
version, never guesses a product, and never infers that a port is safe. Where
Nmap gives no answer, the result is an explicit "unknown".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from defusedxml import ElementTree as DefusedET

__all__ = [
    "NmapParseError",
    "ParsedService",
    "ParsedHost",
    "ParsedScan",
    "parse_nmap_xml",
    "repair_truncated_xml",
]


class NmapParseError(Exception):
    """Raised when Nmap XML is missing, malformed, or not actually Nmap output."""


# Elements that may legitimately be left unclosed by a killed Nmap process.
# Anything deeper than this is dropped rather than guessed at.
_RECOVERABLE_CONTAINERS = ("ports", "host", "nmaprun")

_OPEN_TAG_RE = re.compile(r"<(/?)([A-Za-z_][\w.-]*)((?:\"[^\"]*\"|'[^']*'|[^>\"'])*?)(/?)>")


def repair_truncated_xml(xml_text: str) -> tuple[str, list[str]]:
    """Best-effort repair of Nmap XML cut off mid-write.

    Why this is needed. Nmap streams `-oX` output as it scans, so a run that is
    killed — a timeout, Ctrl-C, the OOM killer, a full disk, a Colima VM going
    away mid-scan — leaves a file with a valid prologue, real host results, and
    no closing tags. The stdlib and defusedxml parsers both reject the whole
    document, which produced the observed failure:

        NmapParseError: Nmap XML is not well-formed:
        no element found: line N, column M

    Discarding the file loses the only evidence of the hosts that *were*
    scanned. So the truncated tail is dropped, the open containers are closed,
    and the recovery is reported to the caller — never hidden. A recovered scan
    is marked incomplete, exactly like a `--host-timeout` scan, so it can never
    be read as an exhaustive sweep.

    Returns:
        (repaired_xml, notes). `notes` is empty when nothing had to be changed.
    """
    text = xml_text
    notes: list[str] = []

    # 1. Drop a partial final line. A truncated write usually ends mid-tag or
    #    mid-attribute, which no amount of tag-closing can fix.
    if not text.rstrip().endswith(">"):
        cut = text.rfind(">")
        if cut == -1:
            raise NmapParseError(
                "Nmap XML contains no complete element. The file was truncated "
                "before any result was written."
            )
        dropped = len(text) - (cut + 1)
        text = text[: cut + 1]
        notes.append(f"discarded {dropped} trailing bytes written mid-element")

    # 2. Walk the tags and find what is still open.
    stack: list[str] = []
    for match in _OPEN_TAG_RE.finditer(text):
        closing, name, _attrs, self_closing = match.groups()
        if closing:
            # Unwind to the matching open tag; ignore a stray close.
            if name in stack:
                while stack and stack.pop() != name:
                    continue
        elif not self_closing:
            stack.append(name)

    if not stack:
        return text, notes

    # 3. Drop any unclosed element that is not a known container: half of a
    #    <port> or <service> element carries attributes we cannot trust.
    while stack and stack[-1] not in _RECOVERABLE_CONTAINERS:
        unusable = stack.pop()
        opening = text.rfind(f"<{unusable}")
        if opening == -1:
            break
        text = text[:opening]
        notes.append(f"discarded an incomplete <{unusable}> element")

    for name in reversed(stack):
        text += f"</{name}>"
    if stack:
        notes.append(f"closed unterminated element(s): {', '.join(reversed(stack))}")

    return text, notes


def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _clean(value: str | None) -> str | None:
    """Normalise an attribute to a non-empty string, or None."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


@dataclass(frozen=True)
class ParsedService:
    """One port and whatever Nmap could determine about it."""

    port: int
    proto: str
    state: str
    reason: str | None = None

    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None

    # Nmap's own confidence in the service match, 1-10.
    confidence: int | None = None
    # "table" (port-number guess) or "probed" (banner-confirmed). This
    # distinction matters: a "table" result is a guess from the port number
    # alone and carries no evidence about what is actually running.
    method: str | None = None
    cpes: tuple[str, ...] = ()

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def version_confidence(self) -> str:
        """'known' only when Nmap actually reported a version string (spec §8).

        Never inferred. An absent version stays unknown.
        """
        return "known" if self.version else "unknown"

    @property
    def identification_status(self) -> str:
        """How much of the software identity Nmap established.

        Deliberately has no "clean" value: a service Nmap could not identify is
        undetermined, which is not the same as a service known to be safe.
        """
        if self.product and self.version:
            return "identified"
        if self.product:
            return "product_only"
        return "undetermined"

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.proto,
            "state": self.state,
            "service": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "confidence": self.confidence,
            "method": self.method,
            "cpes": list(self.cpes),
            "version_confidence": self.version_confidence,
            "identification_status": self.identification_status,
        }


@dataclass(frozen=True)
class ParsedHost:
    address: str
    addr_type: str = "ipv4"
    hostname: str | None = None
    state: str = "unknown"
    mac_address: str | None = None
    vendor: str | None = None
    services: tuple[ParsedService, ...] = ()

    # Nmap sets timedout="true" on <host> when --host-timeout expires. The host
    # is still reported "up", but its port list is TRUNCATED or empty. Without
    # this flag a timed-out host is indistinguishable from one with no open
    # ports — a partial scan silently reading as a clean result. Observed
    # against the laboratory on 2026-08-30, where all four hosts timed out and
    # the run reported "4 hosts up, 0 open services".
    timed_out: bool = False

    # Nmap does not emit a <port> element for every probed port. Ports that all
    # share one uninteresting state are collapsed into
    # <extraports state="closed" count="44"/>, and the individual entries are
    # omitted. Ignoring that block loses the single most important distinction
    # on a real LAN: a host that answered every probe with RST (all ports
    # CLOSED — definitively reachable, nothing listening) produces exactly the
    # same empty `services` tuple as a host that answered nothing at all.
    # Observed against 192.168.10.4 on 2026-09-20, where 44 closed ports were
    # reported to the operator as "unreachable — every probed port was
    # filtered". Stored as {state: count}.
    extra_ports: tuple[tuple[str, int], ...] = ()

    @property
    def is_up(self) -> bool:
        return self.state == "up"

    @property
    def extra_port_counts(self) -> dict[str, int]:
        return dict(self.extra_ports)

    @property
    def closed_port_count(self) -> int:
        """Ports that answered with a refusal — proof a packet got through."""
        explicit = sum(1 for s in self.services if s.state == "closed")
        return explicit + self.extra_port_counts.get("closed", 0)

    @property
    def responded(self) -> bool:
        """True when this host demonstrably answered at least one TCP probe.

        An "open" or "closed" port is an answer: the host sent SYN/ACK or RST.
        "filtered" is the absence of one. Counted from both the explicit <port>
        elements and the collapsed <extraports> summary, because Nmap puts the
        answer in whichever of the two it feels like.
        """
        if any(s.state in ("open", "closed") for s in self.services):
            return True
        return any(
            state in ("open", "closed") and count > 0
            for state, count in self.extra_ports
        )

    @property
    def results_are_complete(self) -> bool:
        """False when this host's port list cannot be trusted as exhaustive."""
        return not self.timed_out

    @property
    def open_services(self) -> tuple[ParsedService, ...]:
        return tuple(s for s in self.services if s.is_open)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "state": self.state,
            "mac_address": self.mac_address,
            "timed_out": self.timed_out,
            "results_are_complete": self.results_are_complete,
            "extra_ports": self.extra_port_counts,
            "responded": self.responded,
            "services": [s.to_dict() for s in self.services],
        }


@dataclass(frozen=True)
class ParsedScan:
    nmap_version: str | None = None
    args: str | None = None
    start_epoch: int | None = None
    elapsed_seconds: float | None = None
    exit_status: str | None = None
    hosts: tuple[ParsedHost, ...] = ()
    # Present when Nmap ran but aborted; surfaced rather than swallowed.
    error_message: str | None = None

    # True when the XML had to be repaired before it could be parsed, i.e. Nmap
    # was killed mid-write. The results below are whatever survived; they are
    # never exhaustive, and `is_complete` is False as a result.
    recovered_from_truncation: bool = False
    recovery_notes: tuple[str, ...] = ()

    @property
    def hosts_up(self) -> tuple[ParsedHost, ...]:
        return tuple(h for h in self.hosts if h.is_up)

    @property
    def hosts_timed_out(self) -> tuple[ParsedHost, ...]:
        """Hosts whose port results are truncated by --host-timeout."""
        return tuple(h for h in self.hosts if h.timed_out)

    @property
    def is_complete(self) -> bool:
        """False if the scan under-reports for any reason.

        Either a host hit --host-timeout, or the XML itself was truncated and
        repaired. Both mean an absent port proves nothing.
        """
        return not self.hosts_timed_out and not self.recovered_from_truncation

    @property
    def total_open_services(self) -> int:
        return sum(len(h.open_services) for h in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nmap_version": self.nmap_version,
            "args": self.args,
            "start_epoch": self.start_epoch,
            "elapsed_seconds": self.elapsed_seconds,
            "exit_status": self.exit_status,
            "is_complete": self.is_complete,
            "recovered_from_truncation": self.recovered_from_truncation,
            "recovery_notes": list(self.recovery_notes),
            "hosts_timed_out": [h.address for h in self.hosts_timed_out],
            "hosts": [h.to_dict() for h in self.hosts],
        }


def _parse_service_element(service_el: Any) -> dict[str, Any]:
    cpes = tuple(
        text
        for cpe_el in service_el.findall("cpe")
        if (text := _clean(cpe_el.text)) is not None
    )
    return {
        "service_name": _clean(service_el.get("name")),
        "product": _clean(service_el.get("product")),
        "version": _clean(service_el.get("version")),
        "extra_info": _clean(service_el.get("extrainfo")),
        "confidence": _int_or_none(service_el.get("conf")),
        "method": _clean(service_el.get("method")),
        "cpes": cpes,
    }


def _parse_port_element(port_el: Any) -> ParsedService | None:
    port = _int_or_none(port_el.get("portid"))
    if port is None:
        return None

    state_el = port_el.find("state")
    state = _clean(state_el.get("state")) if state_el is not None else None
    reason = _clean(state_el.get("reason")) if state_el is not None else None

    service_fields: dict[str, Any] = {}
    service_el = port_el.find("service")
    if service_el is not None:
        service_fields = _parse_service_element(service_el)

    return ParsedService(
        port=port,
        proto=_clean(port_el.get("protocol")) or "tcp",
        state=state or "unknown",
        reason=reason,
        **service_fields,
    )


def _parse_host_element(host_el: Any) -> ParsedHost | None:
    address = None
    addr_type = "ipv4"
    mac_address = None
    vendor = None

    for addr_el in host_el.findall("address"):
        kind = addr_el.get("addrtype")
        value = _clean(addr_el.get("addr"))
        if kind in ("ipv4", "ipv6") and address is None:
            address = value
            addr_type = kind
        elif kind == "mac":
            mac_address = value
            vendor = _clean(addr_el.get("vendor"))

    # A host block with no IP address is unusable downstream; skip rather than
    # invent a placeholder address.
    if address is None:
        return None

    status_el = host_el.find("status")
    state = _clean(status_el.get("state")) if status_el is not None else None

    hostname = None
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        for hostname_el in hostnames_el.findall("hostname"):
            candidate = _clean(hostname_el.get("name"))
            if candidate:
                hostname = candidate
                break

    services: list[ParsedService] = []
    extra_ports: list[tuple[str, int]] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            parsed = _parse_port_element(port_el)
            if parsed is not None:
                services.append(parsed)
        # Ports Nmap collapsed instead of listing individually. Never expanded
        # into ParsedService rows — there is no per-port evidence to store, and
        # inventing 44 synthetic "closed" services would corrupt every count
        # downstream. Kept as a summary, which is all it is.
        for extra_el in ports_el.findall("extraports"):
            extra_state = _clean(extra_el.get("state"))
            count = _int_or_none(extra_el.get("count"))
            if extra_state and count:
                extra_ports.append((extra_state, count))

    services.sort(key=lambda s: (s.proto, s.port))

    return ParsedHost(
        address=address,
        addr_type=addr_type,
        hostname=hostname,
        state=state or "unknown",
        mac_address=mac_address,
        vendor=vendor,
        services=tuple(services),
        timed_out=host_el.get("timedout") == "true",
        extra_ports=tuple(extra_ports),
    )


def parse_nmap_xml(xml_text: str) -> ParsedScan:
    """Parse Nmap `-oX` output into structured results.

    Raises:
        NmapParseError: if the input is empty, not well-formed XML, or not an
            `<nmaprun>` document.
    """
    if not xml_text or not xml_text.strip():
        raise NmapParseError("Nmap produced no XML output.")

    recovery_notes: tuple[str, ...] = ()
    try:
        root = DefusedET.fromstring(xml_text)
    except Exception as first_error:  # defusedxml raises several distinct types
        # Most real-world failures here are a truncated file from a killed Nmap,
        # not corruption. Try to recover the part that was written, and record
        # that a recovery happened.
        try:
            repaired, notes = repair_truncated_xml(xml_text)
            root = DefusedET.fromstring(repaired)
        except NmapParseError:
            raise
        except Exception:
            raise NmapParseError(
                f"Nmap XML is not well-formed and could not be recovered: "
                f"{first_error}. The raw file is retained under data/raw/ for "
                "inspection. No results were inferred from it."
            ) from first_error
        recovery_notes = tuple(notes)

    if root.tag != "nmaprun":
        raise NmapParseError(
            f"Expected an <nmaprun> document, found <{root.tag}>. "
            "This does not look like Nmap XML output."
        )

    elapsed = None
    exit_status = None
    error_message = None

    runstats_el = root.find("runstats")
    if runstats_el is not None:
        finished_el = runstats_el.find("finished")
        if finished_el is not None:
            elapsed = _float_or_none(finished_el.get("elapsed"))
            exit_status = _clean(finished_el.get("exit"))
            # Nmap sets exit="error" and an errormsg when it aborts.
            error_message = _clean(finished_el.get("errormsg"))

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        parsed = _parse_host_element(host_el)
        if parsed is not None:
            hosts.append(parsed)

    return ParsedScan(
        nmap_version=_clean(root.get("version")),
        args=_clean(root.get("args")),
        start_epoch=_int_or_none(root.get("start")),
        elapsed_seconds=elapsed,
        exit_status=exit_status,
        hosts=tuple(hosts),
        error_message=error_message,
        recovered_from_truncation=bool(recovery_notes),
        recovery_notes=recovery_notes,
    )
