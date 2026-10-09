"""Nmap invocation.

The only place Nmap is executed. Two rules hold here:

  * **Raw flags are never accepted from a caller.** Arguments come from a named
    profile in `config/scan_profiles.yaml`; the only caller-supplied values are
    a validated target and a validated port list, each appended as its own argv
    element. There is no code path that lets API or UI input become an Nmap flag.
  * **Raw XML is always written to disk before parsing.** That file is the
    primary evidence for the research write-up, and it survives a parser bug.

Scans use `-sT` (TCP connect) rather than `-sS`, so CyberShield never needs
root for assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from backend.core.config import DATA_DIR, Config, ScanProfile
from backend.core.exec import CommandError, CommandResult, resolve_executable, run_command
from backend.core.validation import ParsedTarget, validate_port

__all__ = [
    "NmapError",
    "NmapExecution",
    "build_argv",
    "run_nmap",
    "get_nmap_version",
    "RAW_DIR",
]

RAW_DIR = DATA_DIR / "raw"

# Nmap arguments the runner itself controls. A profile containing any of these
# is rejected at config load; this is the second half of that guarantee.
#
# `-p` is deliberately NOT here. A profile must be able to declare an explicit
# port set: --top-ports proved unusable for this work because Nmap's ranking
# excludes 6379/tcp (Redis) even at --top-ports 2000, so the laboratory's Redis
# target was silently missing from full scans. When a caller supplies an
# explicit port list, _strip_port_selection removes the profile's own -p first,
# so the two can never conflict.
_RUNNER_CONTROLLED = frozenset({"-oX", "-oN", "-oG", "-oA", "-iL"})

# Port-selection arguments that conflict with an explicit `-p` list.
#
# This matters more than it looks. Nmap given both `--top-ports 1000` and
# `-p 8080` scans NOTHING: it emits no <port> elements, exits with
# exit="success", and prints no warning. A verification rescan built that way
# would silently report "no open ports" and be indistinguishable from a
# successful isolation. So whenever a caller supplies an explicit port list,
# these are stripped from the profile first.
_PORT_SELECTION_WITH_VALUE = frozenset({"--top-ports", "--port-ratio", "--exclude-ports"})
_PORT_SELECTION_FLAGS = frozenset({"-F", "-p-"})


def _strip_port_selection(args: tuple[str, ...]) -> list[str]:
    """Remove profile port-selection arguments so an explicit -p list wins."""
    cleaned: list[str] = []
    skip_next = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue

        base = arg.split("=", 1)[0]

        if base in _PORT_SELECTION_WITH_VALUE:
            # "--top-ports 1000" consumes the following argument too;
            # "--top-ports=1000" is self-contained.
            skip_next = "=" not in arg
            continue

        if arg in _PORT_SELECTION_FLAGS or base == "-p":
            continue

        cleaned.append(arg)

    return cleaned


class NmapError(Exception):
    """Raised when Nmap could not be run or produced unusable output."""


@dataclass(frozen=True)
class NmapExecution:
    argv: tuple[str, ...]
    returncode: int
    duration_seconds: float
    timed_out: bool
    raw_xml_path: Path
    xml_text: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def get_nmap_version() -> str | None:
    """Return the Nmap version string, or None if Nmap is unavailable."""
    try:
        result = run_command(["nmap", "--version"], timeout_seconds=15)
    except CommandError:
        return None
    if not result.ok:
        return None
    match = re.search(r"Nmap version (\S+)", result.stdout)
    return match.group(1) if match else None


def build_argv(
    profile: ScanProfile,
    target: ParsedTarget,
    output_path: Path,
    *,
    ports: list[int] | None = None,
) -> list[str]:
    """Assemble the Nmap command line as a validated argv list.

    Args:
        ports: Explicit port list. Each entry is range-checked, then joined into
            a single `-p` value. Used by verification rescans, which look at one
            known port rather than a whole profile's port set.

    Raises:
        NmapError: if the profile tries to set an argument the runner owns.
    """
    for arg in profile.args:
        base = arg.split("=", 1)[0]
        if base in _RUNNER_CONTROLLED:
            raise NmapError(
                f"Profile {profile.name!r} sets {base!r}, which is controlled by "
                "the runner. Remove it from config/scan_profiles.yaml."
            )

    if ports is None:
        argv: list[str] = ["nmap", *profile.args]
    else:
        if not ports:
            raise NmapError("An explicit port list was supplied but is empty.")
        # Strip the profile's own port selection first, otherwise Nmap receives
        # two conflicting selections and silently scans nothing.
        argv = ["nmap", *_strip_port_selection(profile.args)]
        # validate_port raises on anything out of range or non-numeric, so no
        # caller-controlled text reaches the command line.
        checked = [str(validate_port(p)) for p in ports]
        argv += ["-p", ",".join(checked)]

    # XML output path is set by the runner, never by a profile or a caller.
    argv += ["-oX", str(output_path)]

    # Target last, as a single argument. `str(target.network)` is the output of
    # ipaddress parsing, so it cannot carry shell metacharacters or extra flags.
    argv.append(str(target.network))
    return argv


def run_nmap(
    config: Config,
    profile_name: str,
    target: ParsedTarget,
    *,
    session_id: str,
    ports: list[int] | None = None,
    raw_dir: Path | None = None,
) -> NmapExecution:
    """Run one Nmap scan and return its raw output.

    This function performs **no authorization check**. Callers must have already
    passed the target through `backend.core.authorization`; `discovery.py` and
    `service_detect.py` do exactly that. Keeping the check out of here means it
    happens once, visibly, at the orchestration layer.

    Raises:
        NmapError: if the profile is unknown, Nmap is missing, or no XML was
            produced.
    """
    profile = config.scan_profiles.get(profile_name)
    if profile is None:
        known = ", ".join(sorted(config.scan_profiles))
        raise NmapError(f"Unknown scan profile {profile_name!r}. Available: {known}.")

    try:
        resolve_executable("nmap")
    except CommandError as exc:
        raise NmapError(str(exc)) from exc

    directory = raw_dir or RAW_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = directory / f"{session_id}_{profile_name}_{stamp}.xml"

    argv = build_argv(profile, target, output_path, ports=ports)

    timeout = min(profile.timeout_seconds, config.global_max_timeout_seconds)
    result: CommandResult = run_command(argv, timeout_seconds=timeout)

    # Nmap writes XML incrementally, so a timed-out or failed run often still
    # leaves partial, useful evidence. Read whatever exists.
    xml_text = ""
    if output_path.exists():
        xml_text = output_path.read_text(errors="replace")

    if not xml_text.strip():
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        if result.timed_out:
            raise NmapError(
                f"Nmap timed out after {timeout}s and produced no XML. "
                f"Target {target.network} may be unreachable, or the profile's "
                "port range is too large for this timeout."
            )
        raise NmapError(
            f"Nmap exited {result.returncode} and produced no XML output: {detail}"
        )

    return NmapExecution(
        argv=tuple(argv),
        returncode=result.returncode,
        duration_seconds=result.duration_seconds,
        timed_out=result.timed_out,
        raw_xml_path=output_path,
        xml_text=xml_text,
        stderr=result.stderr,
    )
