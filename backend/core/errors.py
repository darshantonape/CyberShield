"""Operator-facing error messages.

The problem this solves. The scope check produced, verbatim:

    192.168.0.176/32 is not inside any authorized range.

That is accurate and useless. It does not say what to do, and an operator
reading it cannot tell whether the tool is broken, the address is wrong, or the
target simply needs authorizing.

So every failure the operator can encounter is translated into four parts:

    title       what went wrong, in three or four words
    message     what it means, in plain language
    hint        the next action to take, concretely
    technical   the original exception text, kept verbatim for debugging

The technical detail is never discarded — it is shown in a collapsed block and
written to the audit log. Explaining an error and hiding it are different
things.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = ["FriendlyError", "explain", "scope_refusal"]


@dataclass(frozen=True)
class FriendlyError:
    title: str
    message: str
    hint: str
    technical: str
    kind: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "message": self.message,
            "hint": self.hint,
            "technical": self.technical,
            "kind": self.kind,
        }

    def flat(self) -> str:
        """Single-line rendering, for a redirect query string or a log."""
        return f"{self.title} — {self.message} {self.hint}".strip()


# An address or CIDR mentioned in a scope refusal, so the hint can name it.
_ADDRESS_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)")


def scope_refusal(target: str, reason: str, authorized: list[str] | None = None) -> FriendlyError:
    """Explain why a target is out of scope, and how to bring it into scope.

    Replaces the bare "not inside any authorized range" message. The
    authorization model itself is unchanged: this is wording, not permission.
    """
    ranges = ", ".join(authorized or []) or "none configured"
    address = target.strip()

    if "defines no targets" in reason:
        return FriendlyError(
            title="No authorized scope",
            message=(
                "CyberShield has no authorized targets configured, so every scan "
                "is refused. This is the intended default — nothing is scanned "
                "until you authorize it explicitly."
            ),
            hint=(
                "Open Targets and add the private IP address or subnet you have "
                "permission to assess."
            ),
            technical=reason,
        )

    if "looks like IPv6" in reason:
        return FriendlyError(
            title="IPv4 address required",
            message=(
                f"{address} looks like an IPv6 address. This version of "
                "CyberShield scans IPv4 only."
            ),
            hint="Enter the target's IPv4 address, for example 192.168.1.25.",
            technical=reason,
        )

    if "not a valid IPv4" in reason or "is empty" in reason:
        return FriendlyError(
            title="Invalid target",
            message=(
                f"{address!r} is not a valid IPv4 address or CIDR range. Host "
                "names are deliberately not accepted: DNS could resolve a name "
                "to a different address than the one that was authorized."
            ),
            hint=(
                "Enter a numeric address such as 192.168.1.25, or a range such "
                "as 192.168.1.0/24."
            ),
            technical=reason,
        )

    found = _ADDRESS_RE.search(address) or _ADDRESS_RE.search(reason)
    named = found.group(1) if found else address
    return FriendlyError(
        title="Target not authorized",
        message=(
            f"{named} is outside the currently authorized scan scope, so the "
            f"scan was refused before Nmap was invoked. Authorized ranges: "
            f"{ranges}."
        ),
        hint=(
            "Add this private IP address or CIDR range on the Targets page, "
            "confirm that you are authorized to assess it, then run the scan "
            "again. A target is never scanned just because it is reachable."
        ),
        technical=reason,
    )


# (matched substring, title, message, hint) — first match wins, so the more
# specific patterns come first.
_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    (
        "AUTHORIZATION.md",
        "Authorization not signed",
        "CyberShield refuses to scan or remediate until AUTHORIZATION.md is "
        "signed. This is a deliberate control, not a bug.",
        "Open AUTHORIZATION.md, set signed: true, complete every field, then "
        "re-run scripts/preflight.py.",
    ),
    (
        "not found on PATH",
        "Nmap is not installed",
        "The scanner could not find the nmap executable, so no scan can run.",
        "Install it with: brew install nmap — then reload this page.",
    ),
    (
        "could not be recovered",
        "Unreadable Nmap output",
        "Nmap produced output that could not be parsed even after attempting to "
        "repair a truncated file. No results were inferred from it, and no "
        "findings were recorded.",
        "The raw file is kept under data/raw/ for inspection. Re-run the scan; "
        "if it recurs, check free disk space and that the scan is not being "
        "killed by the system.",
    ),
    (
        "is not well-formed",
        "Unreadable Nmap output",
        "Nmap's XML output was malformed. This usually means the scan was "
        "interrupted while Nmap was still writing.",
        "Re-run the scan. The raw output is retained under data/raw/ and the "
        "failure is recorded in the scan history and the audit log.",
    ),
    (
        # Deliberately "Nmap timed out", not "timed out": an SSH failure whose
        # text happens to contain "timed out" was being explained as a scan
        # timeout, telling the operator to narrow their port set for a problem
        # that had nothing to do with scanning.
        "nmap timed out",
        "Scan timed out",
        "Nmap exceeded its profile timeout. Results, if any, are truncated and "
        "an absent port proves nothing.",
        "Try a narrower target (a single /32 rather than a whole subnet), or a "
        "profile with a smaller port set.",
    ),
    (
        "produced no XML",
        "Nmap produced no results",
        "Nmap started but wrote no output at all.",
        "Check that the target address is on a subnet this machine can reach, "
        "and that nmap runs from your terminal.",
    ),
    (
        "Operation not permitted",
        "Insufficient permissions",
        "Nmap was refused an operation by the operating system. CyberShield "
        "deliberately uses unprivileged TCP connect scans so that sudo is never "
        "required, so this usually points at a sandbox or security policy.",
        "Run the scan from a normal terminal session. Do not grant the tool "
        "elevated privileges to work around this.",
    ),
    (
        "is not flagged 'is_lab: true'",
        "Remediation not permitted here",
        "This target is authorized for assessment only. Firewall changes are "
        "refused on it.",
        "Only laboratory targets configured with is_lab: true and SSH details "
        "in config/authorized_targets.yaml can be remediated. Targets added "
        "from the Targets page are always assessment-only.",
    ),
    (
        "protected port",
        "Protected port",
        "This port can never be isolated. Blocking it risks losing management "
        "access or breaking a core service.",
        "There is no override for this rule — no force flag, no API field, no "
        "setting. Choose a different service.",
    ),
    (
        "SSH key not found",
        "SSH key missing",
        "The private key configured for laboratory remediation does not exist "
        "at the expected path, so the action could not be applied or rolled "
        "back.",
        "Check CYBERSHIELD_SSH_KEY_PATH in .env and that the key file is "
        "present and readable.",
    ),
    (
        "SSH",
        "SSH connection failed",
        "CyberShield could not reach the laboratory target over SSH, so no "
        "firewall rule was applied. Nothing was changed on the target.",
        "Confirm the lab containers are running (docker ps) and that the "
        "management port in config/authorized_targets.yaml is correct.",
    ),
    (
        "NVD",
        "CVE lookup failed",
        "The NVD API could not be reached or refused the request, so CVE "
        "correlation is incomplete. Detected services are still recorded; the "
        "absence of CVE candidates here means nothing was looked up, not that "
        "nothing was found.",
        "Check your internet connection. Adding CYBERSHIELD_NVD_API_KEY to "
        ".env raises the rate limit from 5 to 50 requests per 30 seconds.",
    ),
    (
        "database is locked",
        "Database busy",
        "Another operation held the database open too long.",
        "Wait a moment and retry. If it persists, check whether a scan job is "
        "stuck on the Scans page.",
    ),
    (
        "Configuration error",
        "Configuration problem",
        "A policy file under config/ is missing or invalid, so CyberShield "
        "refused to act rather than run with a partially-loaded policy.",
        "Run ./.venv/bin/python scripts/preflight.py — it names the exact file "
        "and field.",
    ),
)


def explain(error: BaseException | str, *, fallback_hint: str = "") -> FriendlyError:
    """Translate an exception or message into an operator-facing explanation."""
    technical = str(error) if not isinstance(error, str) else error
    exception_name = type(error).__name__ if isinstance(error, BaseException) else ""

    for needle, title, message, hint in _PATTERNS:
        if needle.lower() in technical.lower():
            return FriendlyError(
                title=title, message=message, hint=hint, technical=technical
            )

    if "not inside any authorized range" in technical:
        return scope_refusal("", technical)

    return FriendlyError(
        title="Operation failed",
        message=(
            technical
            if technical
            else f"An unexpected {exception_name or 'error'} occurred."
        ),
        hint=fallback_hint
        or (
            "The full error is shown below. Nothing was changed on any target as "
            "a result of this failure."
        ),
        technical=f"{exception_name}: {technical}" if exception_name else technical,
    )
