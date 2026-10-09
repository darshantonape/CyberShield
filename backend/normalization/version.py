"""Version string cleaning.

Nmap reports what a service advertises, which is often not a bare version:

    "5.7.44-log"          MySQL with a build suffix
    "2.4.49 ((Ubuntu))"   Apache with distribution packaging
    "1.18.0 (Ubuntu)"     nginx
    "7.2p2 Ubuntu 4ubuntu2.10"

NVD's CPE version component holds the upstream version only, so a distribution
suffix must be removed before a lookup will match.

The one rule this module follows: **never invent a version.** If nothing
version-like is present, the result is None, and the caller reports the service
as version-unknown rather than guessing. Every change is reported alongside the
result so the transformation is auditable against the raw Nmap evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["NormalizedVersion", "normalize_version"]

# A version starts with a digit and continues through digits, dots, and short
# alphanumeric qualifiers such as "p2", "rc1", "beta3".
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*[A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*")

# Build/packaging suffixes that are not part of the upstream version. Anchored
# to a separator so a genuine version segment is never stripped.
_PACKAGING_SUFFIX_RE = re.compile(
    r"[-_.]?(?:"
    r"log|ubuntu\d*|debian\d*|deb\d*|el\d+|centos\d*|fc\d+|rhel\d*|"
    r"win32|win64|mdv|generic|community|enterprise"
    r")\b.*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class NormalizedVersion:
    """The outcome of cleaning one version string."""

    raw: str | None
    version: str | None
    changed: bool
    note: str | None = None

    @property
    def is_known(self) -> bool:
        return self.version is not None

    @property
    def confidence(self) -> str:
        """'known' or 'unknown' (spec §8). Never anything in between."""
        return "known" if self.version else "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "normalized": self.version,
            "changed": self.changed,
            "note": self.note,
        }


def normalize_version(raw: str | None) -> NormalizedVersion:
    """Extract the upstream version from an Nmap version string.

    Returns a NormalizedVersion whose `version` is None when no version-like
    token is present. Absence is reported, never filled in.
    """
    if raw is None:
        return NormalizedVersion(raw=None, version=None, changed=False, note="No version reported by Nmap.")

    text = raw.strip()
    if not text:
        return NormalizedVersion(raw=raw, version=None, changed=False, note="Empty version string.")

    # MariaDB 10.x advertises itself as "5.5.5-10.5.29". The "5.5.5-" prefix is
    # a deliberate compatibility hack so that MySQL clients, which cannot parse
    # a major version of 10, still connect. It is not part of the version.
    #
    # Measured against NVD on 2026-08-30, this matters enormously:
    #   mariadb:mariadb:10.5.29        ->   3 CVE candidates  (correct)
    #   mariadb:mariadb:5.5.5-10.5.29  -> 250 CVE candidates  (~83x over-report)
    # Leaving the prefix in place would inflate the finding count by two orders
    # of magnitude.
    mariadb_prefixed = re.match(r"^5\.5\.5-(\d+\.\d+.*)$", text)
    if mariadb_prefixed:
        inner = mariadb_prefixed.group(1)
        return NormalizedVersion(
            raw=raw,
            version=inner.split()[0].rstrip(".-_"),
            changed=True,
            note=(
                f"Stripped MariaDB's '5.5.5-' compatibility prefix from {text!r}; "
                "it is a client-compatibility artifact, not a version component."
            ),
        )

    # Drop parenthesised commentary: "2.4.49 ((Ubuntu))", "0.6 (Python 3.13)".
    without_parens = re.sub(r"\s*\([^)]*\)\s*", " ", text).strip()

    # Keep only the leading token; anything after whitespace is commentary.
    leading = without_parens.split()[0] if without_parens.split() else ""

    match = _VERSION_RE.match(leading)
    if not match:
        return NormalizedVersion(
            raw=raw,
            version=None,
            changed=False,
            note=f"No version-like token found in {raw!r}; reported as unknown.",
        )

    candidate = match.group(0)

    stripped = _PACKAGING_SUFFIX_RE.sub("", candidate)
    # Only accept the strip if something version-like survives.
    if stripped and _VERSION_RE.match(stripped):
        candidate = stripped

    candidate = candidate.rstrip(".-_")
    if not candidate:
        return NormalizedVersion(
            raw=raw, version=None, changed=False, note=f"Nothing usable left from {raw!r}."
        )

    changed = candidate != text
    note = None
    if changed:
        note = f"Normalized {text!r} to {candidate!r}."

    return NormalizedVersion(raw=raw, version=candidate, changed=changed, note=note)
