"""CVSS severity resolution (spec §10).

NVD returns a `metrics` object whose keys vary per CVE. A single response can
mix generations: measured during planning, CVE-2015-1419 carried only
`cvssMetricV2`, while CVE-2021-41773 carried `cvssMetricV31`.

Two consequences this module handles:

  * **v3.1 is preferred**, per spec §10, then v4.0, v3.0, and v2 last. The
    version actually used is always returned alongside the score, so a v2 score
    is never silently compared against a v3.1 one.
  * **CVSS v2 entries have no `baseSeverity` field** — NVD returns null. The
    band is derived from the numeric score using the official v2 ranges, and
    flagged as derived rather than reported.

When NVD supplies no usable score the result is `None` throughout. No score is
ever estimated, and no default severity is assumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["ResolvedSeverity", "resolve_severity", "severity_band"]

# Spec §10: prefer v3.1. v2 is last because its scoring model differs enough
# that its scores are not comparable with v3.x.
_METRIC_PREFERENCE: tuple[tuple[str, str], ...] = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


@dataclass(frozen=True)
class ResolvedSeverity:
    """The score selected for display, plus everything NVD offered."""

    version: str | None = None
    base_score: float | None = None
    base_severity: str | None = None
    vector_string: str | None = None
    source: str | None = None
    # True when base_severity was computed from the score because NVD did not
    # supply one (always the case for CVSS v2).
    severity_derived: bool = False
    # Every metric NVD returned, keyed by CVSS version. Retained for the
    # paper's CVSS-coverage analysis.
    all_metrics: dict[str, Any] | None = None

    @property
    def has_score(self) -> bool:
        return self.base_score is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cvss_version": self.version,
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "vector_string": self.vector_string,
            "source": self.source,
            "severity_derived": self.severity_derived,
        }


def severity_band(score: float | None, cvss_version: str | None) -> str | None:
    """Map a base score to a qualitative band.

    CVSS v3.x defines NONE/LOW/MEDIUM/HIGH/CRITICAL. **CVSS v2 has no CRITICAL
    band** — its top band is HIGH (7.0-10.0), so a 9.8 v2 score is HIGH, not
    CRITICAL. Applying v3 bands to a v2 score would inflate severity.
    """
    if score is None:
        return None

    if cvss_version and cvss_version.startswith("2"):
        if score < 4.0:
            return "LOW"
        if score < 7.0:
            return "MEDIUM"
        return "HIGH"

    if score <= 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _select_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Prefer NVD's own Primary scoring over a third-party Secondary one."""
    if not entries:
        return None
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0]


def resolve_severity(cve: dict[str, Any]) -> ResolvedSeverity:
    """Pick the score to display from an NVD CVE object.

    Args:
        cve: The `cve` object from an NVD `vulnerabilities[]` element.
    """
    metrics = cve.get("metrics") or {}
    if not isinstance(metrics, dict) or not metrics:
        return ResolvedSeverity(all_metrics=None)

    # Record everything NVD supplied before choosing one.
    collected: dict[str, Any] = {}
    for key, version in _METRIC_PREFERENCE:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = _select_entry(entries)
        if entry is None:
            continue
        data = entry.get("cvssData") or {}
        collected[version] = {
            "base_score": data.get("baseScore"),
            "base_severity": data.get("baseSeverity"),
            "vector_string": data.get("vectorString"),
            "source": entry.get("source"),
            "type": entry.get("type"),
        }

    for key, version in _METRIC_PREFERENCE:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = _select_entry(entries)
        if entry is None:
            continue

        data = entry.get("cvssData") or {}
        raw_score = data.get("baseScore")
        if raw_score is None:
            continue
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue

        reported = data.get("baseSeverity")
        derived = False
        if reported:
            severity = str(reported).upper()
        else:
            # CVSS v2 has no baseSeverity in NVD's schema.
            severity = severity_band(score, version) or "UNKNOWN"
            derived = True

        return ResolvedSeverity(
            version=version,
            base_score=score,
            base_severity=severity,
            vector_string=data.get("vectorString"),
            source=entry.get("source"),
            severity_derived=derived,
            all_metrics=collected or None,
        )

    # Metrics were present but none carried a usable score.
    return ResolvedSeverity(all_metrics=collected or None)
