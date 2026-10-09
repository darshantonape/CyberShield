"""Operator-facing assessment reports.

A report assembles one scan session's stored evidence — hosts, services, CVE
candidates, CVSS scores, remediation actions and their verification — into a
single professional document, rendered as HTML in the console and downloadable
as PDF.

The central honesty rule (spec §5, §8, §16, and the project's stated boundary)
lives in `builder.summarise`: a report must NEVER read "0 vulnerabilities" as
"the target is clean" when the scan did not gather sufficient evidence. A
failed scan, an unreachable target, a partial (timed-out) scan, and a scan that
has not yet been correlated against NVD each produce a distinct summary state,
none of which is "clean".
"""

from backend.reports.builder import (
    Report,
    ReportSummary,
    SummaryState,
    build_report,
    list_reportable_scans,
)

__all__ = [
    "Report",
    "ReportSummary",
    "SummaryState",
    "build_report",
    "list_reportable_scans",
]
