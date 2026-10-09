"""Render a Report to PDF with ReportLab.

Kept separate from the HTML template so the two presentations share one data
source (`builder.Report`) but neither depends on the other. Uses only the
Platypus high-level API, so there is no manual coordinate math to get wrong.
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.reports.builder import Report, ReportService, SummaryState

__all__ = ["render_pdf"]

_INK = colors.HexColor("#1f2937")
_MUTED = colors.HexColor("#6b7280")
_LINE = colors.HexColor("#d1d5db")
_HEADER_BG = colors.HexColor("#111827")

_SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#1d4ed8"),
    "NONE": _MUTED,
}

# Summary state → banner colour. Insufficient-evidence states are amber/red, not
# green, so a reader never mistakes them for a clean result.
_STATE_COLOR = {
    SummaryState.FAILED: colors.HexColor("#b91c1c"),
    SummaryState.UNREACHABLE: colors.HexColor("#b45309"),
    SummaryState.PARTIAL: colors.HexColor("#b45309"),
    SummaryState.IN_PROGRESS: _MUTED,
    SummaryState.NO_OPEN_SERVICES: colors.HexColor("#b45309"),
    SummaryState.NOT_CORRELATED: colors.HexColor("#b45309"),
    SummaryState.UNDETERMINED: colors.HexColor("#b45309"),
    SummaryState.CANDIDATES: colors.HexColor("#b91c1c"),
    SummaryState.NO_CANDIDATES: colors.HexColor("#15803d"),
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=20, textColor=_INK, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9.5, textColor=_MUTED),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, textColor=_INK, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=11, textColor=_INK, spaceBefore=8, spaceAfter=2),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9, textColor=_INK, leading=12, alignment=TA_LEFT),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=7.5, textColor=_MUTED, leading=9.5),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=7.5, textColor=_INK, leading=9.5),
        "cellhead": ParagraphStyle("ch", parent=base["Normal"], fontSize=7.5, textColor=colors.white, leading=9.5),
        "banner": ParagraphStyle("bn", parent=base["Normal"], fontSize=11, textColor=colors.white, leading=14),
        "bannerd": ParagraphStyle("bd", parent=base["Normal"], fontSize=8.5, textColor=colors.white, leading=11),
    }


def _meta_table(report: Report, st: dict[str, ParagraphStyle]) -> Table:
    def p(v: Any) -> Paragraph:
        return Paragraph("—" if v in (None, "") else str(v), st["cell"])

    started = report.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if report.started_at else "—"
    dur = f"{report.duration_seconds:.2f}s" if report.duration_seconds is not None else "—"
    rows = [
        [Paragraph("Session", st["small"]), p(report.session_id),
         Paragraph("Target", st["small"]), p(report.target)],
        [Paragraph("Scan kind", st["small"]), p(report.scan_kind),
         Paragraph("Profile", st["small"]), p(report.profile)],
        [Paragraph("Status", st["small"]), p(report.status),
         Paragraph("Reachability", st["small"]), p((report.reachability or "unknown").upper())],
        [Paragraph("Started", st["small"]), p(started),
         Paragraph("Duration", st["small"]), p(dur)],
        [Paragraph("Operator", st["small"]), p(report.operator),
         Paragraph("Nmap", st["small"]), p(report.nmap_version)],
        [Paragraph("Config hash", st["small"]), p(report.config_hash),
         Paragraph("Generated", st["small"]),
         p(report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"))],
    ]
    t = Table(rows, colWidths=[24 * mm, 62 * mm, 24 * mm, 60 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f3f4f6")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _summary_banner(report: Report, st: dict[str, ParagraphStyle]) -> Table:
    color = _STATE_COLOR.get(report.summary.state, _MUTED)
    inner = [
        [Paragraph(report.summary.headline, st["banner"])],
        [Paragraph(report.summary.detail, st["bannerd"])],
    ]
    t = Table(inner, colWidths=[170 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (0, 0), 7),
        ("BOTTOMPADDING", (0, 1), (0, 1), 7),
    ]))
    return t


def _services_table(host_services: list[ReportService], st: dict[str, ParagraphStyle]) -> Table:
    head = [Paragraph(h, st["cellhead"]) for h in
            ("Port", "State", "Service", "Product", "Version", "Ver.conf", "Ident.", "Policy", "CVEs")]
    data = [head]
    for s in host_services:
        data.append([
            Paragraph(f"{s.proto}/{s.port}", st["cell"]),
            Paragraph(s.state, st["cell"]),
            Paragraph(s.service_name or "—", st["cell"]),
            Paragraph(s.product or "—", st["cell"]),
            Paragraph(s.version or "—", st["cell"]),
            Paragraph(s.version_confidence, st["cell"]),
            Paragraph(s.identification_status, st["cell"]),
            Paragraph(s.policy or "—", st["cell"]),
            Paragraph(str(len(s.vulnerabilities)), st["cell"]),
        ])
    t = Table(data, colWidths=[15*mm, 15*mm, 20*mm, 34*mm, 26*mm, 15*mm, 20*mm, 20*mm, 10*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    return t


def _cve_table(service: ReportService, st: dict[str, ParagraphStyle]) -> Table:
    head = [Paragraph(h, st["cellhead"]) for h in
            ("CVE", "Severity", "CVSS", "Conf.", "Method", "Status", "Note")]
    data = [head]
    styles_extra = []
    for i, v in enumerate(service.vulnerabilities, start=1):
        sev = v.severity or "—"
        score = f"{v.base_score} (v{v.cvss_version})" if v.base_score is not None else "—"
        note = "probable FP" if v.probable_false_positive else ""
        data.append([
            Paragraph(v.cve_id, st["cell"]),
            Paragraph(sev, st["cell"]),
            Paragraph(score, st["cell"]),
            Paragraph(v.confidence, st["cell"]),
            Paragraph(v.matching_method, st["cell"]),
            Paragraph(v.status, st["cell"]),
            Paragraph(note, st["cell"]),
        ])
        if sev in _SEVERITY_COLOR:
            styles_extra.append(("TEXTCOLOR", (1, i), (1, i), _SEVERITY_COLOR[sev]))
    t = Table(data, colWidths=[34*mm, 20*mm, 30*mm, 16*mm, 22*mm, 30*mm, 18*mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, _LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        *styles_extra,
    ]))
    return t


def render_pdf(report: Report) -> bytes:
    """Render a Report to PDF bytes."""
    st = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"CyberShield report {report.session_id}",
        author="CyberShield",
    )
    flow: list[Any] = []

    flow.append(Paragraph("CyberShield assessment report", st["title"]))
    flow.append(Paragraph(
        f"Target {report.target} · session {report.session_id} · "
        "authorized laboratory use only", st["sub"]))
    flow.append(Spacer(1, 6))
    flow.append(_summary_banner(report, st))
    flow.append(Spacer(1, 8))
    flow.append(Paragraph("Scan information", st["h2"]))
    flow.append(_meta_table(report, st))

    # Counts strip
    c = report.counts
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        f"<b>{c['hosts']}</b> hosts · <b>{c['open_services']}</b> open services · "
        f"<b>{c['candidates']}</b> CVE candidates "
        f"(<b>{c['flagged_false_positives']}</b> probable false positives) · "
        f"<b>{c['undetermined_services']}</b> undetermined services · "
        f"<b>{c['remediations']}</b> remediation actions", st["body"]))

    if report.reachability_note:
        flow.append(Spacer(1, 4))
        flow.append(Paragraph(f"<i>{report.reachability_note}</i>", st["small"]))

    # Hosts & services
    flow.append(Paragraph("Hosts, services and CVE candidates", st["h2"]))
    if not report.hosts:
        flow.append(Paragraph("No hosts were recorded for this scan.", st["body"]))
    for host in report.hosts:
        label = f"{host.address}"
        if host.hostname:
            label += f" ({host.hostname})"
        label += f" — {host.state}"
        flow.append(Paragraph(label, st["h3"]))
        if not host.services:
            flow.append(Paragraph("No ports recorded for this host.", st["small"]))
            continue
        flow.append(_services_table(host.services, st))
        for s in host.services:
            if s.vulnerabilities:
                flow.append(Spacer(1, 3))
                flow.append(Paragraph(
                    f"{s.proto}/{s.port} — {len(s.vulnerabilities)} CVE candidate(s):",
                    st["small"]))
                flow.append(_cve_table(s, st))
            if s.state == "open":
                flow.append(Paragraph(f"Recommendation: {s.recommendation}", st["small"]))
        flow.append(Spacer(1, 4))

    # Remediation & verification
    flow.append(Paragraph("Remediation status & verification", st["h2"]))
    if not report.remediations:
        flow.append(Paragraph(
            "No remediation actions have been taken against the hosts in this scan.",
            st["body"]))
    else:
        head = [Paragraph(h, st["cellhead"]) for h in
                ("Request", "Port", "State", "Dry run", "Exposure reduced", "Mgmt intact", "Verification")]
        data = [head]
        for r in report.remediations:
            data.append([
                Paragraph(r.request_id[:10], st["cell"]),
                Paragraph(f"{r.proto}/{r.port}", st["cell"]),
                Paragraph(r.state, st["cell"]),
                Paragraph("yes" if r.is_dry_run else "no", st["cell"]),
                Paragraph(_tri(r.exposure_reduced), st["cell"]),
                Paragraph(_tri(r.management_channel_intact), st["cell"]),
                Paragraph(" ".join(r.verification_findings) or "—", st["cell"]),
            ])
        t = Table(data, colWidths=[22*mm, 15*mm, 20*mm, 14*mm, 22*mm, 18*mm, 59*mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
            ("GRID", (0, 0), (-1, -1), 0.4, _LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        flow.append(t)

    # Footer
    flow.append(Spacer(1, 10))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=_LINE))
    flow.append(Spacer(1, 3))
    flow.append(Paragraph(
        "Every CVE listed is a candidate: a detected version string resembling a "
        "CVE's affected software is not proof of vulnerability or exploitability, "
        "and no exploitation was attempted. “Exposure reduced” means a port's "
        "reachability changed as observed by this scanner — the service kept "
        "running and no software was patched. Authorized laboratory use only.",
        st["small"]))

    doc.build(flow)
    return buf.getvalue()


def _tri(value: bool | None) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "—"
