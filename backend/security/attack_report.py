"""
VENOM AI — Active Scan PDF Report Builder
─────────────────────────────────────────────────────────────────────────
Builds a professional PDF from an AttackScan + its AttackFinding rows,
including AI explanations and AI code fixes. Uses ReportLab (already a
dependency), so no extra packages are needed.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import List

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak,
)


_SEV_HEX = {
    "critical": "#e53935", "high": "#fb8c00", "medium": "#f9a825",
    "low": "#00c853", "info": "#4fc3f7",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(s) -> str:
    s = "" if s is None else str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_attack_pdf(scan, findings: List) -> bytes:
    """Return PDF bytes for an AttackScan and its findings."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"VENOM OWASP Report — {scan.target_url}",
        author="VENOM AI",
    )

    DARK  = colors.HexColor("#0a0f18")
    ACID  = colors.HexColor("#2fbf3f")
    TEXT  = colors.HexColor("#1c2333")
    MUTED = colors.HexColor("#6b7a99")

    def P(name, **kw):
        base = dict(fontName="Helvetica", fontSize=9.5, textColor=TEXT, leading=14)
        base.update(kw)
        return ParagraphStyle(name, **base)

    h1     = P("h1", fontName="Helvetica-Bold", fontSize=22, textColor=DARK, leading=26, spaceAfter=2)
    sub    = P("sub", fontSize=10, textColor=MUTED, leading=14, spaceAfter=10)
    h2     = P("h2", fontName="Helvetica-Bold", fontSize=13, textColor=DARK, leading=17, spaceBefore=12, spaceAfter=5)
    body   = P("body", fontSize=9.5, textColor=TEXT, leading=14, spaceAfter=3)
    label  = P("label", fontName="Helvetica-Bold", fontSize=8, textColor=MUTED, leading=11, spaceBefore=4)
    mono   = P("mono", fontName="Courier", fontSize=8, textColor=colors.HexColor("#1b4332"), leading=11)
    small  = P("small", fontSize=8, textColor=MUTED, leading=11, alignment=TA_CENTER)

    story = []

    # ── Header ────────────────────────────────────────────────────────────
    story.append(Paragraph("VENOM — OWASP Security Report", h1))
    story.append(Paragraph(
        f"Virtual Engine for Network Offensive Monitoring · "
        f"Generated {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}", sub))
    story.append(HRFlowable(width="100%", thickness=1, color=ACID, spaceAfter=8))

    # ── Summary counts ────────────────────────────────────────────────────
    vulns = [f for f in findings if f.category == "vulnerability"]
    hard  = [f for f in findings if f.category == "hardening"]
    cnt = {s: sum(1 for f in vulns if (f.severity or "").lower() == s)
           for s in ("critical", "high", "medium", "low", "info")}

    meta_rows = [
        ["Target",       scan.target_url or "—"],
        ["Scan ID",      str(scan.id)],
        ["Started",      str(scan.started_at)[:19] if scan.started_at else "—"],
        ["Duration",     f"{(scan.duration_s or 0):.1f}s"],
        ["Engines",      ", ".join(scan.enabled_categories or [])],
        ["Vulnerabilities", str(len(vulns))],
        ["Hardening items", str(len(hard))],
    ]
    t = Table([[Paragraph(f"<b>{k}</b>", label), Paragraph(_esc(v), body)] for k, v in meta_rows],
              colWidths=[40 * mm, None])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e5e8ee")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))

    # Severity chips row
    chips = []
    for sev in ("critical", "high", "medium", "low"):
        chips.append(Paragraph(
            f'<font color="{_SEV_HEX[sev]}"><b>{cnt[sev]}</b></font><br/>'
            f'<font size="7" color="#6b7a99">{sev.upper()}</font>',
            P("chip", alignment=TA_CENTER, fontSize=15, leading=17)))
    chip_t = Table([chips], colWidths=[None] * 4)
    chip_t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e8ee")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e8ee")),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(chip_t)

    # ── Vulnerabilities ───────────────────────────────────────────────────
    def _render_finding(f, idx):
        sev = (f.severity or "info").lower()
        col = _SEV_HEX.get(sev, "#6b7a99")
        story.append(Paragraph(
            f'<font color="{col}"><b>#{idx} · [{sev.upper()}]</b></font> {_esc(f.title)}', h2))
        badges = " · ".join(x for x in [
            f.owasp, f.cwe_id, (f"CVSS {f.cvss_score}" if f.cvss_score else ""),
            (f"Risk {f.risk_score}/25" if f.risk_score else ""),
            ("VERIFIED" if f.verified else ""),
        ] if x)
        story.append(Paragraph(f'<font size="8" color="#6b7a99">{_esc(badges)}</font>', body))
        if f.affected_url:
            story.append(Paragraph("Affected URL", label))
            story.append(Paragraph(_esc(f.affected_url), mono))
        if f.parameter:
            story.append(Paragraph("Parameter", label))
            story.append(Paragraph(_esc(f.parameter), mono))
        if f.payload:
            story.append(Paragraph("Payload", label))
            story.append(Paragraph(_esc(f.payload), mono))
        if f.description:
            story.append(Paragraph("Description", label))
            story.append(Paragraph(_esc(f.description), body))
        if f.ai_explanation:
            story.append(Paragraph("AI Explanation", label))
            story.append(Paragraph(_esc(f.ai_explanation), body))
        if f.evidence:
            story.append(Paragraph("Evidence", label))
            story.append(Paragraph(_esc(f.evidence), mono))
        if f.recommendation:
            story.append(Paragraph("Recommended Fix", label))
            story.append(Paragraph(_esc(f.recommendation), body))
        if f.ai_code_fix:
            story.append(Paragraph(f"AI Code Fix ({_esc(f.ai_fix_language or '')})", label))
            # Preserve line breaks for code
            code_html = _esc(f.ai_code_fix).replace("\n", "<br/>")
            story.append(Paragraph(code_html, mono))
        if f.poc:
            story.append(Paragraph("Proof of Concept", label))
            story.append(Paragraph(_esc(f.poc).replace("\n", "<br/>"), mono))
        story.append(HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#e5e8ee"),
                                spaceBefore=6, spaceAfter=4))

    if vulns:
        story.append(HRFlowable(width="100%", thickness=1, color=ACID, spaceBefore=14, spaceAfter=4))
        story.append(Paragraph(f"Vulnerabilities ({len(vulns)})", h2))
        vulns_sorted = sorted(vulns, key=lambda f: (-(f.risk_score or 0),
                                                    _SEV_ORDER.get((f.severity or "info").lower(), 9)))
        for i, f in enumerate(vulns_sorted, 1):
            _render_finding(f, i)
    else:
        story.append(Spacer(1, 8))
        story.append(Paragraph("No exploitable vulnerabilities were found. 🎉", body))

    # ── Hardening ─────────────────────────────────────────────────────────
    if hard:
        story.append(HRFlowable(width="100%", thickness=1, color=ACID, spaceBefore=14, spaceAfter=4))
        story.append(Paragraph(f"Hardening Recommendations ({len(hard)})", h2))
        for i, f in enumerate(hard, 1):
            story.append(Paragraph(f"<b>{i}. {_esc(f.title)}</b> "
                                   f'<font size="8" color="#6b7a99">({_esc(f.owasp)})</font>', body))
            if f.recommendation:
                story.append(Paragraph(_esc(f.recommendation), small if False else body))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e8ee")))
    story.append(Paragraph(
        "Generated by VENOM AI · This report is for authorized security testing only. "
        "Findings should be validated by a qualified professional.", small))

    doc.build(story)
    return buf.getvalue()
