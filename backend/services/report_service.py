"""
VENOM AI · backend/services/report_service.py
Professional PDF security report generator — VENOM AI v2.0
Includes: Vulnerabilities, PoE status, NHI findings, Compliance, Attack Chains, AutoFix
"""
from __future__ import annotations
import io
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("venom.report")

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
REPORTS_DIR.mkdir(exist_ok=True)


def _get_db():
    try:
        from db.database import SessionLocal
        return SessionLocal()
    except ImportError:
        from db.database import SessionLocal
        return SessionLocal()


def _get_models():
    try:
        from db import models
        return models
    except ImportError:
        from db import models
        return models


# ── HTML Template ─────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Helvetica Neue",Arial,sans-serif;color:#1a1a2e;background:#fff;font-size:12px}}
.cover{{background:linear-gradient(135deg,#03040a 0%,#080c18 60%,#0a1428 100%);color:#fff;padding:55px 50px;page-break-after:always;min-height:100vh}}
.cover-brand{{font-family:monospace;font-size:10px;letter-spacing:4px;color:#39ff14;text-transform:uppercase;margin-bottom:40px;opacity:.8}}
.cover-venom{{font-size:48px;font-weight:900;letter-spacing:.05em;color:#fff;line-height:1;margin-bottom:4px}}
.cover-venom span{{color:#39ff14}}
.cover-sub{{font-size:12px;color:#3d5070;letter-spacing:2px;text-transform:uppercase;margin-bottom:50px;font-family:monospace}}
.cover-title{{font-size:22px;font-weight:700;margin-bottom:6px}}
.cover-url{{font-family:monospace;font-size:13px;color:#39ff14;margin-bottom:50px}}
.meta-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-bottom:40px}}
.meta-item{{background:rgba(255,255,255,.04);border:1px solid rgba(57,255,20,.1);border-radius:8px;padding:14px}}
.meta-label{{font-size:9px;color:#3d5070;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px;font-family:monospace}}
.meta-val{{font-size:18px;font-weight:800;color:#fff}}
.meta-val.acid{{color:#39ff14}}
.meta-val.red{{color:#ff4466}}
.meta-val.orange{{color:#ff6b00}}
.meta-val.yellow{{color:#ffd500}}
.poe-strip{{background:rgba(57,255,20,.08);border:1px solid rgba(57,255,20,.2);border-radius:6px;padding:12px 16px;font-family:monospace;font-size:10px;color:#39ff14}}
section{{padding:30px 40px;page-break-inside:avoid}}
h2{{font-size:16px;font-weight:800;color:#1a1a2e;border-bottom:2px solid #39ff14;padding-bottom:8px;margin-bottom:18px;text-transform:uppercase;letter-spacing:.08em}}
h3{{font-size:13px;font-weight:700;color:#1a1a2e;margin:14px 0 8px}}
.sev{{display:inline-block;font-size:9px;font-weight:800;padding:2px 8px;border-radius:3px;text-transform:uppercase;letter-spacing:.08em;font-family:monospace}}
.sev-critical{{background:#ffe0e6;color:#c01030}}
.sev-high{{background:#ffe8d0;color:#c04000}}
.sev-medium{{background:#fff5d0;color:#806000}}
.sev-low{{background:#d0f0ff;color:#0060a0}}
.sev-info{{background:#e8e0ff;color:#5030a0}}
.vuln-card{{border:1px solid #e0e5f0;border-radius:8px;margin-bottom:12px;overflow:hidden}}
.vuln-header{{padding:12px 16px;background:#f8f9fc;display:flex;align-items:center;gap:12px}}
.vuln-title{{font-weight:700;font-size:13px;flex:1}}
.vuln-body{{padding:14px 16px;border-top:1px solid #e0e5f0}}
.vuln-row{{margin-bottom:8px}}
.vuln-label{{font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#6070a0;font-weight:600;margin-bottom:2px;font-family:monospace}}
.vuln-text{{font-size:11px;color:#2a3060;line-height:1.5}}
code{{background:#f0f4ff;border:1px solid #d0d8f0;border-radius:3px;padding:1px 5px;font-size:10px;color:#2040a0;font-family:monospace}}
pre{{background:#f5f7ff;border:1px solid #d0d8f0;border-radius:6px;padding:12px;font-family:monospace;font-size:10px;overflow:hidden;margin:6px 0;color:#1a2060;white-space:pre-wrap;word-break:break-all}}
.poe-confirmed{{background:#ffe0e6;color:#c01030;border-radius:3px;padding:2px 8px;font-size:9px;font-weight:700;font-family:monospace;text-transform:uppercase}}
.poe-safe{{background:#e0f8e8;color:#107030;border-radius:3px;padding:2px 8px;font-size:9px;font-weight:700;font-family:monospace}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}
th{{background:#f0f4ff;color:#3040a0;font-size:9px;text-transform:uppercase;letter-spacing:.1em;padding:8px 12px;text-align:left;border-bottom:2px solid #d0d8f0;font-weight:700}}
td{{padding:9px 12px;border-bottom:1px solid #e8eaf5;font-size:11px;vertical-align:top}}
tr:hover td{{background:#f8f9fc}}
.compliance-bar{{background:#e8eaf5;border-radius:4px;height:8px;overflow:hidden;margin-top:4px}}
.compliance-fill{{height:100%;border-radius:4px}}
.chain-box{{background:#fff5f5;border:1px solid #f0d0d5;border-radius:6px;padding:12px;margin-bottom:8px}}
.chain-step{{font-family:monospace;font-size:10px;color:#2a3060;padding:2px 0;line-height:1.6}}
.summary-box{{background:#f0fff4;border:1px solid #b0e8c0;border-radius:8px;padding:16px;margin-bottom:16px}}
.nhi-badge{{background:#ffe0e6;color:#c01030;border-radius:3px;padding:2px 8px;font-size:9px;font-weight:700;font-family:monospace}}
footer{{position:fixed;bottom:0;left:0;right:0;padding:10px 40px;background:#f8f9fc;border-top:1px solid #e0e5f0;font-size:9px;color:#6070a0;display:flex;justify-content:space-between;font-family:monospace}}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-brand">Virtual Engine for Network Offensive Monitoring</div>
  <div class="cover-venom">VENOM <span>AI</span></div>
  <div class="cover-sub">Security Assessment Report · v2.0</div>
  <div class="cover-title">Vulnerability & Exposure Analysis</div>
  <div class="cover-url">{target_url}</div>
  <div class="meta-grid">
    <div class="meta-item">
      <div class="meta-label">Security Score</div>
      <div class="meta-val {score_color}">{security_score}/100</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Risk Grade</div>
      <div class="meta-val {grade_color}">{grade}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Total Issues</div>
      <div class="meta-val red">{total_issues}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">PoE Confirmed</div>
      <div class="meta-val orange">{poe_count}</div>
    </div>
  </div>
  <div class="poe-strip">
    ⚡ CRITICAL: {critical_count} · HIGH: {high_count} · MEDIUM: {medium_count} · LOW: {low_count}
    &nbsp;&nbsp;|&nbsp;&nbsp; SCAN DATE: {scan_date} &nbsp;&nbsp;|&nbsp;&nbsp; VENOM AI v2.0
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<section>
  <h2>Executive Summary</h2>
  <div class="summary-box">
    <p style="font-size:12px;line-height:1.7;color:#1a2a50">{ai_summary}</p>
  </div>
  <h3>Severity Distribution</h3>
  <table>
    <tr><th>Severity</th><th>Count</th><th>Risk Weight</th><th>Status</th></tr>
    <tr><td><span class="sev sev-critical">Critical</span></td><td><strong>{critical_count}</strong></td><td>25 pts each</td><td style="color:#c01030">Immediate action required</td></tr>
    <tr><td><span class="sev sev-high">High</span></td><td><strong>{high_count}</strong></td><td>15 pts each</td><td style="color:#c04000">Fix within 48 hours</td></tr>
    <tr><td><span class="sev sev-medium">Medium</span></td><td><strong>{medium_count}</strong></td><td>8 pts each</td><td style="color:#806000">Fix within 2 weeks</td></tr>
    <tr><td><span class="sev sev-low">Low</span></td><td><strong>{low_count}</strong></td><td>3 pts each</td><td style="color:#0060a0">Fix in next cycle</td></tr>
  </table>
</section>

<!-- VULNERABILITIES -->
<section>
  <h2>Vulnerability Findings</h2>
  {vuln_html}
</section>

<!-- NHI FINDINGS -->
{nhi_section}

<!-- COMPLIANCE -->
{compliance_section}

<!-- ATTACK CHAINS -->
{attack_chain_section}

<!-- APPENDIX -->
<section>
  <h2>Appendix — Scan Metadata</h2>
  <table>
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Target URL</td><td><code>{target_url}</code></td></tr>
    <tr><td>Scan Date</td><td>{scan_date}</td></tr>
    <tr><td>Scan Engine</td><td>VENOM AI v2.0</td></tr>
    <tr><td>Security Score</td><td>{security_score}/100 (Grade {grade})</td></tr>
    <tr><td>Total Issues</td><td>{total_issues}</td></tr>
    <tr><td>PoE Confirmed</td><td>{poe_count}</td></tr>
    <tr><td>Report Generated</td><td>{report_date}</td></tr>
  </table>
  <p style="margin-top:16px;font-size:10px;color:#6070a0;line-height:1.6">
    This report was generated automatically by VENOM AI. Findings should be validated by a qualified security professional
    before remediation activities commence. This report is confidential and intended for authorized personnel only.
  </p>
</section>

<footer>
  <span>VENOM AI — Virtual Engine for Network Offensive Monitoring</span>
  <span>CONFIDENTIAL · {scan_date}</span>
  <span>venom-report-{scan_id}</span>
</footer>
</body>
</html>"""


def _sev_class(sev: str) -> str:
    return {"critical": "sev-critical", "high": "sev-high",
            "medium": "sev-medium", "low": "sev-low"}.get(sev, "sev-info")


def _score_color(score: int) -> str:
    if score >= 80: return "acid"
    if score >= 60: return "yellow"
    return "red"


def _grade_color(grade: str) -> str:
    return {"A": "acid", "B": "acid", "C": "yellow", "D": "orange", "F": "red"}.get(grade, "red")


def _build_vuln_html(vulns: list) -> str:
    if not vulns:
        return '<p style="color:#6070a0;font-style:italic">No vulnerabilities detected.</p>'
    parts = []
    for v in sorted(vulns, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3)):
        sev = v.get("severity", "info")
        poe = v.get("poe_confirmed") or v.get("verified")
        parts.append(f"""
<div class="vuln-card">
  <div class="vuln-header">
    <span class="sev {_sev_class(sev)}">{sev}</span>
    <span class="vuln-title">{v.get('title') or v.get('vuln_type','Unknown')}</span>
    {"<span class='poe-confirmed'>⚡ PoE Confirmed</span>" if poe else "<span class='poe-safe'>Not verified</span>"}
    {f"<code>{v.get('cwe_id')}</code>" if v.get('cwe_id') else ""}
    {f"<code>CVSS {v.get('cvss_score')}</code>" if v.get('cvss_score') else ""}
  </div>
  <div class="vuln-body">
    {"<div class='vuln-row'><div class='vuln-label'>Affected URL</div><div class='vuln-text'><code>" + str(v.get('affected_url','')) + "</code></div></div>" if v.get('affected_url') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Description</div><div class='vuln-text'>" + str(v.get('description','')) + "</div></div>" if v.get('description') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Evidence</div><pre>" + str(v.get('evidence','')) + "</pre></div>" if v.get('evidence') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Impact</div><div class='vuln-text'>" + str(v.get('impact','')) + "</div></div>" if v.get('impact') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Recommended Fix</div><div class='vuln-text'>" + str(v.get('fix') or v.get('recommendation','')) + "</div></div>" if (v.get('fix') or v.get('recommendation')) else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Secure Code Example</div><pre>" + str(v.get('code_example','')) + "</pre></div>" if v.get('code_example') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>PoE Detail</div><div class='vuln-text'>" + str(v.get('poe_detail','')) + "</div></div>" if v.get('poe_detail') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>AI Explanation</div><div class='vuln-text'>" + str(v.get('ai_explanation','')) + "</div></div>" if v.get('ai_explanation') else ""}
    {"<div class='vuln-row'><div class='vuln-label'>Reference</div><div class='vuln-text'><a href='" + str(v.get('reference','')) + "'>" + str(v.get('reference','')) + "</a></div></div>" if v.get('reference') else ""}
  </div>
</div>""")
    return "\n".join(parts)


def _build_nhi_section(vulns: list) -> str:
    nhi = [v for v in vulns if v.get("nhi_type") == "leaked_credential" or
           "key" in (v.get("vuln_type","") + v.get("title","")).lower() or
           "token" in (v.get("vuln_type","") + v.get("title","")).lower() or
           "secret" in (v.get("vuln_type","") + v.get("title","")).lower()]
    if not nhi:
        return ""
    rows = "".join(f"<tr><td>{v.get('type') or v.get('title','?')}</td><td><span class='sev {_sev_class(v.get('severity','high'))}'>{v.get('severity','?')}</span></td><td><code>{v.get('evidence','—')}</code></td><td>{v.get('remediation') or v.get('fix','—')}</td></tr>" for v in nhi)
    return f"""
<section>
  <h2>NHI — Non-Human Identity Leaks</h2>
  <p style="font-size:11px;color:#6070a0;margin-bottom:12px">The following API keys, tokens, and machine credentials were found exposed in page source, JavaScript bundles, or configuration files.</p>
  <table>
    <tr><th>Secret Type</th><th>Severity</th><th>Evidence (Redacted)</th><th>Remediation</th></tr>
    {rows}
  </table>
</section>"""


def _build_compliance_section(vulns: list) -> str:
    try:
        try:
            from services.compliance_service import generate_full_compliance_report
        except ImportError:
            from services.compliance_service import generate_full_compliance_report
        report = generate_full_compliance_report(vulns)
    except Exception:
        return ""

    def fw_html(key, name):
        fw = report.get(key, {})
        score = fw.get("score", 0)
        color = "#39c260" if score >= 80 else "#c0a000" if score >= 60 else "#c01030"
        controls_html = ""
        for c in fw.get("controls", [])[:8]:
            st = c["status"]
            st_color = "#107030" if st == "pass" else "#c01030" if st == "fail" else "#806000"
            controls_html += f"<tr><td><code>{c['id']}</code></td><td>{c['name']}</td><td style='color:{st_color};font-weight:700;font-family:monospace;font-size:9px'>{st.upper()}</td></tr>"
        return f"""
<h3>{name} — {score}% Readiness</h3>
<div class="compliance-bar"><div class="compliance-fill" style="width:{score}%;background:{color}"></div></div>
<table style="margin-top:8px">
  <tr><th>Control ID</th><th>Control Name</th><th>Status</th></tr>
  {controls_html}
</table>"""

    return f"""
<section>
  <h2>Compliance Readiness Assessment</h2>
  <table style="margin-bottom:16px">
    <tr><th>Framework</th><th>Score</th><th>Grade</th><th>Passing</th><th>Failing</th></tr>
    <tr><td>ISO 27001</td><td>{report.get('iso_27001',{}).get('score','—')}%</td><td>{report.get('iso_27001',{}).get('grade','—')}</td><td>{report.get('iso_27001',{}).get('passing','—')}</td><td>{report.get('iso_27001',{}).get('failing','—')}</td></tr>
    <tr><td>SOC 2 Type II</td><td>{report.get('soc2',{}).get('score','—')}%</td><td>{report.get('soc2',{}).get('grade','—')}</td><td>{report.get('soc2',{}).get('passing','—')}</td><td>{report.get('soc2',{}).get('failing','—')}</td></tr>
    <tr><td>GDPR</td><td>{report.get('gdpr',{}).get('score','—')}%</td><td>{report.get('gdpr',{}).get('grade','—')}</td><td>{report.get('gdpr',{}).get('passing','—')}</td><td>{report.get('gdpr',{}).get('failing','—')}</td></tr>
  </table>
  {fw_html('iso_27001', 'ISO 27001 Controls')}
  {fw_html('soc2', 'SOC 2 Criteria')}
  {fw_html('gdpr', 'GDPR Articles')}
</section>"""


def _build_chain_section(vulns: list, target_url: str) -> str:
    try:
        try:
            from services.attack_path_service import build_attack_chains, attack_chains_to_dict
        except ImportError:
            from services.attack_path_service import build_attack_chains, attack_chains_to_dict
        chains = attack_chains_to_dict(build_attack_chains(vulns, target_url))
    except Exception:
        return ""
    if not chains:
        return ""
    chain_html = ""
    for ch in chains[:5]:
        steps = "".join(f"<div class='chain-step'>{s}</div>" for s in ch.get("steps", []))
        mitre = ", ".join(ch.get("mitre_techniques", []))
        chain_html += f"""
<div class="chain-box">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span class="sev {_sev_class(ch.get('severity','high'))}">{ch.get('severity','?')}</span>
    <strong style="font-size:12px">{ch.get('title','?')}</strong>
    <span style="margin-left:auto;font-size:10px;color:#6070a0">Blast Radius: {ch.get('blast_radius',0)} assets</span>
  </div>
  <p style="font-size:11px;color:#3040a0;margin-bottom:8px">{ch.get('description','')}</p>
  {steps}
  {f"<div style='margin-top:8px;font-family:monospace;font-size:9px;color:#6070a0'>MITRE: {mitre}</div>" if mitre else ""}
</div>"""
    return f"""
<section>
  <h2>Attack Path Analysis</h2>
  <p style="font-size:11px;color:#6070a0;margin-bottom:12px">Correlated attack chains showing how individual vulnerabilities can be chained to reach critical assets.</p>
  {chain_html}
</section>"""


def generate_pdf_report(scan_id: int) -> bytes:
    """Generate a professional PDF report for a scan. Returns PDF bytes."""
    db = _get_db()
    models = _get_models()
    try:
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        vulns_db = db.query(models.Vulnerability).filter(models.Vulnerability.scan_id == scan_id).all()
        vulns = [
            {
                "id": v.id, "title": v.title or v.vuln_type, "vuln_type": v.vuln_type,
                "severity": v.severity, "description": v.description, "evidence": v.evidence,
                "affected_url": v.affected_url, "recommendation": v.recommendation,
                "cvss_score": v.cvss_score, "cve_id": v.cve_id, "cwe_id": v.cwe_id,
                "impact": v.impact, "fix": v.fix, "code_example": v.code_example,
                "reference": v.reference, "source_tool": str(v.source_tool),
                "verified": v.verified, "ai_explanation": v.ai_explanation,
                "poe_confirmed": getattr(v, "poe_confirmed", v.verified),
                "poe_detail": getattr(v, "poe_detail", ""),
                "nhi_type": getattr(v, "nhi_type", ""),
            }
            for v in vulns_db
        ]
        poe_count = sum(1 for v in vulns if v.get("poe_confirmed"))
        score = scan.security_score or 0
        grade = scan.grade or "F"
        scan_date = (scan.created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")

        html = _HTML_TEMPLATE.format(
            target_url=scan.target_url or "Unknown",
            security_score=score,
            grade=grade,
            total_issues=scan.total_issues or 0,
            critical_count=scan.critical_count or 0,
            high_count=scan.high_count or 0,
            medium_count=scan.medium_count or 0,
            low_count=scan.low_count or 0,
            poe_count=poe_count,
            scan_date=scan_date,
            report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            scan_id=scan_id,
            ai_summary=scan.ai_summary or "VENOM AI security assessment completed. Review findings below.",
            score_color=_score_color(score),
            grade_color=_grade_color(grade),
            vuln_html=_build_vuln_html(vulns),
            nhi_section=_build_nhi_section(vulns),
            compliance_section=_build_compliance_section(vulns),
            attack_chain_section=_build_chain_section(vulns, scan.target_url or ""),
        )

        # Try weasyprint first, fallback to xhtml2pdf, fallback to raw HTML as PDF
        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html, base_url=None).write_pdf()
            logger.info(f"Report generated with WeasyPrint: scan={scan_id}")
            return pdf_bytes
        except ImportError:
            pass

        try:
            from xhtml2pdf import pisa
            buf = io.BytesIO()
            pisa.pisaDocument(io.StringIO(html), buf, encoding="utf-8")
            pdf_bytes = buf.getvalue()
            if pdf_bytes:
                logger.info(f"Report generated with xhtml2pdf: scan={scan_id}")
                return pdf_bytes
        except ImportError:
            pass

        # Final fallback — return HTML with PDF-like content disposition
        logger.warning(f"No PDF library available — returning HTML report for scan={scan_id}")
        return html.encode("utf-8")

    finally:
        db.close()
