"""
VENOM AI · backend/routes/reports.py
PDF Report generation endpoint.
FIX: This file was missing — main.py imports it but it didn't exist.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

from auth.dependencies import get_optional_user
from db.models import User as _AuthUser
from billing.quotas import require_feature

router = APIRouter()
logger = logging.getLogger("venom.reports")


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


def _find_scan(db, models, scan_id: str, current_user: Optional[_AuthUser] = None):
    """
    Look up scan by integer ID first, then celery_task_id.
    Enforces ownership: a logged-in user only sees their own scans;
    anonymous callers only see scans with owner_id IS NULL.
    """
    scan = None
    try:
        int_id = int(scan_id)
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int_id).first()
    except (ValueError, TypeError):
        pass
    if not scan and hasattr(models.ScanJob, "celery_task_id"):
        scan = db.query(models.ScanJob).filter(
            models.ScanJob.celery_task_id == scan_id
        ).first()
    if not scan:
        return None
    # ── Ownership enforcement ───────────────────────────────────────────
    if current_user is not None:
        if scan.owner_id != current_user.id:
            return None
    else:
        if scan.owner_id is not None:
            return None
    return scan


def _vuln_to_dict(v) -> dict:
    """Extract every field from a Vulnerability ORM row."""
    return {
        "id":             getattr(v, "id", None),
        "title":          getattr(v, "title", "") or getattr(v, "vuln_type", "") or "Unknown",
        "vuln_type":      getattr(v, "vuln_type", "") or "",
        "category":       getattr(v, "category", "") or "",
        "severity":       getattr(v, "severity", "info") or "info",
        "risk_level":     getattr(v, "risk_level", "") or "",
        "affected_url":   getattr(v, "affected_url", "") or "",
        "evidence":       getattr(v, "evidence", "") or "",
        "description":    getattr(v, "description", "") or "",
        "impact":         getattr(v, "impact", "") or "",
        "recommendation": getattr(v, "recommendation", "") or "",
        "fix":            getattr(v, "fix", "") or "",
        "code_example":   getattr(v, "code_example", "") or "",
        "reference":      getattr(v, "reference", "") or "",
        "references":     getattr(v, "references", None) or [],
        "ai_explanation": getattr(v, "ai_explanation", "") or "",
        "ai_risk_level":  getattr(v, "ai_risk_level", "") or "",
        "cvss_score":     getattr(v, "cvss_score", 0.0) or 0.0,
        "cve_id":         getattr(v, "cve_id", "") or "",
        "cwe_id":         getattr(v, "cwe_id", "") or "",
        "source_tool":    str(getattr(v, "source_tool", "venom") or "venom"),
        "verified":       bool(getattr(v, "verified", False) or getattr(v, "is_verified", False)),
        "false_positive": bool(getattr(v, "false_positive", False) or getattr(v, "is_false_positive", False)),
        "poe_confirmed":  bool(getattr(v, "poe_confirmed", False)),
        "poe_detail":     getattr(v, "poe_detail", "") or "",
        "poe_attempted":  bool(getattr(v, "poe_attempted", False)),
        "created_at":     str(getattr(v, "created_at", "") or ""),
    }


def _build_html_report(scan, vulns: list, scan_id: str) -> str:
    """Build a comprehensive cybersecurity HTML report — all findings, all fields, no truncation."""
    url        = scan.target_url or "Unknown"
    score      = getattr(scan, "security_score", 0) or 0
    grade      = getattr(scan, "grade", "F") or "F"
    total      = getattr(scan, "total_issues", 0) or len(vulns)
    critical   = getattr(scan, "critical_count", 0) or sum(1 for v in vulns if v.get("severity") == "critical")
    high       = getattr(scan, "high_count", 0)     or sum(1 for v in vulns if v.get("severity") == "high")
    medium     = getattr(scan, "medium_count", 0)   or sum(1 for v in vulns if v.get("severity") == "medium")
    low        = getattr(scan, "low_count", 0)       or sum(1 for v in vulns if v.get("severity") == "low")
    info_cnt   = sum(1 for v in vulns if v.get("severity") == "info")
    scan_type  = getattr(scan, "scan_type", "full") or "full"
    scan_dur   = getattr(scan, "scan_duration", None)
    dur_str    = f"{scan_dur:.1f}s" if scan_dur else "—"
    scan_date  = str(getattr(scan, "created_at", ""))[:19] or "—"
    completed  = str(getattr(scan, "completed_at", ""))[:19] or scan_date
    ai_summary = (getattr(scan, "ai_summary", "") or
                  f"VENOM AI completed a {scan_type} security assessment of {url}. "
                  f"Detected {total} issues: {critical} critical, {high} high, {medium} medium, {low} low.")
    poe_count  = sum(1 for v in vulns if v.get("poe_confirmed"))
    fp_count   = sum(1 for v in vulns if v.get("false_positive"))
    gen_time   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    SC = {"critical": "#ff1744", "high": "#ff6d00", "medium": "#ffd600", "low": "#00e676", "info": "#90a4ae"}
    score_color = "#00c853" if score >= 80 else "#ffd600" if score >= 60 else "#ff1744"
    grade_color = {"A":"#00c853","B":"#69f0ae","C":"#ffd600","D":"#ff6d00","F":"#ff1744"}.get(grade, "#ff1744")

    def badge(sev):
        c = SC.get(sev, "#90a4ae")
        return (f'<span style="background:{c}22;color:{c};border:1px solid {c}66;'
                f'border-radius:3px;padding:2px 9px;font-size:10px;font-weight:800;'
                f'text-transform:uppercase;font-family:monospace;letter-spacing:.06em">{sev}</span>')

    def field(label, value, mono=False, code=False, pre=False, accent=None):
        if not value:
            return ""
        color = accent or "#ccc"
        if pre:
            content = (f'<pre style="background:#0a0d16;border:1px solid #1e2a1e;border-left:3px solid #00e676;'
                       f'border-radius:4px;padding:12px 16px;font-family:monospace;font-size:11px;color:#7ee787;'
                       f'white-space:pre-wrap;word-break:break-all;margin:0">{value}</pre>')
        elif code:
            content = (f'<div style="background:#0a0d16;border:1px solid #1a2a1a;border-left:3px solid #00e676;'
                       f'border-radius:4px;padding:10px 14px;font-family:monospace;font-size:11px;color:#7ee787;'
                       f'word-break:break-all">{value}</div>')
        elif mono:
            content = (f'<div style="font-family:monospace;font-size:11px;color:{color};'
                       f'background:#0d1117;border:1px solid #1e1e2e;padding:8px 12px;'
                       f'border-radius:4px;word-break:break-all">{value}</div>')
        else:
            content = f'<div style="font-size:13px;color:{color};line-height:1.65">{value}</div>'
        return (f'<div style="margin-bottom:12px">'
                f'<div style="font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.1em;'
                f'margin-bottom:5px;font-weight:600">{label}</div>'
                f'{content}</div>')

    def cvss_bar(val):
        try:
            pct = min(100, float(val or 0) * 10)
            c   = "#ff1744" if pct >= 90 else "#ff6d00" if pct >= 70 else "#ffd600" if pct >= 40 else "#00e676"
            return (f'<div style="display:inline-flex;align-items:center;gap:8px">'
                    f'<span style="font-weight:800;color:{c};font-size:16px">{val}</span>'
                    f'<div style="width:70px;height:7px;background:#1e1e2e;border-radius:4px;overflow:hidden">'
                    f'<div style="width:{pct:.0f}%;height:100%;background:{c};border-radius:4px"></div>'
                    f'</div></div>')
        except:
            return str(val or "—")

    # ── Summary table ────────────────────────────────────────────────────────
    sorted_vulns = sorted(vulns,
                          key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"), 4))
    vuln_rows = ""
    for i, v in enumerate(sorted_vulns):
        sev = v.get("severity", "info")
        c   = SC.get(sev, "#90a4ae")
        cve_cell = f'<span style="color:#ff6d00;font-family:monospace;font-size:10px">{v["cve_id"]}</span>' if v.get("cve_id") else "—"
        poe_cell = '<span style="color:#ff1744;font-weight:700">⚡ PoE</span>' if v.get("poe_confirmed") else ""
        fp_cell  = '<span style="color:#888;font-size:10px">[FP]</span>' if v.get("false_positive") else ""
        vuln_rows += (
            f'<tr style="border-bottom:1px solid #111520">'
            f'<td style="padding:9px 12px;color:#555;font-size:11px;width:28px">{i+1}</td>'
            f'<td style="padding:9px 12px">{badge(sev)}</td>'
            f'<td style="padding:9px 12px;font-weight:600;color:#e0e0e0">{v.get("title","Unknown")} {poe_cell} {fp_cell}</td>'
            f'<td style="padding:9px 12px;font-family:monospace;font-size:10px;color:#aaa">{v.get("cwe_id","—")}</td>'
            f'<td style="padding:9px 12px">{cve_cell}</td>'
            f'<td style="padding:9px 12px">{cvss_bar(v.get("cvss_score",0))}</td>'
            f'<td style="padding:9px 12px;font-family:monospace;font-size:10px;color:#64b5f6;word-break:break-all">{v.get("affected_url","—")}</td>'
            f'</tr>'
        )

    # ── Detailed findings — ALL vulns, ALL fields, no truncation ────────────
    detail_html = ""
    for i, v in enumerate(sorted_vulns):
        sev  = v.get("severity", "info")
        c    = SC.get(sev, "#90a4ae")
        rec  = v.get("recommendation") or v.get("fix") or ""
        refs = v.get("references") or []
        ref_links = ""
        if refs:
            ref_links = "<ul style='padding-left:18px;margin:4px 0'>" + "".join(
                f"<li style='font-size:11px;color:#64b5f6;font-family:monospace'>{r}</li>" for r in refs
            ) + "</ul>"
        elif v.get("reference"):
            ref_links = f'<div style="font-family:monospace;font-size:11px;color:#64b5f6">{v["reference"]}</div>'

        detail_html += f"""
<div style="margin-bottom:32px;border:1px solid {c}44;border-radius:10px;overflow:hidden;page-break-inside:avoid">
  <!-- Finding header -->
  <div style="background:{c}18;border-bottom:1px solid {c}44;padding:14px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    {badge(sev)}
    <span style="font-size:15px;font-weight:800;color:#fff">#{i+1} · {v.get('title','Unknown')}</span>
    {'<span style="background:#ff174422;color:#ff1744;border:1px solid #ff174455;border-radius:3px;padding:2px 8px;font-size:10px;font-weight:700;font-family:monospace">⚡ PoE CONFIRMED</span>' if v.get('poe_confirmed') else ''}
    {'<span style="background:#66888822;color:#668888;border:1px solid #66888855;border-radius:3px;padding:2px 8px;font-size:10px;font-family:monospace">FALSE POSITIVE</span>' if v.get('false_positive') else ''}
    <span style="margin-left:auto;font-family:monospace;font-size:12px;color:#64b5f6">{v.get('cwe_id','')}</span>
    {f'<span style="font-family:monospace;font-size:11px;color:#ff9800">{v.get("cve_id","")}</span>' if v.get('cve_id') else ''}
  </div>
  <!-- Metrics row -->
  <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:0;border-bottom:1px solid #111820">
    <div style="padding:12px;text-align:center;border-right:1px solid #111820">
      <div style="font-size:10px;color:#555;margin-bottom:4px">CVSS</div>
      <div style="font-size:20px;font-weight:800;color:{c}">{v.get('cvss_score',0) or '—'}</div>
    </div>
    <div style="padding:12px;text-align:center;border-right:1px solid #111820">
      <div style="font-size:10px;color:#555;margin-bottom:4px">Severity</div>
      <div style="font-size:12px;font-weight:700;color:{c};text-transform:uppercase">{sev}</div>
    </div>
    <div style="padding:12px;text-align:center;border-right:1px solid #111820">
      <div style="font-size:10px;color:#555;margin-bottom:4px">Category</div>
      <div style="font-size:11px;color:#aaa">{v.get('category','') or v.get('vuln_type','') or '—'}</div>
    </div>
    <div style="padding:12px;text-align:center;border-right:1px solid #111820">
      <div style="font-size:10px;color:#555;margin-bottom:4px">Verified</div>
      <div style="font-size:13px;font-weight:700;color:{'#00e676' if v.get('verified') else '#444'}">{'✓' if v.get('verified') else '○'}</div>
    </div>
    <div style="padding:12px;text-align:center;border-right:1px solid #111820">
      <div style="font-size:10px;color:#555;margin-bottom:4px">PoE</div>
      <div style="font-size:13px;font-weight:700;color:{'#ff1744' if v.get('poe_confirmed') else '#444'}">{'⚡' if v.get('poe_confirmed') else '○'}</div>
    </div>
    <div style="padding:12px;text-align:center">
      <div style="font-size:10px;color:#555;margin-bottom:4px">Source</div>
      <div style="font-size:10px;color:#888;font-family:monospace">{v.get('source_tool','venom')}</div>
    </div>
  </div>
  <!-- Body -->
  <div style="padding:18px 22px">
    {field('Affected URL', v.get('affected_url',''), mono=True, accent='#64b5f6')}
    {field('Description', v.get('description',''))}
    {field('Impact', v.get('impact',''))}
    {field('Evidence', v.get('evidence',''), code=True) if v.get('evidence') else ''}
    {field('PoE Detail', v.get('poe_detail',''), code=True) if v.get('poe_detail') else ''}
    {f'<div style="margin-bottom:12px"><div style="font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;font-weight:600">Recommended Fix</div><div style="background:#001a08;border:1px solid #003316;border-left:3px solid #00e676;border-radius:4px;padding:12px 16px;font-size:13px;color:#b9f6ca;line-height:1.65">{rec}</div></div>' if rec else ''}
    {field('Secure Code Example', v.get('code_example',''), pre=True) if v.get('code_example') else ''}
    {field('AI Explanation', v.get('ai_explanation','')) if v.get('ai_explanation') else ''}
    {f'<div style="margin-bottom:12px"><div style="font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px;font-weight:600">References</div>{ref_links}</div>' if (ref_links) else ''}
  </div>
</div>"""

    # ── Full remediation roadmap (ALL severities) ────────────────────────────
    roadmap_html = ""
    for sev_key, sev_label, sev_col in [
        ("critical","Critical — Immediate Action","#ff1744"),
        ("high",    "High — Fix Within 48 Hours", "#ff6d00"),
        ("medium",  "Medium — Fix Within 2 Weeks","#ffd600"),
        ("low",     "Low — Fix in Next Cycle",    "#00e676"),
    ]:
        group = [v for v in sorted_vulns if v.get("severity") == sev_key]
        if not group:
            continue
        rows = ""
        for idx, v in enumerate(group, 1):
            fix_text  = v.get("recommendation") or v.get("fix") or "Apply security best practices and patch the affected component."
            poe_badge = ' <span style="color:#ff1744;font-size:10px">⚡PoE</span>' if v.get("poe_confirmed") else ""
            url_line  = ('<div style="font-family:monospace;font-size:10px;color:#555;margin-top:4px">'
                         + v.get("affected_url", "") + '</div>') if v.get("affected_url") else ""
            rows += (
                f'<div style="display:flex;align-items:flex-start;gap:12px;padding:10px 14px;'
                f'background:#0d1117;border:1px solid #111820;border-radius:6px;margin-bottom:6px">'
                f'<span style="color:{sev_col};font-weight:800;min-width:24px;font-family:monospace">{idx}.</span>'
                f'<div style="flex:1">'
                f'<div style="font-weight:700;color:#e0e0e0;margin-bottom:4px">{v.get("title","")}{poe_badge}</div>'
                f'<div style="font-size:12px;color:#888;line-height:1.5">{fix_text}</div>'
                f'{url_line}'
                f'</div></div>'
            )
        roadmap_html += (f'<div style="margin-bottom:24px">'
                         f'<div style="font-size:12px;font-weight:800;color:{sev_col};margin-bottom:10px;'
                         f'text-transform:uppercase;letter-spacing:.06em;display:flex;align-items:center;gap:8px">'
                         f'<span style="width:10px;height:10px;background:{sev_col};border-radius:50%;display:inline-block"></span>'
                         f'{sev_label} ({len(group)} issues)</div>'
                         f'{rows}</div>')

    if not roadmap_html:
        roadmap_html = '<div style="padding:20px;text-align:center;color:#666;background:#0d1117;border:1px solid #111820;border-radius:8px">No vulnerabilities found. Continue monitoring regularly.</div>'

    # ── Tool breakdown ────────────────────────────────────────────────────────
    tools = {}
    for v in vulns:
        t = v.get("source_tool", "venom")
        tools[t] = tools.get(t, 0) + 1
    tool_rows = "".join(
        f'<tr style="border-bottom:1px solid #111820">'
        f'<td style="padding:8px 12px;font-family:monospace;font-size:11px;color:#aaa">{t}</td>'
        f'<td style="padding:8px 12px;font-weight:700;color:#e0e0e0">{cnt}</td>'
        f'</tr>'
        for t, cnt in sorted(tools.items(), key=lambda x: -x[1])
    )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VENOM AI Security Report — {url}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;color:#c8d0e0;background:#080c18;}}
  @page{{margin:0}}

  .cover{{background:linear-gradient(135deg,#020509 0%,#050a14 55%,#091020 100%);
          padding:52px 56px;border-bottom:2px solid #00c853;page-break-after:always;min-height:100vh}}
  .brand{{font-family:monospace;font-size:9px;letter-spacing:4px;color:#39ff14;margin-bottom:32px;opacity:.7;text-transform:uppercase}}
  .title{{font-size:44px;font-weight:900;color:#fff;letter-spacing:.04em;line-height:1}}
  .title span{{color:#39ff14}}
  .subtitle{{font-size:11px;color:#3a4a60;letter-spacing:2px;text-transform:uppercase;margin:6px 0 48px;font-family:monospace}}
  .cover-target{{font-family:monospace;font-size:14px;color:#39ff14;margin-bottom:40px;word-break:break-all}}
  .meta-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:36px}}
  .meta-card{{background:rgba(255,255,255,.03);border:1px solid rgba(57,255,20,.12);border-radius:8px;padding:14px}}
  .meta-label{{font-size:9px;color:#384858;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px;font-family:monospace}}
  .meta-val{{font-size:22px;font-weight:900;color:#fff}}
  .strip{{background:rgba(57,255,20,.07);border:1px solid rgba(57,255,20,.18);border-radius:6px;
          padding:12px 16px;font-family:monospace;font-size:10px;color:#39ff14;letter-spacing:.04em}}

  .sec{{padding:34px 50px;border-bottom:1px solid #0d1020}}
  .sec-title{{font-size:14px;font-weight:800;color:#39ff14;text-transform:uppercase;letter-spacing:.1em;
              margin-bottom:22px;display:flex;align-items:center;gap:10px}}
  .sec-title::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,#39ff1433,transparent)}}

  .score-wrap{{display:grid;grid-template-columns:180px 1fr;gap:22px}}
  .score-card{{background:#0d1117;border:1px solid #0e2216;border-radius:12px;padding:22px;text-align:center}}
  .score-num{{font-size:52px;font-weight:900;color:{score_color};line-height:1}}
  .grade-num{{font-size:38px;font-weight:900;color:{grade_color};margin-top:6px}}
  .score-lbl{{font-size:10px;color:#445;margin-top:5px;text-transform:uppercase;letter-spacing:.1em}}

  .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}}
  .stat-card{{background:#0d1117;border:1px solid #0e1825;border-radius:8px;padding:14px;text-align:center}}
  .stat-num{{font-size:28px;font-weight:900}}
  .stat-lbl{{font-size:9px;color:#445;text-transform:uppercase;letter-spacing:.1em;margin-top:3px}}

  table{{width:100%;border-collapse:collapse}}
  thead tr{{background:#0c1020;border-bottom:2px solid #0e1c2e}}
  thead th{{padding:10px 12px;text-align:left;font-size:10px;color:#4a5870;text-transform:uppercase;letter-spacing:.09em;font-weight:700}}
  tbody td{{vertical-align:top}}
</style>
</head>
<body>

<!-- ══ COVER PAGE ══════════════════════════════════════════════════════════ -->
<div class="cover">
  <div class="brand">Virtual Engine for Network Offensive Monitoring — Agentic Exposure Management</div>
  <div class="title">VENOM <span>AI</span></div>
  <div class="subtitle">Security Assessment Report · v2.0</div>
  <div style="font-size:13px;color:#4a5870;margin-bottom:10px;font-family:monospace">TARGET</div>
  <div class="cover-target">{url}</div>
  <div class="meta-grid">
    <div class="meta-card"><div class="meta-label">Security Score</div><div class="meta-val" style="color:{score_color}">{score}/100</div></div>
    <div class="meta-card"><div class="meta-label">Risk Grade</div><div class="meta-val" style="color:{grade_color}">{grade}</div></div>
    <div class="meta-card"><div class="meta-label">Total Issues</div><div class="meta-val" style="color:#ff4466">{total}</div></div>
    <div class="meta-card"><div class="meta-label">PoE Confirmed</div><div class="meta-val" style="color:#ff6d00">{poe_count}</div></div>
  </div>
  <div class="strip">
    ⚡ CRITICAL: {critical} &nbsp;·&nbsp; HIGH: {high} &nbsp;·&nbsp; MEDIUM: {medium} &nbsp;·&nbsp; LOW: {low} &nbsp;·&nbsp; INFO: {info_cnt}
    &nbsp;&nbsp;│&nbsp;&nbsp; SCAN TYPE: {scan_type.upper()} &nbsp;&nbsp;│&nbsp;&nbsp; DURATION: {dur_str}
    &nbsp;&nbsp;│&nbsp;&nbsp; STARTED: {scan_date} &nbsp;&nbsp;│&nbsp;&nbsp; COMPLETED: {completed}
    &nbsp;&nbsp;│&nbsp;&nbsp; REPORT: {gen_time}
  </div>
</div>

<!-- ══ EXECUTIVE SUMMARY ══════════════════════════════════════════════════ -->
<div class="sec">
  <div class="sec-title">Executive Summary</div>
  <div class="score-wrap">
    <div class="score-card">
      <div class="score-num">{score}</div>
      <div class="score-lbl">Security Score</div>
      <div class="grade-num">{grade}</div>
      <div class="score-lbl">Risk Grade</div>
    </div>
    <div>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-num" style="color:#ff1744">{critical}</div><div class="stat-lbl">Critical</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#ff6d00">{high}</div><div class="stat-lbl">High</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#ffd600">{medium}</div><div class="stat-lbl">Medium</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#00e676">{low}</div><div class="stat-lbl">Low</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#90a4ae">{info_cnt}</div><div class="stat-lbl">Info</div></div>
      </div>
      <div style="background:#0d1117;border:1px solid #0e1825;border-radius:8px;padding:16px;margin-bottom:12px">
        <div style="font-size:10px;color:#445;text-transform:uppercase;letter-spacing:.09em;margin-bottom:8px;font-weight:700">AI Risk Assessment</div>
        <div style="font-size:13px;color:#b0bcd4;line-height:1.7">{ai_summary}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
        <div style="background:#0d1117;border:1px solid #0e1825;border-radius:6px;padding:10px;text-align:center">
          <div style="font-size:10px;color:#445;margin-bottom:4px">PoE Confirmed</div>
          <div style="font-size:18px;font-weight:800;color:#ff6d00">{poe_count}</div>
        </div>
        <div style="background:#0d1117;border:1px solid #0e1825;border-radius:6px;padding:10px;text-align:center">
          <div style="font-size:10px;color:#445;margin-bottom:4px">False Positives</div>
          <div style="font-size:18px;font-weight:800;color:#888">{fp_count}</div>
        </div>
        <div style="background:#0d1117;border:1px solid #0e1825;border-radius:6px;padding:10px;text-align:center">
          <div style="font-size:10px;color:#445;margin-bottom:4px">Scan Duration</div>
          <div style="font-size:18px;font-weight:800;color:#64b5f6">{dur_str}</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ══ SEVERITY DISTRIBUTION ══════════════════════════════════════════════ -->
<div class="sec">
  <div class="sec-title">Severity Distribution & SLA</div>
  <table>
    <thead><tr>
      <th>Severity</th><th>Count</th><th>Risk Weight</th><th>SLA Requirement</th><th>Status</th>
    </tr></thead>
    <tbody>
      <tr style="border-bottom:1px solid #0d1020"><td style="padding:10px 12px">{badge('critical')}</td><td style="padding:10px 12px;font-size:20px;font-weight:900;color:#ff1744">{critical}</td><td style="padding:10px 12px;color:#888">25 pts each</td><td style="padding:10px 12px;color:#ff1744;font-weight:700">Immediate — same day</td><td style="padding:10px 12px;color:#ff1744">{'⚠ Action required' if critical else '✓ None'}</td></tr>
      <tr style="border-bottom:1px solid #0d1020"><td style="padding:10px 12px">{badge('high')}</td><td style="padding:10px 12px;font-size:20px;font-weight:900;color:#ff6d00">{high}</td><td style="padding:10px 12px;color:#888">15 pts each</td><td style="padding:10px 12px;color:#ff6d00;font-weight:700">Within 48 hours</td><td style="padding:10px 12px;color:#ff6d00">{'⚠ Action required' if high else '✓ None'}</td></tr>
      <tr style="border-bottom:1px solid #0d1020"><td style="padding:10px 12px">{badge('medium')}</td><td style="padding:10px 12px;font-size:20px;font-weight:900;color:#ffd600">{medium}</td><td style="padding:10px 12px;color:#888">8 pts each</td><td style="padding:10px 12px;color:#ffd600;font-weight:700">Within 2 weeks</td><td style="padding:10px 12px;color:#ffd600">{'⚠ Action required' if medium else '✓ None'}</td></tr>
      <tr style="border-bottom:1px solid #0d1020"><td style="padding:10px 12px">{badge('low')}</td><td style="padding:10px 12px;font-size:20px;font-weight:900;color:#00e676">{low}</td><td style="padding:10px 12px;color:#888">3 pts each</td><td style="padding:10px 12px;color:#00e676;font-weight:700">Next release cycle</td><td style="padding:10px 12px;color:#00e676">{'Monitor' if low else '✓ None'}</td></tr>
      <tr><td style="padding:10px 12px">{badge('info')}</td><td style="padding:10px 12px;font-size:20px;font-weight:900;color:#90a4ae">{info_cnt}</td><td style="padding:10px 12px;color:#888">0 pts</td><td style="padding:10px 12px;color:#90a4ae">Review at convenience</td><td style="padding:10px 12px;color:#90a4ae">Informational</td></tr>
    </tbody>
  </table>
</div>

<!-- ══ VULNERABILITY SUMMARY TABLE ═══════════════════════════════════════ -->
{'<div class="sec"><div class="sec-title">Vulnerability Summary (' + str(total) + ' findings)</div><table><thead><tr><th style="width:30px">#</th><th>Severity</th><th>Finding</th><th>CWE</th><th>CVE</th><th>CVSS</th><th>Affected URL</th></tr></thead><tbody>' + vuln_rows + '</tbody></table></div>' if vulns else ''}

<!-- ══ DETAILED FINDINGS ══════════════════════════════════════════════════ -->
{'<div class="sec"><div class="sec-title">Detailed Findings (' + str(len(vulns)) + ' total)</div>' + detail_html + '</div>' if vulns else '<div class="sec"><div style="background:#0d1117;border:1px solid #0e1825;border-radius:8px;padding:28px;text-align:center;color:#555">No vulnerabilities detected during this scan. Maintain regular monitoring schedules.</div></div>'}

<!-- ══ REMEDIATION ROADMAP ════════════════════════════════════════════════ -->
<div class="sec">
  <div class="sec-title">Full Remediation Roadmap</div>
  {roadmap_html}
</div>

<!-- ══ SCAN METADATA & TOOL BREAKDOWN ════════════════════════════════════ -->
<div class="sec">
  <div class="sec-title">Scan Metadata</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
    <table>
      <thead><tr><th>Property</th><th>Value</th></tr></thead>
      <tbody>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Target</td><td style="padding:9px 12px;font-family:monospace;font-size:11px;color:#64b5f6">{url}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Scan ID</td><td style="padding:9px 12px;font-family:monospace;font-size:11px">{scan_id}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Scan Type</td><td style="padding:9px 12px;text-transform:uppercase;font-weight:700">{scan_type}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Started</td><td style="padding:9px 12px;font-family:monospace;font-size:11px">{scan_date}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Completed</td><td style="padding:9px 12px;font-family:monospace;font-size:11px">{completed}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Duration</td><td style="padding:9px 12px">{dur_str}</td></tr>
        <tr style="border-bottom:1px solid #0d1020"><td style="padding:9px 12px;color:#556">Security Score</td><td style="padding:9px 12px;font-weight:800;color:{score_color}">{score}/100 (Grade {grade})</td></tr>
        <tr><td style="padding:9px 12px;color:#556">Report Generated</td><td style="padding:9px 12px;font-family:monospace;font-size:11px">{gen_time}</td></tr>
      </tbody>
    </table>
    <div>
      <div style="font-size:11px;color:#445;text-transform:uppercase;letter-spacing:.09em;margin-bottom:10px;font-weight:700">Tool Breakdown</div>
      <table>
        <thead><tr><th>Tool / Source</th><th>Issues</th></tr></thead>
        <tbody>{tool_rows}</tbody>
      </table>
    </div>
  </div>
  <div style="margin-top:20px;padding:16px;background:#0d1117;border:1px solid #0e1825;border-radius:6px;font-size:11px;color:#445;line-height:1.7">
    ⚠ This report was generated automatically by VENOM AI. All findings should be validated by a qualified security professional
    before remediation activities commence. This report is confidential and intended only for authorized personnel.
    False positives may be present — verify each finding in context before acting.
  </div>
</div>

<!-- ══ FOOTER ═════════════════════════════════════════════════════════════ -->
<div style="padding:16px 50px;background:#050810;border-top:1px solid #0a0f1a;display:flex;justify-content:space-between;font-size:10px;color:#334;font-family:monospace">
  <span>VENOM AI Security Platform · Virtual Engine for Network Offensive Monitoring</span>
  <span>CONFIDENTIAL · {gen_time}</span>
  <span>Scan #{scan_id}</span>
</div>

</body>
</html>"""


def _build_reportlab_pdf(scan, vuln_dicts: list, scan_id: str) -> bytes:
    """Generate a professional, fully-detailed PDF using ReportLab."""
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable, KeepTogether,
                                    PageBreak)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    # ── Safe data extraction (all None-safe) ──────────────────────────
    def gs(attr, default=''):
        val = getattr(scan, attr, None)
        return str(val) if val is not None else str(default)

    target_url   = gs('target_url', scan_id)
    scan_type    = gs('scan_type', 'full').upper()
    score_val    = int(getattr(scan, 'security_score', 0) or 0)
    grade        = gs('grade', 'F')
    total        = int(getattr(scan, 'total_issues', 0) or len(vuln_dicts))
    ai_summary   = gs('ai_summary',
                       f"VENOM AI security assessment of {target_url} completed. "
                       f"{len(vuln_dicts)} vulnerabilities identified.")
    duration     = getattr(scan, 'scan_duration', None)
    dur_str      = f"{duration:.1f}s" if duration else 'N/A'
    created      = getattr(scan, 'created_at', None)
    completed    = getattr(scan, 'completed_at', None)
    date_str     = (created.strftime('%Y-%m-%d %H:%M UTC')
                    if created else datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))
    end_str      = (completed.strftime('%Y-%m-%d %H:%M UTC')
                    if completed else date_str)
    gen_str      = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sv = sorted(vuln_dicts,
                key=lambda x: sev_ord.get((x.get('severity') or 'info').lower(), 4))

    cnt = {s: sum(1 for v in sv if (v.get('severity') or 'info').lower() == s)
           for s in ('critical','high','medium','low','info')}
    poe_cnt = sum(1 for v in sv if v.get('poe_confirmed'))
    fp_cnt  = sum(1 for v in sv if v.get('false_positive'))

    # ── Colors (readable on white paper) ──────────────────────────────
    C_BG     = colors.HexColor('#0a0e1a')   # dark cover bg
    C_PANEL  = colors.HexColor('#111827')   # panel bg
    C_PANEL2 = colors.HexColor('#1a2235')   # alt row
    C_GREEN  = colors.HexColor('#00c853')
    C_WHITE  = colors.white
    C_BLACK  = colors.HexColor('#0d1117')
    C_BODY   = colors.HexColor('#1e2333')   # body text (dark on white)
    C_LABEL  = colors.HexColor('#6b7a99')   # label/muted text
    C_BORDER = colors.HexColor('#2a3455')
    C_RED    = colors.HexColor('#e53935')
    C_ORANGE = colors.HexColor('#fb8c00')
    C_YELLOW = colors.HexColor('#fdd835')
    C_BLUE   = colors.HexColor('#1565c0')
    C_MONO   = colors.HexColor('#1b4332')   # monospace text color
    C_PAGE   = colors.HexColor('#f8fafc')   # page bg (near-white)

    SEV_C = {'critical': C_RED, 'high': C_ORANGE, 'medium': C_YELLOW,
             'low': C_GREEN, 'info': C_LABEL}
    # Plain #RRGGBB strings for Paragraph XML markup (hexval() returns 0xRRGGBB format)
    SEV_HEX = {'critical': '#e53935', 'high': '#fb8c00', 'medium': '#f9a825',
               'low': '#00c853', 'info': '#6b7a99'}
    GRADE_HEX = {'A':'#00c853','B':'#00c853','C':'#f9a825','D':'#fb8c00','F':'#e53935'}

    def to_hex(c):
        """Convert a ReportLab color to #RRGGBB string safe for Paragraph markup."""
        try:
            h = str(c.hexval())                    # e.g. '0x00c853'
            return '#' + h.replace('0x','').zfill(6)
        except Exception:
            try:
                return '#{:02x}{:02x}{:02x}'.format(
                    int(c.red*255), int(c.green*255), int(c.blue*255))
            except Exception:
                return '#555555'

    SEV_BG = {
        'critical': colors.HexColor('#fff5f5'),
        'high':     colors.HexColor('#fff8f0'),
        'medium':   colors.HexColor('#fffde7'),
        'low':      colors.HexColor('#f0fff4'),
        'info':     colors.HexColor('#f5f7ff'),
    }

    # ── Paragraph styles (all dark text for white paper) ──────────────
    def P(name, **kw):
        defaults = dict(fontName='Helvetica', fontSize=9, textColor=C_BODY,
                        leading=13, spaceAfter=2)
        defaults.update(kw)
        return ParagraphStyle(name, **defaults)

    S_TITLE  = P('TI', fontName='Helvetica-Bold', fontSize=24, textColor=C_WHITE,
                 leading=28, spaceAfter=4)
    S_SUB    = P('SU', fontName='Helvetica', fontSize=10, textColor=C_GREEN,
                 leading=14, spaceAfter=2)
    S_H1     = P('H1', fontName='Helvetica-Bold', fontSize=14, textColor=C_BLACK,
                 leading=17, spaceBefore=8, spaceAfter=5)
    S_H2     = P('H2', fontName='Helvetica-Bold', fontSize=11, textColor=C_BLACK,
                 leading=14, spaceBefore=6, spaceAfter=3)
    S_BODY   = P('BO', fontName='Helvetica', fontSize=9,  textColor=C_BODY,
                 leading=13, spaceAfter=2)
    S_SMALL  = P('SM', fontName='Helvetica', fontSize=8,  textColor=C_LABEL,
                 leading=11, spaceAfter=1)
    S_MONO   = P('MO', fontName='Courier',   fontSize=8,  textColor=C_MONO,
                 leading=11, spaceAfter=1)
    S_MONO_B = P('MB', fontName='Courier-Bold', fontSize=8, textColor=C_BODY,
                 leading=11, spaceAfter=1)
    S_LABEL  = P('LB', fontName='Helvetica-Bold', fontSize=8, textColor=C_LABEL,
                 leading=10, spaceAfter=1)
    S_FOOT   = P('FO', fontName='Helvetica', fontSize=7, textColor=C_LABEL,
                 alignment=TA_CENTER, leading=10)
    S_CENTER = P('CE', fontName='Helvetica-Bold', fontSize=20, textColor=C_WHITE,
                 alignment=TA_CENTER, leading=24)
    S_GRADE  = P('GR', fontName='Helvetica-Bold', fontSize=36, textColor=C_GREEN,
                 alignment=TA_CENTER, leading=40)

    W = A4[0] - 40*mm   # usable content width
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=15*mm, bottomMargin=15*mm,
                            title=f"VENOM AI Report — {target_url}",
                            author="VENOM AI Security Platform")
    story = []

    def hr(color=C_BORDER, thick=0.5, space_before=2, space_after=4):
        return HRFlowable(width="100%", thickness=thick, color=color,
                          spaceBefore=space_before, spaceAfter=space_after)

    def tbl(data, widths, style_cmds, h_pad=4, v_pad=4):
        t = Table(data, colWidths=widths, repeatRows=1)
        base = [
            ('FONTSIZE',     (0,0), (-1,-1), 9),
            ('BOTTOMPADDING',(0,0), (-1,-1), v_pad),
            ('TOPPADDING',   (0,0), (-1,-1), v_pad),
            ('LEFTPADDING',  (0,0), (-1,-1), h_pad),
            ('RIGHTPADDING', (0,0), (-1,-1), h_pad),
            ('VALIGN',       (0,0), (-1,-1), 'TOP'),
        ]
        base.extend(style_cmds)
        t.setStyle(TableStyle(base))
        return t

    # ══════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════
    score_col = C_GREEN if score_val >= 80 else C_YELLOW if score_val >= 60 else C_RED
    grade_col = {'A':C_GREEN,'B':C_GREEN,'C':C_YELLOW,'D':C_ORANGE,'F':C_RED}.get(grade, C_RED)

    cover_data = [[
        Paragraph("VENOM AI", S_TITLE),
        Paragraph(f"<font color='#00c853'>{score_val}</font>", S_CENTER)
    ]]
    cover_tbl = Table(cover_data, colWidths=[W*0.7, W*0.3])
    cover_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), C_BG),
        ('TOPPADDING',    (0,0), (-1,-1), 16),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('RIGHTPADDING',  (0,0), (-1,-1), 12),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(cover_tbl)

    # Sub-header dark bar
    sub_data = [[
        Paragraph("Security Assessment Report · v2.0", S_SUB),
        Paragraph("CONFIDENTIAL", P('CF', fontName='Helvetica-Bold', fontSize=8,
                                    textColor=C_GREEN, alignment=TA_RIGHT))
    ]]
    sub_tbl = Table(sub_data, colWidths=[W*0.7, W*0.3])
    sub_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), C_PANEL),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('RIGHTPADDING',  (0,0), (-1,-1), 12),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(sub_tbl)
    story.append(Spacer(1, 4*mm))

    # ── Scan metadata table ───────────────────────────────────────────
    meta_rows = [
        [Paragraph('<b>Target URL</b>', S_LABEL),
         Paragraph(target_url, S_MONO_B)],
        [Paragraph('<b>Scan ID</b>', S_LABEL),
         Paragraph(str(scan_id), S_MONO)],
        [Paragraph('<b>Scan Type</b>', S_LABEL),
         Paragraph(scan_type, S_MONO_B)],
        [Paragraph('<b>Started</b>', S_LABEL),
         Paragraph(date_str, S_MONO)],
        [Paragraph('<b>Completed</b>', S_LABEL),
         Paragraph(end_str, S_MONO)],
        [Paragraph('<b>Duration</b>', S_LABEL),
         Paragraph(dur_str, S_MONO)],
        [Paragraph('<b>Report Generated</b>', S_LABEL),
         Paragraph(gen_str, S_MONO)],
        [Paragraph('<b>Security Score</b>', S_LABEL),
         Paragraph(f'<font color="{to_hex(score_col)}"><b>{score_val}/100</b></font>  —  Grade: <font color="{GRADE_HEX.get(grade,"#e53935")}"><b>{grade}</b></font>', S_BODY)],
    ]
    story.append(tbl(meta_rows, [45*mm, W - 45*mm], [
        ('BACKGROUND',    (0,0), (-1,-1), C_PAGE),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [C_PAGE, colors.white]),
        ('LINEBELOW',     (0,0), (-1,-2), 0.25, C_BORDER),
        ('FONTNAME',      (0,0), (0,-1), 'Helvetica-Bold'),
    ], v_pad=5))
    story.append(Spacer(1, 4*mm))

    # ── Score + severity counts side by side ──────────────────────────
    sev_rows = [
        [Paragraph('<b>Severity</b>', S_LABEL), Paragraph('<b>Count</b>', S_LABEL),
         Paragraph('<b>SLA</b>', S_LABEL), Paragraph('<b>Weight</b>', S_LABEL)],
        [Paragraph('<b><font color="#e53935">CRITICAL</font></b>', S_BODY),
         Paragraph(f'<b>{cnt["critical"]}</b>', S_BODY),
         Paragraph('Immediate', S_SMALL), Paragraph('25 pts', S_SMALL)],
        [Paragraph('<b><font color="#fb8c00">HIGH</font></b>', S_BODY),
         Paragraph(f'<b>{cnt["high"]}</b>', S_BODY),
         Paragraph('Within 48 h', S_SMALL), Paragraph('15 pts', S_SMALL)],
        [Paragraph('<b><font color="#f9a825">MEDIUM</font></b>', S_BODY),
         Paragraph(f'<b>{cnt["medium"]}</b>', S_BODY),
         Paragraph('2 weeks', S_SMALL), Paragraph('8 pts', S_SMALL)],
        [Paragraph('<b><font color="#00c853">LOW</font></b>', S_BODY),
         Paragraph(f'<b>{cnt["low"]}</b>', S_BODY),
         Paragraph('Next cycle', S_SMALL), Paragraph('3 pts', S_SMALL)],
        [Paragraph('INFO', S_SMALL),
         Paragraph(str(cnt["info"]), S_SMALL),
         Paragraph('As needed', S_SMALL), Paragraph('0 pts', S_SMALL)],
        [Paragraph('<b>TOTAL</b>', S_LABEL),
         Paragraph(f'<b>{total}</b>', S_BODY),
         Paragraph(f'PoE confirmed: {poe_cnt}', S_SMALL),
         Paragraph(f'False pos.: {fp_cnt}', S_SMALL)],
    ]
    cw = W / 4
    story.append(tbl(sev_rows, [cw]*4, [
        ('BACKGROUND',    (0,0), (-1,0),  C_PANEL),
        ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('ROWBACKGROUNDS',(0,1), (-1,-2), [C_PAGE, colors.white]),
        ('BACKGROUND',    (0,-1),(-1,-1), C_PAGE),
        ('FONTNAME',      (0,-1),(-1,-1), 'Helvetica-Bold'),
        ('GRID',          (0,0), (-1,-1), 0.3, C_BORDER),
        ('LINEABOVE',     (0,-1),(-1,-1), 1,   C_BORDER),
    ], v_pad=5))
    story.append(Spacer(1, 4*mm))

    # ── AI Risk Assessment ────────────────────────────────────────────
    ai_rows = [[Paragraph('<b>AI Risk Assessment</b>', S_LABEL)],
               [Paragraph(ai_summary, S_BODY)]]
    story.append(tbl(ai_rows, [W], [
        ('BACKGROUND', (0,0), (-1,0), C_PANEL),
        ('TEXTCOLOR',  (0,0), (-1,0), C_WHITE),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f0fff4')),
        ('GRID',       (0,0), (-1,-1), 0.3, C_BORDER),
    ], v_pad=6))
    story.append(Spacer(1, 3*mm))

    # ══════════════════════════════════════════════════════════════════
    # VULNERABILITY SUMMARY TABLE (all findings at a glance)
    # ══════════════════════════════════════════════════════════════════
    if sv:
        story.append(hr(C_GREEN, thick=1))
        story.append(Paragraph(f"Vulnerability Summary  ({len(sv)} findings)", S_H1))
        header = [
            Paragraph('#', S_LABEL), Paragraph('Severity', S_LABEL),
            Paragraph('Title', S_LABEL), Paragraph('CWE', S_LABEL),
            Paragraph('CVE', S_LABEL), Paragraph('CVSS', S_LABEL),
        ]
        rows = [header]
        alt_bg = [C_PAGE, colors.white]
        for i, v in enumerate(sv):
            sev   = (v.get('severity') or 'info').lower()
            sc    = SEV_C.get(sev, C_LABEL)
            poe   = ' ⚡' if v.get('poe_confirmed') else ''
            rows.append([
                Paragraph(str(i+1), S_SMALL),
                Paragraph(f'<b><font color="{SEV_HEX.get(sev, "#555555")}">{sev.upper()}</font></b>', S_SMALL),
                Paragraph(str(v.get('title','Unknown')) + poe, S_BODY),
                Paragraph(str(v.get('cwe_id') or '—'), S_SMALL),
                Paragraph(str(v.get('cve_id') or '—'), S_SMALL),
                Paragraph(str(v.get('cvss_score') or '—'), S_SMALL),
            ])
        story.append(tbl(rows, [8*mm, 22*mm, W-85*mm, 18*mm, 22*mm, 15*mm], [
            ('BACKGROUND',    (0,0), (-1,0),  C_PANEL),
            ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), alt_bg),
            ('GRID',          (0,0), (-1,-1), 0.25, C_BORDER),
            ('WORDWRAP',      (0,0), (-1,-1), True),
        ], v_pad=4))
        story.append(Spacer(1, 4*mm))

    # ══════════════════════════════════════════════════════════════════
    # DETAILED FINDINGS — every field, tight spacing
    # ══════════════════════════════════════════════════════════════════
    if sv:
        story.append(hr(C_GREEN, thick=1))
        story.append(Paragraph(f"Detailed Findings  ({len(sv)} total)", S_H1))

        for i, v in enumerate(sv, 1):
            sev   = (v.get('severity') or 'info').lower()
            sc    = SEV_C.get(sev, C_LABEL)
            sbg   = SEV_BG.get(sev, C_PAGE)
            title = str(v.get('title') or v.get('vuln_type') or 'Unknown Finding')
            poe   = v.get('poe_confirmed', False)
            fp    = v.get('false_positive', False)

            # Hex string for Paragraph XML markup
            sc_hex = SEV_HEX.get(sev, '#555555')

            # ── Finding header ────────────────────────────────────────
            poe_tag = '  [⚡ PoE CONFIRMED]' if poe else ''
            fp_tag  = '  [FALSE POSITIVE]'  if fp  else ''
            heading_para = Paragraph(
                f'<font color="{sc_hex}"><b>#{i} · [{sev.upper()}]</b></font>  '
                f'{title}{poe_tag}{fp_tag}', S_H2)

            # ── Metrics mini-table ────────────────────────────────────
            cvss = str(v.get('cvss_score') or '—')
            cwe  = str(v.get('cwe_id')     or '—')
            cve  = str(v.get('cve_id')     or '—')
            src  = str(v.get('source_tool')or 'venom')
            ver  = 'Yes ✓' if v.get('verified') else 'No'
            poe_s = 'Confirmed ⚡' if poe else 'No'
            cat  = str(v.get('category') or v.get('vuln_type') or '—')

            metrics = tbl(
                [[Paragraph('<b>CVSS</b>', S_LABEL), Paragraph('<b>CWE</b>', S_LABEL),
                  Paragraph('<b>CVE</b>', S_LABEL),  Paragraph('<b>Category</b>', S_LABEL),
                  Paragraph('<b>Source</b>', S_LABEL),Paragraph('<b>Verified</b>', S_LABEL),
                  Paragraph('<b>PoE</b>', S_LABEL)],
                 [Paragraph(f'<b><font color="{sc_hex}">{cvss}</font></b>', S_MONO_B),
                  Paragraph(cwe, S_MONO), Paragraph(cve, S_MONO), Paragraph(cat, S_SMALL),
                  Paragraph(src, S_SMALL), Paragraph(ver, S_SMALL), Paragraph(poe_s, S_SMALL)]],
                [12*mm, 18*mm, 24*mm, W-96*mm, 18*mm, 12*mm, 12*mm],
                [('BACKGROUND', (0,0), (-1,0), C_PANEL),
                 ('TEXTCOLOR',  (0,0), (-1,0), C_WHITE),
                 ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
                 ('BACKGROUND', (0,1), (-1,1), sbg),
                 ('GRID',       (0,0), (-1,-1), 0.25, C_BORDER)],
                v_pad=3
            )

            # ── Build all text fields ─────────────────────────────────
            body_items = [heading_para, metrics]

            def add_field(label, value, style=S_BODY, mono=False):
                if not value:
                    return
                st = S_MONO if mono else style
                body_items.append(tbl(
                    [[Paragraph(label, S_LABEL)], [Paragraph(str(value), st)]],
                    [W], [
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
                        ('BACKGROUND', (0,1), (-1,-1), colors.white),
                        ('LINEBELOW',  (0,-1),(-1,-1), 0.25, C_BORDER),
                    ], v_pad=3
                ))

            add_field('Affected URL',         v.get('affected_url',''),    mono=True)
            add_field('Description',          v.get('description',''))
            add_field('Impact',               v.get('impact',''))
            add_field('Evidence',             v.get('evidence',''),         mono=True)
            add_field('Proof-of-Exploit Detail', v.get('poe_detail',''),   mono=True)

            rec = v.get('recommendation') or v.get('fix') or ''
            if rec:
                body_items.append(tbl(
                    [[Paragraph('Recommended Fix / Patch', S_LABEL)],
                     [Paragraph(str(rec), S_BODY)]],
                    [W], [
                        ('BACKGROUND', (0,0), (-1,0),  colors.HexColor('#e8f5e9')),
                        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f0fff4')),
                        ('LINEBELOW',  (0,-1),(-1,-1), 0.25, C_GREEN),
                        ('LEFTPADDING',(0,0), (-1,-1), 6),
                    ], v_pad=3
                ))

            add_field('Secure Code Patch',    v.get('code_example',''),    mono=True)
            add_field('AI Analysis',          v.get('ai_explanation',''))
            add_field('Reference / Advisory', v.get('reference',''),        mono=True)

            # Additional refs list
            refs = v.get('references') or []
            if isinstance(refs, list) and refs:
                refs_text = '  |  '.join(str(r) for r in refs)
                add_field('Additional References', refs_text, mono=True)

            # Wrap entire finding in a KeepTogether block with separator
            finding_block = [
                Spacer(1, 2*mm),
            ] + body_items + [
                hr(sc, thick=0.4, space_before=2, space_after=1),
            ]
            story.append(KeepTogether(finding_block[:6]))   # header + first few fields together
            for item in finding_block[6:]:
                story.append(item)

    else:
        story.append(Spacer(1, 4*mm))
        story.append(tbl(
            [[Paragraph('No vulnerabilities found for this scan.', S_BODY)]],
            [W], [('BACKGROUND', (0,0), (-1,-1), C_PAGE),
                  ('GRID', (0,0), (-1,-1), 0.25, C_BORDER)], v_pad=10
        ))

    # ══════════════════════════════════════════════════════════════════
    # FULL REMEDIATION ROADMAP
    # ══════════════════════════════════════════════════════════════════
    story.append(hr(C_GREEN, thick=1))
    story.append(Paragraph("Full Remediation Roadmap", S_H1))

    for sev_key, sev_label, sev_c in [
        ('critical', 'CRITICAL — Immediate Action Required', C_RED),
        ('high',     'HIGH — Fix Within 48 Hours',           C_ORANGE),
        ('medium',   'MEDIUM — Fix Within 2 Weeks',          C_YELLOW),
        ('low',      'LOW — Fix in Next Release Cycle',       C_GREEN),
    ]:
        group = [v for v in sv if (v.get('severity') or 'info').lower() == sev_key]
        if not group:
            continue
        sc_hex = SEV_HEX.get(sev_key, '#555555')
        story.append(Paragraph(
            f'<font color="{sc_hex}"><b>▌ {sev_label}  ({len(group)} issues)</b></font>',
            S_H2))
        for idx, v in enumerate(group, 1):
            title   = str(v.get('title') or 'Unknown')
            fix_txt = str(v.get('recommendation') or v.get('fix') or
                          'Apply security best practices. Patch the affected component.')
            url_txt = str(v.get('affected_url') or '')
            poe_str = ' [⚡PoE]' if v.get('poe_confirmed') else ''
            row_data = [
                [Paragraph(f'<b>{idx}. {title}{poe_str}</b>', S_BODY),
                 Paragraph(fix_txt, S_SMALL)],
            ]
            if url_txt:
                row_data.append([Paragraph('URL:', S_LABEL), Paragraph(url_txt, S_MONO)])
            story.append(tbl(row_data, [35*mm, W-35*mm], [
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_PAGE, colors.white]),
                ('LINEBELOW', (0,-1), (-1,-1), 0.25, C_BORDER),
            ], v_pad=3))
        story.append(Spacer(1, 2*mm))

    # ══════════════════════════════════════════════════════════════════
    # APPENDIX — Scan Metadata
    # ══════════════════════════════════════════════════════════════════
    story.append(hr(C_GREEN, thick=1))
    story.append(Paragraph("Appendix — Scan Metadata", S_H1))
    tool_counts = {}
    for v in sv:
        t = str(v.get('source_tool') or 'venom')
        tool_counts[t] = tool_counts.get(t, 0) + 1
    tool_rows = [[Paragraph('<b>Tool / Source</b>', S_LABEL),
                  Paragraph('<b>Findings</b>', S_LABEL)]]
    for t, c in sorted(tool_counts.items(), key=lambda x: -x[1]):
        tool_rows.append([Paragraph(t, S_MONO), Paragraph(str(c), S_BODY)])
    story.append(tbl(tool_rows, [80*mm, 30*mm], [
        ('BACKGROUND',    (0,0), (-1,0),  C_PANEL),
        ('TEXTCOLOR',     (0,0), (-1,0),  C_WHITE),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [C_PAGE, colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.25, C_BORDER),
    ], v_pad=4))

    story.append(Spacer(1, 4*mm))
    story.append(tbl(
        [[Paragraph(
            'This report was generated automatically by VENOM AI. All findings should be '
            'validated by a qualified security professional before remediation. '
            'False positives may be present. This document is CONFIDENTIAL.',
            S_SMALL)]],
        [W], [('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fafbff')),
              ('GRID', (0,0), (-1,-1), 0.25, C_BORDER)], v_pad=8
    ))

    # ── Footer ────────────────────────────────────────────────────────
    story.append(Spacer(1, 4*mm))
    story.append(hr(C_BORDER, thick=0.5))
    story.append(Paragraph(
        f"VENOM AI Security Platform  ·  Generated: {gen_str}  ·  Scan #{scan_id}  ·  CONFIDENTIAL",
        S_FOOT))

    doc.build(story)
    return buf.getvalue()


@router.get("/generate/{scan_id}")
async def generate_report(scan_id: str,
                          current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """Generate and download a PDF security report for a scan (owner only, Pro+ feature)."""
    require_feature(current_user, "pdf_reports")
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, scan_id, current_user)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        vuln_dicts = [_vuln_to_dict(v) for v in vulns]
        html = _build_html_report(scan, vuln_dicts, scan_id)

        # Try WeasyPrint first (best quality)
        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html).write_pdf()
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="venom-report-{scan_id[:8]}.pdf"'}
            )
        except ImportError:
            pass

        # Try xhtml2pdf second
        try:
            from xhtml2pdf import pisa
            import io
            buf = io.BytesIO()
            pisa.CreatePDF(html, dest=buf)
            pdf_bytes = buf.getvalue()
            if pdf_bytes:
                return Response(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="venom-report-{scan_id[:8]}.pdf"'}
                )
        except ImportError:
            pass

        # ReportLab fallback — always available (in requirements.txt)
        try:
            pdf_bytes = _build_reportlab_pdf(scan, vuln_dicts, scan_id)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="venom-report-{scan_id[:8]}.pdf"'}
            )
        except Exception as rl_err:
            logger.warning(f"ReportLab PDF failed: {rl_err}")

        # Last resort: return HTML so user can print-to-PDF from browser
        logger.warning(f"All PDF libraries failed. Returning HTML for scan {scan_id}.")
        return Response(
            content=html.encode("utf-8"),
            media_type="text/html",
            headers={"Content-Disposition": f'inline; filename="venom-report-{scan_id[:8]}.html"'}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
    finally:
        db.close()


class EmailReportRequest(BaseModel):
    email: str


@router.post("/email/{scan_id}")
async def email_report(scan_id: str, req: EmailReportRequest,
                       current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """Generate the PDF report for a scan and email it as an attachment (owner only)."""
    from pydantic import BaseModel as _BM

    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, scan_id, current_user)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        vuln_dicts = [_vuln_to_dict(v) for v in vulns]
        html = _build_html_report(scan, vuln_dicts, scan_id)

        # Generate PDF bytes (same chain as download endpoint)
        pdf_bytes: bytes | None = None
        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html).write_pdf()
        except ImportError:
            pass

        if not pdf_bytes:
            try:
                from xhtml2pdf import pisa
                import io
                buf = io.BytesIO()
                pisa.CreatePDF(html, dest=buf)
                if buf.tell() > 0:
                    pdf_bytes = buf.getvalue()
            except ImportError:
                pass

        if not pdf_bytes:
            try:
                pdf_bytes = _build_reportlab_pdf(scan, vuln_dicts, scan_id)
            except Exception:
                pass

        # Fall back to HTML attachment if no PDF lib available
        if pdf_bytes:
            attachment_bytes = pdf_bytes
            attachment_name  = f"venom-report-{scan_id[:8]}.pdf"
        else:
            attachment_bytes = html.encode("utf-8")
            attachment_name  = f"venom-report-{scan_id[:8]}.html"

        # Build email
        score     = getattr(scan, "security_score", 0) or 0
        grade     = getattr(scan, "grade", "F") or "F"
        total     = getattr(scan, "total_issues", 0) or len(vuln_dicts)
        critical  = getattr(scan, "critical_count", 0) or sum(1 for v in vuln_dicts if v.get("severity") == "critical")
        high      = getattr(scan, "high_count", 0)     or sum(1 for v in vuln_dicts if v.get("severity") == "high")
        medium    = getattr(scan, "medium_count", 0)   or sum(1 for v in vuln_dicts if v.get("severity") == "medium")
        low       = getattr(scan, "low_count", 0)      or sum(1 for v in vuln_dicts if v.get("severity") == "low")

        from routes.email_service import send_email, build_report_email
        html_email = build_report_email(
            target_url=scan.target_url or "Unknown",
            score=score, grade=grade, total=total,
            critical=critical, high=high, medium=medium, low=low,
            scan_id=scan_id,
        )
        subject = f"📊 VENOM AI Security Report — {scan.target_url or 'Unknown'}"
        ok = send_email(req.email, subject, html_email, attachment_bytes, attachment_name)
        if ok:
            return {"message": f"Report emailed to {req.email}", "attachment": attachment_name}
        else:
            raise HTTPException(
                status_code=503,
                detail="Email could not be sent. Check SMTP_USER / SMTP_PASS in your .env file.",
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email report error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email failed: {str(e)}")
    finally:
        db.close()


@router.get("/consolidated")
async def consolidated_report(current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """
    Generate a single PDF summarising ALL of the current user's completed scans:
    one cover page + a portfolio table + a one-page per-scan section.

    Returns the PDF as a streaming download.

    Gated to Starter+ (pdf_reports feature flag).
    """
    require_feature(current_user, "pdf_reports")
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak)
    from reportlab.lib.enums import TA_LEFT, TA_CENTER

    db = _get_db()
    models = _get_models()
    try:
        q = db.query(models.ScanJob).filter(models.ScanJob.status == "COMPLETED")
        if current_user is not None:
            q = q.filter(models.ScanJob.owner_id == current_user.id)
        else:
            q = q.filter(models.ScanJob.owner_id.is_(None))
        scans = q.order_by(models.ScanJob.created_at.desc()).all()

        if not scans:
            raise HTTPException(404, "No completed scans found to consolidate.")

        # ── PDF skeleton ────────────────────────────────────────────────
        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=18*mm, rightMargin=18*mm,
            topMargin=18*mm, bottomMargin=18*mm,
            title="VENOM AI — Consolidated Security Report",
        )

        ACID  = colors.HexColor("#39ff14")
        DARK  = colors.HexColor("#0a0f18")
        TEXT  = colors.HexColor("#1c2333")
        MUTED = colors.HexColor("#6b7a99")
        RED   = colors.HexColor("#dc143c")
        ORG   = colors.HexColor("#fb8c00")
        YEL   = colors.HexColor("#f9a825")

        h1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=26,
                            textColor=DARK, alignment=TA_CENTER, leading=30, spaceAfter=8)
        h2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=15,
                            textColor=DARK, leading=18, spaceBefore=14, spaceAfter=6)
        body  = ParagraphStyle("b", fontName="Helvetica", fontSize=10,
                               textColor=TEXT, leading=14, spaceAfter=4)
        small = ParagraphStyle("s", fontName="Helvetica", fontSize=9,
                               textColor=MUTED, leading=12, alignment=TA_CENTER)
        cap   = ParagraphStyle("c", fontName="Helvetica", fontSize=11,
                               textColor=MUTED, leading=14, alignment=TA_CENTER, spaceAfter=18)

        story = []

        # ── Cover ───────────────────────────────────────────────────────
        owner_name = (
            (current_user.full_name or current_user.username or current_user.email)
            if current_user else "Guest"
        )
        story.append(Spacer(1, 40*mm))
        story.append(Paragraph("VENOM AI", h1))
        story.append(Paragraph("Consolidated Security Report", cap))
        story.append(Spacer(1, 30*mm))

        # Portfolio totals
        avg_score = round(sum((s.security_score or 0) for s in scans) / len(scans), 1)
        tot_issues = sum((s.total_issues or 0) for s in scans)

        cover_t = Table(
            [
                ["Account",          owner_name],
                ["Generated",        datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")],
                ["Total scans",      str(len(scans))],
                ["Average score",    f"{avg_score} / 100"],
                ["Total findings",   str(tot_issues)],
            ],
            colWidths=[55*mm, 95*mm],
        )
        cover_t.setStyle(TableStyle([
            ("FONTNAME", (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE", (0,0),(-1,-1), 11),
            ("TEXTCOLOR",(0,0),(0,-1), MUTED),
            ("TEXTCOLOR",(1,0),(1,-1), DARK),
            ("FONTNAME", (1,0),(1,-1), "Helvetica-Bold"),
            ("LINEBELOW",(0,0),(-1,-1), 0.4, colors.HexColor("#e5e8ee")),
            ("LEFTPADDING",(0,0),(-1,-1), 12),
            ("RIGHTPADDING",(0,0),(-1,-1), 12),
            ("TOPPADDING",(0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ]))
        story.append(cover_t)
        story.append(PageBreak())

        # ── Portfolio table ─────────────────────────────────────────────
        story.append(Paragraph("Portfolio Overview", h2))
        story.append(Paragraph(
            f"All {len(scans)} completed scans, most recent first.", body))
        story.append(Spacer(1, 6))

        rows = [["#", "Target", "Date", "Score", "Grade", "Issues"]]
        for i, s in enumerate(scans, 1):
            dt = s.created_at.strftime("%d %b %Y") if s.created_at else "—"
            target = (s.target_url or "—")[:50]
            score = s.security_score if s.security_score is not None else 0
            grade = s.grade or "—"
            rows.append([str(i), target, dt, f"{score}", grade, str(s.total_issues or 0)])

        port_t = Table(rows, colWidths=[10*mm, 70*mm, 28*mm, 16*mm, 16*mm, 18*mm])
        port_t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), DARK),
            ("TEXTCOLOR", (0,0),(-1,0), ACID),
            ("FONTNAME",  (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1), 9),
            ("ALIGN",     (0,0),(-1,-1), "CENTER"),
            ("ALIGN",     (1,1),(1,-1),  "LEFT"),
            ("VALIGN",    (0,0),(-1,-1), "MIDDLE"),
            ("TEXTCOLOR", (0,1),(-1,-1), TEXT),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#f6f9f7")]),
            ("LINEBELOW", (0,0),(-1,-1), 0.3, colors.HexColor("#dde2ea")),
            ("TOPPADDING",   (0,0),(-1,-1), 7),
            ("BOTTOMPADDING",(0,0),(-1,-1), 7),
        ]))
        story.append(port_t)
        story.append(PageBreak())

        # ── Per-scan detail pages ──────────────────────────────────────
        for i, s in enumerate(scans, 1):
            target = s.target_url or "—"
            score = s.security_score if s.security_score is not None else 0
            grade = s.grade or "—"
            issues = s.total_issues or 0
            dt = s.created_at.strftime("%d %b %Y · %H:%M") if s.created_at else "—"

            story.append(Paragraph(f"Scan #{i} — {target}", h2))
            story.append(Paragraph(f"Scanned on {dt}", small))
            story.append(Spacer(1, 8))

            score_color = (
                colors.HexColor("#39ff14") if score >= 90 else
                colors.HexColor("#f9a825") if score >= 70 else
                colors.HexColor("#fb8c00") if score >= 50 else
                colors.HexColor("#dc143c")
            )
            detail = Table(
                [
                    ["Security Score", f"{score} / 100"],
                    ["Grade",          grade],
                    ["Total Issues",   str(issues)],
                    ["Critical",       str(getattr(s, "critical_count", 0) or 0)],
                    ["High",           str(getattr(s, "high_count", 0) or 0)],
                    ["Medium",         str(getattr(s, "medium_count", 0) or 0)],
                    ["Low",            str(getattr(s, "low_count", 0) or 0)],
                    ["Status",         (s.status or "—").title()],
                ],
                colWidths=[55*mm, 95*mm],
            )
            detail.setStyle(TableStyle([
                ("FONTNAME", (0,0),(-1,-1), "Helvetica"),
                ("FONTSIZE", (0,0),(-1,-1), 10),
                ("TEXTCOLOR",(0,0),(0,-1), MUTED),
                ("TEXTCOLOR",(1,0),(1,0),  score_color),
                ("FONTNAME", (1,0),(1,-1), "Helvetica-Bold"),
                ("LINEBELOW",(0,0),(-1,-1), 0.4, colors.HexColor("#e5e8ee")),
                ("LEFTPADDING",(0,0),(-1,-1), 12),
                ("TOPPADDING", (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1), 6),
            ]))
            story.append(detail)

            if i < len(scans):
                story.append(PageBreak())

        # Footer with timestamp
        story.append(Spacer(1, 20))
        story.append(Paragraph(
            f"Generated by VENOM AI · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            small,
        ))

        doc.build(story)
        pdf_bytes = buf.getvalue()
        buf.close()

        filename = f"venom-consolidated-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        db.close()


@router.get("/")
async def list_reports(current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """List completed scans available for report generation — current user only."""
    db = _get_db()
    models = _get_models()
    try:
        q = db.query(models.ScanJob).filter(models.ScanJob.status == "COMPLETED")
        if current_user is not None:
            q = q.filter(models.ScanJob.owner_id == current_user.id)
        else:
            q = q.filter(models.ScanJob.owner_id.is_(None))
        scans = q.order_by(models.ScanJob.created_at.desc()).limit(50).all()
        return {
            "reports": [
                {
                    "scan_id": s.id,
                    "task_id": getattr(s, "celery_task_id", None) or s.id,
                    "target_url": s.target_url,
                    "security_score": getattr(s, "security_score", 0) or 0,
                    "grade": getattr(s, "grade", "F") or "F",
                    "total_issues": getattr(s, "total_issues", 0) or 0,
                    "created_at": str(s.created_at),
                    "download_url": f"/api/reports/generate/{s.id}",
                }
                for s in scans
            ],
            "total": len(scans),
        }
    finally:
        db.close()