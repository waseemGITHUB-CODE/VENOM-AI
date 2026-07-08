"""
workers/report_worker.py
Professional Report Generation Worker

Generates:
  - Security Audit Reports (with vulnerability details)
  - Document Extraction Summaries
  - Compliance Reports
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# @celery_app.task(name="workers.report_worker.generate_report")
def generate_report(scan_id: Optional[str], doc_id: Optional[str],
                    user_id: str, report_type: str, report_id: str) -> dict:
    """Generate a professional report in PDF/DOCX format."""
    logger.info(f"Generating {report_type} report: {report_id}")

    try:
        if report_type == "security_audit" and scan_id:
            scan_data   = fetch_scan_data(scan_id)
            report_path = build_security_report(report_id, scan_data)

        elif report_type == "doc_summary" and doc_id:
            doc_data    = fetch_doc_data(doc_id)
            report_path = build_doc_summary_report(report_id, doc_data)

        else:
            raise ValueError(f"Unknown report type: {report_type}")

        store_report(report_id, report_type, str(report_path))
        logger.info(f"Report generated: {report_path}")
        return {"status": "done", "report_id": report_id, "path": str(report_path)}

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise


# ── Security Audit Report Builder ────────────────────────────
def build_security_report(report_id: str, scan_data: dict) -> Path:
    """Build a professional security audit PDF report using ReportLab."""

    # In production, use reportlab or weasyprint:
    # from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
    # from reportlab.lib.styles import getSampleStyleSheet
    # from reportlab.lib import colors

    output_path = REPORTS_DIR / f"{report_id}.txt"  # .pdf in production

    report_content = f"""
SECURITY AUDIT REPORT
=====================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Report ID: {report_id}

TARGET INFORMATION
------------------
Website: {scan_data.get('url', 'N/A')}
Scan Date: {scan_data.get('scanned_at', 'N/A')}

EXECUTIVE SUMMARY
-----------------
Security Score: {scan_data.get('security_score', 0)}/100  Grade: {scan_data.get('grade', 'N/A')}

{scan_data.get('ai_summary', 'No summary available.')}

VULNERABILITY SUMMARY
---------------------
Critical Issues:  {scan_data.get('critical_count', 0)}
High Issues:      {scan_data.get('high_count', 0)}
Medium Issues:    {scan_data.get('medium_count', 0)}
Low Issues:       {scan_data.get('low_count', 0)}
Total Issues:     {scan_data.get('total_issues', 0)}

DETAILED FINDINGS
-----------------
"""
    for i, vuln in enumerate(scan_data.get('vulnerabilities', []), 1):
        report_content += f"""
Finding #{i}: {vuln.get('title', '')}
Severity:       {vuln.get('severity', '').upper()}
Type:           {vuln.get('vuln_type', '')}
Description:    {vuln.get('description', '')}
Evidence:       {vuln.get('evidence', '')}
Recommendation: {vuln.get('recommendation', '')}
{'─' * 50}"""

    report_content += """

TECHNICAL DETAILS
-----------------
Open Ports:     """ + str(scan_data.get('open_ports', [])) + """
Detected Tech:  """ + json.dumps(scan_data.get('detected_tech', {}), indent=2) + """

RECOMMENDATIONS SUMMARY
-----------------------
1. Immediately address all CRITICAL severity issues
2. Fix HIGH severity issues within 7 days
3. Schedule MEDIUM issues for next maintenance window
4. Review LOW issues in quarterly security review

DISCLAIMER
----------
This automated scan provides a point-in-time security assessment.
A manual penetration test is recommended for comprehensive security evaluation.
"""

    output_path.write_text(report_content)
    return output_path


def build_doc_summary_report(report_id: str, doc_data: dict) -> Path:
    """Build a document extraction summary report."""
    output_path = REPORTS_DIR / f"{report_id}.txt"

    report_content = f"""
DOCUMENT EXTRACTION REPORT
===========================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Report ID: {report_id}

DOCUMENT INFORMATION
--------------------
Filename:  {doc_data.get('filename', 'N/A')}
Category:  {doc_data.get('category', 'N/A')}
Processed: {doc_data.get('processed_at', 'N/A')}

EXTRACTED FIELDS
----------------
"""
    fields = doc_data.get('fields', {})
    for key, value in fields.items():
        report_content += f"{key:<25}: {value}\n"

    report_content += f"""

AI SUMMARY
----------
{doc_data.get('summary', 'No summary available.')}
"""
    output_path.write_text(report_content)
    return output_path


# ── Data Fetchers ─────────────────────────────────────────────
def fetch_scan_data(scan_id: str) -> dict:
    """Fetch scan result from database."""
    # In production: SELECT * FROM scan_results JOIN vulnerabilities WHERE target_id=...
    return {
        "url": "https://example.com",
        "security_score": 72,
        "grade": "C",
        "ai_summary": "Your website has moderate security issues that should be addressed.",
        "critical_count": 0, "high_count": 2, "medium_count": 3, "low_count": 4,
        "total_issues": 9,
        "vulnerabilities": [
            {"title": "Missing HSTS Header", "severity": "high",
             "vuln_type": "Missing Header", "description": "HSTS not configured",
             "evidence": "Header not found", "recommendation": "Add HSTS header"},
        ],
        "open_ports": [80, 443, 22],
        "detected_tech": {"cms": "WordPress", "server": "nginx"},
    }


def fetch_doc_data(doc_id: str) -> dict:
    """Fetch document extraction data from database."""
    return {
        "filename": "invoice_001.pdf",
        "category": "invoice",
        "processed_at": datetime.now().isoformat(),
        "fields": {
            "company_name": "Acme Corp",
            "invoice_number": "INV-2024-001",
            "invoice_amount": "$5,250.00",
        },
        "summary": "Invoice from Supplier Ltd for $5,250.00 due on Feb 15, 2024.",
    }


def store_report(report_id: str, report_type: str, file_path: str):
    """Store report metadata in database."""
    logger.info(f"Stored report {report_id} at {file_path}")
    # In production: UPDATE reports SET file_path=..., status='done' WHERE id=...
