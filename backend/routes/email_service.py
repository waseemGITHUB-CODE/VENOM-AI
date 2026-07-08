"""
VENOM AI — Email Service
Sends PDF report attachments via SMTP.
Alert notifications use the desktop notification system — no email alerts.
Uses Python's built-in smtplib — no extra packages required.

Setup (Gmail):
  1. Enable 2-Step Verification on your Google Account
  2. Go to: myaccount.google.com → Security → App Passwords
  3. Generate a 16-char App Password for "Mail"
  4. Set in .env:
       SMTP_HOST=smtp.gmail.com
       SMTP_PORT=587
       SMTP_USER=you@gmail.com
       SMTP_PASS=xxxx-xxxx-xxxx-xxxx
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger("venom.email")


# ── Config ────────────────────────────────────────────────────────────────────
def _smtp_ready() -> bool:
    """Return True only when all SMTP vars are configured."""
    return all([
        os.getenv("SMTP_USER", "").strip(),
        os.getenv("SMTP_PASS", "").strip(),
        os.getenv("SMTP_HOST", "smtp.gmail.com").strip(),
    ])


def send_email(
    to: str,
    subject: str,
    html_body: str,
    attachment_bytes: Optional[bytes] = None,
    attachment_name: Optional[str] = None,
) -> bool:
    """
    Send an HTML email, optionally with a binary attachment.
    Returns True on success, False on failure (never raises).
    """
    if not _smtp_ready():
        logger.warning("[Email] SMTP not configured — set SMTP_USER / SMTP_PASS / SMTP_HOST in .env")
        return False

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    from_name = os.getenv("SMTP_FROM_NAME", "VENOM AI")
    from_addr = f"{from_name} <{smtp_user}>"

    try:
        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to

        # HTML body
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        # Optional attachment
        if attachment_bytes and attachment_name:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment_bytes)
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f'attachment; filename="{attachment_name}"',
            )
            msg.attach(part)

        ctx = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx) as s:
                s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_user, [to], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as s:
                s.ehlo()
                s.starttls(context=ctx)
                s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_user, [to], msg.as_string())

        logger.info(f"[Email] Sent '{subject}' → {to}")
        return True

    except Exception as e:
        logger.error(f"[Email] Failed to send to {to}: {e}")
        return False


# ── Report email HTML ─────────────────────────────────────────────────────────
def build_report_email(
    target_url: str,
    score: int,
    grade: str,
    total: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    scan_id: str,
) -> str:
    score_color = "#00c853" if score >= 80 else "#ffd600" if score >= 60 else "#ff1744"
    grade_color = {"A": "#00c853", "B": "#69f0ae", "C": "#ffd600", "D": "#ff6d00", "F": "#ff1744"}.get(grade, "#ff1744")

    try:
        from urllib.parse import urlparse as _up
        host = _up(target_url).hostname or target_url
    except Exception:
        host = target_url

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0d16;font-family:'Segoe UI',Arial,sans-serif;color:#c8d0e0">
  <div style="max-width:560px;margin:32px auto;border-radius:12px;overflow:hidden;
              border:1px solid rgba(57,255,20,.15);background:#0d1117">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#050a14,#091020);padding:28px 32px;
                border-bottom:2px solid #39ff14">
      <div style="font-family:monospace;font-size:9px;letter-spacing:4px;
                  color:#39ff14;margin-bottom:10px;opacity:.7">VENOM AI · SECURITY REPORT</div>
      <div style="font-size:22px;font-weight:900;color:#fff">📊 Your Security Report is Ready</div>
      <div style="font-family:monospace;font-size:12px;color:#39ff14;margin-top:8px;
                  word-break:break-all">{target_url}</div>
    </div>

    <!-- Score -->
    <div style="padding:28px 32px;display:flex;gap:24px;align-items:center;
                border-bottom:1px solid #151b28">
      <div style="text-align:center;min-width:90px">
        <div style="font-size:52px;font-weight:900;color:{score_color};line-height:1">{score}</div>
        <div style="font-size:10px;color:#566;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Score</div>
      </div>
      <div style="text-align:center;min-width:70px">
        <div style="font-size:44px;font-weight:900;color:{grade_color};line-height:1">{grade}</div>
        <div style="font-size:10px;color:#566;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Grade</div>
      </div>
      <div style="flex:1">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          <div style="background:#0a0d16;border-radius:6px;padding:10px;text-align:center;border:1px solid #ff174422">
            <div style="font-size:20px;font-weight:900;color:#ff1744">{critical}</div>
            <div style="font-size:9px;color:#566;text-transform:uppercase;letter-spacing:.08em">Critical</div>
          </div>
          <div style="background:#0a0d16;border-radius:6px;padding:10px;text-align:center;border:1px solid #ff6d0022">
            <div style="font-size:20px;font-weight:900;color:#ff6d00">{high}</div>
            <div style="font-size:9px;color:#566;text-transform:uppercase;letter-spacing:.08em">High</div>
          </div>
          <div style="background:#0a0d16;border-radius:6px;padding:10px;text-align:center;border:1px solid #ffd60022">
            <div style="font-size:20px;font-weight:900;color:#ffd600">{medium}</div>
            <div style="font-size:9px;color:#566;text-transform:uppercase;letter-spacing:.08em">Medium</div>
          </div>
          <div style="background:#0a0d16;border-radius:6px;padding:10px;text-align:center;border:1px solid #00e67622">
            <div style="font-size:20px;font-weight:900;color:#00e676">{low}</div>
            <div style="font-size:9px;color:#566;text-transform:uppercase;letter-spacing:.08em">Low</div>
          </div>
        </div>
      </div>
    </div>

    <!-- CTA -->
    <div style="padding:24px 32px;text-align:center">
      <p style="font-size:13px;color:#8898aa;margin-bottom:20px">
        The full PDF report is attached to this email. Open it to view all
        {total} finding(s) with detailed descriptions and remediation steps.
      </p>
      <a href="http://localhost:8080" style="display:inline-block;background:#39ff14;color:#000;
         text-decoration:none;padding:10px 22px;border-radius:6px;font-weight:700;
         font-size:12px;letter-spacing:.05em">Open VENOM AI →</a>
    </div>

    <!-- Footer -->
    <div style="background:#060a14;padding:16px 32px;border-top:1px solid #151b28;
                font-size:10px;color:#3a4a60;font-family:monospace;text-align:center">
      VENOM AI · Security Report · {host}
    </div>
  </div>
</body>
</html>"""
