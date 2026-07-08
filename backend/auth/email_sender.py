"""
VENOM AI — auth/email_sender.py
Resend-first email delivery with SMTP fallback. Templated HTML emails.

If RESEND_API_KEY is set, uses Resend (recommended).
Otherwise falls back to smtplib via routes.email_service.send_email.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from core.config import settings

logger = logging.getLogger("venom.auth.email")

RESEND_API_URL = "https://api.resend.com/emails"


def _send_via_resend(to: str, subject: str, html: str) -> bool:
    """Send via Resend HTTP API. Returns True on success."""
    if not settings.RESEND_API_KEY:
        return False
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(
                RESEND_API_URL,
                headers={
                    "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "from":    settings.EMAIL_FROM,
                    "to":      [to],
                    "subject": subject,
                    "html":    html,
                },
            )
            if r.status_code >= 300:
                logger.warning(f"[Resend] {r.status_code}: {r.text[:300]}")
                return False
            logger.info(f"[Resend] sent '{subject}' → {to}")
            return True
    except Exception as e:
        logger.error(f"[Resend] error: {e}")
        return False


def _send_via_smtp(to: str, subject: str, html: str) -> bool:
    """Fallback to legacy SMTP sender."""
    try:
        from routes.email_service import send_email
        return send_email(to=to, subject=subject, html_body=html)
    except Exception as e:
        logger.error(f"[SMTP fallback] error: {e}")
        return False


def send_email(to: str, subject: str, html: str) -> bool:
    """Try Resend, then SMTP. Never raises."""
    if _send_via_resend(to, subject, html):
        return True
    return _send_via_smtp(to, subject, html)


# ── HTML email templates (cyberpunk neon theme) ───────────────────────────────
def _wrap(title: str, body_html: str, cta_url: Optional[str] = None, cta_text: Optional[str] = None) -> str:
    """Wrap content in the VENOM AI cyberpunk email shell."""
    cta_block = ""
    if cta_url and cta_text:
        cta_block = f"""
        <div style="text-align:center;margin:32px 0">
          <a href="{cta_url}" style="display:inline-block;background:#39ff14;color:#000;
             text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:800;
             font-size:13px;letter-spacing:.08em;text-transform:uppercase;
             box-shadow:0 0 24px rgba(57,255,20,.4)">{cta_text}</a>
        </div>
        <p style="font-size:11px;color:#566;text-align:center;font-family:monospace;
                  word-break:break-all;margin:12px 0">
          If the button doesn't work, paste this link into your browser:<br>
          <span style="color:#39ff14">{cta_url}</span>
        </p>"""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0d16;font-family:'Segoe UI',Arial,sans-serif;color:#c8d0e0">
  <div style="max-width:560px;margin:32px auto;border-radius:12px;overflow:hidden;
              border:1px solid rgba(57,255,20,.18);background:#0d1117">
    <div style="background:linear-gradient(135deg,#050a14,#091020);padding:28px 32px;
                border-bottom:2px solid #39ff14">
      <div style="font-family:monospace;font-size:9px;letter-spacing:4px;
                  color:#39ff14;margin-bottom:10px;opacity:.7">VENOM AI · SECURITY PLATFORM</div>
      <div style="font-size:22px;font-weight:900;color:#fff">{title}</div>
    </div>
    <div style="padding:28px 32px;font-size:14px;line-height:1.65;color:#dde0e8">
      {body_html}
      {cta_block}
    </div>
    <div style="background:#060a14;padding:16px 32px;border-top:1px solid #151b28;
                font-size:10px;color:#3a4a60;font-family:monospace;text-align:center">
      VENOM AI · Virtual Engine for Network Offensive Monitoring<br>
      You received this email because an account action was requested. Ignore if it wasn't you.
    </div>
  </div>
</body></html>"""


def send_verification_email(to: str, full_name: str, verify_url: str) -> bool:
    body = f"""
    <p>Hey <strong style="color:#39ff14">{full_name or to}</strong>,</p>
    <p>Welcome to VENOM AI. Confirm your email address to activate your account and start scanning.</p>
    <p>This link expires in {settings.EMAIL_TOKEN_EXPIRE_HOURS} hours.</p>
    """
    html = _wrap("📧 Confirm Your Email", body, verify_url, "Verify Email")
    return send_email(to, "Verify your VENOM AI account", html)


def send_password_reset_email(to: str, full_name: str, reset_url: str) -> bool:
    body = f"""
    <p>Hey <strong style="color:#39ff14">{full_name or to}</strong>,</p>
    <p>We received a request to reset your VENOM AI password.</p>
    <p>If this was you, click the button below to set a new password.
       This link expires in {settings.RESET_TOKEN_EXPIRE_HOURS} hour
       — after that you'll need to request a new one.</p>
    <p style="color:#ff8c00">If you didn't request this, ignore this email — your password is safe.</p>
    """
    html = _wrap("🔐 Password Reset", body, reset_url, "Reset Password")
    return send_email(to, "Reset your VENOM AI password", html)


def send_welcome_email(to: str, full_name: str, dashboard_url: str) -> bool:
    body = f"""
    <p>Welcome aboard, <strong style="color:#39ff14">{full_name or to}</strong>!</p>
    <p>Your VENOM AI account is verified and ready. Here's what you can do:</p>
    <ul style="line-height:1.9">
      <li>🛡️ Scan any URL for vulnerabilities — instant, deep, AI-assisted</li>
      <li>🤖 Chat with VENOM AI — vision for images, RAG for documents</li>
      <li>📊 Set up continuous monitoring with real-time email alerts</li>
      <li>📑 Generate professional security reports with one click</li>
    </ul>
    <p>Need help? Just reply to this email.</p>
    """
    html = _wrap("⚡ Welcome to VENOM AI", body, dashboard_url, "Open Dashboard")
    return send_email(to, "Welcome to VENOM AI", html)


def send_login_alert_email(to: str, full_name: str, ip: str, user_agent: str) -> bool:
    body = f"""
    <p>Hey <strong style="color:#39ff14">{full_name or to}</strong>,</p>
    <p>A new sign-in was detected on your VENOM AI account.</p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;font-family:monospace;font-size:12px">
      <tr><td style="padding:6px 0;color:#566">IP Address</td><td style="color:#39ff14">{ip}</td></tr>
      <tr><td style="padding:6px 0;color:#566">Device</td><td style="color:#39ff14">{user_agent[:80]}</td></tr>
    </table>
    <p style="color:#ff8c00">If this wasn't you, reset your password immediately.</p>
    """
    html = _wrap("🔔 New Sign-In Detected", body)
    return send_email(to, "New sign-in to your VENOM AI account", html)
