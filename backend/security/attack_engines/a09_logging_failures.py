"""
VENOM AI — A09 Security Logging & Alerting Failures Engine (OWASP Top 10:2025 #9)
─────────────────────────────────────────────────────────────────────────
This category is about what the app FAILS to do: detect, log, and alert on
attacks. We can't read the target's server logs, so we probe its *reactive
behaviour* — does it ever detect or block obvious attacks?

Safe tests:
  1. No attack detection — send a burst of blatantly malicious requests
     (classic SQLi / XSS / path-traversal probes). If the app never blocks,
     rate-limits, or challenges us, it has no active detection/alerting.
  2. Errors expose internal detail instead of being logged & sanitised
     (verbose error leakage, which also implies poor log hygiene).

We send a SMALL number of harmless probe strings (they don't exploit
anything) and observe whether any protective response ever appears.
"""
from __future__ import annotations

import logging
import time
from typing import List
from urllib.parse import urlparse

from .common import AttackClient, Finding, inject_into_url

logger = logging.getLogger("venom.attack.a09")


# Blatant attack signatures — WAFs/IDS should flag these instantly.
LOUD_PROBES = [
    "?q=' OR '1'='1' --",
    "?q=<script>alert(document.cookie)</script>",
    "?file=../../../../etc/passwd",
    "?cmd=;cat /etc/passwd",
    "?id=1 UNION SELECT username,password FROM users",
    "?x=<img src=x onerror=alert(1)>",
]


def test_no_attack_detection(client: AttackClient, target_url: str) -> List[Finding]:
    """
    Fire a handful of obviously-malicious requests. If NONE are ever blocked
    (no 403/406/429, no WAF challenge, no CAPTCHA), the target has no active
    attack detection or alerting.
    """
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}{p.path}"

    detected = False
    detection_evidence = ""
    statuses = []
    for probe in LOUD_PROBES:
        url = base + probe
        r = client.get(url)
        if not r:
            continue
        statuses.append(r.status_code)
        body = (r.text or "").lower()[:2000]
        # WAF / detection signals
        if (r.status_code in (403, 406, 419, 429) or
                "blocked" in body or "waf" in body or "forbidden" in body or
                "request rejected" in body or "security" in body and "violation" in body or
                "captcha" in body or "suspicious" in body):
            detected = True
            detection_evidence = f"probe '{probe[:30]}...' -> HTTP {r.status_code}"
            break

    if statuses and not detected:
        findings.append(Finding(
            title="No Attack Detection / Alerting (WAF/IDS Absent)",
            category="vulnerability",
            owasp="A09",
            severity="medium",
            cwe_id="CWE-778",
            cvss_score=5.3,
            affected_url=target_url,
            evidence=(
                f"Sent {len(statuses)} blatantly malicious requests (SQLi, XSS, path "
                f"traversal, command injection). None were blocked or challenged "
                f"(statuses: {statuses})."
            ),
            description=(
                "The application accepted obviously-malicious requests without any "
                "detection, blocking, rate-limiting, or challenge. This indicates a "
                "lack of security monitoring, a Web Application Firewall, and attack "
                "alerting — attacks against this app will go unnoticed."
            ),
            impact=(
                "Attacks (and successful breaches) are neither detected nor alerted on, "
                "so an intrusion can continue for a long time before anyone notices. "
                "Per OWASP, poor logging/monitoring is a factor in most major breaches."
            ),
            recommendation=(
                "Deploy a WAF (e.g. ModSecurity, Cloudflare, AWS WAF). Log all "
                "authentication, access-control, and input-validation failures with "
                "enough context. Send real-time alerts on attack patterns and monitor "
                "them. Ensure logs are tamper-resistant and centrally aggregated."
            ),
            poc="# A burst of SQLi/XSS/traversal probes was never blocked or flagged.",
            verified=True,
            likelihood=3, impact_score=3, risk_score=9,
        ))
    return findings


def test_verbose_errors_imply_poor_logging(client: AttackClient, target_url: str) -> List[Finding]:
    """
    Trigger an error and see if raw internal details are returned to the client.
    Verbose client-facing errors usually mean the app leaks instead of logging
    server-side — a logging-hygiene failure with information disclosure.
    """
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"
    probe = base + "/%ff%fe/" + "A" * 20 + "?venom[]=1&debug=1"
    r = client.get(probe)
    if not r:
        return findings
    body = r.text or ""
    leak_markers = [
        "traceback (most recent call last)", "stack trace", "at java.",
        "system.exception", "line ", "in <module>", "sqlstate",
        "warning: ", "fatal error:", "exception in thread",
    ]
    low = body.lower()
    hits = [m for m in leak_markers if m in low]
    if r.status_code >= 500 and hits:
        findings.append(Finding(
            title="Verbose Error Leakage (Insufficient Log Sanitisation)",
            category="vulnerability",
            owasp="A09",
            severity="medium",
            cwe_id="CWE-209",
            cvss_score=5.3,
            affected_url=probe,
            evidence=f"Error response contains internal markers: {hits[:3]}",
            description=(
                "Triggering an error returned raw internal details (stack traces / "
                "framework errors) to the client instead of logging them server-side "
                "and returning a generic message. This both discloses information and "
                "signals poor logging discipline."
            ),
            impact="Internal paths, versions, and logic are disclosed; real errors may not be logged/alerted properly.",
            recommendation=(
                "Return generic error pages to clients. Log full details server-side "
                "in a structured, monitored, tamper-resistant log with alerting."
            ),
            verified=True,
            likelihood=3, impact_score=3, risk_score=9,
        ))
    return findings


def run_a09_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_no_attack_detection(client, target_url)
        except Exception as e: logger.warning(f"[A09] detection: {e}")
        try: findings += test_verbose_errors_imply_poor_logging(client, target_url)
        except Exception as e: logger.warning(f"[A09] verbose: {e}")
    finally:
        client.close()
    logger.info(f"[A09] Found {len(findings)} logging/alerting findings")
    return findings
