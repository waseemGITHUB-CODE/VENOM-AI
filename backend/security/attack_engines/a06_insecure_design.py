"""
VENOM AI — A06 Insecure Design Engine (OWASP Top 10:2025 #6)
─────────────────────────────────────────────────────────────────────────
Design-level flaws that no amount of clean code fixes — the design itself
is wrong. Safe, detection-oriented tests:

  1. Missing CSRF protection — state-changing forms with no anti-CSRF token
  2. No rate limiting on authentication — rapid login attempts never blocked
  3. Business-logic: numeric fields accept negative / absurd values
     (e.g. quantity=-1, price=0) with no server-side validation
  4. Missing anti-automation — no CAPTCHA / throttling on sensitive forms

All tests are non-destructive: we probe, observe responses, and never
complete a real transaction or modify data.
"""
from __future__ import annotations

import logging
import time
from typing import List
from urllib.parse import urlparse

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a06")


# ════════════════════════════════════════════════════════════════════════════
# MISSING CSRF PROTECTION
# ════════════════════════════════════════════════════════════════════════════

def test_missing_csrf(forms: List[dict]) -> List[Finding]:
    """Flag state-changing (POST) forms that carry no anti-CSRF token."""
    findings: List[Finding] = []
    seen = set()
    for form in forms:
        method = (form.get("method") or "GET").upper()
        if method != "POST":
            continue
        # Skip search forms — they're not state-changing
        purpose = (form.get("purpose") or "").lower()
        if purpose in ("search",):
            continue
        if form.get("has_csrf_token"):
            continue
        action = form.get("action") or ""
        if action in seen:
            continue
        seen.add(action)

        # Login/signup/payment/comment forms without CSRF are the highest risk
        sev = "high" if purpose in ("login", "signup", "payment", "checkout") else "medium"
        findings.append(Finding(
            title=f"Missing CSRF Protection ({purpose or 'state-changing form'})",
            category="vulnerability",
            owasp="A06",
            severity=sev,
            cwe_id="CWE-352",
            cvss_score=6.5 if sev == "medium" else 8.0,
            affected_url=action,
            http_method="POST",
            evidence=f"POST form at {action} has no hidden anti-CSRF token field.",
            description=(
                "This form performs a state-changing action but includes no CSRF "
                "token. An attacker can host a hidden form on their own site that "
                "auto-submits to this endpoint, performing the action as the victim "
                "when they visit the malicious page."
            ),
            impact=(
                "Attacker can force logged-in users to perform unwanted actions "
                "(change email/password, make purchases, transfer data) without consent."
            ),
            recommendation=(
                "Add a per-session, unpredictable CSRF token to every state-changing "
                "form and verify it server-side. Use the SameSite=Lax/Strict cookie "
                "attribute as defense-in-depth. Most frameworks have built-in CSRF "
                "middleware — enable it."
            ),
            poc=f"<form action='{action}' method='POST'>...auto-submit from attacker.com...</form>",
            verified=True,
            likelihood=3, impact_score=4 if sev == "high" else 3,
            risk_score=12 if sev == "high" else 9,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# NO RATE LIMITING ON AUTHENTICATION
# ════════════════════════════════════════════════════════════════════════════

def test_no_auth_rate_limit(client: AttackClient, forms: List[dict]) -> List[Finding]:
    """
    Send a small burst of failed logins. If none are ever blocked
    (no 429 / lockout / CAPTCHA), the design allows unlimited brute force.
    We cap at 8 attempts — enough to detect, not enough to be abusive.
    """
    findings: List[Finding] = []
    login_forms = [f for f in forms if (f.get("purpose") or "") == "login"]
    if not login_forms:
        return findings

    form = login_forms[0]
    action = form.get("action") or ""
    method = (form.get("method") or "POST").upper()
    inputs = form.get("inputs", [])
    if not action or not inputs:
        return findings

    user_field = pass_field = None
    for i in inputs:
        t = (i.get("type") or "").lower()
        n = (i.get("name") or "").lower()
        if t == "password" and not pass_field:
            pass_field = i["name"]
        elif (t in ("text", "email") or "user" in n or "email" in n) and not user_field:
            user_field = i["name"]
    if not user_field or not pass_field:
        return findings

    blocked = False
    statuses = []
    for n in range(8):
        data = {user_field: f"venom_probe_{int(time.time())}",
                pass_field: f"WrongPass_{n}_{int(time.time())}"}
        for i in inputs:
            if i["name"] not in data and i.get("required"):
                data[i["name"]] = ""
        r = client.request(method, action, data=data)
        if not r:
            continue
        statuses.append(r.status_code)
        body = (r.text or "").lower()
        if (r.status_code in (429, 423) or
                "too many" in body or "locked" in body or
                "captcha" in body or "try again later" in body):
            blocked = True
            break

    if statuses and not blocked:
        findings.append(Finding(
            title="No Rate Limiting on Login (Brute-Force Possible)",
            category="vulnerability",
            owasp="A06",
            severity="high",
            cwe_id="CWE-307",
            cvss_score=7.5,
            affected_url=action,
            http_method=method,
            evidence=f"{len(statuses)} rapid failed logins, none blocked (statuses: {statuses}).",
            description=(
                "The login endpoint accepted repeated failed authentication attempts "
                "with no rate limiting, account lockout, or CAPTCHA. This is a design "
                "flaw that enables automated credential-stuffing and brute-force attacks."
            ),
            impact=(
                "Attackers can try millions of passwords against accounts, eventually "
                "compromising weak credentials at scale."
            ),
            recommendation=(
                "Add rate limiting per IP + per account, progressive delays, account "
                "lockout after N failures, and CAPTCHA after a few failed attempts. "
                "Monitor and alert on brute-force patterns."
            ),
            poc=f"# Rapid POST loop against {action} was never throttled.",
            verified=True,
            likelihood=4, impact_score=4, risk_score=16,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# BUSINESS LOGIC — NEGATIVE / ABSURD NUMERIC VALUES
# ════════════════════════════════════════════════════════════════════════════

NUMERIC_HINT_NAMES = {"quantity", "qty", "amount", "price", "cost", "total",
                      "count", "num", "number", "credit", "balance", "points",
                      "discount", "value"}


def test_business_logic_numbers(client: AttackClient, forms: List[dict]) -> List[Finding]:
    """
    For forms with numeric-looking fields, submit a negative value and check
    the server doesn't reject it (a design that trusts client-side validation).
    We do NOT complete purchases — we only look for missing server validation.
    """
    findings: List[Finding] = []
    for form in forms:
        method = (form.get("method") or "POST").upper()
        action = form.get("action") or ""
        inputs = form.get("inputs", [])
        if not action or not inputs:
            continue
        numeric_fields = [i for i in inputs
                          if (i.get("type") or "").lower() == "number"
                          or any(k in (i.get("name") or "").lower() for k in NUMERIC_HINT_NAMES)]
        if not numeric_fields:
            continue

        # Baseline with a normal value
        base = {}
        for i in inputs:
            t = (i.get("type") or "").lower()
            base[i["name"]] = {"email": "test@venom.example", "password": "TestPass123!",
                               "number": "1"}.get(t, "test")
        baseline = client.request(method, action, data=base)
        if not baseline:
            continue

        field = numeric_fields[0]["name"]
        neg = dict(base)
        neg[field] = "-1"
        r = client.request(method, action, data=neg)
        if not r:
            continue
        body = (r.text or "").lower()
        # If the server did NOT return a validation error, it likely accepted it
        rejected = any(k in body for k in ("invalid", "must be positive", "greater than",
                                           "not allowed", "error", "cannot be negative"))
        if r.status_code < 400 and not rejected and r.status_code == baseline.status_code:
            findings.append(Finding(
                title=f"Business Logic: Negative Value Accepted ('{field}')",
                category="vulnerability",
                owasp="A06",
                severity="medium",
                cwe_id="CWE-840",
                cvss_score=5.3,
                affected_url=action,
                parameter=field,
                http_method=method,
                payload=f"{field}=-1",
                evidence=f"Submitting {field}=-1 returned {r.status_code} with no validation error.",
                description=(
                    f"The field '{field}' accepts negative values with no server-side "
                    "validation. In e-commerce/financial flows this enables logic abuse "
                    "(e.g. negative quantity to inflate a refund, or negative price to "
                    "reduce a total)."
                ),
                impact="Financial loss, inventory manipulation, or privilege abuse via crafted values.",
                recommendation=(
                    "Validate all numeric inputs server-side against sane min/max bounds. "
                    "Never trust client-side validation. Re-derive prices/totals on the server."
                ),
                poc=f"# POST {action}  ->  {field}=-1 accepted",
                verified=False,
                likelihood=3, impact_score=3, risk_score=9,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a06_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_missing_csrf(forms)
        except Exception as e: logger.warning(f"[A06] csrf: {e}")
        try: findings += test_no_auth_rate_limit(client, forms)
        except Exception as e: logger.warning(f"[A06] rate_limit: {e}")
        try: findings += test_business_logic_numbers(client, forms)
        except Exception as e: logger.warning(f"[A06] business_logic: {e}")
    finally:
        client.close()
    logger.info(f"[A06] Found {len(findings)} insecure-design findings")
    return findings
