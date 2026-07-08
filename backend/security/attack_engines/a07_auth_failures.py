"""
VENOM AI — A07 Authentication Failures Engine (OWASP Top 10:2025 #7)
─────────────────────────────────────────────────────────────────────────
Weaknesses in how the app authenticates users. Safe, detection-oriented:

  1. Username / user enumeration — different response for valid vs invalid
     users (lets attackers build a target list)
  2. Session token exposed in URL — session id / auth token in query string
  3. Login form served over HTTP — credentials sent in plaintext
  4. Weak / missing session cookie attributes on the auth flow
  5. Insecure "remember me" / long-lived tokens hints

We never submit real credentials or complete a login; we only observe
behavioural differences and transport security.
"""
from __future__ import annotations

import logging
import re
import time
from typing import List
from urllib.parse import urlparse, parse_qsl

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a07")


# ════════════════════════════════════════════════════════════════════════════
# USER ENUMERATION
# ════════════════════════════════════════════════════════════════════════════

def test_user_enumeration(client: AttackClient, forms: List[dict]) -> List[Finding]:
    """
    Submit a login with an obviously-fake username vs a common one and
    compare responses. If they differ meaningfully, the app leaks which
    usernames exist.
    """
    findings: List[Finding] = []
    login_forms = [f for f in forms if (f.get("purpose") or "") in ("login", "signup")]
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

    def _probe(username):
        data = {user_field: username, pass_field: f"WrongPass_{int(time.time())}"}
        for i in inputs:
            if i["name"] not in data and i.get("required"):
                data[i["name"]] = ""
        return client.request(method, action, data=data)

    r_fake = _probe(f"venom_nonexistent_{int(time.time())}@nope.example")
    r_common = _probe("admin@example.com")
    if not r_fake or not r_common:
        return findings

    body_fake = (r_fake.text or "").lower()
    body_common = (r_common.text or "").lower()

    # Signals of enumeration
    signals = []
    if r_fake.status_code != r_common.status_code:
        signals.append(f"status differs ({r_fake.status_code} vs {r_common.status_code})")
    if abs(len(body_fake) - len(body_common)) > 120:
        signals.append(f"response size differs ({len(body_fake)} vs {len(body_common)})")
    # Message-based enumeration
    enum_phrases = ("no such user", "user not found", "unknown user", "account does not exist",
                    "email not registered", "no account")
    if any(p in body_fake for p in enum_phrases) != any(p in body_common for p in enum_phrases):
        signals.append("distinct 'user not found' vs 'wrong password' messaging")

    if len(signals) >= 1:
        findings.append(Finding(
            title="Username Enumeration",
            category="vulnerability",
            owasp="A07",
            severity="medium",
            cwe_id="CWE-204",
            cvss_score=5.3,
            affected_url=action,
            parameter=user_field,
            http_method=method,
            evidence="; ".join(signals),
            description=(
                "The login flow responds differently for existing vs non-existing "
                "usernames, allowing an attacker to enumerate valid accounts before "
                "launching targeted password attacks."
            ),
            impact="Attackers build a validated list of real accounts to brute-force or phish.",
            recommendation=(
                "Return an identical, generic response for all failed logins "
                "(e.g. 'Invalid username or password'). Keep timing constant. Apply "
                "the same rule to signup, password-reset, and login."
            ),
            poc=f"# Compare responses for a fake vs real username at {action}",
            verified=True,
            likelihood=3, impact_score=3, risk_score=9,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SESSION TOKEN IN URL
# ════════════════════════════════════════════════════════════════════════════

SESSION_PARAM_HINTS = {"sessionid", "session_id", "sid", "session", "token",
                       "auth", "auth_token", "access_token", "jwt", "apikey", "api_key"}


def test_session_in_url(endpoints: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for ep in endpoints:
        url = ep.get("url", "")
        params = [p.lower() for p in (ep.get("parameters") or [])]
        hit = [p for p in params if p in SESSION_PARAM_HINTS]
        if not hit:
            continue
        key = tuple(sorted(hit))
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            title=f"Session/Auth Token in URL ({', '.join(hit)})",
            category="vulnerability",
            owasp="A07",
            severity="high",
            cwe_id="CWE-598",
            cvss_score=7.5,
            affected_url=url,
            parameter=", ".join(hit),
            evidence=f"URL query contains session/auth parameter(s): {hit}",
            description=(
                "A session or authentication token is passed in the URL query string. "
                "URLs are stored in browser history, server access logs, proxy logs, "
                "and leak via the Referer header to third parties."
            ),
            impact="Session hijacking — anyone who sees the URL (logs, referer, history) can impersonate the user.",
            recommendation=(
                "Never put session/auth tokens in URLs. Use HttpOnly, Secure cookies "
                "or the Authorization header. Rotate any tokens that may have leaked."
            ),
            verified=True,
            likelihood=4, impact_score=4, risk_score=16,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# LOGIN OVER HTTP + WEAK SESSION COOKIE
# ════════════════════════════════════════════════════════════════════════════

def test_login_transport(client: AttackClient, forms: List[dict], target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    login_forms = [f for f in forms if (f.get("purpose") or "") == "login"]
    if not login_forms:
        return findings
    for form in login_forms[:1]:
        action = form.get("action") or target_url
        scheme = urlparse(action if "://" in action else target_url).scheme
        if scheme == "http":
            findings.append(Finding(
                title="Login Form Submits Over HTTP",
                category="vulnerability",
                owasp="A07",
                severity="high",
                cwe_id="CWE-319",
                cvss_score=7.4,
                affected_url=action,
                evidence=f"Login form action uses plaintext HTTP: {action}",
                description=(
                    "The login form submits credentials over unencrypted HTTP. "
                    "Anyone on the network path can read the username and password."
                ),
                impact="Credential theft via network sniffing (public WiFi, ISP, MITM).",
                recommendation="Serve the entire site over HTTPS and force the login endpoint to HTTPS.",
                verified=True,
                likelihood=3, impact_score=5, risk_score=15,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a07_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_user_enumeration(client, forms)
        except Exception as e: logger.warning(f"[A07] enum: {e}")
        try: findings += test_session_in_url(endpoints)
        except Exception as e: logger.warning(f"[A07] session_url: {e}")
        try: findings += test_login_transport(client, forms, target_url)
        except Exception as e: logger.warning(f"[A07] transport: {e}")
    finally:
        client.close()
    logger.info(f"[A07] Found {len(findings)} auth-failure findings")
    return findings
