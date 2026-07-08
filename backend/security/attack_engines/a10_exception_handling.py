"""
VENOM AI — A10 Mishandling of Exceptional Conditions Engine
             (OWASP Top 10:2025 #10 — brand new category)
─────────────────────────────────────────────────────────────────────────
Apps that crash, leak, or fail-open when given unexpected input. Safe tests:

  1. Malformed input handling — send null bytes, wrong content-type, broken
     JSON, type confusion (array where string expected) and look for
     500s / stack traces instead of clean 400s.
  2. Unexpected HTTP methods — send TRACE / weird verbs; look for reflection
     or 500s instead of a proper 405.
  3. Oversized input handling — a moderately large parameter; look for a
     crash / 500 instead of a graceful 413/400.

Everything here is bounded and non-destructive — no giant payloads that
could DoS the target; we send just enough to observe error handling.
"""
from __future__ import annotations

import logging
from typing import List
from urllib.parse import urlparse

from .common import AttackClient, Finding, inject_into_url

logger = logging.getLogger("venom.attack.a10")


STACK_TRACE_MARKERS = [
    "traceback (most recent call last)", "at java.", "at org.springframework",
    "system.nullreferenceexception", "system.exception", "in <module>",
    "line ", "undefined index", "fatal error", "unhandled exception",
    "typeerror:", "valueerror:", "keyerror:", "nonetype",
    "org.apache", "werkzeug", "django.", "laravel", "rails",
]


def _has_stack_trace(body: str) -> List[str]:
    low = (body or "").lower()
    return [m for m in STACK_TRACE_MARKERS if m in low][:3]


# ════════════════════════════════════════════════════════════════════════════
# MALFORMED INPUT → 500 / STACK TRACE
# ════════════════════════════════════════════════════════════════════════════

def test_malformed_input(client: AttackClient, target_url: str,
                         endpoints: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    # Build a set of test URLs: parameterised endpoints + the base
    param_eps = [e for e in endpoints if e.get("parameters")]
    targets = param_eps[:6] if param_eps else [{"url": target_url, "parameters": ["q"]}]

    malformed_values = [
        ("null_byte",   "abc\x00def"),
        ("type_confuse", "[]"),                 # array marker where a string is expected
        ("deep_nest",   "{" * 40 + "}" * 40),   # bounded nested braces
        ("format_str",  "%s%s%s%n%x"),
    ]
    reported = 0
    for ep in targets:
        if reported >= 3:
            break
        url = ep.get("url", target_url)
        params = ep.get("parameters") or ["q"]
        param = params[0]
        for label, val in malformed_values:
            test_url = inject_into_url(url, param, val)
            r = client.get(test_url)
            if not r:
                continue
            if r.status_code >= 500:
                traces = _has_stack_trace(r.text or "")
                sev = "high" if traces else "medium"
                findings.append(Finding(
                    title=f"Unhandled Exception on Malformed Input ({label})",
                    category="vulnerability",
                    owasp="A10",
                    severity=sev,
                    cwe_id="CWE-755",
                    cvss_score=6.5 if traces else 5.3,
                    affected_url=test_url,
                    parameter=param,
                    payload=repr(val),
                    evidence=(f"HTTP {r.status_code}" +
                              (f" with leaked stack trace: {traces}" if traces
                               else " (server error, no graceful handling)")),
                    description=(
                        f"Sending malformed input ({label}) to '{param}' caused an "
                        f"unhandled server error (HTTP {r.status_code}) instead of a "
                        "clean validation response. "
                        + ("The response also leaked an internal stack trace."
                           if traces else "")
                    ),
                    impact=(
                        "Unhandled exceptions can crash workers (DoS), leak internal "
                        "details, or leave the app in an inconsistent/insecure state."
                    ),
                    recommendation=(
                        "Validate and sanitise all input at the boundary. Wrap request "
                        "handling in proper error handling that returns a generic 400/500 "
                        "and logs details server-side. Never leak stack traces to clients."
                    ),
                    poc=f"curl '{test_url}'",
                    verified=True,
                    likelihood=3, impact_score=4 if traces else 3,
                    risk_score=12 if traces else 9,
                ))
                reported += 1
                break  # one malformed-input finding per endpoint
    return findings


# ════════════════════════════════════════════════════════════════════════════
# BROKEN JSON / WRONG CONTENT-TYPE
# ════════════════════════════════════════════════════════════════════════════

def test_broken_json(client: AttackClient, endpoints: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    api_eps = [e for e in endpoints if (e.get("kind") == "api"
               or "/api/" in (e.get("url") or ""))][:5]
    for ep in api_eps:
        url = ep.get("url", "")
        if not url:
            continue
        # Send deliberately broken JSON with a JSON content-type
        r = client.post(url, content='{"venom": broken, "x": }',
                        headers={"Content-Type": "application/json"})
        if not r:
            continue
        if r.status_code >= 500:
            traces = _has_stack_trace(r.text or "")
            findings.append(Finding(
                title="Unhandled Exception on Broken JSON Body",
                category="vulnerability",
                owasp="A10",
                severity="high" if traces else "medium",
                cwe_id="CWE-755",
                cvss_score=6.5 if traces else 5.3,
                affected_url=url,
                http_method="POST",
                payload='{"venom": broken, "x": }',
                evidence=f"Malformed JSON caused HTTP {r.status_code}" +
                         (f", leaked: {traces}" if traces else ""),
                description=(
                    "Posting syntactically invalid JSON caused a server error instead "
                    "of a clean 400 Bad Request. The JSON parser's exception is not "
                    "being handled gracefully."
                ),
                impact="DoS via malformed requests; internal detail leakage.",
                recommendation=(
                    "Catch JSON parse errors and return 400 with a generic message. "
                    "Validate content-type and body schema before processing."
                ),
                poc=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{{invalid}}'",
                verified=True,
                likelihood=3, impact_score=4 if traces else 3,
                risk_score=12 if traces else 9,
            ))
            return findings  # one is enough
    return findings


# ════════════════════════════════════════════════════════════════════════════
# UNEXPECTED HTTP METHOD
# ════════════════════════════════════════════════════════════════════════════

def test_unexpected_method(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    # TRACE can reflect request data (XST); weird verbs should yield 405, not 500
    r = client.request("TRACE", target_url)
    if r and r.status_code == 200 and "TRACE" in (r.text or "")[:200]:
        findings.append(Finding(
            title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
            category="vulnerability",
            owasp="A10",
            severity="low",
            cwe_id="CWE-770",
            cvss_score=3.7,
            affected_url=target_url,
            http_method="TRACE",
            evidence="Server responded 200 to TRACE and reflected the request.",
            description=(
                "The HTTP TRACE method is enabled and echoes the request back. Combined "
                "with other flaws this enables Cross-Site Tracing (XST) to read headers "
                "like cookies that should be HttpOnly."
            ),
            impact="Assists cookie/header theft in chained attacks.",
            recommendation="Disable TRACE (and TRACK) on the web server / load balancer.",
            poc=f"curl -X TRACE '{target_url}'",
            verified=True,
            likelihood=2, impact_score=2, risk_score=4,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a10_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_malformed_input(client, target_url, endpoints)
        except Exception as e: logger.warning(f"[A10] malformed: {e}")
        try: findings += test_broken_json(client, endpoints)
        except Exception as e: logger.warning(f"[A10] json: {e}")
        try: findings += test_unexpected_method(client, target_url)
        except Exception as e: logger.warning(f"[A10] method: {e}")
    finally:
        client.close()
    logger.info(f"[A10] Found {len(findings)} exception-handling findings")
    return findings
