"""
Security Scanner Service
─────────────────────────────────────────────────────────────────────
Checks performed:
  1. HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
  2. SSL/TLS certificate validity and configuration
  3. Open dangerous ports (FTP, Telnet, DB ports, Redis)
  4. HTTP → HTTPS redirect enforcement
  5. Server version disclosure

Each finding is enriched with an AI plain-English explanation + fix steps.
A 0–100 security score is computed based on finding severity.
─────────────────────────────────────────────────────────────────────
"""
import asyncio
import socket
import ssl
from datetime import datetime
from typing import List
from urllib.parse import urlparse

import httpx
from groq import Groq

from core.config import settings

_groq = Groq(api_key=settings.GROQ_API_KEY)


# ══════════════════════════════════════════════════════════════════════
# VULNERABILITY TEMPLATES
# ══════════════════════════════════════════════════════════════════════

_VULN_DB = {
    "missing_hsts":   {"title": "Missing HSTS Header",            "risk": "medium", "cat": "headers",  "cvss": 5.3},
    "missing_csp":    {"title": "Missing Content-Security-Policy", "risk": "medium", "cat": "headers",  "cvss": 5.0},
    "missing_xframe": {"title": "Missing X-Frame-Options",         "risk": "medium", "cat": "headers",  "cvss": 4.3},
    "missing_xcto":   {"title": "Missing X-Content-Type-Options",  "risk": "low",    "cat": "headers",  "cvss": 3.1},
    "missing_ref":    {"title": "Missing Referrer-Policy",         "risk": "low",    "cat": "headers",  "cvss": 2.5},
    "server_version": {"title": "Server Version Disclosed",        "risk": "low",    "cat": "headers",  "cvss": 2.1},
    "http_only":      {"title": "Site Accessible Over HTTP",       "risk": "medium", "cat": "ssl",      "cvss": 5.3},
    "expired_cert":   {"title": "SSL Certificate Expired",         "risk": "critical","cat": "ssl",     "cvss": 9.0},
    "self_signed":    {"title": "Self-Signed SSL Certificate",     "risk": "medium", "cat": "ssl",      "cvss": 5.9},
    "weak_ssl":       {"title": "Weak SSL/TLS Configuration",      "risk": "high",   "cat": "ssl",      "cvss": 7.4},
    "open_ftp":       {"title": "FTP Port Exposed (21)",           "risk": "high",   "cat": "ports",    "cvss": 7.5},
    "open_ssh":       {"title": "SSH Port Exposed (22)",           "risk": "medium", "cat": "ports",    "cvss": 5.0},
    "open_telnet":    {"title": "Telnet Port Exposed (23)",        "risk": "critical","cat": "ports",   "cvss": 9.8},
    "open_mysql":     {"title": "MySQL Port Exposed (3306)",       "risk": "critical","cat": "ports",   "cvss": 9.8},
    "open_postgres":  {"title": "PostgreSQL Port Exposed (5432)",  "risk": "critical","cat": "ports",   "cvss": 9.8},
    "open_redis":     {"title": "Redis Port Exposed (6379)",       "risk": "critical","cat": "ports",   "cvss": 9.8},
    "open_mongo":     {"title": "MongoDB Port Exposed (27017)",    "risk": "critical","cat": "ports",   "cvss": 9.8},
}

_HEADERS_MAP = {
    "strict-transport-security": "missing_hsts",
    "content-security-policy":   "missing_csp",
    "x-frame-options":           "missing_xframe",
    "x-content-type-options":    "missing_xcto",
    "referrer-policy":           "missing_ref",
}

_PORT_MAP = {
    21: "open_ftp", 22: "open_ssh", 23: "open_telnet",
    3306: "open_mysql", 5432: "open_postgres",
    6379: "open_redis", 27017: "open_mongo",
}


# ══════════════════════════════════════════════════════════════════════
# INDIVIDUAL CHECKS
# ══════════════════════════════════════════════════════════════════════

async def _check_headers(url: str) -> list:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
            resp = await c.get(url)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for hdr, key in _HEADERS_MAP.items():
            if hdr not in headers:
                f = dict(_VULN_DB[key])
                f["evidence"] = f"Header '{hdr}' is absent from the HTTP response."
                findings.append(f)

        if "server" in headers and any(ch.isdigit() for ch in headers["server"]):
            f = dict(_VULN_DB["server_version"])
            f["evidence"] = f"Server header exposes version: {headers['server']}"
            findings.append(f)
    except Exception:
        pass
    return findings


def _check_ssl(hostname: str) -> list:
    findings = []
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            if not_after < datetime.utcnow():
                f = dict(_VULN_DB["expired_cert"])
                f["evidence"] = f"Certificate expired on {cert['notAfter']}"
                findings.append(f)
    except ssl.SSLCertVerificationError as e:
        key = "self_signed" if "self signed" in str(e).lower() else "weak_ssl"
        f   = dict(_VULN_DB[key]); f["evidence"] = str(e); findings.append(f)
    except ConnectionRefusedError:
        f = dict(_VULN_DB["http_only"]); f["evidence"] = "Port 443 refused."; findings.append(f)
    except Exception:
        pass
    return findings


def _check_ports(hostname: str) -> list:
    findings = []
    for port, key in _PORT_MAP.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            if s.connect_ex((hostname, port)) == 0:
                f = dict(_VULN_DB[key])
                f["evidence"] = f"Port {port} is open and accepting connections."
                findings.append(f)
            s.close()
        except Exception:
            pass
    return findings


async def _check_http_redirect(url: str) -> list:
    findings = []
    http_url = url.replace("https://", "http://", 1) if url.startswith("https://") else url
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
            resp = await c.get(http_url)
        if resp.status_code not in (301, 302, 307, 308):
            f = dict(_VULN_DB["http_only"])
            f["evidence"] = f"HTTP {resp.status_code} — no redirect to HTTPS."
            findings.append(f)
    except Exception:
        pass
    return findings


# ══════════════════════════════════════════════════════════════════════
# AI ENRICHMENT
# ══════════════════════════════════════════════════════════════════════

def _ai_explain(title: str, evidence: str) -> tuple[str, str]:
    """Returns (plain_explanation, recommendation)."""
    prompt = f"""You are a cybersecurity expert writing for a non-technical client.

Vulnerability: {title}
Evidence: {evidence}

Write exactly two sections:
EXPLANATION: <2-3 sentences in plain English explaining the issue and its risk>
RECOMMENDATION: <2-3 numbered concrete steps to fix it>"""
    try:
        resp = _groq.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=350, temperature=0.4,
        )
        text = resp.choices[0].message.content.strip()
        exp  = rec = ""
        for line in text.split("\n"):
            if line.startswith("EXPLANATION:"):
                exp = line.replace("EXPLANATION:", "").strip()
            elif line.startswith("RECOMMENDATION:"):
                rec = line.replace("RECOMMENDATION:", "").strip()
        return exp or text, rec or "Consult a security professional."
    except Exception:
        return "See evidence for details.", "Consult a security professional."


def _ai_summary(findings: list, score: int, url: str) -> str:
    vuln_lines = "\n".join(f"- [{f['risk'].upper()}] {f['title']}" for f in findings) or "None"
    prompt = f"""Write a 3-sentence executive summary for a website security audit.

Target: {url}
Score:  {score}/100
Findings:\n{vuln_lines}

Write for a non-technical business owner. Professional and concise."""
    try:
        resp = _groq.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200, temperature=0.5,
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return f"Security audit completed for {url}. Score: {score}/100."


# ══════════════════════════════════════════════════════════════════════
# SCORE CALCULATION
# ══════════════════════════════════════════════════════════════════════

_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3}

def _calc_score(findings: list) -> int:
    score = 100
    for f in findings:
        score -= _DEDUCTIONS.get(f.get("risk", "low"), 3)
    return max(0, min(100, score))


# ══════════════════════════════════════════════════════════════════════
# MAIN SCAN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

async def run_full_scan(url: str) -> dict:
    """
    Full scan pipeline. Returns:
      {
        "score":      int,
        "findings":   list[dict],
        "ai_summary": str,
        "raw":        dict,
      }
    """
    if "://" not in url:
        url = "https://" + url
    parsed   = urlparse(url)
    hostname = parsed.netloc or parsed.path.split("/")[0]

    # Run all checks (headers + http_redirect are async)
    header_f, http_f = await asyncio.gather(
        _check_headers(url),
        _check_http_redirect(url),
    )
    ssl_f  = _check_ssl(hostname)
    port_f = _check_ports(hostname)

    raw_findings = header_f + ssl_f + port_f + http_f

    # Deduplicate by title
    seen, deduped = set(), []
    for f in raw_findings:
        if f["title"] not in seen:
            seen.add(f["title"]); deduped.append(f)

    # AI enrich each finding
    enriched = []
    for f in deduped:
        exp, rec = _ai_explain(f["title"], f.get("evidence", ""))
        enriched.append({
            **f,
            "ai_explanation": exp,
            "recommendation": rec,
        })

    score   = _calc_score(enriched)
    summary = _ai_summary(enriched, score, url)

    return {
        "score":      score,
        "findings":   enriched,
        "ai_summary": summary,
        "raw":        {"url": url, "hostname": hostname, "total": len(enriched)},
    }
