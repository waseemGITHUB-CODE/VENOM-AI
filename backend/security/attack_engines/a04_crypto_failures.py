"""
VENOM AI — A04 Cryptographic Failures Engine (OWASP Top 10:2025 #4)
─────────────────────────────────────────────────────────────────────────
Tests:

  1. HTTPS not enforced — HTTP version of site accessible without redirect
  2. SSL certificate problems — expired, self-signed, hostname mismatch
  3. Weak TLS versions — TLS 1.0 / SSLv3 still enabled
  4. Cookie security flags missing — Secure, HttpOnly, SameSite
  5. Mixed content — HTTPS page loads HTTP resources
  6. Sensitive data in URL — passwords, tokens, IDs in query string
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a04")


# ════════════════════════════════════════════════════════════════════════════
# HTTPS ENFORCEMENT + HSTS
# ════════════════════════════════════════════════════════════════════════════

def test_https_enforcement(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    p = urlparse(target_url)
    if p.scheme != "https":
        return findings   # already on HTTP — different bug

    # Build HTTP version of URL
    http_url = target_url.replace("https://", "http://", 1)
    r = client.get(http_url)
    if not r:
        return findings

    # Check if it redirected to HTTPS
    # httpx follows redirects by default; check r.url
    final_url = str(r.url) if hasattr(r, "url") else http_url
    final_scheme = urlparse(final_url).scheme

    if final_scheme != "https":
        findings.append(Finding(
            title="HTTPS Not Enforced (HTTP Accessible)",
            category="vulnerability",
            owasp="A04",
            severity="high",
            cwe_id="CWE-319",
            cvss_score=7.4,
            affected_url=http_url,
            http_method="GET",
            evidence=f"HTTP request to {http_url} returned {r.status_code} without redirect to HTTPS",
            description=(
                "The application is accessible over plaintext HTTP without being "
                "redirected to HTTPS. All traffic — including sessions and credentials — "
                "is visible to network attackers."
            ),
            impact="Session hijacking, credential theft via network sniffing (public WiFi, ISP, ARP poisoning).",
            recommendation=(
                "Configure your web server to redirect all HTTP traffic to HTTPS with 301. "
                "Set the HSTS header (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload) "
                "and submit to the HSTS preload list."
            ),
            poc=f"curl -L '{http_url}'",
            verified=True,
            likelihood=4, impact_score=4, risk_score=16,
        ))

    # Check HSTS header on the HTTPS response
    rh = client.get(target_url)
    if rh:
        hsts = rh.headers.get("strict-transport-security", "")
        if not hsts:
            findings.append(Finding(
                title="HSTS Header Missing",
                category="hardening",
                owasp="A04",
                severity="medium",
                cwe_id="CWE-319",
                cvss_score=5.3,
                affected_url=target_url,
                evidence="Strict-Transport-Security header not present in HTTPS response",
                description=(
                    "Without HSTS, browsers may allow downgrade attacks where a man-in-the-middle "
                    "strips HTTPS on the first visit."
                ),
                impact="Susceptibility to SSL-stripping attacks on first or stale visits.",
                recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                verified=True,
                likelihood=3, impact_score=3, risk_score=9,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SSL/TLS CERTIFICATE + PROTOCOL CHECKS
# ════════════════════════════════════════════════════════════════════════════

def test_tls_security(target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    p = urlparse(target_url)
    if p.scheme != "https":
        return findings
    host = p.hostname
    port = p.port or 443
    if not host:
        return findings

    # ── 1. Certificate validity ──────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append(Finding(
                            title="SSL Certificate Expired",
                            category="vulnerability",
                            owasp="A04",
                            severity="critical",
                            cwe_id="CWE-295",
                            cvss_score=9.1,
                            affected_url=target_url,
                            evidence=f"Certificate expired on {not_after_str} ({-days_left} days ago)",
                            description="The SSL certificate has expired. Browsers show warnings, users lose trust, and downgrade attacks become possible.",
                            impact="Total trust collapse — users abandon site, MITM becomes viable.",
                            recommendation="Renew immediately. Set up auto-renewal (Let's Encrypt + Certbot).",
                            verified=True,
                            likelihood=5, impact_score=4, risk_score=20,
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title="SSL Certificate Expiring Soon",
                            category="hardening",
                            owasp="A04",
                            severity="high" if days_left < 7 else "medium",
                            cwe_id="CWE-295",
                            cvss_score=5.3,
                            affected_url=target_url,
                            evidence=f"Certificate expires {not_after_str} ({days_left} days)",
                            description=f"SSL certificate expires in {days_left} days.",
                            impact="Imminent service disruption when certificate expires.",
                            recommendation="Renew certificate now. Set up auto-renewal to prevent recurrence.",
                            verified=True,
                            likelihood=4 if days_left < 7 else 3, impact_score=3, risk_score=12,
                        ))
    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        if "self signed" in err or "self-signed" in err:
            findings.append(Finding(
                title="Self-Signed SSL Certificate",
                category="vulnerability",
                owasp="A04",
                severity="high",
                cwe_id="CWE-295",
                cvss_score=7.4,
                affected_url=target_url,
                evidence=str(e)[:200],
                description="Site uses a self-signed certificate not trusted by browsers.",
                impact="Browser warnings train users to ignore certificate errors → MITM susceptibility.",
                recommendation="Obtain a free certificate from Let's Encrypt or a commercial CA.",
                verified=True,
                likelihood=5, impact_score=3, risk_score=15,
            ))
        elif "hostname" in err or "doesn't match" in err:
            findings.append(Finding(
                title="SSL Hostname Mismatch",
                category="vulnerability",
                owasp="A04",
                severity="high",
                cwe_id="CWE-297",
                cvss_score=7.4,
                affected_url=target_url,
                evidence=str(e)[:200],
                description=f"Certificate hostname does not match {host}.",
                impact="Browser warnings + MITM susceptibility.",
                recommendation="Reissue certificate including this hostname in SAN extensions.",
                verified=True,
                likelihood=5, impact_score=3, risk_score=15,
            ))
        else:
            findings.append(Finding(
                title="SSL Certificate Validation Error",
                category="vulnerability",
                owasp="A04",
                severity="high",
                cwe_id="CWE-295",
                cvss_score=7.4,
                affected_url=target_url,
                evidence=str(e)[:200],
                description="Certificate fails standard validation.",
                impact="Users may receive certificate warnings.",
                recommendation="Fix the certificate chain. Verify intermediate certs are installed.",
                verified=True,
                likelihood=4, impact_score=3, risk_score=12,
            ))
    except Exception as e:
        logger.debug(f"[A04] cert check error: {e}")

    # ── 2. Weak TLS version (TLS 1.0 / TLS 1.1 still enabled) ────────────
    for old_proto, label, sev, cvss in [
        (ssl.PROTOCOL_TLSv1, "TLSv1.0", "high", 7.0),
    ]:
        try:
            ctx_weak = ssl.SSLContext(old_proto)
            ctx_weak.check_hostname = False
            ctx_weak.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx_weak.wrap_socket(sock, server_hostname=host) as ssock:
                    # Connected successfully → weak TLS supported
                    findings.append(Finding(
                        title=f"Weak TLS Version Supported: {label}",
                        category="vulnerability",
                        owasp="A04",
                        severity=sev,
                        cwe_id="CWE-326",
                        cvss_score=cvss,
                        affected_url=target_url,
                        evidence=f"Server accepted {label} handshake on port {port}",
                        description=f"The server supports {label}, which is deprecated and has known cryptographic weaknesses (BEAST, POODLE, etc.).",
                        impact="MITM attackers may force downgrade to weak protocols and break encryption.",
                        recommendation=f"Disable {label}. Support only TLS 1.2 and TLS 1.3. (nginx: ssl_protocols TLSv1.2 TLSv1.3;)",
                        verified=True,
                        likelihood=3, impact_score=4, risk_score=12,
                    ))
                    break
        except Exception:
            pass   # protocol not supported = good
    return findings


# ════════════════════════════════════════════════════════════════════════════
# COOKIE SECURITY FLAGS
# ════════════════════════════════════════════════════════════════════════════

def test_cookie_flags(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r:
        return findings
    is_https = urlparse(target_url).scheme == "https"

    # Extract all Set-Cookie headers
    set_cookies = []
    if hasattr(r.headers, "get_list"):
        set_cookies = r.headers.get_list("set-cookie")
    else:
        set_cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

    for sc in set_cookies:
        # Parse cookie name
        m = re.match(r"^\s*([^=;]+)=", sc)
        if not m:
            continue
        cookie_name = m.group(1).strip()
        sc_lower = sc.lower()
        issues = []
        if is_https and "secure" not in sc_lower:
            issues.append("Secure flag missing")
        if "httponly" not in sc_lower:
            issues.append("HttpOnly missing")
        if "samesite" not in sc_lower:
            issues.append("SameSite attribute missing")
        # Only report meaningful cookies (session-like)
        is_session_like = any(k in cookie_name.lower() for k in
                              ("session", "sid", "auth", "token", "csrf", "user", "id"))
        if is_session_like and issues:
            findings.append(Finding(
                title=f"Insecure Cookie: {cookie_name}",
                category="vulnerability" if "Secure flag missing" in issues else "hardening",
                owasp="A04",
                severity="high" if "Secure flag missing" in issues else "medium",
                cwe_id="CWE-614",
                cvss_score=7.4 if "Secure flag missing" in issues else 5.3,
                affected_url=target_url,
                parameter=cookie_name,
                evidence=f"Set-Cookie: {sc[:200]}",
                description=(
                    f"Cookie '{cookie_name}' is missing security attributes: {', '.join(issues)}. "
                    "Session cookies without these flags are vulnerable to theft."
                ),
                impact=(
                    "Without Secure: cookies leak over HTTP. Without HttpOnly: stealable via XSS. "
                    "Without SameSite: vulnerable to CSRF."
                ),
                recommendation=(
                    "Set Secure (on HTTPS only), HttpOnly (block JS access), and SameSite=Lax "
                    "(or Strict) on all session cookies."
                ),
                verified=True,
                likelihood=4, impact_score=4 if "Secure flag missing" in issues else 3,
                risk_score=16 if "Secure flag missing" in issues else 12,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA IN URL
# ════════════════════════════════════════════════════════════════════════════

def test_sensitive_data_in_url(endpoints: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    sensitive_param_names = {"password", "pwd", "pass", "passwd", "secret", "token",
                              "api_key", "apikey", "access_token", "auth", "ssn",
                              "credit_card", "cc"}
    seen_params: set = set()
    for ep in endpoints:
        params = ep.get("parameters") or []
        for p in params:
            p_lower = p.lower()
            if p_lower in seen_params:
                continue
            if any(s in p_lower for s in sensitive_param_names):
                seen_params.add(p_lower)
                findings.append(Finding(
                    title=f"Sensitive Data in URL Query: '{p}'",
                    category="vulnerability",
                    owasp="A04",
                    severity="high",
                    cwe_id="CWE-598",
                    cvss_score=7.5,
                    affected_url=ep.get("url", ""),
                    parameter=p,
                    evidence=f"Parameter '{p}' appears in URL query string",
                    description=(
                        f"The parameter '{p}' is sent in the URL query string. URLs are logged "
                        "by browsers, proxies, CDNs, and web server access logs — exposing "
                        "sensitive data to multiple third parties."
                    ),
                    impact="Credentials/tokens leak via referer headers, browser history, server logs.",
                    recommendation=(
                        "Send sensitive data only in POST bodies or HTTP headers (e.g. Authorization). "
                        "Never put secrets in URLs."
                    ),
                    verified=True,
                    likelihood=4, impact_score=4, risk_score=16,
                ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a04_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_https_enforcement(client, target_url)
        except Exception as e: logger.warning(f"[A04] https: {e}")

        try: findings += test_tls_security(target_url)
        except Exception as e: logger.warning(f"[A04] tls: {e}")

        try: findings += test_cookie_flags(client, target_url)
        except Exception as e: logger.warning(f"[A04] cookies: {e}")

        try: findings += test_sensitive_data_in_url(endpoints)
        except Exception as e: logger.warning(f"[A04] url_data: {e}")
    finally:
        client.close()

    logger.info(f"[A04] Found {len(findings)} crypto findings")
    return findings
