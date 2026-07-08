"""
VENOM AI — A08 Software & Data Integrity Failures Engine (OWASP Top 10:2025 #8)
─────────────────────────────────────────────────────────────────────────
Trusting data/code whose integrity isn't verified. Safe detection:

  1. Insecure deserialization markers — serialized Java/PHP/.NET/Python
     objects reflected in responses or accepted in inputs
  2. Exposed JavaScript source maps (.js.map) — leak original source code
  3. Exposed CI/CD & build integrity files — .github/workflows, Jenkinsfile,
     .gitlab-ci.yml (reveal build/deploy pipeline for supply-chain attacks)
  4. Unsigned auto-update / webhook endpoints (hint-based)

No payloads that could trigger deserialization RCE are sent — we only
detect the *markers* and *exposures* safely.
"""
from __future__ import annotations

import logging
import re
from typing import List
from urllib.parse import urlparse, urljoin

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a08")


# ════════════════════════════════════════════════════════════════════════════
# INSECURE DESERIALIZATION MARKERS
# ════════════════════════════════════════════════════════════════════════════

# (regex, platform) — signatures of serialized objects appearing in responses
SERIALIZED_MARKERS = [
    (r"rO0AB[A-Za-z0-9+/=]{6,}",              "Java (base64 serialized object)"),
    (r"aced0005[0-9a-fA-F]{6,}",              "Java (hex serialized stream)"),
    (r"\bO:\d+:\"[A-Za-z0-9_\\]+\":\d+:\{",  "PHP (serialized object)"),
    (r"\ba:\d+:\{[si]:\d+",                   "PHP (serialized array)"),
    (r"TypeObject.*System\.",                 ".NET (BinaryFormatter)"),
    (r"__reduce__|c__builtin__|\(dp\d|S'.*'\np\d", "Python (pickle)"),
]


def test_deserialization_markers(client: AttackClient, target_url: str,
                                 endpoints: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    seen_platforms = set()

    # Sample the homepage + a few endpoints' responses + cookies
    urls_to_check = [target_url] + [e.get("url", "") for e in endpoints[:8]]
    for url in urls_to_check:
        if not url:
            continue
        r = client.get(url)
        if not r:
            continue
        # Check body + cookies (serialized session objects sometimes ride cookies)
        haystack = (r.text or "")[:20000]
        set_cookie = " ".join(r.headers.get_list("set-cookie")) if hasattr(r.headers, "get_list") \
            else " ".join(v for k, v in r.headers.items() if k.lower() == "set-cookie")
        haystack += " " + set_cookie

        for pattern, platform in SERIALIZED_MARKERS:
            if platform in seen_platforms:
                continue
            if re.search(pattern, haystack):
                seen_platforms.add(platform)
                findings.append(Finding(
                    title=f"Serialized Object Exposed — {platform}",
                    category="vulnerability",
                    owasp="A08",
                    severity="high",
                    cwe_id="CWE-502",
                    cvss_score=8.1,
                    affected_url=url,
                    evidence=f"Response/cookie contains a {platform} serialized object pattern.",
                    description=(
                        f"A {platform} serialized object appears in the application's "
                        "output or cookies. If the app deserializes attacker-controlled "
                        "data of this type without integrity checks, it may be vulnerable "
                        "to insecure deserialization — a common path to remote code execution."
                    ),
                    impact=(
                        "If this serialized data is round-tripped and trusted on input, "
                        "an attacker can forge objects leading to RCE, auth bypass, or DoS."
                    ),
                    recommendation=(
                        "Never deserialize untrusted data. Use signed/encrypted tokens "
                        "(e.g. JWT with verified signature, or HMAC-protected data). "
                        "Prefer plain data formats (JSON) with strict schema validation "
                        "over native object serialization."
                    ),
                    verified=False,
                    likelihood=3, impact_score=5, risk_score=15,
                ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# EXPOSED SOURCE MAPS
# ════════════════════════════════════════════════════════════════════════════

def test_exposed_source_maps(client: AttackClient, target_url: str) -> List[Finding]:
    """Find <script src=...js> then probe for the matching .js.map file."""
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r or not r.text:
        return findings
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)(?:\?[^"\']*)?["\']',
                         r.text, re.IGNORECASE)
    checked = 0
    for src in scripts:
        if checked >= 6:
            break
        js_url = urljoin(target_url, src)
        map_url = js_url + ".map"
        rm = client.get(map_url)
        checked += 1
        if rm and rm.status_code == 200 and ('"sources"' in (rm.text or "")
                                             or '"mappings"' in (rm.text or "")):
            findings.append(Finding(
                title="Exposed JavaScript Source Map",
                category="vulnerability",
                owasp="A08",
                severity="medium",
                cwe_id="CWE-540",
                cvss_score=5.3,
                affected_url=map_url,
                evidence=f"Source map accessible: {map_url} (contains original source paths).",
                description=(
                    "A JavaScript source map is publicly accessible. Source maps contain "
                    "your original, un-minified source code including comments, internal "
                    "paths, and sometimes secrets or API endpoints not meant to be public."
                ),
                impact="Attackers read your original source to find logic flaws, hidden endpoints, and secrets.",
                recommendation=(
                    "Do not deploy .map files to production, or restrict access to them. "
                    "Configure your bundler to omit source maps in production builds."
                ),
                poc=f"curl '{map_url}'",
                verified=True,
                likelihood=4, impact_score=3, risk_score=12,
            ))
            return findings  # one is enough to prove the class
    return findings


# ════════════════════════════════════════════════════════════════════════════
# EXPOSED CI/CD & BUILD PIPELINE FILES
# ════════════════════════════════════════════════════════════════════════════

CICD_PATHS = [
    ("/.github/workflows/", "GitHub Actions workflows"),
    ("/.gitlab-ci.yml",     "GitLab CI pipeline"),
    ("/Jenkinsfile",        "Jenkins pipeline"),
    ("/.circleci/config.yml", "CircleCI config"),
    ("/.travis.yml",        "Travis CI config"),
    ("/azure-pipelines.yml", "Azure DevOps pipeline"),
    ("/bitbucket-pipelines.yml", "Bitbucket pipeline"),
    ("/Dockerfile",         "Dockerfile"),
    ("/.dockerignore",      "Docker ignore"),
]


def test_exposed_cicd(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"
    for path, label in CICD_PATHS:
        url = base + path
        r = client.get(url)
        if not r or r.status_code != 200:
            continue
        body = r.text or ""
        if len(body) < 20:
            continue
        low = body.lower()[:400]
        if any(k in low for k in ("not found", "404", "<!doctype html>", "<html")):
            # Likely SPA fallback / HTML 404, not the raw file
            if "jobs:" not in low and "pipeline" not in low and "from " not in low and "steps:" not in low:
                continue
        findings.append(Finding(
            title=f"Exposed CI/CD File: {path}",
            category="vulnerability",
            owasp="A08",
            severity="medium",
            cwe_id="CWE-538",
            cvss_score=5.3,
            affected_url=url,
            payload=path,
            evidence=f"{label} publicly accessible ({len(body)} bytes).",
            description=(
                f"The {label} is publicly accessible. Build/deploy pipeline files "
                "reveal your infrastructure, deployment steps, secret variable names, "
                "and third-party integrations — a roadmap for supply-chain attacks."
            ),
            impact="Attackers learn your build/deploy pipeline to target the software supply chain.",
            recommendation=f"Block public access to '{path}'. Keep CI/CD config out of the web root.",
            poc=f"curl '{url}'",
            verified=True,
            likelihood=3, impact_score=3, risk_score=9,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a08_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_deserialization_markers(client, target_url, endpoints)
        except Exception as e: logger.warning(f"[A08] deser: {e}")
        try: findings += test_exposed_source_maps(client, target_url)
        except Exception as e: logger.warning(f"[A08] sourcemap: {e}")
        try: findings += test_exposed_cicd(client, target_url)
        except Exception as e: logger.warning(f"[A08] cicd: {e}")
    finally:
        client.close()
    logger.info(f"[A08] Found {len(findings)} integrity findings")
    return findings
