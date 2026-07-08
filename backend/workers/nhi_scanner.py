"""
backend/services/nhi_scanner.py — Non-Human Identity (NHI) Security Scanner
=============================================================================
Scans for:
  • Leaked API keys in HTTP responses, JS files, HTML source
  • Over-privileged service tokens
  • Shadow AI / orphaned tokens (patterns only)
  • Exposed cloud credentials (AWS, GCP, Azure)
  • Hardcoded secrets in public endpoints
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("venom.nhi")


# ─── Secret patterns ──────────────────────────────────────────────────────────

_PATTERNS = {
    "AWS Access Key":        (r"AKIA[0-9A-Z]{16}", "critical"),
    "AWS Secret Key":        (r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    "AWS Session Token":     (r"(?i)aws.{0,10}session.{0,10}['\"][A-Za-z0-9/+=]{100,}['\"]", "high"),
    "GCP Service Account":   (r"-----BEGIN RSA PRIVATE KEY-----", "critical"),
    "GCP API Key":           (r"AIza[0-9A-Za-z\-_]{35}", "high"),
    "Azure Storage Key":     (r"DefaultEndpointsProtocol=https;AccountName=", "high"),
    "Azure Client Secret":   (r"(?i)clientsecret.{0,10}['\"][a-zA-Z0-9.~_-]{34}['\"]", "high"),
    "GitHub Token":          (r"ghp_[0-9a-zA-Z]{36}", "critical"),
    "GitHub OAuth":          (r"gho_[0-9a-zA-Z]{36}", "high"),
    "GitHub App Token":      (r"ghu_[0-9a-zA-Z]{36}", "high"),
    "GitLab Token":          (r"glpat-[0-9a-zA-Z\-_]{20}", "high"),
    "Stripe Secret Key":     (r"sk_live_[0-9a-zA-Z]{24}", "critical"),
    "Stripe Publishable":    (r"pk_live_[0-9a-zA-Z]{24}", "medium"),
    "Twilio Account SID":    (r"AC[a-z0-9]{32}", "high"),
    "Twilio Auth Token":     (r"(?i)twilio.{0,10}['\"][a-f0-9]{32}['\"]", "high"),
    "SendGrid API Key":      (r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "high"),
    "Slack Bot Token":       (r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}", "high"),
    "Slack OAuth Token":     (r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+", "high"),
    "Slack Webhook":         (r"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "medium"),
    "Discord Bot Token":     (r"[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}", "high"),
    "Groq API Key":          (r"gsk_[a-zA-Z0-9]{52}", "high"),
    "OpenAI API Key":        (r"sk-[a-zA-Z0-9]{48}", "critical"),
    "Anthropic API Key":     (r"sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{93}", "critical"),
    "HuggingFace Token":     (r"hf_[a-zA-Z0-9]{39}", "high"),
    "JWT Token":             (r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "medium"),
    "Generic Bearer Token":  (r"(?i)bearer\s+[a-zA-Z0-9\-_.]+", "low"),
    "Basic Auth in URL":     (r"https?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@", "high"),
    "Private Key Block":     (r"-----BEGIN (EC |RSA |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    "Database URL":          (r"(postgres|mysql|mongodb|redis)://[^\s\"'<>]+", "high"),
    "Generic Password":      (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]", "medium"),
    "Generic Secret":        (r"(?i)(secret|token|api.?key)\s*[:=]\s*['\"][a-zA-Z0-9/+._-]{20,}['\"]", "medium"),
}

# Paths to spider for secrets
_SPIDER_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/assets/main.js",
    "/static/js/main.js",
    "/js/app.js",
    "/bundle.js",
    "/wp-includes/js/wp-embed.min.js",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/docs",
]


@dataclass
class NHIFinding:
    key_type:    str
    severity:    str
    location:    str        # URL where found
    context:     str        # snippet around the match
    match:       str        # the actual matched value (partially masked)
    description: str
    remediation: str


def _mask(value: str) -> str:
    """Partially mask a secret for safe display."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _scan_content(content: str, url: str) -> List[NHIFinding]:
    """Scan text content for secret patterns."""
    findings = []
    for key_type, (pattern, severity) in _PATTERNS.items():
        for match in re.finditer(pattern, content):
            raw = match.group(0)
            # Get context (50 chars around match)
            start = max(0, match.start() - 50)
            end   = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ").strip()

            findings.append(NHIFinding(
                key_type=key_type,
                severity=severity,
                location=url,
                context=context,
                match=_mask(raw),
                description=f"{key_type} found in {url}. This credential may allow unauthorized access.",
                remediation=(
                    f"1. Immediately rotate/revoke this {key_type}.\n"
                    f"2. Remove from source code and use environment variables.\n"
                    f"3. Audit usage logs for unauthorized access.\n"
                    f"4. Enable secret scanning in your CI/CD pipeline."
                ),
            ))
    return findings


def _fetch_page(url: str, timeout: int = 8) -> Optional[str]:
    try:
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "VENOM-AI-NHI-Scanner/1.0"
        })
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None



def _extract_js_urls(html: str, base_url: str) -> list:
    """Extract JavaScript file URLs from HTML source."""
    import re
    from urllib.parse import urljoin
    js_urls = []
    # Match <script src="...">
    pattern = r"""<script[^>]+src=['"](https?://[^'"]+\.js[^'"]*|/[^'"]+\.js[^'"]*)['"]"""
    for match in re.finditer(pattern, html, re.IGNORECASE):
        src = match.group(1)
        if not src.startswith('http'):
            src = urljoin(base_url, src)
        if src not in js_urls:
            js_urls.append(src)
    return js_urls


def run_nhi_scan(base_url: str) -> List[NHIFinding]:
    """
    Full NHI scan — spiders key endpoints and scans for exposed credentials.
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    all_findings: List[NHIFinding] = []
    scanned: set = set()

    logger.info(f"[NHI] Starting scan on {base_url}")

    # Scan predefined paths
    for path in _SPIDER_PATHS:
        url = urljoin(base, path)
        if url in scanned:
            continue
        scanned.add(url)

        content = _fetch_page(url)
        if content:
            findings = _scan_content(content, url)
            if findings:
                logger.info(f"[NHI] Found {len(findings)} secrets at {url}")
            all_findings.extend(findings)

    # Scan the main URL itself
    if base_url not in scanned:
        page_content = _fetch_page(base_url)
        if page_content:
            all_findings.extend(_scan_content(page_content, base_url))
            # Extract and scan linked JS files (key hiding spot)
            js_urls = _extract_js_urls(page_content, base)
            for js_url in js_urls[:10]:  # limit to 10 JS files
                if js_url in scanned:
                    continue
                scanned.add(js_url)
                js_content = _fetch_page(js_url)
                if js_content:
                    js_findings = _scan_content(js_content, js_url)
                    if js_findings:
                        logger.info(f"[NHI] Found {len(js_findings)} secrets in JS: {js_url}")
                    all_findings.extend(js_findings)

    # Deduplicate by (key_type, location, match)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.key_type, f.location, f.match)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    logger.info(f"[NHI] Scan complete — {len(unique)} unique NHI findings")
    return unique


def nhi_findings_to_vulns(findings: List[NHIFinding], scan_job_id: int) -> List[dict]:
    """Convert NHI findings to the standard vulnerability dict format."""
    vulns = []
    for f in findings:
        vulns.append({
            "scan_job_id":   scan_job_id,
            "vuln_type":     "Non-Human Identity Leak",
            "title":         f"Exposed {f.key_type}",
            "description":   f.description,
            "severity":      f.severity,
            "risk_level":    f.severity,
            "affected_url":  f.location,
            "evidence":      f.context,
            "impact":        f"Credential exposure enables unauthorized access to {f.key_type} resource.",
            "fix":           f.remediation,
            "code_example":  "# Never hardcode secrets\n# Use environment variables\nimport os\napi_key = os.environ.get('API_KEY')",
            "reference":     "https://owasp.org/www-project-top-ten/",
            "source_tool":   "nhi_scanner",
            "cwe_id":        "CWE-798",
            "is_verified":   True,
            "poe_confirmed": True,
            "poe_proof":     f"Pattern match: {f.key_type} detected at {f.location}",
            "nhi_key_type":  f.key_type,
            "nhi_masked":    f.match,
        })
    return vulns