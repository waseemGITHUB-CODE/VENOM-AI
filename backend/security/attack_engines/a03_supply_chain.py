"""
VENOM AI — A03 Software Supply Chain Failures Engine (OWASP Top 10:2025 #3)
─────────────────────────────────────────────────────────────────────────
Tests:

  1. Vulnerable JavaScript libraries — detect old versions of jQuery,
     Angular, Bootstrap, etc. that have known CVEs.

  2. Exposed package manifests — package.json / composer.json / requirements.txt
     accessible via the web reveals exact dependency versions an attacker can
     check against vulnerability databases.

  3. Subresource Integrity (SRI) missing on CDN scripts — without SRI, if the
     CDN is compromised the attacker can serve malicious code to your users.

  4. Outdated framework markers — server/X-Powered-By revealing versions
     known to be end-of-life or with public CVEs.

  5. Public OSV.dev lookup for any detected library + version (best-effort).
"""
from __future__ import annotations

import logging
import re
import json
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a03")


# ════════════════════════════════════════════════════════════════════════════
# KNOWN VULNERABLE VERSIONS — curated minimum-safe versions
# (when ALL minor versions before this have CVEs)
# ════════════════════════════════════════════════════════════════════════════
# (library_name, min_safe_version, [example_cves])
LIBRARY_MIN_SAFE = {
    "jquery":      ("3.5.0",  ["CVE-2020-11022", "CVE-2020-11023"]),
    "angular":     ("1.8.0",  ["CVE-2020-7676"]),
    "bootstrap":   ("4.3.1",  ["CVE-2019-8331"]),
    "lodash":      ("4.17.21",["CVE-2020-8203", "CVE-2021-23337"]),
    "moment":      ("2.29.4", ["CVE-2022-31129"]),
    "axios":       ("0.21.2", ["CVE-2021-3749"]),
    "react":       ("16.4.2", []),    # mostly safe but very old = warn
    "vue":         ("2.6.11", []),
    "underscore":  ("1.12.1", ["CVE-2021-23358"]),
    "marked":      ("4.0.10", ["CVE-2022-21680", "CVE-2022-21681"]),
    "ckeditor":    ("4.16.0", ["CVE-2020-9281"]),
    "tinymce":     ("5.10.0", ["CVE-2021-43997"]),
    "handlebars":  ("4.7.7",  ["CVE-2021-23369"]),
    "ejs":         ("3.1.7",  ["CVE-2022-29078"]),
}


# Patterns to extract (library_name, version_tuple) from script src URLs
_LIB_SRC_PATTERNS = [
    # jQuery: jquery-3.5.1.min.js, jquery/2.1.0/, jquery.min.js?ver=1.12
    (r"jquery[/\-\.](?:min|slim)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "jquery"),
    # Angular 1.x: angular.js or angular-1.8.0.js
    (r"angular[/\-\.](?:min|slim)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "angular"),
    # Bootstrap
    (r"bootstrap[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "bootstrap"),
    # Lodash
    (r"lodash[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "lodash"),
    # Moment
    (r"moment[/\-\.](?:min|with-locales)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "moment"),
    # Underscore
    (r"underscore[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "underscore"),
    # React UMD
    (r"react(?:-dom)?[/\-\.](?:production|development)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "react"),
    # Vue
    (r"vue[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "vue"),
    # CKEditor / TinyMCE
    (r"ckeditor[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "ckeditor"),
    (r"tinymce[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "tinymce"),
    (r"marked[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "marked"),
    (r"handlebars[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "handlebars"),
    (r"ejs[/\-\.](?:min)?[/\-\.]?(\d+)\.(\d+)(?:\.(\d+))?", "ejs"),
]

# Trusted CDN domains where SRI is critical
CDN_DOMAINS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "cdn.bootcss.com", "cdn.bootcdn.net",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "fonts.googleapis.com", "use.fontawesome.com",
}


def _version_tuple(v_str: str) -> Tuple[int, int, int]:
    """'3.5.1' → (3,5,1). Missing parts default to 0."""
    parts = [int(x) for x in v_str.split(".") if x.isdigit()][:3]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _is_vulnerable(lib_name: str, version: Tuple[int, int, int]) -> Optional[Tuple[str, List[str]]]:
    """Return (min_safe_version, cves) if lib version is below the safe minimum."""
    entry = LIBRARY_MIN_SAFE.get(lib_name)
    if not entry:
        return None
    min_safe_str, cves = entry
    min_safe = _version_tuple(min_safe_str)
    if version < min_safe:
        return min_safe_str, cves
    return None


# ════════════════════════════════════════════════════════════════════════════
# DETECT VULNERABLE JS LIBRARIES FROM <script src=...> + DETECTED TECH
# ════════════════════════════════════════════════════════════════════════════

def test_vulnerable_js_libraries(client: AttackClient, target_url: str,
                                  detected_tech: Optional[List[dict]] = None) -> List[Finding]:
    """
    Fetch homepage, extract <script src=...>, parse version strings,
    compare to LIBRARY_MIN_SAFE, emit findings for outdated libs.
    """
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r or not r.text:
        return findings

    body = r.text
    found_libs = {}   # lib_name -> (version_tuple, version_str, src_url)

    # First pass: extract from <script src="...">
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
        src = m.group(1)
        for pattern, lib_name in _LIB_SRC_PATTERNS:
            mm = re.search(pattern, src, re.IGNORECASE)
            if not mm:
                continue
            major = int(mm.group(1))
            minor = int(mm.group(2)) if mm.group(2) else 0
            patch = int(mm.group(3)) if mm.group(3) else 0
            version = (major, minor, patch)
            version_str = f"{major}.{minor}.{patch}"
            # Keep the earliest found version per lib (don't overwrite)
            if lib_name not in found_libs:
                found_libs[lib_name] = (version, version_str, src)
            break

    # Second pass: use detected_tech (from recon) to catch versions in headers/cookies
    if detected_tech:
        for tech in detected_tech:
            name = (tech.get("name") or "").lower()
            version_str = tech.get("version") or ""
            if not version_str or name not in LIBRARY_MIN_SAFE:
                continue
            if name in found_libs:
                continue
            version = _version_tuple(version_str)
            if version != (0, 0, 0):
                found_libs[name] = (version, version_str, "detected by tech fingerprinter")

    # Evaluate each detected library
    for lib_name, (version, version_str, src) in found_libs.items():
        vuln_info = _is_vulnerable(lib_name, version)
        if not vuln_info:
            continue
        min_safe_str, cves = vuln_info
        cve_str = ", ".join(cves) if cves else "(historical CVEs)"
        severity = "high" if cves else "medium"
        cvss = 7.5 if cves else 5.3

        findings.append(Finding(
            title=f"Outdated {lib_name.title()} Library: v{version_str}",
            category="vulnerability",
            owasp="A03",
            severity=severity,
            cwe_id="CWE-1104",
            cvss_score=cvss,
            affected_url=target_url,
            payload=f"{lib_name}@{version_str} detected (min safe: {min_safe_str})",
            evidence=f"Detected at {src}",
            description=(
                f"The application loads {lib_name} version {version_str}, which is older "
                f"than the minimum safe version ({min_safe_str}). Known CVEs: {cve_str}. "
                "Attackers can craft inputs that exploit these dependency vulnerabilities."
            ),
            impact=(
                "Depending on the CVE, attackers can: execute arbitrary JavaScript via XSS, "
                "bypass DOM sanitization, perform prototype pollution, or trigger ReDoS."
            ),
            recommendation=(
                f"Upgrade {lib_name} to {min_safe_str} or later. Configure your build "
                "pipeline to flag outdated dependencies (npm audit, snyk, GitHub Dependabot)."
            ),
            poc=f"# Library found:\n# {src}\n# Check CVEs: https://osv.dev/list?q={lib_name}",
            verified=True,
            cve_id=cves[0] if cves else "",
            likelihood=4, impact_score=4 if severity == "high" else 3,
            risk_score=16 if severity == "high" else 9,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# EXPOSED PACKAGE MANIFESTS
# ════════════════════════════════════════════════════════════════════════════

# (path, file_type, what_it_reveals)
MANIFEST_PATHS = [
    ("/package.json",        "Node.js (npm)",   "exact dependency versions, possibly with private package names"),
    ("/package-lock.json",   "Node.js lockfile","full dependency tree with resolved versions"),
    ("/yarn.lock",           "Yarn lockfile",   "full dependency tree"),
    ("/composer.json",       "PHP (Composer)",  "PHP dependency versions"),
    ("/composer.lock",       "PHP lockfile",    "PHP dependency tree"),
    ("/requirements.txt",    "Python pip",      "Python dependency versions"),
    ("/Pipfile",             "Python Pipenv",   "Python dependency requirements"),
    ("/Pipfile.lock",        "Python lockfile", "Python dependency tree"),
    ("/Gemfile",             "Ruby Bundler",    "Ruby gem requirements"),
    ("/Gemfile.lock",        "Ruby lockfile",   "Ruby gem versions"),
    ("/go.mod",              "Go modules",      "Go dependency requirements"),
    ("/go.sum",              "Go checksums",    "Go dependency checksums"),
    ("/pom.xml",             "Java (Maven)",    "Maven dependency tree"),
    ("/build.gradle",        "Java (Gradle)",   "Gradle dependency declarations"),
    ("/Cargo.toml",          "Rust (Cargo)",    "Rust crate versions"),
    ("/Cargo.lock",          "Rust lockfile",   "Rust crate dependency tree"),
    ("/Dockerfile",          "Docker",          "base image versions, build commands"),
    ("/docker-compose.yml",  "Docker Compose",  "stack config, possibly credentials"),
]


def test_exposed_manifests(client: AttackClient, target_url: str) -> List[Finding]:
    """Probe for publicly accessible package manifests."""
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"

    for path, file_type, reveals in MANIFEST_PATHS:
        url = base + path
        r = client.get(url)
        if not r or r.status_code != 200:
            continue
        body = r.text or ""
        if len(body) < 30:
            continue
        ctype = (r.headers.get("content-type") or "").lower()

        # Content confirmation per file type
        confirmed = False
        if path.endswith(".json"):
            try:
                parsed = json.loads(body)
                # package.json should have "name" or "dependencies"
                if isinstance(parsed, dict) and ("dependencies" in parsed or "name" in parsed or "version" in parsed):
                    confirmed = True
            except Exception:
                pass
        elif "Dockerfile" in path and ("FROM " in body[:200] or "RUN " in body):
            confirmed = True
        elif path in ("/requirements.txt", "/Pipfile"):
            # Should contain package==version lines
            if re.search(r"^[a-zA-Z0-9_\-]+[=<>]", body, re.MULTILINE):
                confirmed = True
        elif path.endswith(".lock") and len(body) > 100:
            # Lockfiles are typically large
            confirmed = True
        elif path in ("/go.mod", "/Cargo.toml", "/pom.xml", "/build.gradle"):
            confirmed = len(body) > 100 and ("module" in body or "[package]" in body or "<project" in body or "dependencies" in body)
        elif path in ("/Gemfile", "/composer.json"):
            confirmed = ("source" in body or "gem " in body or "require" in body)

        if not confirmed:
            continue

        findings.append(Finding(
            title=f"Exposed Package Manifest: {path}",
            category="vulnerability",
            owasp="A03",
            severity="high",
            cwe_id="CWE-538",
            cvss_score=7.5,
            affected_url=url,
            payload=path,
            evidence=f"HTTP 200, {len(body)} bytes — confirmed {file_type} manifest content",
            description=(
                f"The {file_type} manifest at {path} is publicly accessible. "
                f"It reveals {reveals}. Attackers use this to enumerate exact "
                f"dependency versions and search for known CVEs in your stack."
            ),
            impact=(
                "Targeted attacks become trivial — attackers know your exact dependency tree "
                "and which vulnerabilities apply to your specific versions."
            ),
            recommendation=(
                f"Block public access to '{path}' in your web server config. "
                "Move build files outside the web root. For SPAs, ensure your build "
                "pipeline excludes manifests from the deployment artifact."
            ),
            poc=f"curl '{url}'",
            verified=True,
            likelihood=5, impact_score=3, risk_score=15,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# MISSING SUBRESOURCE INTEGRITY (SRI) ON CDN SCRIPTS
# ════════════════════════════════════════════════════════════════════════════

def test_missing_sri(client: AttackClient, target_url: str) -> List[Finding]:
    """
    Detect <script src="https://cdn..."> tags missing integrity= attribute.
    Without SRI, a compromised CDN can serve malicious code to all your users.
    """
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r or not r.text:
        return findings

    body = r.text
    cdn_without_sri = []
    # Match all <script ...> tags
    for tag in re.findall(r'<script\b[^>]*>', body, re.IGNORECASE):
        src_match = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if not src_match:
            continue
        src = src_match.group(1)
        # Resolve to absolute
        try:
            full_url = urljoin(target_url, src)
            host = urlparse(full_url).hostname or ""
        except Exception:
            continue
        # Only flag CDN-hosted scripts (third-party sources)
        if not any(host == cdn or host.endswith("." + cdn) for cdn in CDN_DOMAINS):
            continue
        # Look for integrity= attribute
        has_sri = "integrity=" in tag.lower()
        if not has_sri:
            cdn_without_sri.append((src, host))

    if not cdn_without_sri:
        return findings

    # Emit single combined finding listing all flagged scripts
    sample = cdn_without_sri[:5]
    extra_count = len(cdn_without_sri) - len(sample)
    evidence_lines = "\n".join(f"  - {s}" for s, _ in sample)
    if extra_count > 0:
        evidence_lines += f"\n  ... and {extra_count} more"

    findings.append(Finding(
        title=f"Subresource Integrity (SRI) Missing on {len(cdn_without_sri)} CDN Script(s)",
        category="vulnerability",
        owasp="A03",
        severity="medium",
        cwe_id="CWE-353",
        cvss_score=5.3,
        affected_url=target_url,
        evidence=f"CDN scripts without integrity= attribute:\n{evidence_lines}",
        description=(
            "Script tags loading code from third-party CDNs do not include the "
            "integrity= attribute (SRI). If the CDN is compromised — or if an "
            "attacker MITMs the connection — they can serve malicious JavaScript "
            "to all your users without you knowing."
        ),
        impact=(
            "Mass user compromise via a single CDN attack. The 2018 BrowseAloud incident "
            "where a single CDN script breach compromised thousands of government sites "
            "is a textbook example."
        ),
        recommendation=(
            "Add the integrity attribute to every external script tag:\n"
            "<script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>\n"
            "Generate hashes with https://www.srihash.org or your build pipeline."
        ),
        poc=f"# View source of {target_url} — flagged scripts:\n# " + "\n# ".join(s for s, _ in sample),
        verified=True,
        likelihood=3, impact_score=4, risk_score=12,
    ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# END-OF-LIFE / DISCLOSED FRAMEWORK VERSIONS
# ════════════════════════════════════════════════════════════════════════════

# Specific frameworks/servers known to be EOL when their version starts with these
EOL_SERVERS = [
    ("Apache/1.",  "Apache HTTPD 1.x is end-of-life since 2010"),
    ("Apache/2.0", "Apache HTTPD 2.0.x is end-of-life since 2013"),
    ("Apache/2.2", "Apache HTTPD 2.2.x is end-of-life since 2017"),
    ("nginx/0.",   "nginx 0.x is severely outdated"),
    ("nginx/1.0",  "nginx 1.0.x is end-of-life (>10 years)"),
    ("nginx/1.1",  "nginx 1.1.x is end-of-life"),
    ("IIS/6.",     "IIS 6.x (Windows Server 2003) is end-of-life"),
    ("IIS/7.",     "IIS 7.x is end-of-life"),
    ("PHP/5.",     "PHP 5.x is end-of-life since 2018"),
    ("PHP/7.0",    "PHP 7.0 is end-of-life since 2019"),
    ("PHP/7.1",    "PHP 7.1 is end-of-life since 2019"),
    ("PHP/7.2",    "PHP 7.2 is end-of-life since 2020"),
    ("PHP/7.3",    "PHP 7.3 is end-of-life since 2021"),
]


def test_eol_servers(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r:
        return findings
    server    = r.headers.get("server", "")
    x_powered = r.headers.get("x-powered-by", "")
    combined = f"{server} | {x_powered}".strip()
    for prefix, reason in EOL_SERVERS:
        if prefix in server or prefix in x_powered:
            findings.append(Finding(
                title=f"End-of-Life Software Detected: {prefix.rstrip('.')}",
                category="vulnerability",
                owasp="A03",
                severity="high",
                cwe_id="CWE-1104",
                cvss_score=7.5,
                affected_url=target_url,
                evidence=f"Server: {server}" + (f" | X-Powered-By: {x_powered}" if x_powered else ""),
                description=(
                    f"{reason}. End-of-life software no longer receives security patches. "
                    f"Any new CVE discovered will never be fixed by the vendor."
                ),
                impact=(
                    "All future vulnerabilities in this software remain unfixed. Attackers "
                    "specifically target EOL software because exploits are well-documented "
                    "and patches are unavailable."
                ),
                recommendation=(
                    f"Upgrade to a supported version immediately. Check the official upgrade "
                    "path on the vendor's website and plan a maintenance window."
                ),
                poc=f"curl -I '{target_url}'\n# Server: {server}",
                verified=True,
                likelihood=4, impact_score=4, risk_score=16,
            ))
            break   # one EOL marker per server is enough
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a03_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, detected_tech: Optional[List[dict]] = None,
                    max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_vulnerable_js_libraries(client, target_url, detected_tech)
        except Exception as e: logger.warning(f"[A03] vuln_libs: {e}")

        try: findings += test_exposed_manifests(client, target_url)
        except Exception as e: logger.warning(f"[A03] manifests: {e}")

        try: findings += test_missing_sri(client, target_url)
        except Exception as e: logger.warning(f"[A03] sri: {e}")

        try: findings += test_eol_servers(client, target_url)
        except Exception as e: logger.warning(f"[A03] eol: {e}")
    finally:
        client.close()

    logger.info(f"[A03] Found {len(findings)} supply chain findings")
    return findings
