"""
VENOM AI — A02 Security Misconfiguration Engine (OWASP Top 10:2025 #2)
─────────────────────────────────────────────────────────────────────────
Active tests:

  1. Exposed sensitive files — .env, .git/config, backup.zip, .DS_Store, etc.
  2. Debug pages — Django debug, Rails error pages, Flask debugger, Laravel debug
  3. Default credentials — try common admin/admin, admin/password on /login
  4. CORS misconfiguration — Access-Control-Allow-Origin: * with credentials
  5. Server version disclosure — Server/X-Powered-By revealing exact versions
  6. Stack trace leakage on errors — forcing a 500 to look for SQL/code traces
  7. Verbose error responses — generic crash → error reveals internal paths

A02 moved from #5 (2021) → #2 (2025) — misconfig is now the second most
common root cause of breaches per the OWASP data.
"""
from __future__ import annotations

import logging
import re
import time
from typing import List, Optional
from urllib.parse import urlparse, urljoin

from .common import AttackClient, Finding

logger = logging.getLogger("venom.attack.a02")


# ════════════════════════════════════════════════════════════════════════════
# EXPOSED CONFIG / DEV FILES
# ════════════════════════════════════════════════════════════════════════════

# Path → (severity, description fragment) — these are RAW config files
EXPOSED_FILES = [
    # Environment files
    ("/.env",                 "critical", ".env file (production secrets)"),
    ("/.env.local",           "critical", "Local environment file"),
    ("/.env.production",      "critical", "Production environment file"),
    ("/.env.dev",             "high",     "Development environment file"),
    # Git
    ("/.git/config",          "critical", "Git config (repo metadata)"),
    ("/.git/HEAD",            "critical", "Git HEAD reference"),
    ("/.git/logs/HEAD",       "high",     "Git commit history"),
    # Package manifests with potential secrets
    ("/composer.json",        "medium",   "Composer manifest"),
    ("/composer.lock",        "low",      "Composer dependency lock"),
    ("/package.json",         "low",      "NPM manifest"),
    ("/yarn.lock",            "low",      "Yarn lock file"),
    # DB & backups
    ("/backup.sql",           "critical", "Database backup"),
    ("/dump.sql",             "critical", "Database dump"),
    ("/database.sql",         "critical", "Database SQL export"),
    ("/db.sql",               "critical", "Database export"),
    ("/backup.zip",           "high",     "ZIP backup archive"),
    ("/backup.tar.gz",        "high",     "tar.gz backup archive"),
    ("/site-backup.zip",      "high",     "Site backup"),
    # Server config
    ("/.htaccess",            "medium",   "Apache .htaccess"),
    ("/.htpasswd",            "critical", "Apache basic-auth password file"),
    ("/web.config",           "medium",   "IIS web.config"),
    ("/nginx.conf",           "high",     "nginx config"),
    # Source code leaks
    ("/.svn/entries",         "high",     "SVN repository data"),
    ("/.hg/store",            "high",     "Mercurial repository data"),
    ("/.DS_Store",            "low",      "macOS Finder metadata (path leakage)"),
    ("/Thumbs.db",            "low",      "Windows thumbnails (path leakage)"),
    # IDE/editor leftovers
    ("/.vscode/settings.json","medium",   "VS Code settings"),
    ("/.idea/workspace.xml",  "medium",   "JetBrains workspace"),
    # PHP info
    ("/phpinfo.php",          "high",     "PHP info disclosure page"),
    ("/info.php",             "high",     "Generic info disclosure"),
    ("/test.php",             "medium",   "Test PHP file"),
]


def test_exposed_files(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"

    # Baseline 404 fingerprint
    nf = client.get(base + "/this-path-should-not-exist-" + str(int(time.time())))
    nf_status = nf.status_code if nf else 404
    nf_len = len(nf.text or "") if nf else 0

    for path, sev, desc in EXPOSED_FILES:
        url = base + path
        r = client.get(url)
        if not r:
            continue
        if r.status_code not in (200, 301, 302):
            continue
        body = r.text or ""
        body_len = len(body)
        # Skip SPA fallbacks: same status + size as 404
        if r.status_code == nf_status and body_len > 0 and abs(body_len - nf_len) < 200:
            continue
        # Skip if obviously a 404 page despite 200 status
        if any(k in body.lower()[:500] for k in ("not found", "404", "page does not exist")):
            continue
        # Path-specific content checks for high confidence
        confirmed = False
        body_lower = body.lower()
        if path == "/.env" and any(k in body for k in ("APP_KEY", "SECRET", "PASSWORD", "DB_PASSWORD", "API_KEY")):
            confirmed = True
        elif path.startswith("/.git/") and ("[core]" in body or "ref: refs/" in body or "repositoryformatversion" in body):
            confirmed = True
        elif path in ("/backup.sql", "/dump.sql", "/database.sql", "/db.sql") and (
                "create table" in body_lower or "insert into" in body_lower or "drop table" in body_lower):
            confirmed = True
        elif path == "/.htpasswd" and re.search(r"^[\w\.\-]+:\$", body, re.MULTILINE):
            confirmed = True
        elif path == "/phpinfo.php" and "phpinfo()" in body_lower:
            confirmed = True
        else:
            # Content-type / size heuristics
            ctype = (r.headers.get("content-type") or "").lower()
            if "text/plain" in ctype or "application/json" in ctype or body_len > 100:
                confirmed = True

        if not confirmed:
            continue

        cvss = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}[sev]
        findings.append(Finding(
            title=f"Exposed File: {path}",
            category="vulnerability",
            owasp="A02",
            severity=sev,
            cwe_id="CWE-538",
            cvss_score=cvss,
            affected_url=url,
            http_method="GET",
            payload=path,
            evidence=f"HTTP {r.status_code}, {body_len} bytes. {desc} confirmed via content inspection.",
            description=(
                f"The {desc} is publicly accessible at {path}. This file should never "
                f"be reachable from outside the application."
            ),
            impact=(
                "Direct exposure of secrets, source code, or backups. Attackers can "
                "harvest API keys, database credentials, source code, or full database dumps."
            ),
            recommendation=(
                f"Block public access to '{path}' in your web server config. "
                "Move config files outside the web root. Ensure backup files are "
                "stored on private storage with proper access controls."
            ),
            poc=f"curl '{url}'",
            verified=True,
            likelihood=5,
            impact_score=5 if sev == "critical" else 4 if sev == "high" else 3,
            risk_score=25 if sev == "critical" else 16 if sev == "high" else 9,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# DEBUG PAGE DETECTION
# ════════════════════════════════════════════════════════════════════════════

DEBUG_INDICATORS = [
    # Django
    (r"DEBUG\s*=\s*True", "Django DEBUG=True"),
    (r"You're seeing this error because", "Django debug error page"),
    (r"<title>.*?DisallowedHost", "Django DisallowedHost"),
    # Flask / Werkzeug
    (r"Werkzeug Debugger", "Werkzeug debugger"),
    (r"console=\d+", "Werkzeug debug console"),
    # Rails
    (r"Rails\.application\.routes", "Rails routes exposed"),
    (r"<title>Action Controller: Exception caught", "Rails exception page"),
    # Laravel
    (r"Whoops, looks like something went wrong", "Laravel/Whoops error page"),
    (r"Whoops! There was an error", "Whoops! Generic"),
    (r"Ignition", "Laravel Ignition debug"),
    # PHP
    (r"<b>Fatal error</b>:", "PHP fatal error visible"),
    (r"<b>Warning</b>:.*?on line", "PHP warning visible"),
    # ASP.NET
    (r"<title>Runtime Error</title>", ".NET runtime error page"),
    (r"Server Error in.*Application", "ASP.NET error page"),
    # Express / Node
    (r"<pre>Error: ", "Express error stack trace"),
    (r"at Object\.\<anonymous\>", "Node.js stack trace"),
    # Java/Spring
    (r"<title>Whitelabel Error Page", "Spring Boot error page"),
    (r"javax\.servlet\.ServletException", "Java servlet exception"),
]


def test_debug_pages(client: AttackClient, target_url: str) -> List[Finding]:
    """
    Force errors and look for debug pages.
    Strategy:
      1. Hit baseline pages to see normal responses
      2. Hit URLs likely to trigger errors:
         /nonexistent, /?[]=crash, /search?q=', /test/nonexistent/123
      3. Look for framework debug markers in responses
    """
    findings: List[Finding] = []
    p = urlparse(target_url)
    base = f"{p.scheme}://{p.netloc}"

    # URLs likely to provoke error pages
    probe_paths = [
        "/nonexistent-trigger-error-" + str(int(time.time())),
        "/?[]=&debug=1",
        "/api/x'><script>",
        "/search?q=%00%00",
    ]

    seen_signatures: set = set()
    for probe in probe_paths:
        url = base + probe
        r = client.get(url)
        if not r:
            continue
        body = r.text or ""
        if len(body) < 100:
            continue
        for pattern, label in DEBUG_INDICATORS:
            if label in seen_signatures:
                continue
            if re.search(pattern, body, re.IGNORECASE):
                seen_signatures.add(label)
                findings.append(Finding(
                    title=f"Debug Page Exposed: {label}",
                    category="vulnerability",
                    owasp="A02",
                    severity="high",
                    cwe_id="CWE-209",
                    cvss_score=7.5,
                    affected_url=url,
                    http_method="GET",
                    payload=probe,
                    evidence=f"Response contains debug marker matching '{pattern}'",
                    description=(
                        f"Provoking an error triggered a {label} response. Debug pages "
                        f"in production reveal source code paths, stack traces, environment "
                        f"variables, and database connection details."
                    ),
                    impact=(
                        "Attacker learns internal file paths, framework versions, database "
                        "schema, and sometimes session tokens or secrets — enabling targeted attacks."
                    ),
                    recommendation=(
                        "Disable debug mode in production. Set DEBUG=False (Django), "
                        "APP_DEBUG=false (Laravel), NODE_ENV=production (Node). "
                        "Configure a generic 500 error page that reveals nothing."
                    ),
                    poc=f"curl '{url}'",
                    verified=True,
                    likelihood=4, impact_score=4, risk_score=16,
                ))
                break   # one match per probe is enough
    return findings


# ════════════════════════════════════════════════════════════════════════════
# CORS MISCONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

def test_cors_misconfig(client: AttackClient, target_url: str) -> List[Finding]:
    """
    Test for dangerous CORS configurations:
      1. Access-Control-Allow-Origin: * with Allow-Credentials: true (invalid + dangerous)
      2. Origin reflection — server echoes back any Origin header (very dangerous)
      3. Null origin allowed (allows attacks from sandboxed iframes / data: URIs)
    """
    findings: List[Finding] = []
    attacker_origin = "https://evil.example.com"

    # Probe with attacker origin
    r = client.get(target_url, headers={"Origin": attacker_origin})
    if not r:
        return findings

    aco  = r.headers.get("access-control-allow-origin", "")
    acc  = r.headers.get("access-control-allow-credentials", "").lower() == "true"

    # 1. Origin reflection (echoes any origin)
    if aco == attacker_origin:
        findings.append(Finding(
            title="CORS Origin Reflection",
            category="vulnerability",
            owasp="A02",
            severity="high" if acc else "medium",
            cwe_id="CWE-942",
            cvss_score=7.5 if acc else 5.3,
            affected_url=target_url,
            http_method="GET",
            payload=f"Origin: {attacker_origin}",
            evidence=f"Server echoed back our origin: Access-Control-Allow-Origin: {aco}"
                     + (f"; Access-Control-Allow-Credentials: true" if acc else ""),
            description=(
                "The server reflects any Origin header in its Access-Control-Allow-Origin response. "
                + ("Combined with Allow-Credentials: true, this allows attackers to make "
                   "authenticated cross-origin requests, stealing session data." if acc
                   else "This bypasses CORS protection — any site can read API responses.")
            ),
            impact=("Full account takeover possible — attacker's site can read authenticated "
                    "responses and exfiltrate data." if acc
                    else "Sensitive API responses readable from any malicious site."),
            recommendation=(
                "Maintain an allowlist of trusted origins. Reject unknown Origin values. "
                "Never combine Allow-Origin: * (or reflection) with Allow-Credentials: true."
            ),
            poc=f"curl -H 'Origin: https://evil.com' '{target_url}'",
            verified=True,
            likelihood=4, impact_score=5 if acc else 4, risk_score=20 if acc else 16,
        ))

    # 2. Wildcard origin with credentials (impossible per spec but some misconfigs allow it)
    elif aco == "*" and acc:
        findings.append(Finding(
            title="CORS Wildcard + Credentials",
            category="vulnerability",
            owasp="A02",
            severity="high",
            cwe_id="CWE-942",
            cvss_score=7.5,
            affected_url=target_url,
            payload="Origin: *",
            evidence=f"Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true",
            description="Browser specs forbid this combination, but some custom CORS handlers allow it. Any cross-origin site can make credentialed requests.",
            impact="Authenticated data theft from any origin.",
            recommendation="Use an explicit origin allowlist when credentials are needed.",
            poc=f"curl -H 'Origin: https://any-site.com' '{target_url}'",
            verified=True,
            likelihood=3, impact_score=5, risk_score=15,
        ))

    # 3. Null origin allowed
    r_null = client.get(target_url, headers={"Origin": "null"})
    if r_null and r_null.headers.get("access-control-allow-origin", "").lower() == "null":
        findings.append(Finding(
            title="CORS 'null' Origin Allowed",
            category="vulnerability",
            owasp="A02",
            severity="medium",
            cwe_id="CWE-942",
            cvss_score=5.3,
            affected_url=target_url,
            payload="Origin: null",
            evidence="Access-Control-Allow-Origin: null returned",
            description="The server allows requests with Origin: null. Sandboxed iframes, data: URIs, and file:// origins send Origin: null — these can be abused.",
            impact="Attacker hosting content in a sandboxed iframe can attack this API.",
            recommendation="Never allow 'null' as a valid origin. Use a specific allowlist.",
            poc=f"curl -H 'Origin: null' '{target_url}'",
            verified=True,
            likelihood=3, impact_score=3, risk_score=9,
        ))

    return findings


# ════════════════════════════════════════════════════════════════════════════
# DEFAULT CREDENTIALS PROBE
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
]


def test_default_creds(client: AttackClient, forms: List[dict]) -> List[Finding]:
    """Probe login forms with common default credentials."""
    findings: List[Finding] = []
    login_forms = [f for f in forms if f.get("purpose") == "login"]
    if not login_forms:
        return findings

    for form in login_forms[:2]:   # limit to first 2 login forms
        action = form.get("action", "")
        method = (form.get("method") or "POST").upper()
        inputs = form.get("inputs", [])
        if not action or not inputs:
            continue

        # Identify the username + password fields
        user_field = None
        pass_field = None
        for i in inputs:
            t = (i.get("type") or "").lower()
            n = (i.get("name") or "").lower()
            if t == "password" and not pass_field:
                pass_field = i["name"]
            elif (t in ("text", "email") or "user" in n or "email" in n or "login" in n) and not user_field:
                user_field = i["name"]
        if not user_field or not pass_field:
            continue

        # Baseline: send junk credentials to learn failure response
        bad_data = {user_field: "venom_does_not_exist_" + str(int(time.time())),
                    pass_field: "DefinitelyWrong!42_" + str(int(time.time()))}
        # Fill other required inputs with safe defaults
        for i in inputs:
            if i["name"] not in bad_data and i.get("required"):
                bad_data[i["name"]] = ""
        baseline = client.request(method, action, data=bad_data)
        if not baseline:
            continue
        base_status = baseline.status_code
        base_len = len(baseline.text or "")
        base_redirect = bool(baseline.headers.get("location"))

        for user, pwd in DEFAULT_CREDS:
            test_data = {**bad_data, user_field: user, pass_field: pwd}
            r = client.request(method, action, data=test_data)
            if not r:
                continue
            # Success signals:
            # - Different status code (e.g. 302 redirect to dashboard)
            # - Significantly different response size
            # - Different Location header (redirect to dashboard)
            success_signals = 0
            if r.status_code != base_status: success_signals += 1
            if abs(len(r.text or "") - base_len) > 500: success_signals += 1
            r_redirect = r.headers.get("location", "")
            if r_redirect and r_redirect != baseline.headers.get("location", ""): success_signals += 1
            # Stronger signal: redirect to /dashboard, /home, /admin etc.
            if any(s in (r_redirect or "").lower() for s in ("/dashboard", "/home", "/admin", "/account")):
                success_signals += 2

            if success_signals >= 2:
                findings.append(Finding(
                    title=f"Default Credentials Accepted: {user}/{pwd}",
                    category="vulnerability",
                    owasp="A02",
                    severity="critical",
                    cwe_id="CWE-798",
                    cvss_score=9.8,
                    affected_url=action,
                    parameter=f"{user_field}={user}, {pass_field}={pwd}",
                    http_method=method,
                    payload=f"{user}/{pwd}",
                    evidence=(
                        f"Default credentials returned {r.status_code} ({len(r.text or '')} bytes, "
                        f"redirect={r_redirect or 'none'}), whereas invalid credentials returned "
                        f"{base_status} ({base_len} bytes, redirect={baseline.headers.get('location','none')})."
                    ),
                    description=(
                        f"The login form at {action} accepts the default credentials "
                        f"'{user}/{pwd}'. This is a complete authentication bypass."
                    ),
                    impact=(
                        "Anyone can log in as a privileged user without any further attack. "
                        "Full account/system compromise."
                    ),
                    recommendation=(
                        "Force password changes on first login. Disable / delete default accounts. "
                        "Enforce strong password policy (min 12 chars, breached-password check)."
                    ),
                    poc=f"# POST {action}\n# {user_field}={user}&{pass_field}={pwd}",
                    verified=True,
                    likelihood=5, impact_score=5, risk_score=25,
                ))
                return findings   # one is enough — server won't appreciate more brute force
    return findings


# ════════════════════════════════════════════════════════════════════════════
# SERVER VERSION DISCLOSURE (informational hardening)
# ════════════════════════════════════════════════════════════════════════════

def test_version_disclosure(client: AttackClient, target_url: str) -> List[Finding]:
    findings: List[Finding] = []
    r = client.get(target_url)
    if not r:
        return findings
    server = r.headers.get("server", "")
    x_powered = r.headers.get("x-powered-by", "")
    x_aspnet  = r.headers.get("x-aspnet-version", "")

    if server and re.search(r"[\d.]{3,}", server):
        findings.append(Finding(
            title="Server Header Reveals Version",
            category="hardening",
            owasp="A02",
            severity="low",
            cwe_id="CWE-200",
            cvss_score=3.1,
            affected_url=target_url,
            evidence=f"Server: {server}",
            description=f"The Server response header exposes software version: {server}",
            impact="Attackers can search for known vulnerabilities in this exact version.",
            recommendation="Configure your web server to suppress version info (nginx: server_tokens off).",
            verified=True,
            likelihood=4, impact_score=2, risk_score=8,
        ))
    if x_powered:
        findings.append(Finding(
            title="X-Powered-By Reveals Stack",
            category="hardening",
            owasp="A02",
            severity="low",
            cwe_id="CWE-200",
            cvss_score=3.1,
            affected_url=target_url,
            evidence=f"X-Powered-By: {x_powered}",
            description=f"The X-Powered-By header exposes backend technology: {x_powered}",
            impact="Targeted attacks possible based on known technology stack vulnerabilities.",
            recommendation="Remove X-Powered-By header. In Express: app.disable('x-powered-by').",
            verified=True,
            likelihood=4, impact_score=2, risk_score=8,
        ))
    if x_aspnet:
        findings.append(Finding(
            title="ASP.NET Version Disclosed",
            category="hardening",
            owasp="A02",
            severity="low",
            cwe_id="CWE-200",
            cvss_score=3.1,
            affected_url=target_url,
            evidence=f"X-AspNet-Version: {x_aspnet}",
            description=f"ASP.NET version exposed: {x_aspnet}",
            impact="Attackers can search for version-specific vulnerabilities.",
            recommendation="Set <httpRuntime enableVersionHeader=\"false\"/> in web.config.",
            verified=True,
            likelihood=4, impact_score=2, risk_score=8,
        ))
    return findings


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def run_a02_engine(plan: dict, endpoints: List[dict], forms: List[dict],
                    target_url: str, max_rps: float = 10.0) -> List[Finding]:
    findings: List[Finding] = []
    client = AttackClient(max_rps=max_rps)
    try:
        try: findings += test_exposed_files(client, target_url)
        except Exception as e: logger.warning(f"[A02] exposed_files: {e}")

        try: findings += test_debug_pages(client, target_url)
        except Exception as e: logger.warning(f"[A02] debug_pages: {e}")

        try: findings += test_cors_misconfig(client, target_url)
        except Exception as e: logger.warning(f"[A02] cors: {e}")

        try: findings += test_default_creds(client, forms)
        except Exception as e: logger.warning(f"[A02] default_creds: {e}")

        try: findings += test_version_disclosure(client, target_url)
        except Exception as e: logger.warning(f"[A02] version: {e}")
    finally:
        client.close()

    logger.info(f"[A02] Found {len(findings)} misconfiguration findings")
    return findings
