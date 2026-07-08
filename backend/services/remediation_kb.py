"""
Vulnerability Remediation Knowledge Base
─────────────────────────────────────────────────────────────────
Maps every vulnerability type → full remediation record:
  • impact       — what an attacker can do
  • fix          — step-by-step guidance
  • code_example — language-agnostic snippet
  • references   — authoritative links
Usage:
    from services.remediation_kb import enrich_vulnerability, lookup
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RemediationEntry:
    vuln_type:    str
    severity:     str
    impact:       str
    fix:          str
    code_example: str
    references:   List[str]


KNOWLEDGE_BASE: Dict[str, RemediationEntry] = {

    "sql_injection": RemediationEntry(
        vuln_type="SQL Injection", severity="critical",
        impact="Attackers can read, modify or delete any database data, bypass authentication, and in some configurations execute OS commands.",
        fix="1. Use parameterized queries / prepared statements for ALL database calls.\n2. Apply an ORM (SQLAlchemy, Django ORM) to abstract raw SQL.\n3. Validate and whitelist all user input server-side.\n4. Apply least-privilege DB accounts (no DROP/ALTER for the app user).\n5. Enable a WAF as a secondary defence layer.",
        code_example="# Python — safe parameterized query\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# SQLAlchemy ORM (automatically parameterized)\nuser = db.query(User).filter(User.id == user_id).first()",
        references=["https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    ),

    "xss": RemediationEntry(
        vuln_type="Cross-Site Scripting (XSS)", severity="high",
        impact="Attackers inject malicious scripts that execute in victims' browsers, enabling session hijacking, credential theft, and phishing.",
        fix="1. HTML-encode all user-supplied output.\n2. Use a Content Security Policy (CSP) header to restrict script sources.\n3. Set HttpOnly and Secure flags on session cookies.\n4. Validate and sanitize input on the server side.",
        code_example="# Python — encode before rendering\nimport html\nsafe_output = html.escape(user_input)\n\n# CSP response header\nContent-Security-Policy: default-src 'self'; script-src 'self'",
        references=["https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    ),

    "csrf": RemediationEntry(
        vuln_type="Cross-Site Request Forgery (CSRF)", severity="high",
        impact="Attackers trick authenticated users into performing unintended actions without their knowledge.",
        fix="1. Use CSRF tokens on every state-changing form and AJAX request.\n2. Set SameSite=Strict or SameSite=Lax on session cookies.\n3. Verify the Origin/Referer header server-side.",
        code_example="# Cookie flag\nSet-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly\n\n# Django — built-in CSRF middleware (enabled by default)\nMIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']",
        references=["https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    ),

    "missing_security_headers": RemediationEntry(
        vuln_type="Missing Security Headers", severity="medium",
        impact="Without security headers, browsers do not enforce protections against clickjacking, MIME sniffing, XSS, and insecure connections.",
        fix="Add the following headers to every HTTP response:\n• X-Frame-Options: SAMEORIGIN\n• X-Content-Type-Options: nosniff\n• Strict-Transport-Security: max-age=31536000; includeSubDomains\n• Content-Security-Policy: default-src 'self'\n• Referrer-Policy: strict-origin-when-cross-origin",
        code_example="# FastAPI — security headers middleware\n@app.middleware('http')\nasync def add_security_headers(request, call_next):\n    response = await call_next(request)\n    response.headers['X-Frame-Options'] = 'SAMEORIGIN'\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n    return response\n\n# Nginx\nadd_header X-Frame-Options SAMEORIGIN;\nadd_header X-Content-Type-Options nosniff;",
        references=["https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"],
    ),

    "ssl_tls_issues": RemediationEntry(
        vuln_type="SSL/TLS Misconfiguration", severity="high",
        impact="Weak or misconfigured TLS allows traffic interception, man-in-the-middle attacks, and decryption of sensitive data.",
        fix="1. Use TLS 1.2 minimum; prefer TLS 1.3.\n2. Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1.\n3. Use strong cipher suites only (AES-GCM, CHACHA20).\n4. Enable HSTS with a long max-age.\n5. Renew certificates before expiry.",
        code_example="# Nginx — TLS hardening\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\nssl_prefer_server_ciphers on;\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
        references=["https://owasp.org/www-project-transport-layer-security-cheat-sheet/",
                    "https://ssl-config.mozilla.org/"],
    ),

    "sensitive_data_exposure": RemediationEntry(
        vuln_type="Sensitive Data Exposure", severity="high",
        impact="Credentials, API keys, PII, or financial data are exposed to unauthorised parties via logs, responses, or public repositories.",
        fix="1. Never log or return raw credentials/keys.\n2. Store secrets in environment variables or a vault.\n3. Encrypt sensitive data at rest and in transit.\n4. Scan git history with tools like truffleHog.",
        code_example="# Use environment variables — never hardcode secrets\nimport os\ndb_password = os.environ['DB_PASSWORD']\n\n# .env (add to .gitignore)\nDB_PASSWORD=supersecret\nAPI_KEY=sk-live-xxxx",
        references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
    ),

    "broken_authentication": RemediationEntry(
        vuln_type="Broken Authentication", severity="critical",
        impact="Attackers gain access to user or admin accounts through weak passwords, credential stuffing, or session fixation.",
        fix="1. Enforce strong password policies (min 12 chars).\n2. Implement multi-factor authentication (MFA).\n3. Use secure, random session tokens and rotate after login.\n4. Implement account lockout after repeated failures.\n5. Use bcrypt/Argon2 for password hashing.",
        code_example="# FastAPI — bcrypt hashing\nfrom passlib.context import CryptContext\npwd_ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')\n\ndef hash_password(plain: str) -> str:\n    return pwd_ctx.hash(plain)\n\ndef verify_password(plain: str, hashed: str) -> bool:\n    return pwd_ctx.verify(plain, hashed)",
        references=["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
    ),

    "open_ports": RemediationEntry(
        vuln_type="Unnecessary Open Ports", severity="medium",
        impact="Exposed services increase the attack surface; each open port is a potential entry point for exploitation.",
        fix="1. Close or firewall all ports not required for the application.\n2. Use a host-based firewall (iptables/ufw/Windows Firewall).\n3. Run services on localhost when external access is not needed.\n4. Regularly audit open ports with nmap.",
        code_example="# UFW — close port 27017 (MongoDB)\nsudo ufw deny 27017\n\n# iptables\niptables -A INPUT -p tcp --dport 27017 -j DROP\n\n# Docker — bind to localhost only\nports:\n  - '127.0.0.1:5432:5432'",
        references=["https://owasp.org/www-project-top-ten/",
                    "https://www.cisecurity.org/controls/"],
    ),

    "outdated_software": RemediationEntry(
        vuln_type="Outdated Software / Known CVEs", severity="high",
        impact="Running software with known CVEs gives attackers documented exploits to compromise the system.",
        fix="1. Keep all dependencies up to date.\n2. Use automated dependency scanning (Dependabot, Snyk, safety).\n3. Subscribe to CVE feeds for your technology stack.\n4. Establish a patch management policy.",
        code_example="# Check Python packages for known vulnerabilities\npip install safety\nsafety check -r requirements.txt\n\n# Node.js\nnpm audit\nnpm audit fix",
        references=["https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                    "https://nvd.nist.gov/"],
    ),

    "clickjacking": RemediationEntry(
        vuln_type="Clickjacking", severity="medium",
        impact="Attackers overlay invisible iframes to trick users into clicking on buttons without their knowledge.",
        fix="Add X-Frame-Options and Content-Security-Policy frame-ancestors headers.",
        code_example="# HTTP headers\nX-Frame-Options: SAMEORIGIN\nContent-Security-Policy: frame-ancestors 'self'\n\n# FastAPI middleware\nresponse.headers['X-Frame-Options'] = 'SAMEORIGIN'",
        references=["https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    ),

    "insecure_cookies": RemediationEntry(
        vuln_type="Insecure Cookie Configuration", severity="medium",
        impact="Session cookies without proper flags can be stolen via XSS or transmitted over plain HTTP.",
        fix="Set all session cookies with: HttpOnly, Secure, SameSite=Strict, and short Max-Age values.",
        code_example="# FastAPI response cookie\nresponse.set_cookie(\n    key='session', value=token,\n    httponly=True, secure=True,\n    samesite='strict', max_age=3600,\n)",
        references=["https://owasp.org/www-community/controls/SecureCookieAttribute",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    ),

    "information_disclosure": RemediationEntry(
        vuln_type="Information Disclosure", severity="low",
        impact="Server version banners and stack traces help attackers fingerprint the technology stack.",
        fix="1. Suppress server version headers (Server:, X-Powered-By:).\n2. Return generic error messages to clients.\n3. Log detailed errors server-side only.\n4. Disable directory listing.",
        code_example="# Nginx — remove version banner\nserver_tokens off;\n\n# FastAPI — hide internals\n@app.exception_handler(Exception)\nasync def generic_handler(request, exc):\n    return JSONResponse(status_code=500, content={'detail': 'An error occurred'})",
        references=["https://owasp.org/www-project-web-security-testing-guide/",
                    "https://cwe.mitre.org/data/definitions/200.html"],
    ),

    "default_credentials": RemediationEntry(
        vuln_type="Default / Weak Credentials", severity="critical",
        impact="Default or guessable admin credentials allow immediate full system compromise.",
        fix="1. Change all default passwords immediately after installation.\n2. Force password change on first login.\n3. Disable or rename default admin accounts.",
        code_example="# FastAPI — force password reset on first login\nif current_user.must_change_password:\n    raise HTTPException(403, 'Password change required')",
        references=["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                    "https://cwe.mitre.org/data/definitions/1392.html"],
    ),

    "missing_rate_limiting": RemediationEntry(
        vuln_type="Missing Rate Limiting", severity="medium",
        impact="Without rate limiting, attackers can brute-force credentials or perform denial-of-service attacks.",
        fix="1. Apply rate limiting to all authentication and sensitive endpoints.\n2. Return 429 Too Many Requests with a Retry-After header.",
        code_example="# FastAPI with slowapi\nfrom slowapi import Limiter\nfrom slowapi.util import get_remote_address\n\nlimiter = Limiter(key_func=get_remote_address)\n\n@router.post('/login')\n@limiter.limit('5/minute')\nasync def login(request: Request, ...):\n    ...",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
    ),

    "directory_traversal": RemediationEntry(
        vuln_type="Directory Traversal / Path Traversal", severity="high",
        impact="Attackers read arbitrary files on the server, including config files and private keys.",
        fix="1. Use os.path.realpath() and verify the resolved path starts within the intended directory.\n2. Never construct file paths directly from user input.",
        code_example="import os\nBASE_DIR = '/app/uploads'\n\ndef safe_open(filename: str):\n    full_path = os.path.realpath(os.path.join(BASE_DIR, filename))\n    if not full_path.startswith(BASE_DIR):\n        raise ValueError('Path traversal detected')\n    return open(full_path)",
        references=["https://owasp.org/www-community/attacks/Path_Traversal",
                    "https://cwe.mitre.org/data/definitions/22.html"],
    ),

    "ssrf": RemediationEntry(
        vuln_type="Server-Side Request Forgery (SSRF)", severity="high",
        impact="Attackers make the server send requests to internal services or cloud metadata APIs.",
        fix="1. Validate and allowlist URLs the server can fetch.\n2. Block requests to private IP ranges.\n3. Use a dedicated egress proxy.",
        code_example="import ipaddress, socket\nBLOCKED = [ipaddress.ip_network('10.0.0.0/8'),\n           ipaddress.ip_network('172.16.0.0/12'),\n           ipaddress.ip_network('192.168.0.0/16'),\n           ipaddress.ip_network('169.254.0.0/16')]\n\ndef is_safe_url(url):\n    host = urlparse(url).hostname\n    ip = ipaddress.ip_address(socket.gethostbyname(host))\n    return not any(ip in r for r in BLOCKED)",
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    ),

    "generic": RemediationEntry(
        vuln_type="Security Vulnerability", severity="medium",
        impact="This vulnerability could be exploited to compromise the security, integrity, or availability of the application.",
        fix="1. Review the finding details and apply the principle of least privilege.\n2. Follow OWASP Top 10 remediation guidance.\n3. Engage a security professional for detailed remediation advice.",
        code_example="# Consult the reference links for specific remediation code.",
        references=["https://owasp.org/www-project-top-ten/",
                    "https://cheatsheetseries.owasp.org/"],
    ),
}

_KEYWORD_MAP: Dict[str, str] = {
    "sql": "sql_injection", "sqli": "sql_injection", "injection": "sql_injection",
    "xss": "xss", "cross-site scripting": "xss", "cross site scripting": "xss",
    "csrf": "csrf", "cross-site request forgery": "csrf",
    "header": "missing_security_headers", "csp": "missing_security_headers",
    "hsts": "missing_security_headers", "missing header": "missing_security_headers",
    "x-frame": "clickjacking", "clickjack": "clickjacking",
    "ssl": "ssl_tls_issues", "tls": "ssl_tls_issues",
    "certificate": "ssl_tls_issues", "weak cipher": "ssl_tls_issues",
    "auth": "broken_authentication", "default cred": "default_credentials",
    "default password": "default_credentials", "brute force": "missing_rate_limiting",
    "rate limit": "missing_rate_limiting",
    "sensitive": "sensitive_data_exposure", "api key": "sensitive_data_exposure",
    "secret": "sensitive_data_exposure",
    "information disclosure": "information_disclosure",
    "server version": "information_disclosure", "banner": "information_disclosure",
    "idor": "idor", "access control": "idor",
    "directory traversal": "directory_traversal", "path traversal": "directory_traversal",
    "open port": "open_ports", "port": "open_ports",
    "outdated": "outdated_software", "cve": "outdated_software",
    "cookie": "insecure_cookies", "session": "insecure_cookies",
    "ssrf": "ssrf", "server-side request": "ssrf",
    "password": "broken_authentication",
}


def lookup(vuln_title: str, vuln_type: str = "", category: str = "") -> RemediationEntry:
    """Find the best-matching remediation entry for a vulnerability."""
    search_text = f"{vuln_title} {vuln_type} {category}".lower()

    if vuln_type and vuln_type.lower() in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[vuln_type.lower()]

    best_key, best_len = None, 0
    for keyword, kb_key in _KEYWORD_MAP.items():
        if keyword in search_text and len(keyword) > best_len:
            best_key, best_len = kb_key, len(keyword)

    return KNOWLEDGE_BASE.get(best_key, KNOWLEDGE_BASE["generic"])


def enrich_vulnerability(vuln: dict) -> dict:
    """Auto-attach impact/fix/references from the knowledge base to a vulnerability dict."""
    entry = lookup(
        vuln_title=vuln.get("title", ""),
        vuln_type=vuln.get("vuln_type", ""),
        category=vuln.get("category", ""),
    )
    if not vuln.get("impact"):
        vuln["impact"] = entry.impact
    if not vuln.get("fix") and not vuln.get("recommendation"):
        vuln["fix"] = entry.fix
    elif not vuln.get("fix"):
        vuln["fix"] = vuln.get("recommendation", entry.fix)
    if not vuln.get("code_example"):
        vuln["code_example"] = entry.code_example
    if not vuln.get("references"):
        vuln["references"] = entry.references
    if not vuln.get("reference"):
        vuln["reference"] = entry.references[0] if entry.references else ""
    return vuln
