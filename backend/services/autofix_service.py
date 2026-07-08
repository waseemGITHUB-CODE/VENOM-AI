"""
VENOM AI · backend/services/autofix_service.py
AI-powered code patch generator
Primary:  Ollama (dolphin-llama3) — local, unlimited, uncensored
Fallback: Groq API
"""
from __future__ import annotations
import json
import logging
import os
from typing import Optional, Dict, List

logger = logging.getLogger("venom.autofix")

OLLAMA_BASE  = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL",    "dolphin-llama3")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = os.getenv("GROQ_MODEL",      "llama3.1-8b-instant")


# ── AI Backend helpers ─────────────────────────────────────────────────────────

def _get_groq_key() -> str:
    try:
        from core.config import settings
        return getattr(settings, "GROQ_API_KEY", "") or ""
    except Exception:
        try:
            from core.config import settings
            return getattr(settings, "GROQ_API_KEY", "") or ""
        except Exception:
            return os.getenv("GROQ_API_KEY", "")


def _is_ollama_running() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=2)
        return True
    except Exception:
        return False


def _call_ollama(prompt: str, system: str = "") -> str:
    import urllib.request
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 2048, "num_ctx": 4096}
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat", data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
    return data["message"]["content"]


def _call_groq(prompt: str, system: str = "") -> str:
    import urllib.request
    api_key = _get_groq_key()
    if not api_key:
        raise ValueError("No GROQ_API_KEY set")
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    payload = json.dumps({
        "model": GROQ_MODEL,
        "messages": messages,
        "max_tokens": 2048,
        "temperature": 0.3,
    }).encode()
    req = urllib.request.Request(
        GROQ_URL, data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode())
    return data["choices"][0]["message"]["content"]


def _call_ai(prompt: str, system: str = "") -> tuple[str, str]:
    """Try Ollama first, then Groq. Returns (response_text, model_used)."""
    if _is_ollama_running():
        try:
            return _call_ollama(prompt, system), f"ollama/{OLLAMA_MODEL}"
        except Exception as e:
            logger.warning(f"[AutoFix] Ollama failed: {e} — falling back to Groq")
    try:
        return _call_groq(prompt, system), f"groq/{GROQ_MODEL}"
    except Exception as e:
        logger.error(f"[AutoFix] Groq also failed: {e}")
        raise RuntimeError("No AI backend available — start Ollama or set GROQ_API_KEY")


# ── Main patch generator ───────────────────────────────────────────────────────

AUTOFIX_SYSTEM = """You are an expert secure software engineer embedded in VENOM AI security platform.
Your job is to generate production-ready, secure code patches for vulnerabilities.
Always respond in valid JSON only. No markdown fences, no preamble.
Be precise, technical, and write real working code."""

def generate_code_patch(vuln_type: str, description: str, evidence: str,
                        language: str = "auto", framework: str = "") -> Dict:
    """
    Generate a contextual code patch for a vulnerability.
    Returns structured patch data including vulnerable code, fix, explanation.
    """
    prompt = f"""Generate a secure code patch for this vulnerability. Respond ONLY in JSON.

VULNERABILITY:
Type: {vuln_type}
Description: {description}
Evidence: {evidence}
Language/Framework: {language} {framework}

Return this exact JSON structure:
{{
  "vuln_title": "short title",
  "language": "detected language",
  "vulnerable_code": "the vulnerable code snippet",
  "patched_code": "the secure replacement code",
  "explanation": "clear explanation of what was wrong and how the fix works",
  "pr_title": "fix: short PR title",
  "pr_description": "markdown PR description with what changed and why",
  "commit_msg": "fix(security): short commit message",
  "cwe_id": "CWE-XX",
  "owasp_category": "A0X - category name",
  "references": ["url1", "url2"]
}}"""

    try:
        raw, model = _call_ai(prompt, AUTOFIX_SYSTEM)
        # Strip possible markdown fences just in case
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        patch = json.loads(clean)
        patch["model_used"] = model
        patch["ai_generated"] = True
        return patch
    except json.JSONDecodeError:
        logger.warning("[AutoFix] JSON parse failed — using fallback")
        return _fallback_patch(vuln_type, description)
    except Exception as e:
        logger.error(f"[AutoFix] AI call failed: {e}")
        return _fallback_patch(vuln_type, description)


def generate_batch_patches(vulnerabilities: List[Dict], max_patches: int = 10) -> List[Dict]:
    """Generate patches for the top critical/high vulnerabilities."""
    priority = [v for v in vulnerabilities
                if v.get("severity", "").lower() in ("critical", "high")][:max_patches]
    if not priority:
        priority = vulnerabilities[:max_patches]

    patches = []
    for v in priority:
        try:
            patch = generate_code_patch(
                vuln_type=v.get("vuln_type") or v.get("title", "Unknown"),
                description=v.get("description", ""),
                evidence=v.get("evidence", ""),
                language="auto",
            )
            patch["vuln_id"]       = v.get("id")
            patch["vuln_severity"] = v.get("severity", "")
            patches.append(patch)
        except Exception as e:
            logger.warning(f"[AutoFix] Patch failed for {v.get('title','?')}: {e}")
    return patches


# ── Static fallback patches ────────────────────────────────────────────────────

def _fallback_patch(vuln_type: str, description: str) -> Dict:
    """High-quality static fallback patches when AI is unavailable."""
    vt = vuln_type.lower()

    if "sql" in vt:
        return {
            "vuln_title": "SQL Injection",
            "language": "python",
            "vulnerable_code": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
            "patched_code": "query = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_id,))",
            "explanation": "String interpolation in SQL queries allows attackers to inject arbitrary SQL. Use parameterized queries — the DB driver safely escapes all parameters.",
            "pr_title": "fix: parameterize SQL queries to prevent injection",
            "pr_description": "## Security Fix: SQL Injection\n\nReplaces string-formatted SQL with parameterized queries.\n\n**Risk:** Attacker could dump entire database, bypass auth, or delete data.\n\n**Fix:** All user-supplied values are now passed as parameters, never interpolated into query strings.",
            "commit_msg": "fix(security): use parameterized queries — prevent SQLi (CWE-89)",
            "cwe_id": "CWE-89", "owasp_category": "A03 - Injection",
            "ai_generated": False,
        }
    if "xss" in vt or "cross-site" in vt:
        return {
            "vuln_title": "Cross-Site Scripting (XSS)",
            "language": "javascript",
            "vulnerable_code": "element.innerHTML = userInput;",
            "patched_code": "// Option 1: Use textContent (safest)\nelement.textContent = userInput;\n\n// Option 2: Sanitize with DOMPurify\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);",
            "explanation": "Setting innerHTML with unsanitized input allows script injection. Use textContent for plain text, or DOMPurify for HTML that must be rendered.",
            "pr_title": "fix: prevent XSS via output encoding",
            "pr_description": "## Security Fix: XSS\n\nReplaces unsafe `innerHTML` assignments with sanitized equivalents.\n\n**Risk:** Attacker steals session cookies, performs actions as victim.\n\n**Fix:** textContent for plain text output; DOMPurify.sanitize() for HTML.",
            "commit_msg": "fix(security): sanitize DOM output — prevent XSS (CWE-79)",
            "cwe_id": "CWE-79", "owasp_category": "A03 - Injection",
            "ai_generated": False,
        }
    if "path traversal" in vt or "lfi" in vt or "directory" in vt:
        return {
            "vuln_title": "Path Traversal / LFI",
            "language": "python",
            "vulnerable_code": "filepath = os.path.join(BASE_DIR, user_filename)\nwith open(filepath) as f:\n    return f.read()",
            "patched_code": "import os\nfrom pathlib import Path\n\nBASE = Path(BASE_DIR).resolve()\nrequested = (BASE / user_filename).resolve()\n\n# Ensure resolved path is still inside BASE_DIR\nif not str(requested).startswith(str(BASE)):\n    raise PermissionError('Path traversal detected')\n\nwith open(requested) as f:\n    return f.read()",
            "explanation": "Without canonicalization, '../../../etc/passwd' sequences escape the base directory. Always resolve the full path and verify it starts with the allowed base directory.",
            "pr_title": "fix: prevent path traversal via path canonicalization",
            "pr_description": "## Security Fix: Path Traversal\n\nAdds path canonicalization and containment check.\n\n**Risk:** Attacker reads arbitrary files including /etc/passwd, .env, private keys.\n\n**Fix:** Resolve both paths and verify the result is inside the allowed directory.",
            "commit_msg": "fix(security): canonicalize paths — prevent LFI (CWE-22)",
            "cwe_id": "CWE-22", "owasp_category": "A01 - Broken Access Control",
            "ai_generated": False,
        }
    if "ssl" in vt or "tls" in vt or "certificate" in vt:
        return {
            "vuln_title": "Insecure SSL/TLS Configuration",
            "language": "python",
            "vulnerable_code": "requests.get(url, verify=False)\n# OR: ssl_context.check_hostname = False",
            "patched_code": "import ssl, certifi\n\n# requests — always verify\nrequests.get(url, verify=certifi.where())\n\n# Manual SSL context\nctx = ssl.create_default_context(cafile=certifi.where())\nctx.minimum_version = ssl.TLSVersion.TLSv1_2\n# Never set: ctx.check_hostname = False or ctx.verify_mode = ssl.CERT_NONE",
            "explanation": "Disabling certificate verification allows MITM attacks — attackers can intercept all traffic. Always verify certificates using a trusted CA bundle.",
            "pr_title": "fix: enforce TLS certificate verification",
            "pr_description": "## Security Fix: SSL/TLS\n\nEnables proper certificate verification across all HTTPS connections.\n\n**Risk:** MITM attacker reads/modifies all encrypted traffic.\n\n**Fix:** Use certifi CA bundle, enforce TLS 1.2+ minimum, never disable verification.",
            "commit_msg": "fix(security): enforce TLS cert verification (CWE-295)",
            "cwe_id": "CWE-295", "owasp_category": "A02 - Cryptographic Failures",
            "ai_generated": False,
        }
    if "ssrf" in vt:
        return {
            "vuln_title": "Server-Side Request Forgery (SSRF)",
            "language": "python",
            "vulnerable_code": "url = request.args.get('url')\nresponse = requests.get(url)  # No validation",
            "patched_code": "import ipaddress, urllib.parse\n\nALLOWLIST = {'api.example.com', 'cdn.example.com'}\n\ndef is_safe_url(url: str) -> bool:\n    parsed = urllib.parse.urlparse(url)\n    host = parsed.hostname or ''\n    # Block private/loopback IPs\n    try:\n        ip = ipaddress.ip_address(host)\n        if ip.is_private or ip.is_loopback or ip.is_link_local:\n            return False\n    except ValueError:\n        pass  # hostname, not IP\n    return host in ALLOWLIST\n\nif not is_safe_url(url):\n    return abort(400, 'URL not permitted')\nresponse = requests.get(url, timeout=5)",
            "explanation": "SSRF lets attackers reach internal services (metadata APIs, Redis, internal dashboards). Validate URLs against an allowlist and block private IP ranges.",
            "pr_title": "fix: add SSRF protection with URL allowlisting",
            "pr_description": "## Security Fix: SSRF\n\nAdds URL validation before making outbound requests.\n\n**Risk:** Attacker accesses cloud metadata (AWS credentials), internal services, or pivots inside the network.\n\n**Fix:** Allowlist of permitted external domains + block all private/loopback IP ranges.",
            "commit_msg": "fix(security): prevent SSRF with URL allowlist (CWE-918)",
            "cwe_id": "CWE-918", "owasp_category": "A10 - SSRF",
            "ai_generated": False,
        }

    if "csrf" in vt or "cross-site request" in vt:
        return {
            "vuln_title": "CSRF (Cross-Site Request Forgery)",
            "language": "python",
            "vulnerable_code": "# No CSRF token validation\n@app.route('/transfer', methods=['POST'])\ndef transfer():\n    amount = request.form['amount']\n    # Processes without verifying request origin",
            "patched_code": "from flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n\n# In template:\n# <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\"/>\n\n# FastAPI example:\nfrom fastapi_csrf_protect import CsrfProtect\n@app.post('/transfer')\nasync def transfer(csrf_protect: CsrfProtect = Depends()):\n    csrf_protect.validate_csrf(request)",
            "explanation": "CSRF allows attackers to trick logged-in users into performing unintended actions. Use CSRF tokens that are unique per session and validated server-side.",
            "pr_title": "fix: add CSRF token validation to state-changing endpoints",
            "pr_description": "## Security Fix: CSRF\n\nAdds CSRF token validation.\n\n**Risk:** Attacker tricks victim into submitting malicious requests.\n\n**Fix:** Synchronizer token pattern with per-session unique tokens.",
            "commit_msg": "fix(security): add CSRF protection (CWE-352)",
            "cwe_id": "CWE-352", "owasp_category": "A01 - Broken Access Control",
            "ai_generated": False,
        }
    if "header" in vt or "missing_header" in vt or "hsts" in vt or "csp" in vt:
        return {
            "vuln_title": "Missing Security Headers",
            "language": "python",
            "vulnerable_code": "# FastAPI with no security headers\napp = FastAPI()",
            "patched_code": "from fastapi import FastAPI\nfrom fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware\n\napp = FastAPI()\n\n@app.middleware('http')\nasync def add_security_headers(request, call_next):\n    response = await call_next(request)\n    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'\n    response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'; object-src 'none'\"\n    response.headers['X-Frame-Options'] = 'DENY'\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'\n    return response\n\n# Nginx equivalent:\n# add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";\n# add_header Content-Security-Policy \"default-src 'self'\";\n# add_header X-Frame-Options DENY;",
            "explanation": "Security headers protect against XSS, clickjacking, MIME sniffing, and protocol downgrade attacks. Add them to all HTTP responses.",
            "pr_title": "fix: add comprehensive HTTP security headers middleware",
            "pr_description": "## Security Fix: Missing Headers\n\nAdds security headers middleware.\n\n**Risk:** XSS, clickjacking, MITM, MIME sniffing attacks.\n\n**Fix:** Middleware adds all OWASP-recommended headers on every response.",
            "commit_msg": "fix(security): add security headers middleware (CWE-693)",
            "cwe_id": "CWE-693", "owasp_category": "A05 - Security Misconfiguration",
            "ai_generated": False,
        }
    if "cookie" in vt or "insecure_cookie" in vt:
        return {
            "vuln_title": "Insecure Cookie Configuration",
            "language": "python",
            "vulnerable_code": "response.set_cookie('session', session_token)\n# Missing: Secure, HttpOnly, SameSite flags",
            "patched_code": "response.set_cookie(\n    key='session',\n    value=session_token,\n    httponly=True,      # Prevent JS access (XSS protection)\n    secure=True,        # HTTPS only\n    samesite='strict',  # Prevent CSRF\n    max_age=3600,       # 1 hour expiry\n    path='/',\n)",
            "explanation": "Cookies without Secure flag can be sent over HTTP. Without HttpOnly, XSS can steal them. Without SameSite, CSRF attacks can replay them.",
            "pr_title": "fix: set Secure, HttpOnly, SameSite on all session cookies",
            "pr_description": "## Security Fix: Insecure Cookies\n\nAdds security flags to all cookies.\n\n**Risk:** Session theft via XSS or network interception.\n\n**Fix:** Secure (HTTPS-only), HttpOnly (no JS), SameSite=Strict (no CSRF).",
            "commit_msg": "fix(security): secure cookie flags — prevent session theft (CWE-614)",
            "cwe_id": "CWE-614", "owasp_category": "A02 - Cryptographic Failures",
            "ai_generated": False,
        }
    if "nhi" in vt or "secret" in vt or "api_key" in vt or "credential" in vt or "token" in vt:
        return {
            "vuln_title": "Exposed Credentials / API Key",
            "language": "python",
            "vulnerable_code": "# Hardcoded secret in source code\nAPI_KEY = 'sk-live-abc123xyz...'\nAWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            "patched_code": "import os\nfrom dotenv import load_dotenv\n\nload_dotenv()  # Load from .env file\n\nAPI_KEY = os.environ.get('API_KEY')\nAWS_SECRET = os.environ.get('AWS_SECRET_ACCESS_KEY')\n\nif not API_KEY:\n    raise RuntimeError('API_KEY environment variable not set')\n\n# .env file (never commit to git):\n# API_KEY=sk-live-abc123xyz...\n\n# .gitignore:\n# .env\n# *.key\n# secrets/",
            "explanation": "Hardcoded credentials in source code leak when code is shared, committed to git, or decompiled. Use environment variables and rotate any exposed credentials immediately.",
            "pr_title": "fix: move hardcoded credentials to environment variables",
            "pr_description": "## Security Fix: Exposed Credentials\n\nMoves secrets to environment variables.\n\n**Risk:** Any access to source code (git, deployment) exposes credentials.\n\n**IMMEDIATE ACTION:** Rotate/revoke all exposed keys NOW.\n\n**Fix:** python-dotenv for local dev, secret manager for production.",
            "commit_msg": "fix(security): remove hardcoded credentials (CWE-798)",
            "cwe_id": "CWE-798", "owasp_category": "A02 - Cryptographic Failures",
            "ai_generated": False,
        }
    if "open port" in vt or "open_port" in vt or "service" in vt:
        return {
            "vuln_title": "Unnecessary Open Port / Service Exposure",
            "language": "bash",
            "vulnerable_code": "# Port 3306 (MySQL) open to internet\n# Port 6379 (Redis) open to internet\n# Port 27017 (MongoDB) open to internet",
            "patched_code": "# UFW firewall rules\nufw default deny incoming\nufw allow ssh\nufw allow 443/tcp\nufw allow 80/tcp\nufw enable\n\n# iptables alternative\niptables -P INPUT DROP\niptables -A INPUT -p tcp --dport 443 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\n\n# Bind services to localhost only (e.g., Redis)\n# redis.conf: bind 127.0.0.1\n# MySQL: bind-address = 127.0.0.1\n\n# AWS Security Group: restrict to VPC CIDR only\n# Never expose databases to 0.0.0.0/0",
            "explanation": "Databases and internal services exposed to the internet are directly attackable. They should only be accessible from trusted internal networks or localhost.",
            "pr_title": "fix: restrict service exposure with firewall rules",
            "pr_description": "## Security Fix: Open Ports\n\nCloses unnecessary exposed services.\n\n**Risk:** Direct exploitation of database services, credential brute-force.\n\n**Fix:** UFW/iptables to block all except HTTP/HTTPS. Bind internal services to 127.0.0.1.",
            "commit_msg": "fix(security): firewall rules to restrict service exposure (CWE-732)",
            "cwe_id": "CWE-732", "owasp_category": "A05 - Security Misconfiguration",
            "ai_generated": False,
        }
    if "auth" in vt or "authentication" in vt or "brute" in vt:
        return {
            "vuln_title": "Authentication Vulnerability",
            "language": "python",
            "vulnerable_code": "# No rate limiting on login\n@app.post('/login')\ndef login(username, password):\n    user = db.query(User).filter_by(username=username).first()\n    if user and user.password == password:  # Plaintext comparison!\n        return create_session(user)",
            "patched_code": "from slowapi import Limiter\nfrom passlib.context import CryptContext\nimport secrets\n\npwd_ctx = CryptContext(schemes=['bcrypt'], deprecated='auto')\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/login')\n@limiter.limit('5/minute')  # Rate limit\nasync def login(request: Request, credentials: LoginSchema):\n    user = db.query(User).filter_by(username=credentials.username).first()\n    # Constant-time comparison — prevents timing attacks\n    if not user or not pwd_ctx.verify(credentials.password, user.hashed_password):\n        raise HTTPException(401, 'Invalid credentials')\n    # Generate cryptographically secure token\n    token = secrets.token_urlsafe(32)\n    return {'token': token}",
            "explanation": "Plaintext password storage, no rate limiting, and non-constant-time comparison enable credential stuffing and timing attacks. Use bcrypt hashing and rate limiting.",
            "pr_title": "fix: secure authentication with bcrypt, rate limiting, constant-time compare",
            "pr_description": "## Security Fix: Authentication\n\nHardens login endpoint.\n\n**Risk:** Credential stuffing, brute-force, password exposure.\n\n**Fix:** bcrypt password hashing, 5 req/min rate limit, constant-time comparison.",
            "commit_msg": "fix(security): harden authentication — bcrypt + rate limit (CWE-307)",
            "cwe_id": "CWE-307", "owasp_category": "A07 - Auth Failures",
            "ai_generated": False,
        }

    # Generic fallback
    return {
        "vuln_title": vuln_type or "Security Issue",
        "language": "general",
        "vulnerable_code": "# Vulnerable code pattern identified",
        "patched_code": f"# Remediate: {description[:200]}",
        "explanation": f"Vulnerability detected: {vuln_type}. {description[:300]} Review and apply secure coding practices for this vulnerability class.",
        "pr_title": f"fix: remediate {vuln_type}",
        "pr_description": f"## Security Fix\n\nAddresses {vuln_type}.\n\n{description[:500]}",
        "commit_msg": f"fix(security): remediate {vuln_type}",
        "cwe_id": "", "owasp_category": "",
        "ai_generated": False,
    }