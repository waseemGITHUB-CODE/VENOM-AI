"""
VENOM AI — Phase 2a Reconnaissance Engine
─────────────────────────────────────────────────────────────────────────
Discovers everything VENOM needs to know BEFORE attacking:

  1. Crawler — BFS spider, depth 2-3, scope-locked to target domain
  2. Tech stack fingerprinter — detects React, Django, Express, etc.
  3. Endpoint discovery — finds API routes from JS bundles + OpenAPI
  4. Form analyzer — extracts every form + input for attack engines
  5. Auth detection — figures out login mechanism (JWT, session, OAuth)

OUTPUT goes into the DB:
  ReconResult → DiscoveredEndpoint, DiscoveredForm, DetectedTech

The downstream attack engines (2c-2g) consume these results to know
WHAT to attack and WHERE.
"""
from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from datetime import datetime
from typing import Optional, Set, List, Dict
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from sqlalchemy.orm import Session

logger = logging.getLogger("venom.recon")


# ── Configuration ──────────────────────────────────────────────────────────
MAX_URLS_TO_CRAWL = 100          # cap to keep recon under 2 minutes
MAX_DEPTH         = 3
HTTP_TIMEOUT      = 10.0
PER_REQUEST_DELAY = 0.1          # be polite, 10 req/s max
HTTP_HEADERS      = {"User-Agent": "VENOM-AI-Recon/2.0"}


# ════════════════════════════════════════════════════════════════════════════
# TECH STACK FINGERPRINTS
# ════════════════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS = {
    # ─── Headers ─────────────────────────────────────────────────────────
    "header": {
        "x-powered-by": {
            "express":      ("Express",      "framework", "Node.js Express"),
            "php":          ("PHP",          "language",  "PHP runtime"),
            "asp.net":      ("ASP.NET",      "framework", "Microsoft ASP.NET"),
            "next.js":      ("Next.js",      "framework", "Next.js React framework"),
        },
        "server": {
            "nginx":        ("nginx",        "server",    "nginx web server"),
            "apache":       ("Apache",       "server",    "Apache web server"),
            "caddy":        ("Caddy",        "server",    "Caddy web server"),
            "cloudflare":   ("Cloudflare",   "cdn",       "Cloudflare CDN/proxy"),
            "iis":          ("Microsoft IIS","server",    "Microsoft IIS"),
            "gunicorn":     ("Gunicorn",     "server",    "Gunicorn (Python WSGI)"),
            "uvicorn":      ("Uvicorn",      "server",    "Uvicorn (Python ASGI)"),
        },
        "x-aspnet-version": {
            "":             ("ASP.NET",      "framework", "ASP.NET (version disclosed)"),
        },
        "x-drupal-cache": {
            "":             ("Drupal",       "cms",       "Drupal CMS"),
        },
    },
    # ─── Cookies ─────────────────────────────────────────────────────────
    "cookie": {
        "phpsessid":        ("PHP",          "language",  "PHP session cookie present"),
        "jsessionid":       ("Java",         "language",  "Java session cookie present"),
        "asp.net_sessionid":("ASP.NET",      "framework", "ASP.NET session cookie"),
        "csrftoken":        ("Django",       "framework", "Django CSRF cookie pattern"),
        "_rails_session":   ("Rails",        "framework", "Ruby on Rails session cookie"),
        "laravel_session":  ("Laravel",      "framework", "Laravel session cookie"),
        "connect.sid":      ("Express",      "framework", "Express session cookie"),
    },
    # ─── HTML body patterns ──────────────────────────────────────────────
    "html": {
        r"window\.__NEXT_DATA__":        ("Next.js",      "framework", "Next.js hydration script"),
        r"window\.__NUXT__":             ("Nuxt.js",      "framework", "Nuxt.js hydration script"),
        r"ng-version=":                  ("Angular",      "framework", "Angular ng-version attribute"),
        r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom": ("React", "framework", "React markers"),
        r"vue-instance|v-cloak|data-v-": ("Vue.js",       "framework", "Vue directives"),
        r"<meta name=\"generator\" content=\"WordPress": ("WordPress", "cms", "WordPress meta generator"),
        r"<meta name=\"generator\" content=\"Drupal":    ("Drupal",    "cms", "Drupal meta generator"),
        r"<meta name=\"generator\" content=\"Joomla":    ("Joomla",    "cms", "Joomla meta generator"),
        r"<meta name=\"generator\" content=\"Hugo":      ("Hugo",      "framework", "Hugo static site"),
        r"<meta name=\"generator\" content=\"Ghost":     ("Ghost",     "cms", "Ghost blogging platform"),
        r"shopify\.theme|cdn\.shopify\.com": ("Shopify", "cms", "Shopify e-commerce"),
        r"wix\.com|wixstatic":               ("Wix",     "cms", "Wix site builder"),
        r"squarespace":                       ("Squarespace", "cms", "Squarespace site"),
        r"wp-content|wp-includes":            ("WordPress", "cms", "WordPress paths"),
        r"\bDjango Administration\b":         ("Django",   "framework", "Django admin reference"),
        r"powered by\s+Flask":                ("Flask",    "framework", "Flask powered-by text"),
        r"Built with FastAPI":                ("FastAPI",  "framework", "FastAPI text"),
        r"Rails\.start\(\)":                  ("Rails",    "framework", "Rails start() call"),
    },
    # ─── Script src patterns (JS libraries) ──────────────────────────────
    "script_src": {
        r"jquery[.\-]([0-9.]+)?":   ("jQuery",        "js_lib", "jQuery library"),
        r"react[.\-]([0-9.]+)?":    ("React",         "js_lib", "React library"),
        r"vue[.\-]([0-9.]+)?":      ("Vue.js",        "js_lib", "Vue.js library"),
        r"angular[.\-]([0-9.]+)?":  ("Angular",       "js_lib", "Angular library"),
        r"bootstrap":                ("Bootstrap",     "js_lib", "Bootstrap CSS/JS"),
        r"axios":                    ("axios",         "js_lib", "axios HTTP client"),
        r"lodash":                   ("Lodash",        "js_lib", "Lodash utility library"),
        r"three\.min\.js|three\.js":("Three.js",      "js_lib", "Three.js 3D library"),
        r"d3\.min\.js|d3\.js":      ("D3.js",         "js_lib", "D3.js visualization"),
        r"chart\.js":                ("Chart.js",      "js_lib", "Chart.js charting"),
        r"googletagmanager":         ("GTM",           "analytics", "Google Tag Manager"),
        r"google-analytics\.com":    ("Google Analytics", "analytics", "Google Analytics"),
        r"hotjar":                   ("Hotjar",        "analytics", "Hotjar analytics"),
        r"segment\.io":              ("Segment",       "analytics", "Segment analytics"),
        r"intercom":                 ("Intercom",      "analytics", "Intercom widget"),
        r"stripe\.com\/v3":          ("Stripe.js",     "payment",   "Stripe payment SDK"),
        r"checkout\.razorpay\.com":  ("Razorpay",      "payment",   "Razorpay checkout SDK"),
    },
}


# ════════════════════════════════════════════════════════════════════════════
# CRAWLER
# ════════════════════════════════════════════════════════════════════════════

def _is_same_origin(url: str, base_host: str) -> bool:
    """Lock crawl scope to the target host (and its sub-domains optional)."""
    try:
        host = urlparse(url).hostname or ""
        return host == base_host or host.endswith("." + base_host)
    except Exception:
        return False


def _extract_links(html: str, base_url: str) -> Set[str]:
    """Extract href and src links from raw HTML using regex (no bs4 dependency)."""
    links: Set[str] = set()
    # href in <a>, <link>
    for m in re.finditer(r'\b(?:href|src|action)\s*=\s*["\']([^"\'#?]+)', html, re.IGNORECASE):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(base_url, raw)
        # Drop fragments
        full = full.split("#", 1)[0]
        links.add(full)
    return links


def _classify_endpoint(url: str, ctype: str) -> str:
    """Decide if URL is page / api / static / etc."""
    ctype = (ctype or "").lower()
    path  = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                                           ".woff", ".woff2", ".ttf", ".ico", ".webp", ".map")):
        return "static"
    if "json" in ctype or "/api/" in path or path.endswith((".json",)):
        return "api"
    if "html" in ctype:
        return "page"
    return "other"


# ════════════════════════════════════════════════════════════════════════════
# TECH FINGERPRINTER
# ════════════════════════════════════════════════════════════════════════════

def _fingerprint_headers(headers: Dict[str, str], detected: Dict[str, dict]):
    """Scan response headers for tech indicators."""
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for hdr, mapping in TECH_FINGERPRINTS["header"].items():
        val = h_lower.get(hdr, "")
        if not val:
            continue
        for needle, (name, cat, evidence) in mapping.items():
            if needle == "" or needle in val:
                # Try to extract version
                version_match = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", val)
                version = version_match.group(1) if version_match else None
                detected.setdefault(name, {
                    "name":       name,
                    "category":   cat,
                    "version":    version,
                    "confidence": 90,
                    "evidence":   f"Header {hdr}: {headers.get(hdr, '')[:120]}",
                })


def _fingerprint_cookies(set_cookie_headers: list, detected: Dict[str, dict]):
    for cookie_str in set_cookie_headers:
        cookie_lower = cookie_str.lower()
        for needle, (name, cat, evidence) in TECH_FINGERPRINTS["cookie"].items():
            if needle in cookie_lower:
                detected.setdefault(name, {
                    "name":       name,
                    "category":   cat,
                    "version":    None,
                    "confidence": 85,
                    "evidence":   evidence,
                })


def _fingerprint_html(html: str, detected: Dict[str, dict]):
    for pattern, (name, cat, evidence) in TECH_FINGERPRINTS["html"].items():
        if re.search(pattern, html, re.IGNORECASE):
            detected.setdefault(name, {
                "name":       name,
                "category":   cat,
                "version":    None,
                "confidence": 80,
                "evidence":   evidence,
            })


def _fingerprint_scripts(html: str, detected: Dict[str, dict]):
    """Look at <script src=...> and detect libraries."""
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE)
    for src in script_srcs:
        src_lower = src.lower()
        for pattern, (name, cat, evidence) in TECH_FINGERPRINTS["script_src"].items():
            m = re.search(pattern, src_lower)
            if m:
                version = m.group(1) if m.lastindex else None
                detected.setdefault(name, {
                    "name":       name,
                    "category":   cat,
                    "version":    version,
                    "confidence": 75,
                    "evidence":   f"Script: {src[:120]}",
                })


# ════════════════════════════════════════════════════════════════════════════
# AUTH DETECTOR
# ════════════════════════════════════════════════════════════════════════════

def _detect_auth(html: str, headers: Dict[str, str], cookies: list) -> Optional[str]:
    """Best-effort guess: jwt | session_cookie | basic | oauth | none."""
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # Basic Auth challenge
    if "www-authenticate" in h_lower:
        wa = h_lower["www-authenticate"]
        if "basic" in wa:
            return "basic"
        if "bearer" in wa:
            return "jwt"

    # JWT-flavoured cookies/headers
    cookies_lower = " ".join(c.lower() for c in cookies)
    if "bearer " in cookies_lower or "authorization" in cookies_lower or "jwt" in cookies_lower:
        return "jwt"

    # Session cookies
    session_cookie_names = ("phpsessid", "jsessionid", "asp.net_sessionid",
                            "connect.sid", "_rails_session", "laravel_session", "sessionid")
    if any(name in cookies_lower for name in session_cookie_names):
        return "session_cookie"

    # OAuth markers in HTML
    if re.search(r"oauth|google[-_]signin|github\.com/login/oauth", html, re.IGNORECASE):
        return "oauth"

    # Login form markers
    if re.search(r'<form[^>]*>.*?<input[^>]+type=["\']password["\']', html,
                 re.IGNORECASE | re.DOTALL):
        return "session_cookie"   # default assumption

    return None


# ════════════════════════════════════════════════════════════════════════════
# FORM EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════

def _extract_forms(html: str, page_url: str) -> List[dict]:
    """Extract every <form> with its inputs as a structured list."""
    forms = []
    # Match every form, allow attribute order variation
    for form_match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        attrs_str = form_match.group(1)
        body      = form_match.group(2)

        # Parse form attributes
        def _attr(name):
            m = re.search(rf'\b{name}\s*=\s*["\']([^"\']*)', attrs_str, re.IGNORECASE)
            return m.group(1) if m else None

        action  = _attr("action") or page_url
        method  = (_attr("method") or "GET").upper()
        enctype = _attr("enctype") or "application/x-www-form-urlencoded"

        # Resolve action to absolute URL
        try:
            action_abs = urljoin(page_url, action)
        except Exception:
            action_abs = action

        # Parse <input>, <select>, <textarea>
        inputs = []
        for m in re.finditer(r'<(input|select|textarea)\b([^>]*)', body, re.IGNORECASE):
            tag = m.group(1).lower()
            a   = m.group(2)
            def _ia(name):
                mm = re.search(rf'\b{name}\s*=\s*["\']([^"\']*)', a, re.IGNORECASE)
                return mm.group(1) if mm else None
            name_ = _ia("name") or _ia("id")
            if not name_:
                continue
            type_ = _ia("type") or ("textarea" if tag == "textarea" else "text")
            required = bool(re.search(r'\brequired\b', a, re.IGNORECASE))
            placeholder = _ia("placeholder") or ""
            inputs.append({
                "name":        name_,
                "type":        type_,
                "required":    required,
                "placeholder": placeholder[:100],
            })

        # Detect CSRF token field
        csrf_field = None
        csrf_names = ("csrf_token", "csrfmiddlewaretoken", "_csrf", "_token",
                      "authenticity_token", "__requestverificationtoken")
        for inp in inputs:
            if inp["name"].lower() in csrf_names or "csrf" in inp["name"].lower():
                csrf_field = inp["name"]
                break

        # Guess purpose
        purpose = "other"
        text = body.lower() + " ".join(i["name"].lower() + " " + i["type"].lower() for i in inputs)
        if any(k in text for k in ("password", "login", "signin", "log-in")):
            purpose = "login"
        elif any(k in text for k in ("signup", "register", "join")):
            purpose = "signup"
        elif "search" in text or "query" in text:
            purpose = "search"
        elif "comment" in text:
            purpose = "comment"
        elif "contact" in text or "message" in text:
            purpose = "contact"
        elif any(k in text for k in ("subscribe", "newsletter", "email")):
            purpose = "subscribe"

        forms.append({
            "action":         action_abs[:1500],
            "method":         method,
            "enctype":        enctype[:100],
            "inputs":         inputs,
            "has_csrf_token": csrf_field is not None,
            "csrf_field_name": csrf_field,
            "purpose":        purpose,
        })
    return forms


# ════════════════════════════════════════════════════════════════════════════
# MAIN RECON ENTRY
# ════════════════════════════════════════════════════════════════════════════

def run_recon(db: Session, target_url: str, owner_id: Optional[int] = None) -> dict:
    """
    Run full recon against target_url. Persists to DB and returns summary.

    NOTE: This is the ONLY entry point. Do not call sub-functions directly
    from routes — they don't enforce safety guardrails.
    """
    # Normalize URL
    if "://" not in target_url:
        target_url = "https://" + target_url
    base = urlparse(target_url)
    base_host = (base.hostname or "").lower()
    if not base_host:
        raise ValueError(f"Invalid target URL: {target_url}")

    base_root = f"{base.scheme}://{base_host}"

    # Create ReconResult row
    try:
        from db.models import ReconResult, DiscoveredEndpoint, DiscoveredForm, DetectedTech
    except ImportError as e:
        raise RuntimeError(f"Recon models not available: {e}")

    recon = ReconResult(
        owner_id=owner_id,
        target_url=target_url,
        status="running",
        progress=5,
        started_at=datetime.utcnow(),
    )
    db.add(recon)
    db.commit()
    db.refresh(recon)
    recon_id = recon.id

    detected_tech: Dict[str, dict] = {}
    discovered_urls: Set[str] = set()
    discovered_forms_per_page: List[tuple] = []
    auth_method: Optional[str] = None

    try:
        # ─── BFS crawl ────────────────────────────────────────────────────
        queue = deque([(target_url, 0)])
        visited: Set[str] = set()

        with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                          verify=False, headers=HTTP_HEADERS) as client:
            while queue and len(visited) < MAX_URLS_TO_CRAWL:
                url, depth = queue.popleft()
                if url in visited:
                    continue
                if not _is_same_origin(url, base_host):
                    continue
                visited.add(url)

                try:
                    r = client.get(url)
                    status      = r.status_code
                    headers     = dict(r.headers)
                    ctype       = headers.get("content-type", "")
                    body        = r.text if "html" in ctype.lower() or ctype == "" else ""
                    response_size = len(r.content)
                    # Collect cookies (raw Set-Cookie list)
                    cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
                              [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

                    # Tech fingerprinting
                    _fingerprint_headers(headers, detected_tech)
                    _fingerprint_cookies(cookies, detected_tech)
                    if body:
                        _fingerprint_html(body, detected_tech)
                        _fingerprint_scripts(body, detected_tech)

                    # Auth detection (only need a hint from one page)
                    if auth_method is None:
                        a = _detect_auth(body, headers, cookies)
                        if a:
                            auth_method = a

                    # Form extraction
                    if body:
                        forms = _extract_forms(body, url)
                        for f in forms:
                            discovered_forms_per_page.append((url, f))

                    # Parameters from URL
                    parsed_url = urlparse(url)
                    params = list(parse_qs(parsed_url.query).keys())

                    # Selected interesting headers to store
                    interesting_hdrs = {
                        k: v for k, v in headers.items()
                        if k.lower() in ("server", "x-powered-by", "content-type",
                                          "x-frame-options", "strict-transport-security",
                                          "content-security-policy")
                    }

                    # Save endpoint
                    db.add(DiscoveredEndpoint(
                        recon_id=recon_id,
                        url=url[:1500],
                        http_method="GET",
                        status_code=status,
                        content_type=ctype[:100],
                        response_size=response_size,
                        kind=_classify_endpoint(url, ctype),
                        is_authenticated=(status in (401, 403)),
                        parameters=params if params else None,
                        headers=interesting_hdrs,
                    ))

                    # Update progress
                    recon.progress = min(85, 5 + int(80 * len(visited) / MAX_URLS_TO_CRAWL))
                    db.commit()

                    # Extract more links to crawl (only HTML pages)
                    if body and depth < MAX_DEPTH:
                        for link in _extract_links(body, url):
                            if link not in visited and _is_same_origin(link, base_host):
                                if len(visited) + len(queue) < MAX_URLS_TO_CRAWL:
                                    queue.append((link, depth + 1))

                    time.sleep(PER_REQUEST_DELAY)

                except Exception as fetch_err:
                    logger.warning(f"[Recon] fetch failed for {url}: {fetch_err}")
                    continue

        # ─── Probe common API spec endpoints ──────────────────────────────
        for spec_path in ("/openapi.json", "/swagger.json", "/api/openapi.json",
                          "/api-docs", "/v3/api-docs"):
            spec_url = base_root + spec_path
            try:
                with httpx.Client(timeout=5, follow_redirects=True, verify=False,
                                  headers=HTTP_HEADERS) as c:
                    r = c.get(spec_url)
                if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                    try:
                        spec = r.json()
                        paths = list((spec.get("paths") or {}).keys())
                        for p in paths[:50]:   # cap at 50 API endpoints from a spec
                            full = base_root + p
                            db.add(DiscoveredEndpoint(
                                recon_id=recon_id,
                                url=full[:1500],
                                http_method="GET",
                                kind="api",
                                content_type="application/json",
                                parameters=None,
                            ))
                        # Record OpenAPI as detected tech
                        detected_tech.setdefault("OpenAPI", {
                            "name": "OpenAPI/Swagger", "category": "api_spec",
                            "version": spec.get("openapi") or spec.get("swagger"),
                            "confidence": 95,
                            "evidence":   f"Found {spec_path}",
                        })
                        db.commit()
                        break
                    except Exception:
                        pass
            except Exception:
                pass

        # ─── Persist forms ────────────────────────────────────────────────
        for page_url, form in discovered_forms_per_page:
            try:
                db.add(DiscoveredForm(
                    recon_id=recon_id,
                    page_url=page_url[:1500],
                    action=form["action"],
                    method=form["method"],
                    enctype=form["enctype"],
                    inputs=form["inputs"],
                    has_csrf_token=form["has_csrf_token"],
                    csrf_field_name=form["csrf_field_name"],
                    purpose=form["purpose"],
                ))
            except Exception as e:
                logger.warning(f"[Recon] Form save failed: {e}")

        # ─── Persist detected tech ────────────────────────────────────────
        for tech in detected_tech.values():
            try:
                db.add(DetectedTech(
                    recon_id=recon_id,
                    name=tech["name"][:100],
                    version=(tech["version"] or "")[:50] or None,
                    category=tech["category"][:50],
                    confidence=tech["confidence"],
                    evidence=tech["evidence"],
                ))
            except Exception as e:
                logger.warning(f"[Recon] Tech save failed: {e}")

        # ─── Finalize ─────────────────────────────────────────────────────
        endpoint_count = db.query(DiscoveredEndpoint).filter(
            DiscoveredEndpoint.recon_id == recon_id).count()
        form_count = db.query(DiscoveredForm).filter(
            DiscoveredForm.recon_id == recon_id).count()

        # Build stack summary
        stack_summary = {}
        for tech in detected_tech.values():
            cat = tech["category"]
            stack_summary.setdefault(cat, []).append({
                "name":    tech["name"],
                "version": tech["version"],
            })

        recon.status        = "completed"
        recon.progress      = 100
        recon.completed_at  = datetime.utcnow()
        recon.total_urls    = len(visited)
        recon.total_forms   = form_count
        recon.total_endpoints = endpoint_count
        recon.stack_summary = stack_summary
        recon.auth_method   = auth_method
        db.commit()

        logger.info(f"[Recon] {target_url} complete: {len(visited)} URLs, "
                    f"{form_count} forms, {len(detected_tech)} tech detected")

        return {
            "recon_id":      recon_id,
            "status":        "completed",
            "target_url":    target_url,
            "total_urls":    len(visited),
            "total_forms":   form_count,
            "total_endpoints": endpoint_count,
            "auth_method":   auth_method,
            "stack_summary": stack_summary,
            "detected_tech": list(detected_tech.values()),
        }

    except Exception as e:
        logger.error(f"[Recon] FAILED {target_url}: {e}", exc_info=True)
        try:
            recon.status   = "failed"
            recon.error    = str(e)[:500]
            recon.completed_at = datetime.utcnow()
            db.commit()
        except Exception:
            db.rollback()
        return {
            "recon_id": recon_id,
            "status":   "failed",
            "error":    str(e),
        }
