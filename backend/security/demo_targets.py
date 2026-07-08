"""
VENOM AI — Demo Targets (Public Vulnerable Test Sites)
─────────────────────────────────────────────────────────────────────────
These are PUBLICLY DECLARED vulnerable applications maintained by major
security vendors and the OWASP foundation for security testing.

They are EXPLICITLY published as targets-anyone-can-scan — using them
to test scanners is legal, expected, and encouraged.

Users can scan these WITHOUT domain ownership verification because:
  1. The owners have publicly invited security testing
  2. The owners run the apps specifically for this purpose
  3. No real users or data are at risk

We also allow `localhost` and `127.0.0.1` (any port) — users own their
own machine and can scan anything on it without verification.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse


# ── Curated demo target list ────────────────────────────────────────────────
# Each entry: (domain, description, vendor)
DEMO_TARGETS = [
    # ─── Acunetix's public vulnerable test sites ────────────────────────
    ("testphp.vulnweb.com",      "Acunetix — vulnerable PHP demo (XSS, SQLi, etc.)",  "Acunetix"),
    ("testasp.vulnweb.com",      "Acunetix — vulnerable ASP demo",                     "Acunetix"),
    ("testaspnet.vulnweb.com",   "Acunetix — vulnerable ASP.NET demo",                 "Acunetix"),
    ("testhtml5.vulnweb.com",    "Acunetix — vulnerable HTML5 demo",                   "Acunetix"),
    # ─── IBM's classic AltoroMutual demo bank ───────────────────────────
    ("demo.testfire.net",        "IBM AppScan — AltoroMutual vulnerable banking demo", "IBM"),
    # ─── Micro Focus vulnerable demo ────────────────────────────────────
    ("zero.webappsecurity.com",  "Micro Focus — Zero Bank vulnerable demo",            "Micro Focus"),
    # ─── OWASP Juice Shop (public hosted instance) ──────────────────────
    ("juice-shop.herokuapp.com", "OWASP Juice Shop — modern vulnerable web app",       "OWASP"),
    ("preview.owasp-juice.shop", "OWASP Juice Shop — preview instance",                "OWASP"),
    # ─── badssl.com — SSL/TLS testing ───────────────────────────────────
    ("badssl.com",               "BadSSL — TLS misconfiguration testing site",         "Chrome Team"),
    ("expired.badssl.com",       "BadSSL — expired certificate test",                  "Chrome Team"),
    ("self-signed.badssl.com",   "BadSSL — self-signed certificate test",              "Chrome Team"),
    # ─── HTTPbin — HTTP testing ─────────────────────────────────────────
    ("httpbin.org",              "Postman — HTTP request/response testing",            "Postman"),
    # ─── Hack The Box public CTF ────────────────────────────────────────
    ("hackthebox.eu",            "Hack The Box — CTF training platform",               "Hack The Box"),
]


# Build a fast lookup set
_DEMO_DOMAIN_SET = {d for d, _, _ in DEMO_TARGETS}


def is_localhost(target_url: str) -> bool:
    """True if target points at localhost / 127.0.0.1 / private IPs."""
    try:
        url = target_url if "://" in target_url else "https://" + target_url
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        # Private RFC1918 IPv4 ranges
        if re.match(r"^10\.\d+\.\d+\.\d+$", host):                    return True
        if re.match(r"^192\.168\.\d+\.\d+$", host):                   return True
        if re.match(r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$", host):   return True
        # Docker internal
        if host.endswith(".local") or host.endswith(".internal"):     return True
        if host.startswith("host.docker.internal"):                   return True
        return False
    except Exception:
        return False


def is_demo_target(target_url: str) -> bool:
    """True if target is on the curated demo-target list."""
    try:
        url = target_url if "://" in target_url else "https://" + target_url
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        # Exact match or sub-domain match against any demo domain
        for demo in _DEMO_DOMAIN_SET:
            if host == demo or host.endswith("." + demo):
                return True
        return False
    except Exception:
        return False


def is_authorized_without_verification(target_url: str) -> tuple:
    """
    Return (allowed, reason) for targets that can be scanned WITHOUT
    requiring domain ownership verification.

    Allowed without verification:
      1. localhost / private IPs / Docker internal
      2. Curated public demo targets (Acunetix, OWASP, etc.)
    """
    if is_localhost(target_url):
        return True, "localhost_or_private_ip"
    if is_demo_target(target_url):
        return True, "public_demo_target"
    return False, None


def list_demo_targets() -> list:
    """Return the user-facing list of demo targets they can scan instantly."""
    return [
        {"domain": d, "url": f"http://{d}", "description": desc, "vendor": vendor}
        for d, desc, vendor in DEMO_TARGETS
    ]
