"""
VENOM AI — Domain Ownership Verification
─────────────────────────────────────────────────────────────────────────
Before VENOM allows an ACTIVE attack-based scan against a domain, the user
must prove they own it. Four verification methods supported:

  1. DNS TXT record    →  venom-verify=<token>   (most secure)
  2. File at root      →  /venom-verification.txt
  3. .well-known file  →  /.well-known/venom-verify
  4. HTML meta tag     →  <meta name="venom-site-verification" content="<token>">

VENOM checks all four methods in parallel — first match wins.

Verification expires never (re-checked periodically). If the proof is
removed (e.g. user deletes the DNS record), `is_domain_verified()` returns
False and active scans are denied until re-verification.
"""
from __future__ import annotations
import logging
import secrets
import socket
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

logger = logging.getLogger("venom.domain_verify")

# ── DNS resolution (use dnspython if available, fallback to socket) ─────────
try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


HTTP_TIMEOUT = 8.0
HTTP_HEADERS = {"User-Agent": "VENOM-AI-DomainVerifier/2.0"}


def normalize_domain(value: str) -> str:
    """Strip scheme, path, port — return clean domain like 'example.com'."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    # If it's a full URL, parse
    if "://" in v:
        v = urlparse(v).hostname or ""
    # Strip port
    if ":" in v:
        v = v.split(":", 1)[0]
    # Strip leading www. (canonical form)
    if v.startswith("www."):
        v = v[4:]
    # Validation
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$", v):
        return ""
    return v


def generate_token() -> str:
    """64-char URL-safe random token."""
    return secrets.token_hex(32)


# ─── Verification check methods ───────────────────────────────────────────────

def _check_dns_txt(domain: str, token: str) -> Tuple[bool, str]:
    """Look up TXT records for venom-verify=<token>."""
    needle = f"venom-verify={token}"
    if _HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
            for rdata in answers:
                # rdata.strings is a list of byte strings
                for txt in rdata.strings:
                    txt_str = txt.decode("utf-8", errors="ignore").strip()
                    if needle in txt_str or txt_str == needle:
                        return True, f"DNS TXT record found: {txt_str[:60]}"
            return False, "TXT records present but token not found"
        except dns.resolver.NXDOMAIN:
            return False, "Domain does not exist (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            return False, "No TXT records on domain"
        except Exception as e:
            return False, f"DNS lookup error: {str(e)[:120]}"
    else:
        # Fallback: dnspython not installed — use socket (limited, no TXT support)
        return False, "DNS TXT check unavailable (dnspython not installed)"


def _check_file(domain: str, token: str) -> Tuple[bool, str]:
    """GET https://<domain>/venom-verification.txt — must contain token."""
    needle = f"venom-verify={token}"
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/venom-verification.txt"
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                              verify=False, headers=HTTP_HEADERS) as c:
                r = c.get(url)
            if r.status_code == 200 and needle in r.text:
                return True, f"File found at {url}"
        except Exception:
            continue
    return False, "venom-verification.txt not found or token missing"


def _check_well_known(domain: str, token: str) -> Tuple[bool, str]:
    """GET https://<domain>/.well-known/venom-verify — must contain token."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/.well-known/venom-verify"
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                              verify=False, headers=HTTP_HEADERS) as c:
                r = c.get(url)
            if r.status_code == 200 and token in r.text:
                return True, f".well-known file found at {url}"
        except Exception:
            continue
    return False, ".well-known/venom-verify not found or token missing"


def _check_meta_tag(domain: str, token: str) -> Tuple[bool, str]:
    """GET https://<domain>/ and look for <meta name='venom-site-verification' content='<token>'>."""
    pattern = re.compile(
        r'<meta\s+[^>]*name\s*=\s*["\']venom-site-verification["\'][^>]*content\s*=\s*["\']' +
        re.escape(token) + r'["\']',
        re.IGNORECASE,
    )
    # Also accept reversed attribute order
    pattern_rev = re.compile(
        r'<meta\s+[^>]*content\s*=\s*["\']' + re.escape(token) +
        r'["\'][^>]*name\s*=\s*["\']venom-site-verification["\']',
        re.IGNORECASE,
    )
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True,
                              verify=False, headers=HTTP_HEADERS) as c:
                r = c.get(url)
            if r.status_code == 200 and (pattern.search(r.text) or pattern_rev.search(r.text)):
                return True, f"Meta tag found on {url}"
        except Exception:
            continue
    return False, "venom-site-verification meta tag not found"


# ─── Top-level verification function ─────────────────────────────────────────

def check_domain_ownership(domain: str, token: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check all 4 methods — first match wins.
    Returns: (verified, method_used, evidence_or_error)
    """
    domain = normalize_domain(domain)
    if not domain:
        return False, None, "Invalid domain format"

    checks = [
        ("dns_txt",    _check_dns_txt),
        ("file",       _check_file),
        ("well_known", _check_well_known),
        ("meta_tag",   _check_meta_tag),
    ]

    errors = []
    for method_name, fn in checks:
        try:
            ok, msg = fn(domain, token)
            if ok:
                logger.info(f"[DomainVerify] {domain} verified via {method_name}: {msg}")
                return True, method_name, msg
            errors.append(f"{method_name}: {msg}")
        except Exception as e:
            errors.append(f"{method_name}: {str(e)[:100]}")

    combined = " | ".join(errors)
    logger.info(f"[DomainVerify] {domain} not verified — {combined}")
    return False, None, combined


# ─── DB-aware helpers ─────────────────────────────────────────────────────────

def is_domain_verified(db: Session, owner_id: Optional[int], target_url: str) -> bool:
    """
    Quick lookup — is this domain verified for this user?
    Returns False if not verified, revoked, or owner_id is None (anonymous).
    """
    if owner_id is None:
        return False
    try:
        from db.models import VerifiedDomain
        domain = normalize_domain(target_url)
        if not domain:
            return False
        # Check exact domain + parent domain (e.g. blog.example.com → example.com is verified)
        candidates = [domain]
        parts = domain.split(".")
        if len(parts) > 2:
            candidates.append(".".join(parts[-2:]))   # last two labels
        rows = db.query(VerifiedDomain).filter(
            VerifiedDomain.owner_id == owner_id,
            VerifiedDomain.domain.in_(candidates),
            VerifiedDomain.verified == True,
            VerifiedDomain.revoked_at.is_(None),
        ).all()
        return len(rows) > 0
    except Exception as e:
        logger.error(f"[DomainVerify] is_domain_verified failed: {e}")
        return False


def get_verification_instructions(domain: str, token: str) -> dict:
    """Return user-facing instructions for all 4 verification methods."""
    domain = normalize_domain(domain)
    return {
        "domain": domain,
        "token":  token,
        "methods": [
            {
                "id":          "dns_txt",
                "label":       "DNS TXT Record (Most Secure)",
                "summary":     "Add a TXT record at your domain registrar.",
                "instructions": [
                    f"Log in to your DNS provider (GoDaddy, Cloudflare, etc.)",
                    f"Add a TXT record:",
                    f"   Name:  @  (or leave blank)",
                    f"   Type:  TXT",
                    f"   Value: venom-verify={token}",
                    f"   TTL:   300 (5 minutes)",
                    f"Wait 1-2 minutes for DNS to propagate, then click Verify.",
                ],
            },
            {
                "id":          "file",
                "label":       "Upload File to Site Root",
                "summary":     "Upload a small text file to your website.",
                "instructions": [
                    f"Create a file named: venom-verification.txt",
                    f"Put this exact content inside it:",
                    f"   venom-verify={token}",
                    f"Upload it to your site so it's accessible at:",
                    f"   https://{domain}/venom-verification.txt",
                    f"Click Verify.",
                ],
                "file_name":    "venom-verification.txt",
                "file_content": f"venom-verify={token}",
                "verify_url":   f"https://{domain}/venom-verification.txt",
            },
            {
                "id":          "well_known",
                "label":       ".well-known File (Most Professional)",
                "summary":     "RFC 8615 standard — used by Let's Encrypt, Apple, etc.",
                "instructions": [
                    f"Create a file named: venom-verify (no extension)",
                    f"Put this content inside:",
                    f"   {token}",
                    f"Upload to: https://{domain}/.well-known/venom-verify",
                    f"Click Verify.",
                ],
                "file_name":    "venom-verify",
                "file_content": token,
                "verify_url":   f"https://{domain}/.well-known/venom-verify",
            },
            {
                "id":          "meta_tag",
                "label":       "HTML Meta Tag (No Upload Needed)",
                "summary":     "Paste a tag into your site's <head>.",
                "instructions": [
                    f"Open your homepage HTML.",
                    f"Inside <head>...</head> paste this tag:",
                    f'   <meta name="venom-site-verification" content="{token}">',
                    f"Save and deploy.",
                    f"Click Verify.",
                ],
                "tag":          f'<meta name="venom-site-verification" content="{token}">',
            },
        ],
    }
