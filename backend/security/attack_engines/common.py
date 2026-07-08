"""
VENOM AI — Attack Engine Common Utilities
Shared HTTP client, finding model, rate limiter, request signer.
"""
from __future__ import annotations

import time
import logging
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode

import httpx

logger = logging.getLogger("venom.attack")


# ── Shared HTTP config ──────────────────────────────────────────────────────
HTTP_TIMEOUT = 10.0
DEFAULT_HEADERS = {
    "User-Agent": "VENOM-AI-Scanner/2.0 (+https://venomai.in/bot)",
    "Accept":     "*/*",
    "Accept-Encoding": "identity",   # avoid gzip — easier response analysis
}


# ── Token-bucket rate limiter (per-target, thread-safe) ────────────────────
class RateLimiter:
    """Simple token bucket: max_rps tokens per second."""
    def __init__(self, max_rps: float = 10.0):
        self.rate     = max_rps
        self.capacity = max_rps
        self.tokens   = float(max_rps)
        self.last     = time.monotonic()
        self.lock     = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                time.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


# ── HTTP client wrapper enforcing rate limit ───────────────────────────────
class AttackClient:
    """httpx wrapper that auto-rate-limits and applies common headers."""
    def __init__(self, max_rps: float = 10.0):
        self.limiter = RateLimiter(max_rps)
        self.client  = httpx.Client(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers=DEFAULT_HEADERS,
        )

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

    def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        self.limiter.acquire()
        try:
            return self.client.request(method, url, **kwargs)
        except Exception as e:
            logger.debug(f"[AttackClient] {method} {url} failed: {e}")
            return None

    def get(self, url: str, **kw):   return self.request("GET", url, **kw)
    def post(self, url: str, **kw):  return self.request("POST", url, **kw)
    def put(self, url: str, **kw):   return self.request("PUT", url, **kw)
    def patch(self, url: str, **kw): return self.request("PATCH", url, **kw)
    def delete(self, url: str, **kw): return self.request("DELETE", url, **kw)


# ── Finding model — what each attack engine returns ─────────────────────────
@dataclass
class Finding:
    """A vulnerability or hardening issue produced by an attack engine."""
    title:            str
    category:         str           # "vulnerability" | "hardening"
    owasp:            str           # "A01" .. "A10" or "hardening"
    severity:         str           # critical | high | medium | low | info
    cwe_id:           str           = ""
    cvss_score:       float         = 0.0
    affected_url:     str           = ""
    parameter:        str           = ""        # which input was vulnerable
    http_method:      str           = "GET"
    payload:          str           = ""        # the payload that worked
    evidence:         str           = ""        # what response proved it
    description:      str           = ""
    impact:           str           = ""
    recommendation:   str           = ""
    poc:              str           = ""        # ready-to-run proof-of-concept
    source_tool:      str           = "venom_active"
    verified:         bool          = False
    # Risk matrix (filled in by Phase 2h)
    likelihood:       int           = 3
    impact_score:     int           = 3
    risk_score:       int           = 9
    request_sample:   str           = ""
    response_sample:  str           = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Helper: inject payload into a URL parameter ─────────────────────────────
def inject_into_url(url: str, param: str, value: str) -> str:
    """Replace or add ?param=value in a URL. Always URL-encodes the value."""
    p = urlparse(url)
    qs = dict(parse_qsl(p.query, keep_blank_values=True))
    qs[param] = value
    new_query = urlencode(qs, doseq=True)
    return p._replace(query=new_query).geturl()


# ── Helper: response timing oracle (for blind injection) ────────────────────
def timed_request(client: AttackClient, method: str, url: str, **kwargs) -> tuple:
    """Returns (response, elapsed_seconds)."""
    start = time.monotonic()
    r = client.request(method, url, **kwargs)
    return r, time.monotonic() - start
