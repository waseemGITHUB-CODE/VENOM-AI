"""
VENOM AI — OSINT / Passive Recon Sweep
─────────────────────────────────────────────────────────────────────────
Gathers a target's public attack-surface profile using ONLY free, keyless
HTTP APIs + the standard library. No browser, no new dependencies, and it is
PASSIVE (no attack payloads are sent — this is intelligence gathering).

Sources:
  • crt.sh              — subdomains via certificate transparency
  • dns.google (DoH)    — A / MX / TXT records, SPF + DMARC email posture
  • rdap.org            — WHOIS (registrar, creation date, age)
  • target itself       — HTTP headers, security headers, title, tech markers
  • TLS handshake       — cert issuer / expiry / protocol
  • web.archive.org     — historical (Wayback) URLs
  • robots.txt/sitemap  — declared paths

Every step is best-effort with its own timeout; failures never abort the sweep.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import logging
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

logger = logging.getLogger("venom.osint")

_UA = "Mozilla/5.0 (compatible; VENOM-AI-OSINT/2.0)"
_STEP_TIMEOUT = 9


def _get(url: str, timeout: int = 8, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _get_json(url: str, timeout: int = 8):
    return json.loads(_get(url, timeout).decode("utf-8", "ignore"))


def _norm_host(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = urllib.parse.urlparse(t).netloc or t
    t = t.split("/")[0].split(":")[0].strip().lower()
    if t.startswith("www."):
        t = t[4:]
    return t


# ── Individual gatherers ─────────────────────────────────────────────────
def _subdomains(host: str) -> list:
    subs = set()
    # Source 1: crt.sh certificate transparency (fail fast — it's often overloaded)
    try:
        data = _get_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(host)}&output=json", 8)
        for row in data:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(host) and name != host and "@" not in name:
                    subs.add(name)
    except Exception as e:
        logger.debug(f"[osint] crt.sh: {e}")
    # Source 2 (fallback): HackerTarget hostsearch — fast, free (rate-limited)
    if not subs:
        try:
            raw = _get(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(host)}", 6).decode("utf-8", "ignore")
            if "API count exceeded" not in raw and "error" not in raw.lower():
                for line in raw.splitlines():
                    name = line.split(",")[0].strip().lower()
                    if name.endswith(host) and name != host:
                        subs.add(name)
        except Exception as e:
            logger.debug(f"[osint] hackertarget: {e}")
    return sorted(subs)[:60]


def _doh(host: str, rtype: str) -> list:
    try:
        data = _get_json(f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type={rtype}", 6)
        return [a.get("data", "").strip('"') for a in data.get("Answer", []) if a.get("data")]
    except Exception:
        return []


def _dns(host: str) -> dict:
    a   = _doh(host, "A")
    mx  = _doh(host, "MX")
    txt = _doh(host, "TXT")
    spf   = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    dmarc = _doh("_dmarc." + host, "TXT")
    dmarc_rec = next((t for t in dmarc if "v=dmarc1" in t.lower()), None)
    return {
        "a_records": a[:8], "mx": mx[:8],
        "spf": spf, "dmarc": dmarc_rec,
        "email_posture": {
            "spf": bool(spf),
            "dmarc": bool(dmarc_rec),
            "note": ("SPF and DMARC present" if spf and dmarc_rec
                     else "Missing " + " and ".join([x for x, ok in (("SPF", bool(spf)), ("DMARC", bool(dmarc_rec))) if not ok])
                     + " — domain is more spoofable"),
        },
    }


def _whois(host: str) -> dict:
    try:
        d = _get_json(f"https://rdap.org/domain/{urllib.parse.quote(host)}", 8)
        reg = None
        for ent in d.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                for v in (ent.get("vcardArray", [None, []])[1] or []):
                    if v and v[0] == "fn":
                        reg = v[3]
        created = expires = None
        for ev in d.get("events", []):
            if ev.get("eventAction") == "registration": created = ev.get("eventDate")
            if ev.get("eventAction") == "expiration":   expires = ev.get("eventDate")
        age_days = None
        if created:
            try:
                c = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - c).days
            except Exception:
                pass
        return {"registrar": reg, "created": created, "expires": expires, "age_days": age_days}
    except Exception as e:
        logger.debug(f"[osint] whois: {e}")
        return {}


_SEC_HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy"]

def _http_probe(host: str) -> dict:
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=8) as r:
                raw = r.read(200_000).decode("utf-8", "ignore")
                hdrs = {k.lower(): v for k, v in r.headers.items()}
            title = (re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S) or [None, None])[1]
            tech = []
            server = hdrs.get("server")
            if server: tech.append(server)
            if hdrs.get("x-powered-by"): tech.append(hdrs["x-powered-by"])
            for pat, name in [(r"wp-content|wp-includes", "WordPress"), (r"Drupal", "Drupal"),
                              (r"/_next/", "Next.js"), (r"react", "React"), (r"ng-version", "Angular"),
                              (r"jquery", "jQuery"), (r"Shopify", "Shopify"), (r"laravel_session", "Laravel")]:
                if re.search(pat, raw, re.I): tech.append(name)
            missing = [h for h in _SEC_HEADERS if h not in hdrs]
            return {
                "scheme": scheme, "status": getattr(r, "status", 200),
                "title": (title or "").strip()[:120],
                "server": server, "tech": sorted(set(tech))[:10],
                "security_headers_present": [h for h in _SEC_HEADERS if h in hdrs],
                "security_headers_missing": missing,
            }
        except Exception:
            continue
    return {}


def _tls(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "protocol": proto,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "expires": cert.get("notAfter"),
        }
    except Exception as e:
        logger.debug(f"[osint] tls: {e}")
        return {}


def _wayback(host: str) -> list:
    try:
        url = ("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(host)
               + "/*&output=json&fl=original&collapse=urlkey&limit=40")
        data = _get_json(url, 8)
        return [row[0] for row in data[1:]][:40] if len(data) > 1 else []
    except Exception:
        return []


def _robots(host: str) -> dict:
    out = {"robots": False, "sitemap": False, "disallow": []}
    try:
        txt = _get(f"https://{host}/robots.txt", 6).decode("utf-8", "ignore")
        out["robots"] = True
        out["disallow"] = re.findall(r"(?i)Disallow:\s*(\S+)", txt)[:20]
        if "sitemap" in txt.lower(): out["sitemap"] = True
    except Exception:
        pass
    return out


# ── Orchestrator ──────────────────────────────────────────────────────────
def gather_intel(target: str) -> dict:
    host = _norm_host(target)
    if not host or "." not in host:
        return {"ok": False, "error": "Invalid domain", "target": target}

    steps = {
        "subdomains": (_subdomains, host),
        "dns":        (_dns, host),
        "whois":      (_whois, host),
        "http":       (_http_probe, host),
        "tls":        (_tls, host),
        "wayback":    (_wayback, host),
        "robots":     (_robots, host),
    }
    result = {"ok": True, "target": host, "generated_at": datetime.now(timezone.utc).isoformat()}
    # All steps run in parallel; we bound EACH independently so one slow source
    # (e.g. crt.sh) can never starve the rest — we just take whatever finished.
    with ThreadPoolExecutor(max_workers=7) as ex:
        futs = {key: ex.submit(fn, arg) for key, (fn, arg) in steps.items()}
        for key, fut in futs.items():
            try:
                result[key] = fut.result(timeout=13)
            except Exception as e:
                logger.debug(f"[osint] step {key} failed/slow: {e}")
                result[key] = [] if key in ("subdomains", "wayback") else {}

    # A compact, spoken-friendly summary line
    n_sub = len(result.get("subdomains") or [])
    http  = result.get("http") or {}
    dns   = result.get("dns") or {}
    tech  = ", ".join(http.get("tech") or []) or "unknown stack"
    miss  = len(http.get("security_headers_missing") or [])
    email = (dns.get("email_posture") or {}).get("note", "")
    n_arch = len(result.get("wayback") or [])
    result["summary"] = (
        f"{host}: {n_sub} subdomains, running {tech}, {miss} security headers missing, "
        f"{n_arch} archived URLs. {email}."
    )
    return result
