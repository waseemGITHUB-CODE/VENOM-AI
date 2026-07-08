"""
VENOM AI · VirusTotal integration
Checks URLs, IPs, domains, and file hashes against VirusTotal.
"""
from __future__ import annotations
import base64
import hashlib
import logging
import os
import urllib.request
import urllib.parse
import json
from typing import Optional

logger = logging.getLogger("venom.virustotal")

VT_BASE = "https://www.virustotal.com/api/v3"


def _get_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _vt_get(path: str) -> dict:
    key = _get_key()
    if not key:
        raise ValueError("VIRUSTOTAL_API_KEY not set in .env")
    req = urllib.request.Request(
        f"{VT_BASE}{path}",
        headers={"x-apikey": key, "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def _parse_stats(data: dict) -> dict:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    verdict = "clean"
    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"

    detections = [
        {"engine": k, "result": v.get("result"), "category": v.get("category")}
        for k, v in results.items()
        if v.get("category") in ("malicious", "suspicious")
    ]

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "detection_rate": f"{malicious}/{total}" if total else "0/0",
        "detections": detections[:10],
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
        "categories": attrs.get("categories", {}),
    }


def check_url(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    try:
        data = _vt_get(f"/urls/{url_id}")
        result = _parse_stats(data)
        result["type"] = "url"
        result["target"] = url
        return result
    except Exception as e:
        logger.error(f"VT URL check failed: {e}")
        raise


def check_ip(ip: str) -> dict:
    try:
        data = _vt_get(f"/ip_addresses/{ip}")
        result = _parse_stats(data)
        attrs = data.get("data", {}).get("attributes", {})
        result["type"] = "ip"
        result["target"] = ip
        result["country"] = attrs.get("country", "")
        result["asn"] = attrs.get("asn", "")
        result["as_owner"] = attrs.get("as_owner", "")
        return result
    except Exception as e:
        logger.error(f"VT IP check failed: {e}")
        raise


def check_domain(domain: str) -> dict:
    try:
        data = _vt_get(f"/domains/{domain}")
        result = _parse_stats(data)
        attrs = data.get("data", {}).get("attributes", {})
        result["type"] = "domain"
        result["target"] = domain
        result["registrar"] = attrs.get("registrar", "")
        result["creation_date"] = attrs.get("creation_date", "")
        result["whois"] = attrs.get("whois", "")[:300] if attrs.get("whois") else ""
        return result
    except Exception as e:
        logger.error(f"VT domain check failed: {e}")
        raise


def check_hash(file_hash: str) -> dict:
    try:
        data = _vt_get(f"/files/{file_hash}")
        result = _parse_stats(data)
        attrs = data.get("data", {}).get("attributes", {})
        result["type"] = "hash"
        result["target"] = file_hash
        result["file_type"] = attrs.get("type_description", "")
        result["file_size"] = attrs.get("size", 0)
        result["names"] = attrs.get("names", [])[:5]
        return result
    except Exception as e:
        logger.error(f"VT hash check failed: {e}")
        raise


def check_auto(target: str) -> dict:
    """Auto-detect target type and run the right check."""
    import re
    target = target.strip()
    if re.match(r"^https?://", target):
        return check_url(target)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return check_ip(target)
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", target):
        return check_hash(target)
    return check_domain(target)
