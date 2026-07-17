"""
VENOM AI · NVD CVE integration
Live CVE lookups from NIST National Vulnerability Database (no API key required).
"""
from __future__ import annotations
import json
import logging
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("venom.nvd")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_get(params: dict) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{NVD_BASE}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "VENOM-AI/2.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description.")
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    cvss_vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                weaknesses.append(d["value"])
    refs = [r.get("url") for r in cve.get("references", [])[:5] if r.get("url")]
    configs = cve.get("configurations", [])
    affected = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected.append(match.get("criteria", ""))
    published = cve.get("published", "")[:10]
    modified = cve.get("lastModified", "")[:10]
    return {
        "cve_id": cve_id,
        "description": desc[:500],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "weaknesses": weaknesses[:5],
        "references": refs,
        "affected_products": affected[:10],
        "published": published,
        "last_modified": modified,
    }


def lookup_cve(cve_id: str) -> dict:
    """Look up a specific CVE by ID (e.g. CVE-2021-44228)."""
    cve_id = cve_id.strip().upper()
    try:
        data = _nvd_get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": f"{cve_id} not found in NVD"}
        return _parse_cve(vulns[0])
    except Exception as e:
        logger.error(f"NVD CVE lookup failed: {e}")
        raise


def search_cves(keyword: str, limit: int = 10) -> list[dict]:
    """Search CVEs by keyword (product, vendor, vuln type)."""
    try:
        data = _nvd_get({"keywordSearch": keyword, "resultsPerPage": min(limit, 20)})
        vulns = data.get("vulnerabilities", [])
        return [_parse_cve(v) for v in vulns]
    except Exception as e:
        logger.error(f"NVD search failed: {e}")
        raise


def recent_cves(limit: int = 10, severity: Optional[str] = None) -> list[dict]:
    """Get recently published CVEs, optionally filtered by severity.

    NVD API 2.0 has no "sort by newest" parameter — recency has to come from
    a pubStartDate/pubEndDate window instead (both required together, ISO-8601
    with milliseconds, max 120-day range). Results within that window come
    back newest-last, so we reverse them.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=30)
    params: dict = {
        "resultsPerPage": min(limit, 20),
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    if severity:
        params["cvssV3Severity"] = severity.upper()
    try:
        data = _nvd_get(params)
        vulns = data.get("vulnerabilities", [])
        return [_parse_cve(v) for v in reversed(vulns)]
    except Exception as e:
        logger.error(f"NVD recent CVEs failed: {e}")
        raise
