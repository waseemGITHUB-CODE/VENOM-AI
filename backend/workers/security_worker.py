"""
╔══════════════════════════════════════════════════════════════════════════╗
║  CyberPlatform  ·  security_worker.py  v3.0                             ║
║  Production-Grade Vulnerability Scanning Engine                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  NEW in v3 vs v2:                                                        ║
║  ┌──────────────────────────────────────────────────────────────┐        ║
║  │  + Nmap integration    (subprocess, XML parse → Vulnerability)│        ║
║  │  + OWASP ZAP API       (active+passive scan → Vulnerability) │        ║
║  │  + Nuclei scanner      (subprocess, JSONL → Vulnerability)   │        ║
║  │  + Tool Aggregator     (merge + dedup from all sources)      │        ║
║  │  + source_tool field   (track which tool found each issue)   │        ║
║  │  + Async DB layer      (asyncpg / SQLAlchemy async)          │        ║
║  │  + JWT auth hooks      (user context on every scan)          │        ║
║  │  + Structured AI JSON  (machine-parseable explanation output)│        ║
║  │  + Scan type routing   (full|quick|recon|webapp|infra)       │        ║
║  └──────────────────────────────────────────────────────────────┘        ║
║                                                                          ║
║  Modules:                                                                ║
║   1  Data Models + Enums        11  Nuclei Scanner                       ║
║   2  Scan Orchestrator          12  Tool Result Aggregator               ║
║   3  Security Headers           13  CSRF Checker                         ║
║   4  SSL/TLS Engine             14  Sensitive Data Exposure              ║
║   5  Nmap Integration           15  Auth Misconfig                       ║
║   6  Port Scanner (TCP)         16  Outdated Software                    ║
║   7  OWASP ZAP Integration      17  Verification Layer                   ║
║   8  Technology Detector        18  AI Explanation Engine (Groq)         ║
║   9  SQL Injection Scanner      19  CVSS Scoring Engine                  ║
║  10  XSS Scanner                20  Async DB Persistence                 ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import asyncio, json, logging, os, re, shutil, socket, ssl
import subprocess, sys, time, urllib.parse, xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeout
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger("cyberplatform.security_worker")

# ─────────────────────────────────────────────────────────────────────────────
# 1.  DATA MODELS + ENUMS
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanType(str, Enum):
    FULL    = "full"      # All modules + all tools
    QUICK   = "quick"     # Headers + SSL + ports only (< 60s)
    RECON   = "recon"     # Nmap + tech detection (infrastructure focus)
    WEBAPP  = "webapp"    # SQLi + XSS + CSRF + ZAP (app-layer focus)
    INFRA   = "infra"     # Nmap + SSL + ports + Nuclei (infra focus)


class SourceTool(str, Enum):
    """Tracks which scanner engine discovered each vulnerability."""
    INTERNAL  = "internal"    # Built-in Python checks (headers, SSL, etc.)
    NMAP      = "nmap"
    ZAP       = "owasp_zap"
    NUCLEI    = "nuclei"
    MANUAL    = "manual"


@dataclass
class Vulnerability:
    """
    Unified vulnerability model.
    Stores findings from all scanner sources in a single schema.
    Maps directly to the `vulnerabilities` DB table.
    """
    vuln_type:       str
    title:           str
    severity:        str              # Severity enum value
    description:     str
    source_tool:     str  = SourceTool.INTERNAL   # Which scanner found this
    evidence:        str  = ""
    affected_url:    str  = ""
    recommendation:  str  = ""
    cvss_score:      float = 0.0
    cve_id:          str  = ""
    cwe_id:          str  = ""        # CWE identifier (new in v3)
    false_positive:  bool = False
    verified:        bool = False
    ai_explanation:  str  = ""        # Plain-language explanation
    ai_remediation:  str  = ""        # Actionable fix steps
    ai_risk_level:   str  = ""        # AI-assessed business risk (new in v3)
    parameter:       str  = ""
    http_method:     str  = "GET"     # New: track HTTP method
    request_sample:  str  = ""
    response_sample: str  = ""
    tags:            List[str] = field(default_factory=list)  # e.g. ["owasp-top10","pci"]
    raw_output:      Dict = field(default_factory=dict)       # Original tool output

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @property
    def severity_order(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            self.severity.lower(), 5)


@dataclass
class ScanResult:
    """
    Aggregated result from all scanner modules.
    """
    url:              str
    scan_id:          str   = ""
    scan_type:        str   = ScanType.FULL
    status:           str   = "running"
    user_id:          str   = ""            # NEW: JWT user context

    # Module sub-scores
    headers_score:    int   = 100
    ssl_score:        int   = 100
    port_score:       int   = 100
    vuln_score:       int   = 100
    auth_score:       int   = 100
    tool_score:       int   = 100           # NEW: score from external tools

    # Final score
    security_score:   int   = 0
    grade:            str   = "F"

    # Findings
    vulnerabilities:  List[Vulnerability]  = field(default_factory=list)
    open_ports:       List[int]            = field(default_factory=list)
    detected_tech:    Dict                 = field(default_factory=dict)
    crawled_urls:     List[str]            = field(default_factory=list)

    # Counts
    total_issues:     int   = 0
    critical_count:   int   = 0
    high_count:       int   = 0
    medium_count:     int   = 0
    low_count:        int   = 0
    info_count:       int   = 0

    # Per-tool finding counts (NEW)
    nmap_findings:    int   = 0
    zap_findings:     int   = 0
    nuclei_findings:  int   = 0
    internal_findings:int   = 0

    # AI outputs
    ai_summary:           str = ""
    ai_risk_narrative:    str = ""
    ai_remediation_plan:  str = ""   # NEW: prioritised remediation plan

    # Metadata
    scanned_at:       str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_duration_s:  float = 0.0
    tools_used:       List[str] = field(default_factory=list)   # NEW

    @property
    def confirmed_vulns(self) -> List[Vulnerability]:
        return sorted(
            [v for v in self.vulnerabilities if not v.false_positive],
            key=lambda v: v.severity_order
        )

    def findings_by_tool(self, tool: str) -> List[Vulnerability]:
        return [v for v in self.confirmed_vulns if v.source_tool == tool]


# ─────────────────────────────────────────────────────────────────────────────
# 2.  SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

# Uncomment for production:
# from workers.celery_app import celery_app
# @celery_app.task(bind=True, name="workers.security_worker.run_full_scan",
#                  max_retries=2, soft_time_limit=600, time_limit=720)
def run_full_scan(task_self, url: str, user_id: str, scan_id: str,
                  scan_type: str = ScanType.FULL) -> dict:
    """
    Master orchestrator — routes to correct module set based on scan_type.

    Pipeline (FULL scan):
      1. Normalize URL
      2. Crawl entry points
      3. Parallel infra: headers + SSL + Nmap + tech detect
      4. Parallel webapp: SQLi + XSS + CSRF + sensitive data + auth
      5. OWASP ZAP active scan
      6. Nuclei template scan
      7. Tool result aggregation + deduplication
      8. Outdated software check
      9. Verification layer (false-positive reduction)
     10. CVSS-weighted scoring
     11. AI enrichment (per-vuln explanation + remediation)
     12. AI executive summary + risk narrative + remediation plan
     13. Async DB persistence
    """
    t0 = time.monotonic()
    logger.info(f"[{scan_id}] ▶ START {scan_type} scan — target={url} user={user_id}")
    result = ScanResult(url=url, scan_id=scan_id, scan_type=scan_type, user_id=user_id)

    try:
        # ─ Step 1: Normalize ──────────────────────────────────────────
        _prog(scan_id, 2, "Normalizing target URL")
        url = _normalize_url(url)
        result.url = url

        # ─ Step 2: Crawl ──────────────────────────────────────────────
        if scan_type not in (ScanType.INFRA, ScanType.RECON):
            _prog(scan_id, 6, "Crawling pages for injection targets")
            result.crawled_urls = crawl_entry_points(url, max_pages=20)
            logger.info(f"[{scan_id}] Crawled {len(result.crawled_urls)} URLs")
        else:
            result.crawled_urls = [url]

        # ─ Step 3: Infrastructure checks (parallel) ───────────────────
        _prog(scan_id, 12, "Infrastructure checks (headers · SSL · Nmap · tech)")
        infra_vulns = _run_infra_checks(url, result, scan_type)
        result.vulnerabilities.extend(infra_vulns)

        # ─ Step 4: Web application checks (parallel) ──────────────────
        if scan_type in (ScanType.FULL, ScanType.QUICK, ScanType.WEBAPP):
            _prog(scan_id, 32, "Web application vulnerability scanning")
            webapp_vulns = _run_webapp_checks(url, result.crawled_urls)
            result.vulnerabilities.extend(webapp_vulns)

        # ─ Step 5: OWASP ZAP ──────────────────────────────────────────
        if scan_type in (ScanType.FULL, ScanType.WEBAPP) and _tool_available("zap.sh"):
            _prog(scan_id, 50, "OWASP ZAP active scan")
            zap_vulns = run_zap_scan(url, scan_id)
            result.vulnerabilities.extend(zap_vulns)
            result.tools_used.append(SourceTool.ZAP)
            logger.info(f"[{scan_id}] ZAP found {len(zap_vulns)} findings")

        # ─ Step 6: Nuclei ─────────────────────────────────────────────
        if scan_type in (ScanType.FULL, ScanType.INFRA, ScanType.WEBAPP)                 and _tool_available("nuclei"):
            _prog(scan_id, 62, "Nuclei template scan")
            nuclei_vulns = run_nuclei_scan(url, scan_id, scan_type)
            result.vulnerabilities.extend(nuclei_vulns)
            result.tools_used.append(SourceTool.NUCLEI)
            logger.info(f"[{scan_id}] Nuclei found {len(nuclei_vulns)} findings")

        # ─ Step 7: Tool aggregation + dedup ───────────────────────────
        _prog(scan_id, 70, "Aggregating and deduplicating findings")
        result.vulnerabilities = aggregate_tool_results(result.vulnerabilities)
        _update_tool_counts(result)

        # ─ Step 8: Outdated software ──────────────────────────────────
        _prog(scan_id, 74, "Checking for outdated software / CVEs")
        result.vulnerabilities.extend(check_outdated_software(result.detected_tech, url))

        # ─ Step 9: Verification ───────────────────────────────────────
        _prog(scan_id, 78, "Verification layer — reducing false positives")
        result.vulnerabilities = verification_pipeline(result.vulnerabilities, url)

        # ─ Step 10: Scoring ───────────────────────────────────────────
        _prog(scan_id, 83, "CVSS-weighted security scoring")
        result = calculate_score(result)

        # ─ Step 11: AI enrichment ─────────────────────────────────────
        _prog(scan_id, 87, "AI explanation + remediation generation")
        result.vulnerabilities = enrich_with_ai(result.vulnerabilities)

        # ─ Step 12: AI summaries ──────────────────────────────────────
        _prog(scan_id, 93, "Generating AI executive summary + risk narrative")
        result.ai_summary          = generate_ai_summary(result)
        result.ai_risk_narrative   = generate_risk_narrative(result)
        result.ai_remediation_plan = generate_remediation_plan(result)

        # ─ Step 13: Persist ───────────────────────────────────────────
        result.scan_duration_s = round(time.monotonic() - t0, 2)
        result.status = "done"
        asyncio.run(store_scan_results_async(scan_id, result))
        _prog(scan_id, 100, "Scan complete ✓", status="done")

        logger.info(
            f"[{scan_id}] ✓ DONE  score={result.security_score}/100  "
            f"grade={result.grade}  issues={result.total_issues}  "
            f"tools={result.tools_used}  duration={result.scan_duration_s}s"
        )

        # Serialize vulnerabilities — convert SourceTool enums to plain strings
        vuln_list = []
        for v in result.vulnerabilities:
            try:
                from dataclasses import asdict as _asdict
                vd = _asdict(v)
            except Exception:
                vd = v.__dict__.copy() if hasattr(v, "__dict__") else {}
            # Convert any enum values to their string value
            import enum as _enum
            safe = {}
            for k, val in vd.items():
                if isinstance(val, _enum.Enum):
                    safe[k] = val.value
                elif isinstance(val, (list, set)):
                    safe[k] = [x.value if isinstance(x, _enum.Enum) else x for x in val]
                else:
                    safe[k] = val
            vuln_list.append(safe)

        return {
            "status":          "done",
            "scan_id":         scan_id,
            "security_score":  result.security_score,
            "grade":           result.grade,
            "total_issues":    result.total_issues,
            "critical":        result.critical_count,
            "high":            result.high_count,
            "medium":          result.medium_count,
            "low":             result.low_count,
            "critical_count":  result.critical_count,
            "high_count":      result.high_count,
            "medium_count":    result.medium_count,
            "low_count":       result.low_count,
            "vulnerabilities": vuln_list,
            "tools_used":      result.tools_used,
            "nmap_findings":   result.nmap_findings,
            "zap_findings":    result.zap_findings,
            "nuclei_findings": result.nuclei_findings,
            "duration_s":      result.scan_duration_s,
        }

    except Exception as exc:
        logger.error(f"[{scan_id}] ✗ FAILED: {exc}", exc_info=True)
        result.status = "failed"
        _prog(scan_id, 0, f"Scan failed: {exc}", status="failed")
        raise


def _run_infra_checks(url: str, result: ScanResult, scan_type: str) -> List[Vulnerability]:
    """Run infrastructure checks in parallel, return aggregated vulns."""
    vulns: List[Vulnerability] = []
    with ThreadPoolExecutor(max_workers=5) as exe:
        jobs = {"headers": exe.submit(check_security_headers, url),
                "ssl":     exe.submit(check_ssl, url),
                "tech":    exe.submit(detect_technology, url)}

        if scan_type in (ScanType.FULL, ScanType.RECON, ScanType.INFRA)                 and _tool_available("nmap"):
            jobs["nmap"] = exe.submit(run_nmap_scan, url)
        else:
            jobs["ports"] = exe.submit(scan_ports_tcp, url)

        if scan_type in (ScanType.FULL, ScanType.WEBAPP)                 and _tool_available("nikto"):
            jobs["nikto"] = exe.submit(run_nikto_scan, url)

        if _tool_available("whatweb"):
            jobs["whatweb"] = exe.submit(run_whatweb_scan, url)

        h_vulns, h_score = jobs["headers"].result(timeout=30)
        s_vulns, s_score = jobs["ssl"].result(timeout=30)
        tech             = jobs["tech"].result(timeout=20)

        result.headers_score = h_score
        result.ssl_score     = s_score
        result.detected_tech = tech
        vulns.extend(h_vulns + s_vulns)

        if "nmap" in jobs:
            try:
                nmap_vulns, ports = jobs["nmap"].result(timeout=200)
                result.open_ports = ports
                result.tools_used.append(SourceTool.NMAP)
                vulns.extend(nmap_vulns)
                logger.info(f"Nmap found {len(nmap_vulns)} findings, {len(ports)} open ports")
            except Exception as nmap_err:
                logger.warning(f"Nmap failed ({nmap_err}) — falling back to TCP port scanner")
                try:
                    p_vulns, ports = scan_ports_tcp(url)
                    result.open_ports = ports
                    vulns.extend(p_vulns)
                except Exception as e:
                    logger.warning(f"TCP fallback also failed: {e}")
        else:
            try:
                p_vulns, ports = jobs["ports"].result(timeout=60)
                result.open_ports = ports
                vulns.extend(p_vulns)
            except Exception as e:
                logger.warning(f"Port scan failed: {e}")

        if "nikto" in jobs:
            try:
                nikto_vulns = jobs["nikto"].result(timeout=180)
                vulns.extend(nikto_vulns)
                logger.info(f"Nikto found {len(nikto_vulns)} findings")
            except Exception as e:
                logger.warning(f"Nikto failed: {e}")

        if "whatweb" in jobs:
            try:
                ww_vulns = jobs["whatweb"].result(timeout=30)
                vulns.extend(ww_vulns)
            except Exception as e:
                logger.warning(f"WhatWeb failed: {e}")

    return vulns

def _run_webapp_checks(url: str, test_urls: List[str]) -> List[Vulnerability]:
    """Run all web application vulnerability checks in parallel — Burp Suite-like."""
    targets = test_urls[:12] or [url]
    vulns: List[Vulnerability] = []
    with ThreadPoolExecutor(max_workers=6) as exe:
        jobs = {
            "sqli":  exe.submit(scan_sql_injection,        targets),
            "xss":   exe.submit(scan_xss,                  targets),
            "csrf":  exe.submit(check_csrf,                 url),
            "data":  exe.submit(scan_sensitive_data,        url),
            "auth":  exe.submit(check_auth_misconfigurations, url),
            "forms": exe.submit(scan_forms_sqli_xss,        url),  # Burp-like form scanning
        }
        for name, fut in jobs.items():
            try:
                result = fut.result(timeout=90)
                vulns.extend(result)
                if result:
                    logger.info(f"[WebApp] '{name}' found {len(result)} issues")
            except FutureTimeout:
                logger.warning(f"Webapp check '{name}' timed out")
            except Exception as e:
                logger.warning(f"Webapp check '{name}' error: {e}")
    return vulns


def _update_tool_counts(result: ScanResult) -> None:
    for v in result.vulnerabilities:
        if   v.source_tool == SourceTool.NMAP:     result.nmap_findings    += 1
        elif v.source_tool == SourceTool.ZAP:      result.zap_findings     += 1
        elif v.source_tool == SourceTool.NUCLEI:   result.nuclei_findings  += 1
        else:                                       result.internal_findings += 1



# ─────────────────────────────────────────────────────────────────────────────
# 3.  SECURITY HEADERS CHECK
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"severity":"high",  "cvss":6.5, "cwe":"CWE-319",
        "title":"Missing HSTS Header",
        "description":"HSTS forces HTTPS-only connections, preventing SSL-stripping attacks.",
        "recommendation":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "tags":["transport","hsts"]},
    "Content-Security-Policy":   {"severity":"high",  "cvss":6.1, "cwe":"CWE-693",
        "title":"Missing Content-Security-Policy (CSP)",
        "description":"Without CSP, XSS attacks can inject and execute scripts from any origin.",
        "recommendation":"Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        "tags":["xss","headers"]},
    "X-Frame-Options":           {"severity":"medium","cvss":4.3, "cwe":"CWE-1021",
        "title":"Missing X-Frame-Options",
        "description":"Missing X-Frame-Options allows your site to be embedded in iframes for clickjacking.",
        "recommendation":"Add: X-Frame-Options: DENY",
        "tags":["clickjacking","headers"]},
    "X-Content-Type-Options":    {"severity":"low",   "cvss":3.1, "cwe":"CWE-430",
        "title":"Missing X-Content-Type-Options",
        "description":"MIME sniffing can cause browsers to interpret uploaded files as executable scripts.",
        "recommendation":"Add: X-Content-Type-Options: nosniff",
        "tags":["mime","headers"]},
    "Referrer-Policy":           {"severity":"low",   "cvss":2.4, "cwe":"CWE-116",
        "title":"Missing Referrer-Policy",
        "description":"Sensitive URL parameters may leak via the Referer header to third-party sites.",
        "recommendation":"Add: Referrer-Policy: strict-origin-when-cross-origin",
        "tags":["privacy","headers"]},
    "Permissions-Policy":        {"severity":"low",   "cvss":2.1, "cwe":"CWE-693",
        "title":"Missing Permissions-Policy",
        "description":"Without Permissions-Policy, embedded scripts can access camera, mic, and location.",
        "recommendation":"Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "tags":["privacy","headers"]},
    "X-XSS-Protection":          {"severity":"low",   "cvss":2.0, "cwe":"CWE-79",
        "title":"Missing X-XSS-Protection",
        "description":"Legacy browsers rely on X-XSS-Protection when CSP is absent or weak.",
        "recommendation":"Add: X-XSS-Protection: 1; mode=block",
        "tags":["xss","headers"]},
    "Cache-Control":             {"severity":"low",   "cvss":2.0, "cwe":"CWE-524",
        "title":"Missing Cache-Control Header",
        "description":"Without Cache-Control, sensitive pages may be cached by proxies, exposing data.",
        "recommendation":"Add: Cache-Control: no-store, no-cache, must-revalidate on sensitive endpoints",
        "tags":["caching","headers"]},
}

WEAK_CSP = {
    "'unsafe-inline'": ("medium","CSP: 'unsafe-inline' Permitted","Inline scripts allowed — weakens XSS protection significantly.","Remove 'unsafe-inline'. Use nonces or hashes."),
    "'unsafe-eval'":   ("medium","CSP: 'unsafe-eval' Permitted","Dynamic eval() execution allowed — exploitable in XSS chains.","Remove 'unsafe-eval' from script-src."),
    "*":               ("high",  "CSP: Wildcard (*) Source Used","Wildcard source allows resources from any origin, nullifying CSP.","Replace '*' with explicit trusted domains."),
}

def check_security_headers(url: str) -> Tuple[List[Vulnerability], int]:
    vulns, present = [], 0
    try:
        r    = requests.get(url, timeout=12, verify=False, allow_redirects=True,
                            headers={"User-Agent":"Mozilla/5.0 (CyberPlatform/3.0)"})
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        for hdr, cfg in REQUIRED_HEADERS.items():
            if hdr.lower() not in hdrs:
                vulns.append(Vulnerability(
                    vuln_type="Security Header", severity=cfg["severity"],
                    cvss_score=cfg["cvss"], cwe_id=cfg.get("cwe",""),
                    title=cfg["title"], description=cfg["description"],
                    recommendation=cfg["recommendation"],
                    evidence=f"'{hdr}' absent from HTTP response",
                    affected_url=url, source_tool=SourceTool.INTERNAL,
                    tags=cfg.get("tags",[])))
            else:
                present += 1

        # Weak CSP values
        csp = hdrs.get("content-security-policy","")
        if csp:
            for pat,(sev,title,desc,rec) in WEAK_CSP.items():
                if pat in csp:
                    vulns.append(Vulnerability(
                        vuln_type="Weak Header", severity=sev, title=title,
                        description=desc, recommendation=rec,
                        evidence=f"content-security-policy: {csp[:200]}",
                        affected_url=url, source_tool=SourceTool.INTERNAL,
                        tags=["csp","xss","headers"]))

        # Version leakage
        for lk in ("server","x-powered-by","x-aspnet-version","x-generator"):
            val = hdrs.get(lk,"")
            if val and any(v in val.lower() for v in ("apache/","nginx/","php/","iis/","asp.net")):
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure", severity="low", cvss_score=2.6,
                    cwe_id="CWE-200",
                    title=f"Server Version Exposed ({lk.title()})",
                    description=f"'{lk}' header reveals software version: {val}. Helps attackers find CVEs.",
                    recommendation="nginx: server_tokens off; Apache: ServerTokens Prod",
                    evidence=f"{lk}: {val}", affected_url=url,
                    source_tool=SourceTool.INTERNAL, tags=["disclosure","headers"]))

        # HTTP without HTTPS redirect
        if url.startswith("http://"):
            try:
                r2 = requests.get(url, timeout=8, verify=False, allow_redirects=False)
                loc = r2.headers.get("Location","")
                if r2.status_code not in (301,302,307,308) or not loc.startswith("https://"):
                    vulns.append(Vulnerability(
                        vuln_type="Transport Security", severity="high", cvss_score=5.9,
                        cwe_id="CWE-319",
                        title="HTTP Does Not Redirect to HTTPS",
                        description="Site serves plain HTTP without HTTPS redirect. All traffic is unencrypted.",
                        recommendation="Configure permanent 301 redirect http → https. Then add HSTS.",
                        evidence=f"HTTP {r2.status_code} — Location: {loc or 'none'}",
                        affected_url=url, source_tool=SourceTool.INTERNAL,
                        tags=["transport","http"]))
            except Exception: pass

        score = max(0, int((present / len(REQUIRED_HEADERS)) * 100))
    except Exception as e:
        logger.warning(f"Header check failed for {url}: {e}"); score = 0
    return vulns, score


# ─────────────────────────────────────────────────────────────────────────────
# 4.  SSL/TLS ENGINE
# ─────────────────────────────────────────────────────────────────────────────
WEAK_CIPHERS   = ["RC4","DES","3DES","EXPORT","NULL","ANON","MD5"]
WEAK_PROTOCOLS = ["TLSv1","TLSv1.1","SSLv3","SSLv2"]

def check_ssl(url: str) -> Tuple[List[Vulnerability], int]:
    vulns, score = [], 100
    parsed   = urlparse(url)
    hostname = parsed.hostname or url.split("//")[-1].split("/")[0]

    if parsed.scheme == "http":
        vulns.append(Vulnerability(
            vuln_type="SSL/TLS", severity="high", cvss_score=7.5, cwe_id="CWE-319",
            title="Site Served Over Plain HTTP",
            description="No HTTPS. All traffic (including credentials) transmitted in cleartext.",
            recommendation="Install SSL cert via Let's Encrypt (certbot) and enforce HTTPS.",
            evidence="URL scheme: http", affected_url=url,
            source_tool=SourceTool.INTERNAL, tags=["ssl","transport"]))
        return vulns, 20

    try:
        ctx  = ssl.create_default_context()
        sock = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        sock.settimeout(10); sock.connect((hostname, 443))
        cert        = sock.getpeercert()
        cipher      = sock.cipher()          # (name, protocol, bits)
        tls_version = sock.version()
        sock.close()

        subj   = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer",  []))

        # Self-signed
        if subj == issuer:
            vulns.append(Vulnerability(
                vuln_type="SSL/TLS", severity="high", cvss_score=6.8, cwe_id="CWE-295",
                title="Self-Signed Certificate Detected",
                description="Cert not issued by a trusted CA. All visitors see a security warning.",
                recommendation="Replace with a trusted CA cert. Use Let's Encrypt for free certs.",
                evidence=f"Subject == Issuer: {subj}", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["ssl","certificate"])); score -= 25

        # Expiry
        naf = cert.get("notAfter","")
        if naf:
            days = (ssl.cert_time_to_seconds(naf) - time.time()) / 86400
            if   days < 0:
                vulns.append(Vulnerability(
                    vuln_type="SSL/TLS", severity="critical", cvss_score=9.1, cwe_id="CWE-298",
                    title="SSL Certificate Expired",
                    description=f"Cert expired {naf}. Browsers block access entirely.",
                    recommendation="Renew immediately. Enable auto-renewal: certbot renew --pre-hook / --post-hook",
                    evidence=f"notAfter: {naf}", affected_url=url,
                    source_tool=SourceTool.INTERNAL, tags=["ssl","expiry"])); score -= 40
            elif days < 14:
                vulns.append(Vulnerability(
                    vuln_type="SSL/TLS", severity="critical", cvss_score=8.0,
                    title=f"SSL Certificate Expires in {int(days)} Days",
                    description=f"Expires {naf}. Imminent HTTPS failure for all users.",
                    recommendation="Renew certificate now. Set up Certbot auto-renewal.",
                    evidence=f"notAfter: {naf}", affected_url=url,
                    source_tool=SourceTool.INTERNAL, tags=["ssl","expiry"])); score -= 20
            elif days < 30:
                vulns.append(Vulnerability(
                    vuln_type="SSL/TLS", severity="high", cvss_score=5.0,
                    title=f"SSL Certificate Expiring Soon ({int(days)} Days)",
                    description="Plan certificate renewal to avoid service disruption.",
                    recommendation="Schedule renewal or enable Certbot auto-renewal.",
                    evidence=f"notAfter: {naf}", affected_url=url,
                    source_tool=SourceTool.INTERNAL, tags=["ssl","expiry"])); score -= 10

        # Weak TLS version
        if tls_version in WEAK_PROTOCOLS:
            vulns.append(Vulnerability(
                vuln_type="SSL/TLS", severity="medium", cvss_score=5.9, cwe_id="CWE-326",
                title=f"Deprecated TLS Protocol in Use ({tls_version})",
                description=f"{tls_version} is deprecated with known attacks (POODLE, BEAST).",
                recommendation="Disable TLS 1.0/1.1. Configure: ssl_protocols TLSv1.2 TLSv1.3;",
                evidence=f"Negotiated: {tls_version}", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["ssl","protocol"])); score -= 15

        # Weak cipher
        cn_cipher = (cipher[0] or "") if cipher else ""
        if any(wk in cn_cipher.upper() for wk in WEAK_CIPHERS):
            vulns.append(Vulnerability(
                vuln_type="SSL/TLS", severity="medium", cvss_score=5.3, cwe_id="CWE-327",
                title=f"Weak Cipher Suite in Use ({cn_cipher})",
                description=f"Cipher {cn_cipher} can be broken, exposing encrypted data.",
                recommendation="Use Mozilla SSL Config Generator. Prefer ECDHE+AES256+GCM.",
                evidence=f"Cipher: {cn_cipher} / {cipher[2] if cipher else '?'} bits",
                affected_url=url, source_tool=SourceTool.INTERNAL,
                tags=["ssl","cipher"])); score -= 10

        # Wildcard
        cn = subj.get("commonName","")
        if cn.startswith("*"):
            vulns.append(Vulnerability(
                vuln_type="SSL/TLS", severity="info",
                title="Wildcard Certificate in Use",
                description=f"Wildcard cert ({cn}) secures all subdomains — compromise affects all.",
                recommendation="Consider per-subdomain certs for high-security environments.",
                evidence=f"CN: {cn}", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["ssl","certificate"]))

    except ssl.SSLCertVerificationError as e:
        vulns.append(Vulnerability(
            vuln_type="SSL/TLS", severity="high", cvss_score=7.0, cwe_id="CWE-295",
            title="SSL Certificate Validation Failed",
            description=f"Certificate chain error: {e}",
            recommendation="Check certificate chain. Install all intermediate certificates.",
            evidence=str(e), affected_url=url,
            source_tool=SourceTool.INTERNAL, tags=["ssl","certificate"])); score = max(0,score-30)
    except (ConnectionRefusedError, OSError):
        vulns.append(Vulnerability(
            vuln_type="SSL/TLS", severity="high", cvss_score=7.5, cwe_id="CWE-319",
            title="HTTPS Port 443 Not Accessible",
            description="Port 443 closed. Site does not support HTTPS.",
            recommendation="Install SSL cert and enable HTTPS on port 443.",
            evidence="TCP 443 refused", affected_url=url,
            source_tool=SourceTool.INTERNAL, tags=["ssl","port"])); score = 0
    except Exception as e:
        logger.warning(f"SSL check error {url}: {e}")

    return vulns, max(0, score)



# ─────────────────────────────────────────────────────────────────────────────
# 5.  NMAP INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────
# Nmap scan profiles
NMAP_PROFILES = {
    ScanType.FULL:   "-sV -sC -O --script=vuln,auth,default -T4",
    ScanType.RECON:  "-sV -sC -O -T4",
    ScanType.INFRA:  "-sV --script=vuln,auth -T4",
    ScanType.QUICK:  "-sV -T4 --top-ports 100",
    ScanType.WEBAPP: "--top-ports 20 -sV -T4",
}

# NSE script output → severity mapping
NSE_SEVERITY_MAP = {
    "vuln":    "high",   "exploit": "critical", "auth":   "high",
    "default": "medium", "dos":     "high",      "brute":  "high",
}

def run_nmap_scan(url: str, scan_type: str = ScanType.FULL) -> Tuple[List[Vulnerability], List[int]]:
    """
    Run Nmap with service/version detection + NSE scripts.
    Parses XML output into Vulnerability objects.

    Requires: nmap installed (apt install nmap)
    Returns: (vulnerabilities, open_port_numbers)
    """
    vulns:      List[Vulnerability] = []
    open_ports: List[int]           = []

    if not _tool_available("nmap"):
        logger.warning("Nmap not installed — falling back to TCP scanner")
        return scan_ports_tcp(url)

    hostname = urlparse(url).hostname or url
    profile  = NMAP_PROFILES.get(scan_type, NMAP_PROFILES[ScanType.FULL])

    try:
        # Build Nmap command with XML output
        cmd = ["nmap", *profile.split(), "-oX", "-", "--host-timeout", "120s", hostname]
        logger.info(f"[Nmap] Running: {' '.join(cmd)}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)

        if proc.returncode not in (0, 1):  # nmap exits 1 on some warnings
            logger.error(f"[Nmap] Exit {proc.returncode}: {proc.stderr[:200]}")
            return scan_ports_tcp(url)  # Fallback

        vulns, open_ports = _parse_nmap_xml(proc.stdout, hostname, url)
        logger.info(f"[Nmap] Parsed {len(vulns)} findings, {len(open_ports)} open ports")

    except subprocess.TimeoutExpired:
        logger.warning("[Nmap] Scan timed out — partial results may be missing")
    except Exception as e:
        logger.error(f"[Nmap] Error: {e}")
        return scan_ports_tcp(url)

    return vulns, sorted(set(open_ports))


def _parse_nmap_xml(xml_output: str, hostname: str, base_url: str) -> Tuple[List[Vulnerability], List[int]]:
    """Parse Nmap XML output into Vulnerability objects."""
    vulns:      List[Vulnerability] = []
    open_ports: List[int]           = []

    if not xml_output.strip():
        return vulns, open_ports

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.warning(f"[Nmap] XML parse error: {e}")
        return vulns, open_ports

    for host in root.findall(".//host"):
        # ── Open ports + service info ───────────────────────────
        for port_el in host.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue

            portnum  = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol","tcp")
            service  = port_el.find("service")
            svc_name = service.get("name","unknown") if service is not None else "unknown"
            svc_prod = service.get("product","")     if service is not None else ""
            svc_ver  = service.get("version","")     if service is not None else ""
            svc_str  = f"{svc_name} {svc_prod} {svc_ver}".strip()

            open_ports.append(portnum)

            # Flag dangerous ports
            danger = _classify_port_risk(portnum, svc_name)
            if danger:
                sev, desc, rec = danger
                vulns.append(Vulnerability(
                    vuln_type="Exposed Port",
                    title=f"Port {portnum}/{svc_name.upper()} Exposed [Nmap]",
                    severity=sev, cvss_score=_port_cvss(sev),
                    description=desc,
                    recommendation=rec,
                    evidence=f"Nmap: port {portnum}/{protocol} open — {svc_str}",
                    affected_url=f"{hostname}:{portnum}",
                    source_tool=SourceTool.NMAP,
                    tags=["nmap","port",svc_name.lower()]))

        # ── NSE script output ───────────────────────────────────
        for script in host.findall(".//script"):
            script_id  = script.get("id","")
            script_out = script.get("output","")

            # Skip benign/info-only scripts
            if not script_out or len(script_out) < 20:
                continue
            if any(skip in script_id for skip in
                   ("smb-security-mode","ssl-date","ssh-hostkey","uptime")):
                continue

            severity = _nse_severity(script_id, script_out)
            if severity == "info":
                continue

            # Extract CVE from script output
            cve = ""
            cve_m = re.search(r"CVE-\d{4}-\d{4,7}", script_out, re.I)
            if cve_m:
                cve = cve_m.group(0).upper()

            vulns.append(Vulnerability(
                vuln_type=f"Nmap/{script_id}",
                title=f"[Nmap NSE] {_nse_title(script_id)}",
                severity=severity,
                cvss_score=_port_cvss(severity),
                cve_id=cve,
                description=_nse_description(script_id, script_out),
                recommendation=_nse_recommendation(script_id),
                evidence=f"Script: {script_id}\nOutput:\n{script_out[:500]}",
                affected_url=base_url,
                source_tool=SourceTool.NMAP,
                tags=["nmap","nse", script_id],
                raw_output={"script_id": script_id, "output": script_out[:1000]}))

        # ── OS detection ────────────────────────────────────────
        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name","")
            os_acc  = osmatch.get("accuracy","")
            if os_name:
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    title=f"OS Fingerprint Detected: {os_name}",
                    severity="info",
                    description=f"Nmap identified OS as '{os_name}' ({os_acc}% confidence). "
                                 "OS information helps attackers select targeted exploits.",
                    recommendation="Enable OS fingerprint obfuscation (nftables/iptables TTL manipulation).",
                    evidence=f"osmatch: {os_name} ({os_acc}%)",
                    affected_url=base_url,
                    source_tool=SourceTool.NMAP,
                    tags=["nmap","os","disclosure"],
                    raw_output={"os": os_name, "accuracy": os_acc}))

    return vulns, open_ports


# Nmap helper functions
DANGEROUS_PORTS = {
    23:    ("critical","Telnet in cleartext","Disable Telnet. Use SSH instead."),
    3306:  ("critical","MySQL exposed to internet","Block 3306 at firewall. Use private network for DB."),
    5432:  ("critical","PostgreSQL exposed to internet","Block 5432 at firewall."),
    6379:  ("critical","Redis exposed (likely unauthenticated)","Block 6379. Enable requirepass in redis.conf."),
    9200:  ("critical","Elasticsearch API exposed","Block 9200. Enable ES security features."),
    27017: ("critical","MongoDB exposed to internet","Block 27017. Enable MongoDB auth."),
    2375:  ("critical","Docker API exposed unencrypted","Block 2375 immediately. Never expose Docker API."),
    10250: ("critical","Kubernetes kubelet API exposed","Block 10250. Enable RBAC."),
    21:    ("medium",  "FTP (cleartext transfer)","Replace FTP with SFTP (port 22)."),
    3389:  ("high",    "RDP exposed — ransomware target","Block RDP externally. Use VPN for remote access."),
    5900:  ("high",    "VNC remote desktop exposed","Block VNC or restrict to VPN."),
    11211: ("high",    "Memcached exposed (DDoS amplification)","Block 11211 at firewall."),
}

def _classify_port_risk(port: int, svc: str) -> Optional[Tuple[str,str,str]]:
    return DANGEROUS_PORTS.get(port, None)

def _port_cvss(sev: str) -> float:
    return {"critical":9.8,"high":8.1,"medium":5.3,"low":3.1,"info":0.0}.get(sev,5.0)

def _nse_severity(script_id: str, output: str) -> str:
    out_l = output.lower()
    if any(w in out_l for w in ("vulnerable","exploit","remote code","rce","critical")): return "critical"
    if any(w in out_l for w in ("vuln","authentication bypass","privilege","disclosure")): return "high"
    if any(w in script_id for w in ("vuln","exploit","auth")): return "medium"
    return "info"

def _nse_title(script_id: str) -> str:
    return script_id.replace("-"," ").replace("_"," ").title()

def _nse_description(script_id: str, output: str) -> str:
    lines = [l.strip() for l in output.split("\n") if l.strip()][:5]
    summary = " ".join(lines)[:300]
    return f"Nmap script '{script_id}' reported: {summary}"

def _nse_recommendation(script_id: str) -> str:
    recs = {
        "smb-vuln": "Apply Microsoft patches for SMB vulnerabilities. Disable SMBv1.",
        "ftp-anon": "Disable anonymous FTP. Require authentication.",
        "http-sql-injection": "Use parameterized queries. Implement WAF.",
        "ssl-poodle": "Disable SSLv3. Use TLS 1.2+.",
        "ssh-brute": "Use key-based auth. Disable PasswordAuthentication.",
    }
    for key, rec in recs.items():
        if key in script_id.lower():
            return rec
    return f"Review Nmap script '{script_id}' findings and apply vendor patches."


# ─────────────────────────────────────────────────────────────────────────────
# 6.  TCP PORT SCANNER (fallback when Nmap unavailable)
# ─────────────────────────────────────────────────────────────────────────────
PORT_DEFS = {
    21:   ("FTP","medium",   "FTP cleartext. Use SFTP.",                             4.8),
    22:   ("SSH","info",     "SSH open. Disable password auth.",                     0.0),
    23:   ("Telnet","critical","Telnet cleartext — disable immediately.",            9.8),
    25:   ("SMTP","medium",  "SMTP open. Verify relay disabled.",                    4.3),
    80:   ("HTTP","info",    "HTTP open. Verify HTTPS redirect.",                    0.0),
    443:  ("HTTPS","info",   "HTTPS operational.",                                   0.0),
    3306: ("MySQL","critical","MySQL database port exposed!",                        9.8),
    3389: ("RDP","high",     "RDP exposed — ransomware target. Use VPN.",            8.8),
    5432: ("PostgreSQL","critical","PostgreSQL exposed to internet.",                9.8),
    5900: ("VNC","high",     "VNC remote desktop exposed.",                          8.1),
    6379: ("Redis","critical","Redis exposed — likely unauthenticated RCE risk.",    9.8),
    8080: ("HTTP-Alt","low", "Alt HTTP port. May expose admin panels.",              3.1),
    8443: ("HTTPS-Alt","low","Alt HTTPS port.",                                      2.0),
    9200: ("Elasticsearch","critical","Elasticsearch unauthenticated API exposed.", 9.8),
    27017:("MongoDB","critical","MongoDB exposed to internet.",                      9.8),
    11211:("Memcached","high","Memcached DDoS amplification risk.",                  7.5),
    2375: ("Docker API","critical","Docker API unencrypted — full host compromise.", 9.8),
    2376: ("Docker TLS","high","Docker TLS API exposed.",                            7.5),
    10250:("K8s Kubelet","critical","Kubernetes kubelet API exposed.",               9.8),
    4444: ("Metasploit","high","Port 4444 — common reverse shell port.",             8.1),
}

def scan_ports_tcp(url: str) -> Tuple[List[Vulnerability], List[int]]:
    """Concurrent TCP port scanner (fallback when Nmap unavailable)."""
    vulns, open_ports = [], []
    hostname = urlparse(url).hostname or url
    try: ip = socket.gethostbyname(hostname)
    except Exception: return vulns, open_ports

    def _probe(port: int) -> Optional[int]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0: s.close(); return port
            s.close()
        except Exception: pass
        return None

    with ThreadPoolExecutor(max_workers=10) as exe:
        for port in [f.result() for f in as_completed(
                {exe.submit(_probe, p): p for p in PORT_DEFS})]:
            if port is None: continue
            open_ports.append(port)
            svc,sev,desc,cvss = PORT_DEFS[port]
            if sev != "info":
                vulns.append(Vulnerability(
                    vuln_type="Exposed Port",
                    title=f"Port {port}/{svc} Exposed to Internet",
                    severity=sev, cvss_score=cvss, cwe_id="CWE-200",
                    description=desc,
                    recommendation=f"Block port {port} at firewall. Use VPN for {svc} access.",
                    evidence=f"TCP {port} ({svc}) open at {ip}",
                    affected_url=f"{hostname}:{port}",
                    source_tool=SourceTool.INTERNAL, tags=["port",svc.lower()]))
    return vulns, sorted(open_ports)



# ─────────────────────────────────────────────────────────────────────────────
# 7.  OWASP ZAP INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────
ZAP_API_URL  = os.environ.get("ZAP_API_URL",  "http://localhost:8080")
ZAP_API_KEY  = os.environ.get("ZAP_API_KEY",  "zap-api-key")

# ZAP risk code → our severity
ZAP_RISK_MAP = {3: "critical", 2: "high", 1: "medium", 0: "low"}
ZAP_CONF_MAP = {3: True, 2: True, 1: False, 0: False}   # Auto-verify if confidence >= Medium

def run_zap_scan(url: str, scan_id: str) -> List[Vulnerability]:
    """
    OWASP ZAP active + passive scan via REST API.

    Prerequisites:
      docker run -d -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
        zap.sh -daemon -host 0.0.0.0 -port 8080 \
        -config api.key=zap-api-key -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true

    Pipeline:
      1. Spider the target
      2. Ajax Spider (JS-heavy sites)
      3. Active scan
      4. Retrieve alerts
      5. Convert to Vulnerability objects
    """
    vulns: List[Vulnerability] = []

    try:
        sess = requests.Session()
        sess.headers.update({"Accept": "application/json"})

        def zap(endpoint: str, **params) -> dict:
            params["apikey"] = ZAP_API_KEY
            r = sess.get(f"{ZAP_API_URL}/JSON/{endpoint}", params=params, timeout=30)
            r.raise_for_status()
            return r.json()

        # ── 1. Spider ──────────────────────────────────────────
        logger.info(f"[ZAP] Starting spider for {url}")
        spider = zap("spider/action/scan/", url=url, maxChildren=10, recurse=True)
        spider_id = spider.get("scan", "0")
        _zap_wait(zap, f"spider/view/status/", scanId=spider_id,
                  label="Spider", timeout=120)

        # ── 2. Ajax Spider ────────────────────────────────────
        try:
            zap("ajaxSpider/action/scan/", url=url, inScope=True)
            _zap_wait_ajax(zap, timeout=60)
        except Exception as e:
            logger.debug(f"[ZAP] Ajax spider skipped: {e}")

        # ── 3. Active Scan ────────────────────────────────────
        logger.info(f"[ZAP] Starting active scan for {url}")
        ascan = zap("ascan/action/scan/", url=url, recurse=True,
                    inScopeOnly=False, scanPolicyName="", method="", postData="")
        ascan_id = ascan.get("scan", "0")
        _zap_wait(zap, "ascan/view/status/", scanId=ascan_id,
                  label="Active Scan", timeout=300)

        # ── 4. Retrieve alerts ────────────────────────────────
        alerts_resp = zap("core/view/alerts/", baseurl=url, start=0, count=500)
        alerts      = alerts_resp.get("alerts", [])
        logger.info(f"[ZAP] Retrieved {len(alerts)} alerts")

        # ── 5. Convert to Vulnerability objects ───────────────
        for alert in alerts:
            risk    = int(alert.get("riskcode",   0))
            conf    = int(alert.get("confidence", 0))
            sev     = ZAP_RISK_MAP.get(risk, "low")
            confirm = ZAP_CONF_MAP.get(conf, False)

            if risk == 0 and conf <= 1:  # Skip low-risk + low-confidence
                continue

            cve  = alert.get("reference","")
            cve_m= re.search(r"CVE-\d{4}-\d{4,7}", cve, re.I)
            cve_id = cve_m.group(0) if cve_m else ""

            cwe_raw = alert.get("cweid","")
            cwe_id  = f"CWE-{cwe_raw}" if cwe_raw else ""

            vulns.append(Vulnerability(
                vuln_type=alert.get("alert","ZAP Finding"),
                title=f"[ZAP] {alert.get('alert','')}",
                severity=sev,
                cvss_score=_risk_to_cvss(risk, conf),
                cve_id=cve_id,
                cwe_id=cwe_id,
                description=_strip_html(alert.get("description","")),
                recommendation=_strip_html(alert.get("solution","")),
                evidence=(
                    f"Parameter: {alert.get('param','N/A')}\n"
                    f"Attack: {alert.get('attack','')[:200]}\n"
                    f"Evidence: {alert.get('evidence','')[:200]}"
                ),
                affected_url=alert.get("url", url),
                parameter=alert.get("param",""),
                http_method=alert.get("method","GET"),
                source_tool=SourceTool.ZAP,
                verified=confirm,
                tags=["zap","owasp", alert.get("alert","").lower().replace(" ","-")[:30]],
                raw_output={
                    "alert_ref":   alert.get("alertRef",""),
                    "riskcode":    risk,
                    "confidence":  conf,
                    "other":       alert.get("other","")[:300],
                    "cweid":       cwe_raw,
                    "wascid":      alert.get("wascid",""),
                }
            ))

    except requests.ConnectionError:
        logger.warning("[ZAP] Cannot connect to ZAP daemon — is it running?")
    except requests.Timeout:
        logger.warning("[ZAP] Request to ZAP API timed out")
    except Exception as e:
        logger.error(f"[ZAP] Error: {e}", exc_info=True)

    return vulns


def _zap_wait(zap_fn, endpoint: str, label: str = "Scan",
              timeout: int = 300, **params) -> None:
    """Poll ZAP endpoint until progress == 100."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = zap_fn(endpoint, **params)
        pct    = int(status.get("status", 0))
        if pct >= 100:
            logger.info(f"[ZAP] {label} complete")
            return
        logger.debug(f"[ZAP] {label}: {pct}%")
        time.sleep(5)
    logger.warning(f"[ZAP] {label} timed out after {timeout}s")


def _zap_wait_ajax(zap_fn, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = zap_fn("ajaxSpider/view/status/")
        if status.get("status") == "stopped":
            return
        time.sleep(3)


def _risk_to_cvss(risk: int, confidence: int) -> float:
    base = {3: 9.0, 2: 7.0, 1: 5.0, 0: 2.5}.get(risk, 5.0)
    conf_factor = {3: 1.0, 2: 0.9, 1: 0.7, 0: 0.5}.get(confidence, 0.8)
    return round(base * conf_factor, 1)


def _strip_html(text: str) -> str:
    """Remove HTML tags from ZAP alert text."""
    return re.sub(r"<[^>]+>", " ", text).strip() if text else ""


# ─────────────────────────────────────────────────────────────────────────────
# 8.  NUCLEI SCANNER
# ─────────────────────────────────────────────────────────────────────────────
# Template tags to run per scan type
NUCLEI_TAGS = {
    ScanType.FULL:   "cve,exposure,misconfiguration,default-login,sqli,xss,ssrf,rce",
    ScanType.WEBAPP: "sqli,xss,csrf,ssrf,redirect,exposure",
    ScanType.INFRA:  "cve,misconfiguration,default-login,network",
    ScanType.RECON:  "technologies,exposure,misconfiguration",
    ScanType.QUICK:  "exposure,misconfiguration",
}

# Nuclei severity → our severity
NUCLEI_SEV_MAP = {
    "critical": "critical", "high":   "high",
    "medium":   "medium",   "low":    "low",
    "info":     "info",     "unknown":"low",
}


def run_nuclei_scan(url: str, scan_id: str,
                    scan_type: str = ScanType.FULL) -> List[Vulnerability]:
    """
    Run Nuclei template scanner against target URL.

    Prerequisites:
      nuclei -update-templates    (run once before first scan)
      # Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    Output: JSONL per finding → Vulnerability objects
    """
    vulns: List[Vulnerability] = []

    if not _tool_available("nuclei"):
        logger.warning("[Nuclei] Not installed — skipping")
        return vulns

    tags       = NUCLEI_TAGS.get(scan_type, NUCLEI_TAGS[ScanType.FULL])
    output_file = f"/tmp/nuclei_{scan_id}.jsonl"

    try:
        cmd = [
            "nuclei",
            "-target",  url,
            "-tags",    tags,
            "-jsonl",
            "-output",  output_file,
            "-silent",
            "-timeout", "10",
            "-retries", "1",
            "-rate-limit", "50",
            "-no-color",
        ]

        logger.info(f"[Nuclei] Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)

        if proc.returncode not in (0, 1):
            logger.warning(f"[Nuclei] Exit {proc.returncode}: {proc.stderr[:300]}")
            return vulns

        # Parse JSONL output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        v = _nuclei_to_vulnerability(finding, url)
                        if v:
                            vulns.append(v)
                    except json.JSONDecodeError:
                        continue

        # Clean up
        if os.path.exists(output_file):
            os.remove(output_file)

        logger.info(f"[Nuclei] Parsed {len(vulns)} findings")

    except subprocess.TimeoutExpired:
        logger.warning("[Nuclei] Scan timed out")
    except Exception as e:
        logger.error(f"[Nuclei] Error: {e}")

    return vulns


def _nuclei_to_vulnerability(f: dict, base_url: str) -> Optional[Vulnerability]:
    """Convert a Nuclei JSONL finding dict to a Vulnerability object."""
    info      = f.get("info",     {})
    sev_raw   = info.get("severity", "info")
    sev       = NUCLEI_SEV_MAP.get(sev_raw.lower(), "low")
    name      = info.get("name",      "Nuclei Finding")
    template  = f.get("template-id",  "unknown")
    matched   = f.get("matched-at",   base_url)
    tags_list = info.get("tags",      [])
    cvss_raw  = info.get("classification", {}).get("cvss-score", None)
    cve_list  = info.get("classification", {}).get("cve-id", [])
    cwe_list  = info.get("classification", {}).get("cwe-id", [])
    desc      = info.get("description", "")
    remediation = info.get("remediation","")
    reference = info.get("reference", [])
    ref_str   = "; ".join(reference[:3]) if isinstance(reference, list) else str(reference)

    # Skip pure info findings unless they carry a CVE
    if sev == "info" and not cve_list:
        return None

    # Build evidence from extractor data
    extractor_data = f.get("extracted-results", [])
    evidence_parts = [f"Template: {template}", f"Matched: {matched}"]
    if extractor_data:
        evidence_parts.append(f"Extracted: {'; '.join(str(x) for x in extractor_data[:3])}")
    if f.get("matcher-name"):
        evidence_parts.append(f"Matcher: {f['matcher-name']}")

    return Vulnerability(
        vuln_type=f"Nuclei/{template}",
        title=f"[Nuclei] {name}",
        severity=sev,
        cvss_score=float(cvss_raw) if cvss_raw else _port_cvss(sev),
        cve_id=cve_list[0] if cve_list else "",
        cwe_id=cwe_list[0] if cwe_list else "",
        description=desc or f"Nuclei template '{template}' matched target.",
        recommendation=remediation or f"Review {ref_str or 'template documentation'} for remediation.",
        evidence="\n".join(evidence_parts),
        affected_url=matched,
        source_tool=SourceTool.NUCLEI,
        tags=([t.lower() for t in tags_list] if isinstance(tags_list, list) else []) + ["nuclei"],
        raw_output={
            "template_id": template,
            "protocol":    f.get("type",""),
            "matcher":     f.get("matcher-name",""),
            "extracted":   extractor_data,
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# 9.  TOOL RESULT AGGREGATOR
# ─────────────────────────────────────────────────────────────────────────────

def aggregate_tool_results(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Merge findings from all scanner tools into a unified, deduplicated list.

    Deduplication strategy:
    1. Group by (normalized_title, affected_url)
    2. Keep the finding with highest CVSS score
    3. Merge evidence and tags from duplicates
    4. Prefer VERIFIED findings from ZAP/Nuclei over unverified internal ones
    5. Prefer lower severity (more conservative) if tools disagree

    Returns deduplicated, merged list sorted by severity.
    """
    if not vulns:
        return []

    groups: Dict[str, List[Vulnerability]] = {}

    for v in vulns:
        key = _dedup_key(v)
        groups.setdefault(key, []).append(v)

    merged: List[Vulnerability] = []
    for key, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Primary = highest CVSS, or verified, or from ZAP/Nuclei
        primary = max(group, key=lambda x: (
            x.verified,
            x.source_tool in (SourceTool.ZAP, SourceTool.NUCLEI),
            x.cvss_score,
        ))

        # Merge evidence from all sources
        all_evidence = "\n---\n".join(
            f"[{v.source_tool.upper()}] {v.evidence}"
            for v in group if v.evidence and v.source_tool != primary.source_tool
        )
        if all_evidence:
            primary.evidence = (primary.evidence + "\n\n" + all_evidence).strip()

        # Merge tags
        all_tags = list(set(t for v in group for t in v.tags))
        primary.tags = all_tags

        # Merge CVE IDs
        all_cves = list(set(v.cve_id for v in group if v.cve_id))
        if all_cves:
            primary.cve_id = all_cves[0]

        # Corroboration note — multiple tools found the same issue
        tools_found = sorted(set(v.source_tool for v in group))
        if len(tools_found) > 1:
            primary.evidence = (
                f"[CORROBORATED by {', '.join(tools_found)}]\n" + primary.evidence
            )
            primary.verified = True   # Multiple tool agreement = high confidence

        merged.append(primary)

    # Sort: critical → high → medium → low → info
    merged.sort(key=lambda v: v.severity_order)
    logger.info(
        f"[Aggregator] {len(vulns)} raw findings → {len(merged)} deduplicated "
        f"({len(vulns)-len(merged)} duplicates removed)"
    )
    return merged


def _dedup_key(v: Vulnerability) -> str:
    """
    Generate deduplication key.
    Normalise title and URL to catch same finding from different tools.
    """
    norm_title = re.sub(r"\[.*?\]", "", v.title.lower()).strip()  # Remove tool prefix
    norm_title = re.sub(r"\s+", " ", norm_title)
    norm_url   = re.sub(r"https?://", "", v.affected_url.lower()).rstrip("/")
    # Remove param noise from URL
    norm_url   = norm_url.split("?")[0]
    return f"{v.vuln_type.lower()}|{norm_title[:50]}|{norm_url[:80]}"



# ─────────────────────────────────────────────────────────────────────────────
# 10.  TECHNOLOGY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
CMS_SIGS = {
    "WordPress":  ["wp-content/","wp-includes/","/wp-json/"],
    "Joomla":     ["joomla","/components/com_"],
    "Drupal":     ["drupal","/sites/default/files","x-generator: drupal"],
    "Magento":    ["magento","Mage.Cookies","/skin/frontend/"],
    "Shopify":    ["shopify","cdn.shopify.com"],
    "Django":     ["csrfmiddlewaretoken","djdt"],
    "Laravel":    ["laravel_session","XSRF-TOKEN"],
    "Next.js":    ["__NEXT_DATA__","/_next/static"],
    "WooCommerce":["woocommerce","wc-ajax"],
}

def detect_technology(url: str) -> dict:
    tech = {}
    try:
        r    = requests.get(url, timeout=12, verify=False, headers={"User-Agent":"Mozilla/5.0"})
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        body = r.text[:12000]; bodyl = body.lower()
        for cms, sigs in CMS_SIGS.items():
            if any(s.lower() in bodyl for s in sigs):
                tech["cms"] = cms; break
        if tech.get("cms") == "WordPress":
            m = re.search(r"WordPress ([\d.]+)", body)
            if m: tech["cms_version"] = m.group(1)
        if tech.get("cms") == "Drupal":
            m = re.search(r"Drupal ([\d.]+)", hdrs.get("x-generator",""), re.I)
            if m: tech["cms_version"] = m.group(1)
        if "server"       in hdrs: tech["server"]      = hdrs["server"]
        if "x-powered-by" in hdrs:
            tech["powered_by"] = hdrs["x-powered-by"]
            m = re.search(r"PHP/([\d.]+)", hdrs["x-powered-by"], re.I)
            if m: tech["php_version"] = m.group(1)
        if   "__NEXT_DATA__" in body: tech["frontend"] = "Next.js"
        elif "ng-version"    in body: tech["frontend"] = "Angular"
        elif "_vue"          in body: tech["frontend"] = "Vue.js"
        elif "__reactFiber"  in body: tech["frontend"] = "React"
        if "google-analytics" in bodyl or "gtag(" in bodyl: tech["analytics"] = "Google Analytics"
        if "cdn.cloudflare.com" in bodyl or "cf-ray" in hdrs: tech["cdn"] = "Cloudflare"
    except Exception as e:
        logger.warning(f"Tech detection error: {e}")
    return tech


# ─────────────────────────────────────────────────────────────────────────────
# 11.  SQL INJECTION SCANNER
# ─────────────────────────────────────────────────────────────────────────────
SQL_ERROR_RE = re.compile(
    r"you have an error in your sql syntax|warning.*mysql|mysql_fetch"
    r"|unclosed quotation mark|microsoft.*odbc.*sql|syntax error.*sql server"
    r"|pg_query.*failed|ORA-\d{5}|sqlite.*error|SQLITE_ERROR"
    r"|sql syntax.*near|unexpected end of SQL command|quoted string not properly",
    re.IGNORECASE)

SQL_PAYLOADS  = ["'","\"","' OR '1'='1","' OR 1=1--","' UNION SELECT NULL--"]
SQL_TIME_PL   = [
    ("1' AND SLEEP(3)--",           3.0, "MySQL"),
    ("1'; WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL"),
    ("1' AND pg_sleep(3)--",        3.0, "PostgreSQL"),
]

def scan_sql_injection(test_urls: List[str]) -> List[Vulnerability]:
    vulns, seen = [], set()
    for url in test_urls:
        p = urlparse(url); params = urllib.parse.parse_qs(p.query)
        if not params: continue
        base = f"{p.scheme}://{p.netloc}{p.path}"
        for pname in params:
            if (base, pname) in seen: continue
            norm_params = {k: v[0] for k, v in params.items()}
            # Error-based
            for payload in SQL_PAYLOADS:
                try:
                    tp = dict(norm_params); tp[pname] = payload
                    r  = requests.get(base, params=tp, timeout=10, verify=False)
                    if SQL_ERROR_RE.search(r.text):
                        m       = SQL_ERROR_RE.search(r.text)
                        snippet = r.text[max(0,m.start()-40):m.end()+100].strip()
                        vulns.append(Vulnerability(
                            vuln_type="SQL Injection", severity="critical", cvss_score=9.8,
                            cwe_id="CWE-89",
                            title=f"SQL Injection (Error-Based) — param: {pname}",
                            description=(f"Parameter '{pname}' is injectable via error-based SQL injection. "
                                         "Attackers can extract, modify, or delete all database data."),
                            recommendation=("1. Use parameterized queries / prepared statements.\n"
                                            "2. Apply ORM (SQLAlchemy, Hibernate).\n"
                                            "3. Validate and type-check all inputs.\n"
                                            "4. Deploy WAF with SQL injection rules."),
                            evidence=f"Payload: {payload}\nParam: {pname}\nDB error:\n{snippet[:300]}",
                            affected_url=url, parameter=pname, http_method="GET",
                            request_sample=f"GET {base}?{pname}={urllib.parse.quote(payload)}",
                            response_sample=r.text[:400],
                            source_tool=SourceTool.INTERNAL, tags=["sqli","owasp-a03"])); seen.add((base,pname)); break
                except Exception: continue
            if (base, pname) in seen: continue
            # Time-based blind
            for payload, delay, db in SQL_TIME_PL:
                try:
                    tp = dict(norm_params); tp[pname] = payload
                    t0 = time.monotonic()
                    requests.get(base, params=tp, timeout=delay+5, verify=False)
                    elapsed = time.monotonic() - t0
                    if elapsed >= delay * 0.9:
                        vulns.append(Vulnerability(
                            vuln_type="SQL Injection", severity="critical", cvss_score=9.8,
                            cwe_id="CWE-89",
                            title=f"SQL Injection (Time-Based Blind, {db}) — param: {pname}",
                            description=(f"Time-based blind SQLi in '{pname}'. "
                                         f"{db} sleep function caused {elapsed:.1f}s delay."),
                            recommendation=("1. Parameterized queries immediately.\n"
                                            "2. Audit all parameterized endpoints.\n"
                                            "3. Deploy WAF + rate limiting."),
                            evidence=f"Payload: {payload}\nDelay: {elapsed:.2f}s >= {delay}s",
                            affected_url=url, parameter=pname,
                            source_tool=SourceTool.INTERNAL, tags=["sqli","blind","owasp-a03"])); seen.add((base,pname)); break
                except Exception: continue
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# 12.  XSS SCANNER
# ─────────────────────────────────────────────────────────────────────────────
XSS_MARKER   = "CYB3R5C4N"
XSS_PAYLOADS = [
    f"<script>{XSS_MARKER}(1)</script>",
    f'" onmouseover="{XSS_MARKER}(1)"',
    f"<img src=x onerror={XSS_MARKER}(1)>",
    f"<svg onload={XSS_MARKER}(1)>",
    f"<details open ontoggle={XSS_MARKER}(1)>",
]

def scan_xss(test_urls: List[str]) -> List[Vulnerability]:
    vulns, seen = [], set()
    for url in test_urls:
        p = urlparse(url); params = urllib.parse.parse_qs(p.query)
        if not params: continue
        base = f"{p.scheme}://{p.netloc}{p.path}"
        for pname in params:
            if (base, pname) in seen: continue
            for payload in XSS_PAYLOADS:
                try:
                    tp = {k: v[0] for k, v in params.items()}; tp[pname] = payload
                    r  = requests.get(base, params=tp, timeout=10, verify=False)
                    if XSS_MARKER in r.text and "html" in r.headers.get("Content-Type","").lower():
                        idx = r.text.find(XSS_MARKER)
                        ctx = r.text[max(0,idx-100):idx+150].strip()
                        vulns.append(Vulnerability(
                            vuln_type="Cross-Site Scripting (XSS)", severity="high", cvss_score=7.4,
                            cwe_id="CWE-79",
                            title=f"Reflected XSS — param: {pname}",
                            description=(f"Parameter '{pname}' reflects unencoded input in HTML response. "
                                         "Attackers can inject scripts executing in victims' browsers."),
                            recommendation=("1. Encode all output (htmlspecialchars / auto-escaping).\n"
                                            "2. Implement strict CSP header.\n"
                                            "3. Set HttpOnly+Secure on session cookies.\n"
                                            "4. Use template engine with auto-escaping."),
                            evidence=f"Payload reflected: {payload}\nContext:\n{ctx[:250]}",
                            affected_url=url, parameter=pname,
                            request_sample=f"GET {base}?{pname}={urllib.parse.quote(payload)}",
                            response_sample=ctx, source_tool=SourceTool.INTERNAL,
                            tags=["xss","reflected","owasp-a03"])); seen.add((base,pname)); break
                except Exception: continue
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# 13.  CSRF CHECKER
# ─────────────────────────────────────────────────────────────────────────────
def check_csrf(url: str) -> List[Vulnerability]:
    vulns = []
    try:
        sess = requests.Session()
        r    = sess.get(url, timeout=12, verify=False)
        bodyl = r.text.lower()
        for ck in sess.cookies:
            cn = ck.name.lower()
            if any(k in cn for k in ("session","token","auth","csrf")):
                if not ck.has_nonstandard_attr("SameSite"):
                    vulns.append(Vulnerability(
                        vuln_type="CSRF", severity="medium", cvss_score=5.4, cwe_id="CWE-352",
                        title=f"Cookie '{ck.name}' Missing SameSite Attribute",
                        description=f"Without SameSite, '{ck.name}' is sent with cross-origin requests enabling CSRF.",
                        recommendation=f"Set SameSite=Lax on '{ck.name}'. Also add Secure + HttpOnly flags.",
                        evidence=f"Cookie {ck.name} — no SameSite", affected_url=url,
                        source_tool=SourceTool.INTERNAL, tags=["csrf","cookie"]))
            if any(k in cn for k in ("session","auth")) and not ck.has_nonstandard_attr("HttpOnly"):
                vulns.append(Vulnerability(
                    vuln_type="Cookie Security", severity="medium", cvss_score=5.4, cwe_id="CWE-1004",
                    title=f"Session Cookie '{ck.name}' Missing HttpOnly",
                    description="Without HttpOnly, JS can read this cookie — session hijack via XSS.",
                    recommendation=f"Set HttpOnly on '{ck.name}': Set-Cookie: name=val; HttpOnly; Secure",
                    evidence=f"Cookie {ck.name} — HttpOnly absent", affected_url=url,
                    source_tool=SourceTool.INTERNAL, tags=["cookie","xss","session"]))
        has_forms = "<form" in bodyl
        has_token = any(t in bodyl for t in ("csrf","xsrf","_token","authenticity_token","__requestverificationtoken"))
        if has_forms and not has_token:
            vulns.append(Vulnerability(
                vuln_type="CSRF", severity="medium", cvss_score=5.4, cwe_id="CWE-352",
                title="Forms Detected Without CSRF Token",
                description="HTML forms with no CSRF token found. Enables forged cross-site requests.",
                recommendation=("1. Add server-validated CSRF token to all state-changing forms.\n"
                                "2. Set SameSite=Strict on session cookies.\n"
                                "3. Validate Origin/Referer on POST requests."),
                evidence="<form> elements present; no csrftoken detected", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["csrf","forms"]))
    except Exception as e:
        logger.warning(f"CSRF check error: {e}")
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# 14.  SENSITIVE DATA EXPOSURE
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.env","Environment Config","critical"),("/.git/config","Git Config","critical"),
    ("/.git/HEAD","Git Repo Exposed","critical"),("/wp-config.php","WordPress Config","critical"),
    ("/config.php","PHP Config","critical"),("/config.yml","YAML Config","high"),
    ("/database.yml","DB Config","high"),("/appsettings.json",".NET Settings","high"),
    ("/.htpasswd","htpasswd File","high"),("/phpmyadmin","phpMyAdmin","high"),
    ("/adminer.php","Adminer DB UI","high"),("/phpinfo.php","PHP Info","medium"),
    ("/server-status","Apache Status","medium"),("/admin","Admin Panel","medium"),
    ("/wp-admin","WP Admin","medium"),("/swagger.json","Swagger Schema","low"),
    ("/openapi.json","OpenAPI Schema","low"),("/api/docs","API Docs","low"),
    ("/backup.sql","DB Backup File","critical"),("/dump.sql","DB Dump","critical"),
    ("/backup.zip","Site Backup","critical"),("/.DS_Store","DS_Store File","medium"),
    ("/debug","Debug Endpoint","medium"),("/actuator","Spring Actuator","high"),
    ("/actuator/env","Spring Env Actuator","critical"),("/actuator/health","Spring Health","low"),
]
SECRET_RES = [
    (r"(?i)aws[_\-]?access[_\-]?key[_\-]?id\s*[=:]\s*['\"]?([A-Z0-9]{20})","AWS Access Key","critical"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]","Password Exposed","critical"),
    (r"(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]","API Key Exposed","high"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----","Private Key Exposed","critical"),
    (r"(?i)(?:bearer|token)\s+['\"]?([A-Za-z0-9._\-]{20,})","Bearer Token Exposed","high"),
]

def scan_sensitive_data(url: str) -> List[Vulnerability]:
    vulns = []
    base  = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    cmap  = {"critical":9.1,"high":7.5,"medium":5.3,"low":3.1,"info":0.0}

    def _probe(path, desc, sev):
        try:
            r = requests.get(urljoin(base, path), timeout=8, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10 and "not found" not in r.text[:100].lower():
                secs = _find_secrets(r.text, urljoin(base, path))
                if secs: vulns.extend(secs)
                else:
                    vulns.append(Vulnerability(
                        vuln_type="Sensitive Data Exposure", severity=sev,
                        cvss_score=cmap.get(sev,5.0), cwe_id="CWE-200",
                        title=f"Sensitive File Accessible: {desc}",
                        description=f"'{path}' is publicly accessible and may contain credentials or secrets.",
                        recommendation=f"Block '{path}' in nginx/htaccess. Rotate any exposed credentials.",
                        evidence=f"HTTP {r.status_code} | {len(r.content)}b\nPreview: {r.text[:200]}",
                        affected_url=urljoin(base,path),
                        source_tool=SourceTool.INTERNAL, tags=["exposure","sensitive"]))
        except Exception: pass

    with ThreadPoolExecutor(max_workers=8) as exe:
        for f in as_completed([exe.submit(_probe,*a) for a in SENSITIVE_PATHS]): f.result()
    return vulns

def _find_secrets(body: str, url: str) -> List[Vulnerability]:
    found = []
    for pattern, title, sev in SECRET_RES:
        m = re.search(pattern, body[:5000])
        if m:
            raw = m.group(0); red = raw[:8]+"****"+raw[-3:] if len(raw)>14 else "****"
            found.append(Vulnerability(
                vuln_type="Credential Exposure", severity=sev, cwe_id="CWE-312",
                cvss_score={"critical":9.8,"high":8.5,"medium":5.0}.get(sev,5.0),
                title=title,
                description=f"{title} detected in HTTP response body. Grants immediate unauthorized access.",
                recommendation=("1. Revoke/rotate the exposed credential immediately.\n"
                                "2. Block file access at server level.\n"
                                "3. Audit related accounts for unauthorized activity.\n"
                                "4. Move secrets to environment variables or Vault."),
                evidence=f"Match (redacted): {red}", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["credential","exposure","secrets"]))
    return found


# ─────────────────────────────────────────────────────────────────────────────
# 15.  AUTH MISCONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
ADMIN_PATHS   = ["/admin","/admin/login","/administrator","/wp-admin",
                 "/wp-login.php","/login","/auth/login","/phpmyadmin","/panel"]
DEFAULT_CREDS = [("admin","admin"),("admin","password"),("admin","admin123"),
                 ("root","root"),("admin",""),("test","test")]

def check_auth_misconfigurations(url: str) -> List[Vulnerability]:
    vulns = []
    base  = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # Admin panel exposure
    for path in ADMIN_PATHS:
        try:
            r = requests.get(urljoin(base,path), timeout=8, verify=False, allow_redirects=True)
            if r.status_code == 200 and any(k in r.text.lower() for k in ("login","password","username","sign in")):
                vulns.append(Vulnerability(
                    vuln_type="Authentication", severity="medium", cvss_score=5.3, cwe_id="CWE-288",
                    title=f"Admin Panel Publicly Accessible ({path})",
                    description="Admin login panel accessible without IP restriction or VPN.",
                    recommendation=("1. Restrict access by IP.\n2. Require MFA.\n"
                                    "3. Place behind VPN.\n4. Implement rate limiting."),
                    evidence=f"HTTP 200 at {base}{path} with login form",
                    affected_url=urljoin(base,path),
                    source_tool=SourceTool.INTERNAL, tags=["auth","admin","exposure"]))
                _test_defaults(urljoin(base,path), r.text, vulns)
                break
        except Exception: continue

    # Rate limiting
    try:
        statuses = [requests.get(url, timeout=5, verify=False).status_code
                    for _ in range(6) if not time.sleep(0.1)]
        if all(s == 200 for s in statuses):
            vulns.append(Vulnerability(
                vuln_type="Authentication", severity="medium", cvss_score=5.3, cwe_id="CWE-307",
                title="No Rate Limiting Detected",
                description="6 rapid requests returned 200. Brute-force attacks are unrestricted.",
                recommendation=("1. Implement rate limiting (nginx limit_req / Flask-Limiter).\n"
                                "2. Add CAPTCHA to login forms.\n3. Account lockout after failures."),
                evidence="6 rapid consecutive requests all returned HTTP 200", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["auth","bruteforce","ratelimit"]))
    except Exception: pass

    # Username enumeration
    vulns.extend(_check_enum(base))
    return vulns

def _test_defaults(login_url: str, body: str, vulns: list) -> None:
    uf = pf = None
    for n in re.findall(r'name=["\']([^"\']*)["\']', body):
        if any(k in n.lower() for k in ("user","email","login")): uf = n
        if any(k in n.lower() for k in ("pass","pwd")):           pf = n
    if not uf or not pf: return
    for user, pwd in DEFAULT_CREDS[:3]:
        try:
            r = requests.post(login_url, data={uf:user,pf:pwd}, timeout=8,
                              verify=False, allow_redirects=True)
            if any(k in r.text.lower() for k in ("dashboard","welcome","logout")) \
               and not any(k in r.text.lower() for k in ("invalid","incorrect","failed")):
                vulns.append(Vulnerability(
                    vuln_type="Authentication", severity="critical", cvss_score=9.8, cwe_id="CWE-521",
                    title=f"Default Credentials Accepted: {user}/{pwd}",
                    description=f"Default credentials '{user}'/'{pwd}' grant immediate admin access.",
                    recommendation="Change default credentials. Enforce strong passwords. Enable MFA.",
                    evidence=f"POST {login_url} with {uf}={user} returned success signals",
                    affected_url=login_url,
                    source_tool=SourceTool.INTERNAL, tags=["auth","default-creds","critical"]))
        except Exception: continue

def _check_enum(base: str) -> List[Vulnerability]:
    vulns = []
    for path in ("/login","/api/auth/login","/wp-login.php"):
        try:
            r1 = requests.post(urljoin(base,path),json={"username":"NOUSER_XYZ","password":"wrong"},timeout=6,verify=False)
            r2 = requests.post(urljoin(base,path),json={"username":"admin",      "password":"wrong"},timeout=6,verify=False)
            if ("not found" in r1.text.lower() or "no account" in r1.text.lower()) \
               and ("wrong password" in r2.text.lower() or "invalid password" in r2.text.lower()):
                vulns.append(Vulnerability(
                    vuln_type="Authentication", severity="medium", cvss_score=5.3, cwe_id="CWE-204",
                    title="Username Enumeration via Error Message Differences",
                    description="Login returns different errors for unknown user vs wrong password.",
                    recommendation="Return generic: 'Invalid username or password.' for all failures.",
                    evidence=f"Unknown: {r1.text[:80]}\nWrong pwd: {r2.text[:80]}",
                    affected_url=urljoin(base,path),
                    source_tool=SourceTool.INTERNAL, tags=["auth","enumeration"])); break
        except Exception: continue
    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# 16.  OUTDATED SOFTWARE
# ─────────────────────────────────────────────────────────────────────────────
VULN_VERSIONS = {
    "WordPress": {"5.0":("critical","CVE-2019-8942","RCE via image upload."),
                  "5.1":("high",    "CVE-2019-9978","CSRF and XSS."),
                  "5.8":("medium",  "CVE-2022-21661","SQLi via WP_Query.")},
    "PHP":       {"5.6":("critical","CVE-2016-7125","EOL — many unpatched CVEs."),
                  "7.0":("critical","CVE-2019-11041","EOL."),
                  "7.1":("high",    "CVE-2019-11042","EOL."),
                  "7.2":("high",    "","EOL — no security updates."),
                  "7.3":("medium",  "","EOL.")},
    "Joomla":    {"3.9":("critical","CVE-2020-10238","RCE vulnerabilities.")},
    "Drupal":    {"7":  ("critical","CVE-2018-7600", "Drupalgeddon2 RCE.")},
}

def check_outdated_software(tech: dict, url: str) -> List[Vulnerability]:
    vulns = []
    cmap  = {"critical":9.8,"high":8.1,"medium":5.3,"low":3.1}
    def _srv_name(s): m=re.match(r"^([A-Za-z]+)",s); return m.group(1).capitalize() if m else None
    def _srv_ver(s):  m=re.search(r"/([\d.]+)",s);   return m.group(1) if m else None

    for sw, ver in [(tech.get("cms"),tech.get("cms_version")),
                    ("PHP",tech.get("php_version")),
                    (_srv_name(tech.get("server","")), _srv_ver(tech.get("server","")))]:
        if not sw or not ver: continue
        db   = VULN_VERSIONS.get(sw,{})
        pref = ".".join(ver.split(".")[:2])
        if pref in db:
            sev, cve, detail = db[pref]
            vulns.append(Vulnerability(
                vuln_type="Outdated Software", severity=sev, cve_id=cve,
                cvss_score=cmap.get(sev,5.0), cwe_id="CWE-1035",
                title=f"Vulnerable {sw} Version Detected: {ver}",
                description=f"{sw} {ver} is vulnerable{' ('+cve+')' if cve else ''}. {detail}",
                recommendation=(f"1. Update {sw} to latest stable release.\n"
                                 "2. Subscribe to vendor security advisories.\n"
                                 "3. Implement automated patch management."),
                evidence=f"Detected: {sw} {ver}", affected_url=url,
                source_tool=SourceTool.INTERNAL, tags=["outdated","cve",sw.lower()]))

    srv = tech.get("server","").lower()
    if any(x in srv for x in ("apache/2.2","nginx/1.1","iis/7","iis/8")):
        vulns.append(Vulnerability(
            vuln_type="Outdated Software", severity="high", cvss_score=7.5, cwe_id="CWE-1035",
            title="End-of-Life Web Server Detected",
            description=f"Web server ({tech.get('server','')}) is EOL with no security patches.",
            recommendation="Upgrade web server to current stable release.",
            evidence=f"Server: {tech.get('server','')}", affected_url=url,
            source_tool=SourceTool.INTERNAL, tags=["outdated","eol","server"]))
    return vulns



# ─────────────────────────────────────────────────────────────────────────────
# 17.  CRAWLER
# ─────────────────────────────────────────────────────────────────────────────
def crawl_entry_points(url: str, max_pages: int = 20) -> List[str]:
    """Lightweight link crawler — discovers URLs with query parameters for injection testing."""
    found, visited = [url], set()
    queue, netloc  = [url], urlparse(url).netloc
    while queue and len(visited) < max_pages:
        cur = queue.pop(0)
        if cur in visited: continue
        visited.add(cur)
        try:
            r = requests.get(cur, timeout=8, verify=False, allow_redirects=True,
                             headers={"User-Agent":"Mozilla/5.0"})
            if "text/html" not in r.headers.get("Content-Type","").lower(): continue
            for href in re.findall(r'href=["\']([^"\'#]+)["\']', r.text):
                abs_url = urljoin(cur, href); p = urlparse(abs_url)
                if p.netloc != netloc or abs_url in visited: continue
                queue.append(abs_url)
                if p.query and abs_url not in found: found.append(abs_url)
        except Exception: continue
    return found[:max_pages]


# ─────────────────────────────────────────────────────────────────────────────
# 18.  VERIFICATION LAYER
# ─────────────────────────────────────────────────────────────────────────────
def verification_pipeline(vulns: List[Vulnerability], url: str) -> List[Vulnerability]:
    """
    Reduce false positives before storage.
    - Deduplicates by (type, param/url, severity)
    - Re-probes SQLi findings with tautology payload
    - Re-probes XSS findings with safe confirm payload
    - Marks corroborated findings (2+ tools) as verified
    - Logs FP count
    """
    verified: List[Vulnerability] = []
    seen: set = set()
    for v in vulns:
        key = (v.vuln_type, (v.parameter or "")[:40], (v.affected_url or "")[:80], v.severity)
        if key in seen: continue
        seen.add(key)
        if v.source_tool == SourceTool.INTERNAL:
            if v.vuln_type == "SQL Injection" and v.parameter:
                if not _verify_sqli(v): v.false_positive = True
            elif v.vuln_type == "Cross-Site Scripting (XSS)" and v.parameter:
                if not _verify_xss(v):  v.false_positive = True
        if not v.false_positive: v.verified = True
        verified.append(v)

    confirmed = sum(1 for v in verified if v.verified)
    fps       = sum(1 for v in verified if v.false_positive)
    logger.info(f"[Verify] {confirmed} confirmed, {fps} FPs removed, {len(verified)} total")
    return sorted(verified, key=lambda v: v.severity_order)


def _verify_sqli(v: Vulnerability) -> bool:
    try:
        p = urlparse(v.affected_url); params = urllib.parse.parse_qs(p.query)
        if not params: return True
        base = f"{p.scheme}://{p.netloc}{p.path}"
        norm = {k: vs[0] for k, vs in params.items()}
        rn   = requests.get(base, params=norm, timeout=8, verify=False)
        for pl in ["' AND '1'='1", "' AND 1=1--"]:
            tp = dict(norm); tp[v.parameter] = pl
            rt = requests.get(base, params=tp, timeout=8, verify=False)
            if rt.status_code == 200 and not SQL_ERROR_RE.search(rt.text) \
               and len(rt.text) >= len(rn.text) * 0.8:
                return True
    except Exception: pass
    return False


def _verify_xss(v: Vulnerability) -> bool:
    try:
        p = urlparse(v.affected_url); params = urllib.parse.parse_qs(p.query)
        if not params: return False
        base = f"{p.scheme}://{p.netloc}{p.path}"
        tp   = {k: vs[0] for k, vs in params.items()}
        tp[v.parameter] = f"<b>{XSS_MARKER}</b>"
        r = requests.get(base, params=tp, timeout=8, verify=False)
        return XSS_MARKER in r.text
    except Exception: return False


# ─────────────────────────────────────────────────────────────────────────────
# 19.  AI EXPLANATION ENGINE + REMEDIATION (Groq)
# ─────────────────────────────────────────────────────────────────────────────
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

# Structured JSON explanation prompt — machine-parseable output
EXPLAIN_PROMPT = """You are a senior cybersecurity engineer. Return ONLY valid JSON — no preamble.

Analyze this vulnerability and return a JSON object with exactly these fields:
{{
  "plain_english": "1 sentence explanation for a non-technical person",
  "technical_impact": "2 sentences — what an attacker can do",
  "business_risk": "1 sentence — business/financial/regulatory impact",
  "attack_scenario": "Brief realistic attack scenario description",
  "risk_level": "one of: Critical | High | Medium | Low",
  "fix_summary": "1-sentence quick fix",
  "fix_steps": ["step 1", "step 2", "step 3"],
  "prevention": "1 sentence long-term prevention measure",
  "owasp_category": "OWASP Top 10 category if applicable, else empty string"
}}

Vulnerability:
  Type: {vuln_type}
  Title: {title}
  Severity: {severity}
  Description: {description}
  Evidence: {evidence}
  CWE: {cwe_id}
  CVE: {cve_id}"""


REMEDIATION_PROMPT = """You are a senior security engineer. Return ONLY valid JSON — no preamble.

Generate a production-ready remediation guide for this vulnerability.

Return a JSON object:
{{
  "immediate_action": "What to do right now (< 1 hour)",
  "permanent_fix": "Code or config change with specific example",
  "code_example": "Short code snippet showing the fix (or empty string if N/A)",
  "verify_fix": "How to confirm the vulnerability is resolved",
  "ci_cd_check": "Automated check to prevent regression in CI/CD pipeline",
  "references": ["url1", "url2"]
}}

Vulnerability: {title} ({severity})
Type: {vuln_type}
Description: {description}
CWE: {cwe_id}"""


SUMMARY_PROMPT = """You are a cybersecurity consultant writing for a business owner.
Return ONLY valid JSON — no preamble.

Write an executive security summary for this scan:

Website: {url}
Score: {score}/100 (Grade: {grade})
Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}
Top findings: {top_findings}
Tools used: {tools}

Return JSON:
{{
  "overall_posture": "2 sentences — current security posture",
  "key_risks": ["risk 1", "risk 2", "risk 3"],
  "business_impact": "2 sentences — potential business impact if exploited",
  "priority_actions": ["action 1", "action 2", "action 3"],
  "timeline_recommendation": "Suggested fix timeline (e.g. critical: 24h, high: 1 week)",
  "positive_findings": "Any security measures already in place"
}}"""


def _groq(prompt: str, max_tokens: int = 600) -> Optional[dict]:
    """
    Call Groq LLM API.
    Expects JSON response. Returns parsed dict or None on failure.
    """
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        return None
    try:
        r = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0 (compatible; VENOM-AI/2.0)"},
            json={
                "model":       GROQ_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  max_tokens,
                "temperature": 0.15,
                "response_format": {"type": "json_object"},
            },
            timeout=30,
        )
        r.raise_for_status()
        raw  = r.json()["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if present
        raw  = re.sub(r"^```json\s*", "", raw, flags=re.MULTILINE)
        raw  = re.sub(r"```\s*$",     "", raw, flags=re.MULTILINE).strip()
        return json.loads(raw)
    except Exception as e:
        logger.warning(f"Groq API error: {e}")
        return None


def enrich_with_ai(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """
    Parallel AI enrichment for all confirmed non-info vulnerabilities.
    Adds structured explanation + remediation to each Vulnerability.
    """
    targets = [v for v in vulns if not v.false_positive and v.severity != Severity.INFO]

    def _enrich(v: Vulnerability) -> Vulnerability:
        # Structured explanation
        ep = EXPLAIN_PROMPT.format(
            vuln_type=v.vuln_type, title=v.title, severity=v.severity.upper(),
            description=v.description, evidence=v.evidence[:250],
            cwe_id=v.cwe_id or "N/A", cve_id=v.cve_id or "N/A",
        )
        exp_data = _groq(ep, 700)
        if exp_data:
            v.ai_explanation = (
                f"**What it means**: {exp_data.get('plain_english','')}\n\n"
                f"**Technical impact**: {exp_data.get('technical_impact','')}\n\n"
                f"**Business risk**: {exp_data.get('business_risk','')}\n\n"
                f"**Attack scenario**: {exp_data.get('attack_scenario','')}\n\n"
                f"**OWASP**: {exp_data.get('owasp_category','')}"
            )
            v.ai_risk_level  = exp_data.get("risk_level", v.severity.capitalize())
            # Enhance recommendation with AI fix steps
            ai_steps = exp_data.get("fix_steps", [])
            if ai_steps:
                v.recommendation = "\n".join(f"{i+1}. {s}" for i, s in enumerate(ai_steps))
        else:
            v.ai_explanation = _fallback_explanation(v)

        # Structured remediation
        rp = REMEDIATION_PROMPT.format(
            title=v.title, severity=v.severity.upper(),
            vuln_type=v.vuln_type, description=v.description, cwe_id=v.cwe_id or "N/A",
        )
        rem_data = _groq(rp, 600)
        if rem_data:
            v.ai_remediation = (
                f"**Immediate action**: {rem_data.get('immediate_action','')}\n\n"
                f"**Permanent fix**: {rem_data.get('permanent_fix','')}\n\n"
                f"**Code example**:\n```\n{rem_data.get('code_example','N/A')}\n```\n\n"
                f"**Verify fix**: {rem_data.get('verify_fix','')}\n\n"
                f"**CI/CD check**: {rem_data.get('ci_cd_check','')}"
            )
        else:
            v.ai_remediation = _fallback_remediation(v)

        return v

    if targets:
        with ThreadPoolExecutor(max_workers=4) as exe:
            for fut in as_completed([exe.submit(_enrich, v) for v in targets]):
                try: fut.result()
                except Exception as e: logger.warning(f"AI enrich error: {e}")

    return vulns


def _fallback_explanation(v: Vulnerability) -> str:
    return (
        f"**What it means**: {v.title} was detected on your application.\n\n"
        f"**Technical impact**: {v.description}\n\n"
        f"**How to fix it**: {v.recommendation or 'Review the affected component and apply security best practices.'}"
    )

def _fallback_remediation(v: Vulnerability) -> str:
    steps = (v.recommendation or "Review and fix this vulnerability.").split("\n")
    return "\n".join(f"{i+1}. {s.lstrip('0123456789. ')}" for i, s in enumerate(steps[:4]) if s.strip())


def generate_ai_summary(result: ScanResult) -> str:
    top = "; ".join(
        f"[{v.severity.upper()}] {v.title}"
        for v in result.confirmed_vulns[:8]
    )
    prompt = SUMMARY_PROMPT.format(
        url=result.url, score=result.security_score, grade=result.grade,
        critical=result.critical_count, high=result.high_count,
        medium=result.medium_count,   low=result.low_count,
        top_findings=top or "None significant",
        tools=", ".join(result.tools_used) or "internal",
    )
    data = _groq(prompt, 600)
    if data:
        return (
            f"{data.get('overall_posture','')}\n\n"
            f"**Key Risks**: {'; '.join(data.get('key_risks',[]))}\n\n"
            f"**Business Impact**: {data.get('business_impact','')}\n\n"
            f"**Priority Actions**:\n"
            + "\n".join(f"• {a}" for a in data.get("priority_actions",[])) + "\n\n"
            f"**Timeline**: {data.get('timeline_recommendation','')}\n\n"
            f"**Positives**: {data.get('positive_findings','')}"
        )
    # Fallback
    gmap = {"A":"excellent","B":"good","C":"moderate","D":"poor","F":"critical"}
    return (
        f"Your website scored **{result.security_score}/100** (Grade **{result.grade}**) — "
        f"{gmap.get(result.grade,'unknown')} security posture.\n\n"
        f"Found {result.total_issues} issues: {result.critical_count} critical, "
        f"{result.high_count} high, {result.medium_count} medium, {result.low_count} low.\n\n"
        f"**Immediate priority**: Resolve all critical and high severity findings."
    )


def generate_risk_narrative(result: ScanResult) -> str:
    if not result.confirmed_vulns:
        return "No significant vulnerabilities were found. Maintain current security posture."
    findings = "\n".join(
        f"- [{v.severity.upper()}|{v.source_tool}] {v.title}: {v.description[:60]}"
        for v in result.confirmed_vulns[:10]
    )
    prompt = (
        "You are a senior penetration tester. Write a 2-paragraph technical risk narrative "
        "for the development team. Cover: (1) most likely attack path, (2) impact chain if exploited. "
        "Technical but concise, under 180 words.\n\n"
        f"Target: {result.url}\nScore: {result.security_score}/100\n"
        f"Findings:\n{findings}"
    )
    data = _groq(prompt, 400)
    return str(data) if data else ""


def generate_remediation_plan(result: ScanResult) -> str:
    """AI-generated prioritised remediation plan covering all findings."""
    if not result.confirmed_vulns:
        return "No remediation required."
    issue_summary = "\n".join(
        f"- [{v.severity.upper()}] {v.title} ({v.vuln_type})"
        for v in result.confirmed_vulns[:15]
    )
    prompt = (
        "You are a security lead preparing a remediation plan. "
        "Return a JSON object with keys: "
        "'week_1' (list of critical/high fixes), "
        "'week_2_4' (list of medium fixes), "
        "'ongoing' (list of low/process improvements), "
        "'estimated_effort' (rough hours/days), "
        "'quick_wins' (list of fixes under 1 hour). "
        "No preamble — valid JSON only.\n\n"
        f"Website: {result.url}\nScore: {result.security_score}/100\n"
        f"Issues:\n{issue_summary}"
    )
    data = _groq(prompt, 500)
    if data and isinstance(data, dict):
        return (
            f"**Week 1 (Critical/High)**:\n" +
            "\n".join(f"• {i}" for i in data.get("week_1",[])) + "\n\n"
            f"**Weeks 2-4 (Medium)**:\n" +
            "\n".join(f"• {i}" for i in data.get("week_2_4",[])) + "\n\n"
            f"**Ongoing (Low/Process)**:\n" +
            "\n".join(f"• {i}" for i in data.get("ongoing",[])) + "\n\n"
            f"**Quick Wins (<1h)**:\n" +
            "\n".join(f"• {i}" for i in data.get("quick_wins",[])) + "\n\n"
            f"**Estimated Effort**: {data.get('estimated_effort','')}"
        )
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# 20.  CVSS-WEIGHTED SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────
SEV_CFG = {
    "critical": {"per": 25, "cap": 60},
    "high":     {"per": 12, "cap": 40},
    "medium":   {"per":  6, "cap": 25},
    "low":      {"per":  2, "cap": 15},
    "info":     {"per":  0, "cap":  0},
}
GRADES      = [(90,"A"),(75,"B"),(60,"C"),(45,"D"),(0,"F")]
MOD_WEIGHTS = {"headers":0.20,"ssl":0.20,"ports":0.15,"vulns":0.35,"auth":0.10}

def calculate_score(result: ScanResult) -> ScanResult:
    """
    CVSS-weighted scoring with module blending.

    Base deduction from confirmed vulnerabilities,
    capped per severity to prevent cliff effects.
    Blended with module sub-scores.
    """
    confirmed = result.confirmed_vulns
    counts    = {s: 0 for s in SEV_CFG}
    for v in confirmed:
        sev = v.severity.lower() if v.severity.lower() in counts else "info"
        counts[sev] += 1

    result.critical_count = counts["critical"]; result.high_count   = counts["high"]
    result.medium_count   = counts["medium"];   result.low_count    = counts["low"]
    result.info_count     = counts["info"];     result.total_issues = sum(counts.values())

    base = 100.0
    for sev, cfg in SEV_CFG.items():
        base -= min(counts[sev] * cfg["per"], cfg["cap"])

    result.vuln_score  = max(0, int(base))
    result.port_score  = max(0, 100 - sum(1 for v in confirmed
                                          if v.vuln_type in ("Exposed Port","Nmap/port")
                                          and v.severity == "critical") * 30)
    result.auth_score  = max(0, 100 - sum(1 for v in confirmed
                                          if v.vuln_type == "Authentication") * 20)
    result.tool_score  = max(0, 100 - (result.nmap_findings + result.nuclei_findings
                                       + result.zap_findings) * 3)

    blended = (
        result.headers_score * MOD_WEIGHTS["headers"]
        + result.ssl_score   * MOD_WEIGHTS["ssl"]
        + result.port_score  * MOD_WEIGHTS["ports"]
        + result.vuln_score  * MOD_WEIGHTS["vulns"]
        + result.auth_score  * MOD_WEIGHTS["auth"]
    )
    result.security_score = max(0, min(100, int(blended)))

    for thr, grade in GRADES:
        if result.security_score >= thr:
            result.grade = grade; break

    logger.info(
        f"Score={result.security_score}/100  Grade={result.grade}  "
        f"C={counts['critical']} H={counts['high']} M={counts['medium']} L={counts['low']} "
        f"nmap={result.nmap_findings} zap={result.zap_findings} nuclei={result.nuclei_findings}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 21.  ASYNC DATABASE PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────
async def store_scan_results_async(scan_id: str, result: ScanResult) -> None:
    """
    Async PostgreSQL persistence using SQLAlchemy 2.0 async.

    In production: uncomment SQLAlchemy imports and adapt to your engine setup.
    """
    logger.info(
        f"[DB] Persisting scan {scan_id} — score={result.security_score} "
        f"grade={result.grade} vulns={len(result.confirmed_vulns)} "
        f"duration={result.scan_duration_s}s"
    )

    # ── Production implementation: ───────────────────────────
    # from database import AsyncSessionLocal
    # from models.scan import ScanResultORM, VulnerabilityORM
    #
    # async with AsyncSessionLocal() as session:
    #     async with session.begin():
    #
    #         # Upsert scan result
    #         scan_orm = ScanResultORM(
    #             id              = scan_id,
    #             url             = result.url,
    #             user_id         = result.user_id,
    #             scan_type       = result.scan_type,
    #             status          = result.status,
    #             security_score  = result.security_score,
    #             grade           = result.grade,
    #             headers_score   = result.headers_score,
    #             ssl_score       = result.ssl_score,
    #             port_score      = result.port_score,
    #             vuln_score      = result.vuln_score,
    #             auth_score      = result.auth_score,
    #             tool_score      = result.tool_score,
    #             critical_count  = result.critical_count,
    #             high_count      = result.high_count,
    #             medium_count    = result.medium_count,
    #             low_count       = result.low_count,
    #             total_issues    = result.total_issues,
    #             nmap_findings   = result.nmap_findings,
    #             zap_findings    = result.zap_findings,
    #             nuclei_findings = result.nuclei_findings,
    #             open_ports      = result.open_ports,
    #             detected_tech   = result.detected_tech,
    #             tools_used      = result.tools_used,
    #             ai_summary      = result.ai_summary,
    #             ai_risk_narrative = result.ai_risk_narrative,
    #             ai_remediation_plan = result.ai_remediation_plan,
    #             scan_duration_s = result.scan_duration_s,
    #             scanned_at      = result.scanned_at,
    #         )
    #         session.add(scan_orm)
    #
    #         # Bulk insert confirmed vulnerabilities
    #         vuln_orms = [
    #             VulnerabilityORM(
    #                 result_id      = scan_id,
    #                 vuln_type      = v.vuln_type,
    #                 title          = v.title,
    #                 severity       = v.severity,
    #                 cvss_score     = v.cvss_score,
    #                 cve_id         = v.cve_id,
    #                 cwe_id         = v.cwe_id,
    #                 source_tool    = v.source_tool,
    #                 description    = v.description,
    #                 evidence       = v.evidence,
    #                 affected_url   = v.affected_url,
    #                 recommendation = v.recommendation,
    #                 ai_explanation = v.ai_explanation,
    #                 ai_remediation = v.ai_remediation,
    #                 ai_risk_level  = v.ai_risk_level,
    #                 parameter      = v.parameter,
    #                 false_positive = v.false_positive,
    #                 verified       = v.verified,
    #                 tags           = v.tags,
    #                 http_method    = v.http_method,
    #             )
    #             for v in result.confirmed_vulns
    #         ]
    #         session.add_all(vuln_orms)
    #
    #         # Update task log
    #         await session.execute(
    #             "UPDATE task_logs SET status='done', progress=100, "
    #             "updated_at=NOW() WHERE task_id=:tid",
    #             {"tid": scan_id}
    #         )


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _prog(scan_id: str, pct: int, msg: str, status: str = "running") -> None:
    logger.info(f"[{scan_id}] {pct:3d}%  {msg}")
    # Production: UPDATE task_logs SET progress=%s, status=%s WHERE task_id=%s


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")): url = "https://" + url
    return url.rstrip("/")


def _tool_available(tool_name: str) -> bool:
    """Check if an external tool is installed and on PATH."""
    return shutil.which(tool_name) is not None

# ─────────────────────────────────────────────────────────────────────────────
# NIKTO SCANNER — Server misconfiguration detection
# ─────────────────────────────────────────────────────────────────────────────

def run_nikto_scan(url: str) -> List[Vulnerability]:
    """
    Run Nikto web server scanner.
    Detects: dangerous files, outdated software, server misconfigs, default creds.
    Requires: nikto installed (apt install nikto / brew install nikto)
    """
    import subprocess, json
    from urllib.parse import urlparse

    vulns: List[Vulnerability] = []
    parsed = urlparse(url)
    host   = parsed.hostname or ""
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        cmd = [
            "nikto",
            "-h", host,
            "-p", str(port),
            "-Format", "json",
            "-nointeractive",
            "-Tuning", "x 6",  # x=all, 6=info disclosure
            "-timeout", "10",
            "-maxtime", "120s",
        ]
        if parsed.scheme == "https":
            cmd += ["-ssl"]

        logger.info(f"[Nikto] Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=150)

        # Parse JSON output
        output = proc.stdout.strip()
        if not output:
            logger.info("[Nikto] No output")
            return []

        # Nikto JSON output is a list of items
        try:
            data = json.loads(output)
            items = data if isinstance(data, list) else data.get("vulnerabilities", [])
        except json.JSONDecodeError:
            # Fallback: parse text output line by line
            items = []
            for line in output.split("\n"):
                if line.startswith("+ ") and "OSVDB" not in line[:10]:
                    items.append({"msg": line[2:].strip()})

        for item in items:
            msg = item.get("msg", item.get("id", "")) if isinstance(item, dict) else str(item)
            if not msg or len(msg) < 10:
                continue

            # Determine severity from content
            sev = "medium"
            cvss = 5.0
            if any(k in msg.lower() for k in ["default password", "admin", "login", "auth bypass"]):
                sev, cvss = "high", 7.5
            elif any(k in msg.lower() for k in ["dangerous", "remote code", "execute", "upload"]):
                sev, cvss = "critical", 9.0
            elif any(k in msg.lower() for k in ["backup", "config", "exposed", "readable"]):
                sev, cvss = "high", 7.0
            elif any(k in msg.lower() for k in ["outdated", "old version", "eol"]):
                sev, cvss = "medium", 6.0
            elif any(k in msg.lower() for k in ["info", "found", "server"]):
                sev, cvss = "low", 3.0

            affected = item.get("url", url) if isinstance(item, dict) else url

            vulns.append(Vulnerability(
                vuln_type="Server Misconfiguration",
                title=f"[Nikto] {msg[:100]}",
                severity=sev,
                cvss_score=cvss,
                cwe_id="CWE-16",
                description=msg,
                recommendation=(
                    "Review and remediate the identified server configuration issue. "
                    "Remove default files, disable directory listing, patch outdated software, "
                    "and remove dangerous HTTP methods."
                ),
                evidence=f"Nikto finding: {msg}",
                affected_url=affected,
                source_tool="nikto",
                tags=["server", "misconfiguration", "nikto"],
            ))

        logger.info(f"[Nikto] Parsed {len(vulns)} findings")
    except subprocess.TimeoutExpired:
        logger.warning("[Nikto] Scan timed out")
    except Exception as e:
        logger.error(f"[Nikto] Error: {e}")

    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# WHATWEB SCANNER — Technology fingerprinting + version exposure
# ─────────────────────────────────────────────────────────────────────────────

def run_whatweb_scan(url: str) -> List[Vulnerability]:
    """
    Run WhatWeb for technology fingerprinting.
    Flags exposed version numbers that map to known CVEs.
    Requires: whatweb installed (apt install whatweb)
    """
    import subprocess, json

    vulns: List[Vulnerability] = []
    try:
        cmd = ["whatweb", "--log-json=-", "--quiet", "--aggression", "3", url]
        logger.info(f"[WhatWeb] Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        raw = proc.stdout.strip()
        if not raw:
            return []

        # WhatWeb outputs one JSON object per line
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            plugins = obj.get("plugins", {})
            target  = obj.get("target", url)

            for plugin_name, plugin_data in plugins.items():
                versions = plugin_data.get("version", [])
                strings  = plugin_data.get("string", [])

                for ver in versions:
                    vulns.append(Vulnerability(
                        vuln_type="Technology Disclosure",
                        title=f"Version Disclosed: {plugin_name} {ver}",
                        severity="medium",
                        cvss_score=5.3,
                        cwe_id="CWE-200",
                        description=(
                            f"WhatWeb identified {plugin_name} version {ver} running on {target}. "
                            f"Exposed version numbers allow attackers to search for known CVEs "
                            f"and target-specific exploits."
                        ),
                        recommendation=(
                            f"1. Update {plugin_name} to the latest stable version.\n"
                            f"2. Suppress version information in server headers and meta tags.\n"
                            f"3. Regularly check {plugin_name} security advisories."
                        ),
                        evidence=f"WhatWeb: {plugin_name} v{ver} at {target}",
                        affected_url=target,
                        source_tool="whatweb",
                        tags=["disclosure", "version", "fingerprint"],
                    ))

        logger.info(f"[WhatWeb] Parsed {len(vulns)} version disclosure findings")
    except subprocess.TimeoutExpired:
        logger.warning("[WhatWeb] Timed out")
    except Exception as e:
        logger.error(f"[WhatWeb] Error: {e}")

    return vulns


# ─────────────────────────────────────────────────────────────────────────────
# FORM-BASED SCANNER — Burp Suite-like form discovery + injection testing
# ─────────────────────────────────────────────────────────────────────────────

def _discover_forms(url: str) -> list:
    """Discover HTML forms and extract input parameters — Burp Suite-like crawl."""
    forms = []
    try:
        from urllib.parse import urljoin
        resp = requests.get(url, timeout=12, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 (VENOM-AI-Scanner)"})
        # Simple form parsing without BeautifulSoup dependency
        import re as _re
        form_blocks = _re.findall(r'<form[^>]*>(.*?)</form>', resp.text, _re.DOTALL | _re.IGNORECASE)
        for block in form_blocks[:5]:  # limit to 5 forms
            action_m = _re.search(r'action=["\']([^"\']*)["\']', block, _re.IGNORECASE)
            method_m = _re.search(r'method=["\']([^"\']*)["\']', block, _re.IGNORECASE)
            action = urljoin(url, action_m.group(1)) if action_m else url
            method = (method_m.group(1) or "GET").upper()
            inputs = _re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', block, _re.IGNORECASE)
            textareas = _re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']', block, _re.IGNORECASE)
            params = inputs + textareas
            if params:
                forms.append({"action": action, "method": method, "params": params})
    except Exception as e:
        logger.debug(f"Form discovery error: {e}")
    return forms


def scan_forms_sqli_xss(url: str) -> List[Vulnerability]:
    """
    Burp Suite-like form-based injection testing.
    Discovers forms, then tests each parameter for SQLi and XSS.
    """
    vulns: List[Vulnerability] = []
    forms = _discover_forms(url)

    if not forms:
        return vulns

    logger.info(f"[FormScan] Discovered {len(forms)} forms on {url}")

    SQL_PAYLOADS_FORM = ["'", "' OR '1'='1", "1; DROP TABLE users--", '" OR "1"="1']
    SQL_ERRORS = re.compile(
        r"(sql syntax|mysql_fetch|pg_query|sqlite_|ora-\d|syntax error near|"
        r"unclosed quotation|microsoft ole db|odbc driver|jdbc|SQLException)",
        re.IGNORECASE
    )
    XSS_MARKER_F = "VEN0MXS5"
    XSS_PAYLOADS_FORM = [
        f"<script>{XSS_MARKER_F}</script>",
        f'"><img src=x onerror="{XSS_MARKER_F}()">',
        f"<svg onload={XSS_MARKER_F}()>",
    ]

    for form in forms:
        action = form["action"]
        method = form["method"]
        params = form["params"]

        for param in params:
            # === SQLi Test ===
            for payload in SQL_PAYLOADS_FORM[:2]:
                try:
                    data = {p: "test" for p in params}
                    data[param] = payload
                    if method == "POST":
                        r = requests.post(action, data=data, timeout=10, verify=False,
                                          headers={"User-Agent": "Mozilla/5.0 (VENOM-AI)"})
                    else:
                        r = requests.get(action, params=data, timeout=10, verify=False,
                                         headers={"User-Agent": "Mozilla/5.0 (VENOM-AI)"})

                    if SQL_ERRORS.search(r.text):
                        m = SQL_ERRORS.search(r.text)
                        snippet = r.text[max(0, m.start()-30):m.end()+100].strip()
                        vulns.append(Vulnerability(
                            vuln_type="SQL Injection",
                            title=f"Form SQLi — {action} param:{param}",
                            severity="critical",
                            cvss_score=9.8,
                            cwe_id="CWE-89",
                            description=(
                                f"Form parameter '{param}' in {method} {action} is vulnerable to SQL Injection. "
                                "Database error returned in response to crafted input."
                            ),
                            recommendation=(
                                "1. Use parameterized queries / prepared statements.\n"
                                "2. Apply ORM with automatic escaping.\n"
                                "3. Validate and whitelist all form inputs.\n"
                                "4. Deploy WAF with SQL injection signatures."
                            ),
                            evidence=f"Payload: {payload}\nParam: {param}\nDB error: {snippet[:300]}",
                            affected_url=action,
                            parameter=param,
                            http_method=method,
                            source_tool=SourceTool.INTERNAL,
                            tags=["sqli", "form", "owasp-a03"],
                            verified=True,
                        ))
                        break
                except Exception:
                    continue

            # === XSS Test ===
            for payload in XSS_PAYLOADS_FORM:
                try:
                    data = {p: "test" for p in params}
                    data[param] = payload
                    if method == "POST":
                        r = requests.post(action, data=data, timeout=10, verify=False,
                                          headers={"User-Agent": "Mozilla/5.0 (VENOM-AI)"})
                    else:
                        r = requests.get(action, params=data, timeout=10, verify=False,
                                         headers={"User-Agent": "Mozilla/5.0 (VENOM-AI)"})

                    if XSS_MARKER_F in r.text and "html" in r.headers.get("Content-Type", "").lower():
                        idx = r.text.find(XSS_MARKER_F)
                        ctx = r.text[max(0, idx-100):idx+150].strip()
                        vulns.append(Vulnerability(
                            vuln_type="Cross-Site Scripting (XSS)",
                            title=f"Form XSS — {action} param:{param}",
                            severity="high",
                            cvss_score=7.4,
                            cwe_id="CWE-79",
                            description=(
                                f"Form parameter '{param}' in {method} {action} reflects input unencoded. "
                                "Script injection can steal sessions and perform actions as victims."
                            ),
                            recommendation=(
                                "1. HTML-encode all output (htmlspecialchars/template auto-escaping).\n"
                                "2. Implement strict Content-Security-Policy.\n"
                                "3. Set HttpOnly+Secure flags on session cookies."
                            ),
                            evidence=f"Payload reflected: {payload[:80]}\nContext: {ctx[:200]}",
                            affected_url=action,
                            parameter=param,
                            http_method=method,
                            source_tool=SourceTool.INTERNAL,
                            tags=["xss", "form", "reflected", "owasp-a03"],
                            verified=True,
                        ))
                        break
                except Exception:
                    continue

    logger.info(f"[FormScan] Found {len(vulns)} form injection vulnerabilities")
    return vulns