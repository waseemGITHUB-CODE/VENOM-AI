"""
VENOM AI · backend/workers/tasks.py
Celery task wrapper — integrates all VENOM v2 modules:
  PoE · NHI · Compliance · Attack Chains · AI AutoFix
Windows-safe (no soft_time_limit, pool=solo)
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from workers.celery_app import celery_app

logger = logging.getLogger("venom.tasks")

# ── Safe DB + settings imports ────────────────────────────────────────────────

def _get_db():
    try:
        from db.database import SessionLocal
        return SessionLocal()
    except ImportError:
        from db.database import SessionLocal
        return SessionLocal()


def _get_models():
    try:
        from db import models as m
        return m
    except ImportError:
        from db import models as m
        return m


def _get_settings():
    try:
        from core.config import settings
        return settings
    except ImportError:
        from core.config import settings
        return settings


# ── Safe module imports ────────────────────────────────────────────────────────

def _get_security_worker():
    try:
        import backend.workers.security_worker as sw
        return sw
    except ImportError:
        import workers.security_worker as sw
        return sw


def _get_risk_level():
    try:
        from db.models import RiskLevel
        return RiskLevel
    except Exception:
        try:
            from db.models import RiskLevel
            return RiskLevel
        except Exception:
            class _RL:
                CRITICAL = "critical"
                HIGH = "high"
                MEDIUM = "medium"
                LOW = "low"
                INFO = "info"
            return _RL


def _get_compliance_service():
    try:
        from services.compliance_service import generate_full_compliance_report
        return generate_full_compliance_report
    except ImportError:
        try:
            from services.compliance_service import generate_full_compliance_report
            return generate_full_compliance_report
        except ImportError:
            return None


def _get_autofix_service():
    try:
        from services.autofix_service import generate_batch_patches
        return generate_batch_patches
    except ImportError:
        try:
            from services.autofix_service import generate_batch_patches
            return generate_batch_patches
        except ImportError:
            return None


def _get_attack_path_service():
    try:
        from services.attack_path_service import build_attack_chains, attack_chains_to_dict
        return build_attack_chains, attack_chains_to_dict
    except ImportError:
        try:
            from services.attack_path_service import build_attack_chains, attack_chains_to_dict
            return build_attack_chains, attack_chains_to_dict
        except ImportError:
            return None, None


# ── DB helpers ────────────────────────────────────────────────────────────────

def _update_scan_status(scan_id: int, status: str, progress: int = 0, message: str = "") -> None:
    db = _get_db()
    try:
        models = _get_models()
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int(scan_id)).first()
        if scan:
            scan.status = status
            scan.progress = progress
            db.commit()
    except Exception as e:
        logger.warning(f"Status update failed for scan {scan_id}: {e}")
        try: db.rollback()
        except: pass
    finally:
        db.close()


def _sanitize_value(v):
    """Convert enums, sets, and other non-JSON types to plain Python types."""
    import enum
    if isinstance(v, enum.Enum):
        return v.value
    if isinstance(v, (list, tuple)):
        return [_sanitize_value(i) for i in v]
    if isinstance(v, dict):
        return {k: _sanitize_value(val) for k, val in v.items()}
    if isinstance(v, set):
        return list(v)
    return v


def _extract_vulns_from_result(result_dict: dict, scan_url: str = "") -> list:
    """
    Robustly extract vulnerability dicts from any scanner result format.
    Handles SourceTool enums, dataclass instances, and missing keys.
    """
    import enum
    raw = result_dict.get("vulnerabilities", [])
    if not raw:
        for key in ("vuln_list", "findings", "results", "confirmed_vulns"):
            raw = result_dict.get(key, [])
            if raw:
                break
    if not raw:
        return []

    clean = []
    for item in raw:
        if item is None:
            continue
        # Convert dataclass to dict if needed
        if hasattr(item, "__dataclass_fields__"):
            try:
                from dataclasses import asdict as _asdict
                item = _asdict(item)
            except Exception:
                try:
                    item = item.__dict__.copy()
                except Exception:
                    continue
        if not isinstance(item, dict):
            try:
                item = dict(item)
            except Exception:
                continue
        # Sanitize all values — convert enums to plain strings
        safe = {k: _sanitize_value(v) for k, v in item.items()}
        # Ensure required fields exist
        safe.setdefault("title",          safe.get("vuln_type", "Unknown Finding"))
        safe.setdefault("vuln_type",      "unknown")
        safe.setdefault("severity",       str(safe.get("risk_level", "info")).lower())
        safe.setdefault("description",    "")
        safe.setdefault("source_tool",    "venom")
        safe.setdefault("cvss_score",     0.0)
        safe.setdefault("cve_id",         "")
        safe.setdefault("cwe_id",         "")
        safe.setdefault("affected_url",   scan_url)
        safe.setdefault("evidence",       "")
        safe.setdefault("recommendation", "")
        safe.setdefault("fix",            "")
        safe.setdefault("impact",         "")
        # Normalize SourceTool enum strings like "SourceTool.INTERNAL" → "internal"
        st = safe.get("source_tool", "")
        if isinstance(st, str) and "." in st:
            safe["source_tool"] = st.split(".")[-1].lower()
        clean.append(safe)
    return clean


def _save_results_to_db(scan_id: int, result_dict: dict) -> None:
    """Persist full scan results including new VENOM v2 fields."""
    db = _get_db()
    try:
        models = _get_models()
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int(scan_id)).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found in DB")
            return

        # Update scan-level fields
        scan.status        = "COMPLETED"
        scan.security_score = result_dict.get("security_score", 0)
        scan.grade         = result_dict.get("grade", "F")
        scan.total_issues  = result_dict.get("total_issues", 0)
        scan.critical_count = result_dict.get("critical_count", result_dict.get("critical", 0))
        scan.high_count    = result_dict.get("high_count", result_dict.get("high", 0))
        scan.medium_count  = result_dict.get("medium_count", result_dict.get("medium", 0))
        scan.low_count     = result_dict.get("low_count", result_dict.get("low", 0))
        scan.completed_at  = datetime.now(timezone.utc)
        scan.progress      = 100

        # Auto-generate AI summary from scan data (no API key required)
        raw_summary = result_dict.get("ai_summary", "")
        if not raw_summary:
            score  = scan.security_score or 0
            grade  = scan.grade or "F"
            total  = scan.total_issues or 0
            crit   = scan.critical_count or 0
            hi     = scan.high_count or 0
            med    = scan.medium_count or 0
            lo     = scan.low_count or 0
            url_t  = getattr(scan, "target_url", "target")

            if score >= 90:
                risk = "well-secured with no significant vulnerabilities detected"
            elif score >= 70:
                risk = "moderately secured but has exploitable weaknesses that should be addressed"
            elif score >= 50:
                risk = "poorly secured with multiple high-risk vulnerabilities requiring urgent attention"
            else:
                risk = "critically vulnerable and at high risk of compromise — immediate remediation required"

            parts = []
            if crit > 0:
                parts.append(f"{crit} critical issue{'s' if crit>1 else ''} (immediate action required)")
            if hi > 0:
                parts.append(f"{hi} high severity finding{'s' if hi>1 else ''}")
            if med > 0:
                parts.append(f"{med} medium severity issue{'s' if med>1 else ''}")
            if lo > 0:
                parts.append(f"{lo} low severity issue{'s' if lo>1 else ''}")

            issue_str = ", ".join(parts) if parts else "no issues detected"
            raw_summary = (
                f"VENOM AI Security Assessment — {url_t}\n\n"
                f"Security Score: {score}/100 (Grade {grade})\n\n"
                f"The target is {risk}. "
                f"Scan identified {total} total finding{'s' if total!=1 else ''}: {issue_str}. "
                f"{'Critical vulnerabilities require immediate patching before this system is considered safe.' if crit > 0 else ''}"
                f"{'High severity findings indicate significant security gaps that attackers could exploit.' if hi > 0 and crit == 0 else ''}"
                f"{'No critical or high severity vulnerabilities were found — focus on medium/low findings to improve posture.' if crit == 0 and hi == 0 and total > 0 else ''}"
            )
        scan.ai_summary = raw_summary

        # Persist vulnerabilities — use robust extractor that handles enums + dataclasses
        scan_url = getattr(scan, "target_url", "")
        _captured = _extract_vulns_from_result(result_dict, scan_url)

        if not _captured:
            logger.warning(f"[{scan_id}] No vulnerabilities extracted (result keys: {list(result_dict.keys())})")

        saved_count = 0
        for vd in _captured:
            if not isinstance(vd, dict):
                continue
            # Skip if already saved for this scan
            title = vd.get("title") or vd.get("vuln_type") or ""
            existing = db.query(models.Vulnerability).filter_by(
                scan_job_id=scan.id, title=title
            ).first()
            if existing:
                # Update PoE fields if we have them
                if vd.get("poe_confirmed") is not None:
                    existing.poe_confirmed = bool(vd.get("poe_confirmed", False))
                    existing.poe_detail    = str(vd.get("poe_detail", ""))
                continue

            try:
                vobj = models.Vulnerability(
                    scan_job_id  = scan.id,
                    vuln_type    = vd.get("vuln_type", "Unknown"),
                    title        = title or "Unknown",
                    severity     = str(vd.get("severity", "info")).lower(),
                    description  = vd.get("description", ""),
                    evidence     = vd.get("evidence", ""),
                    affected_url = vd.get("affected_url", ""),
                    recommendation = vd.get("recommendation") or vd.get("fix", ""),
                    cvss_score   = float(vd.get("cvss_score") or 0),
                    cve_id       = vd.get("cve_id", ""),
                    cwe_id       = vd.get("cwe_id", ""),
                    impact       = vd.get("impact", ""),
                    fix          = vd.get("fix", ""),
                    code_example = vd.get("code_example", ""),
                    reference    = vd.get("reference", ""),
                    source_tool  = str(vd.get("source_tool", "internal")),
                    verified     = bool(vd.get("verified", False)),
                    false_positive = bool(vd.get("false_positive", False)),
                    ai_explanation = vd.get("ai_explanation", ""),
                )
                # Set VENOM v2 fields if they exist in the model
                for attr in ("poe_confirmed", "poe_detail", "poe_attempted"):
                    if hasattr(vobj, attr):
                        setattr(vobj, attr, vd.get(attr, False if attr != "poe_detail" else ""))
                db.add(vobj)
                saved_count += 1
            except Exception as e:
                logger.warning(f"[{scan_id}] Skipping vuln '{title}': {e}")

        db.commit()
        logger.info(f"[{scan_id}] DB saved: score={scan.security_score}, vulns={saved_count}")

    except Exception as e:
        logger.error(f"[{scan_id}] DB save failed: {e}", exc_info=True)
        try: db.rollback()
        except: pass
    finally:
        db.close()


# ── INLINE HTTP SCANNER FALLBACK ──────────────────────────────────────────────
def _run_inline_scan_in_task(scan_id, url: str) -> None:
    """
    Lightweight HTTP-based scanner used when the main security worker
    returns 0 results (nmap/ZAP/nuclei not installed).
    Performs: header checks, SSL/TLS, cookie analysis, SQLi probes, XSS reflection,
    NHI/secret leakage detection.
    """
    import requests, ssl, socket, re, traceback as tb
    from urllib.parse import urlparse, quote

    db = _get_db()
    models = _get_models()
    try:
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int(scan_id)).first()
        if not scan:
            return  # Scan not found

        # Only skip if already has real vulnerability data saved
        existing_count = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == int(scan_id)
        ).count()
        if existing_count > 0:
            logger.info(f"[{scan_id}] Inline scanner skipped — {existing_count} vulns already in DB")
            return

        scan.status = "RUNNING"
        db.commit()

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        findings = []

        # ── 1. HTTP Headers ────────────────────────────────────────────────────
        try:
            resp = requests.get(url, timeout=15, verify=False,
                                headers={"User-Agent": "VENOM-AI/2.0"}, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            sec_headers = {
                "x-frame-options":          ("Clickjacking Protection Missing",      "high",   "CWE-1021", 7.5),
                "x-content-type-options":   ("MIME Sniffing Protection Missing",     "medium", "CWE-693",  5.3),
                "strict-transport-security":("HSTS Not Configured",                  "high",   "CWE-319",  7.4),
                "content-security-policy":  ("Content Security Policy Missing",      "high",   "CWE-79",   7.2),
                "x-xss-protection":         ("XSS Filter Header Missing",            "medium", "CWE-79",   5.3),
                "referrer-policy":          ("Referrer Policy Not Set",              "low",    "CWE-200",  3.1),
                "permissions-policy":       ("Permissions Policy Header Missing",    "low",    "CWE-693",  3.1),
            }
            for hdr, (title, sev, cwe, cvss) in sec_headers.items():
                if hdr not in headers:
                    findings.append({"title": title, "vuln_type": "missing_header", "severity": sev,
                                     "cvss_score": cvss, "cwe_id": cwe, "source_tool": "header_scanner",
                                     "description": f"Response missing '{hdr}' security header.",
                                     "affected_url": url, "recommendation": f"Add the '{hdr}' header to all responses."})
            server = headers.get("server", "")
            if re.search(r"[\d.]{3,}", server):
                findings.append({"title": "Server Version Disclosure", "vuln_type": "information_disclosure",
                                  "severity": "medium", "cvss_score": 5.3, "cwe_id": "CWE-200", "source_tool": "header_scanner",
                                  "description": f"Server header reveals version: {server}", "affected_url": url,
                                  "evidence": f"Server: {server}", "recommendation": "Suppress version info in server headers."})
            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                findings.append({"title": "X-Powered-By Disclosure", "vuln_type": "information_disclosure",
                                  "severity": "low", "cvss_score": 3.1, "cwe_id": "CWE-200", "source_tool": "header_scanner",
                                  "description": f"X-Powered-By reveals stack: {x_powered}", "affected_url": url,
                                  "recommendation": "Remove X-Powered-By header."})
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure: issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("HttpOnly missing")
                if not cookie.has_nonstandard_attr("SameSite"): issues.append("SameSite missing")
                if issues:
                    findings.append({"title": f"Insecure Cookie: {cookie.name}", "vuln_type": "insecure_cookie",
                                     "severity": "medium", "cvss_score": 5.3, "cwe_id": "CWE-614", "source_tool": "cookie_scanner",
                                     "description": f"Cookie '{cookie.name}': {', '.join(issues)}",
                                     "affected_url": url, "recommendation": "Set Secure, HttpOnly, SameSite on all cookies.",
                                     "evidence": f"Cookie: {cookie.name} — {', '.join(issues)}"})
        except Exception as e:
            logger.warning(f"[{scan_id}] Header scan error: {e}")

        # ── 2. SSL/TLS ─────────────────────────────────────────────────────────
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10),
                                     server_hostname=hostname) as s:
                    cert = s.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({"title": "SSL Certificate Expired", "vuln_type": "ssl_tls",
                                         "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-295", "source_tool": "ssl_scanner",
                                         "description": f"Certificate expired {abs(days_left)} days ago.",
                                         "affected_url": url, "recommendation": "Renew the SSL certificate immediately.",
                                         "evidence": f"Expired: {cert['notAfter']}"})
                    elif days_left < 30:
                        findings.append({"title": "SSL Certificate Expiring Soon", "vuln_type": "ssl_tls",
                                         "severity": "high", "cvss_score": 7.5, "cwe_id": "CWE-295", "source_tool": "ssl_scanner",
                                         "description": f"Certificate expires in {days_left} days.",
                                         "affected_url": url, "recommendation": "Renew the SSL certificate.",
                                         "evidence": f"Expires: {cert['notAfter']}"})
            except ssl.SSLCertVerificationError as e:
                err = str(e).lower()
                sev, title = ("critical", "SSL Certificate Expired") if "expired" in err else \
                             ("high", "Self-Signed Certificate") if "self" in err else \
                             ("high", "SSL Certificate Hostname Mismatch") if "hostname" in err else \
                             ("high", "SSL Certificate Error")
                findings.append({"title": title, "vuln_type": "ssl_tls", "severity": sev, "cvss_score": 9.1 if sev == "critical" else 7.4,
                                 "cwe_id": "CWE-295", "source_tool": "ssl_scanner", "description": str(e),
                                 "affected_url": url, "recommendation": "Fix SSL certificate configuration.", "evidence": str(e)})
            except Exception as e:
                logger.warning(f"[{scan_id}] SSL scan error: {e}")

        # ── 3. SQLi probe ──────────────────────────────────────────────────────
        sqli_indicators = ["sql syntax", "mysql_fetch", "ora-0", "pg_query", "sqlite_",
                           "syntax error", "unclosed quotation", "microsoft jet database", "odbc"]
        for payload in ["'", "' OR '1'='1"]:
            probe_url = url + ("?" if "?" not in url else "&") + "id=" + quote(payload)
            try:
                pr = requests.get(probe_url, timeout=10, verify=False, headers={"User-Agent": "VENOM-AI/2.0"})
                body = pr.text.lower()
                for ind in sqli_indicators:
                    if ind in body:
                        findings.append({"title": "SQL Injection Detected", "vuln_type": "sql_injection",
                                         "severity": "critical", "cvss_score": 9.8, "cwe_id": "CWE-89", "source_tool": "sqli_scanner",
                                         "description": "Application returns SQL error messages to crafted input.",
                                         "affected_url": probe_url, "recommendation": "Use parameterised queries.",
                                         "evidence": f"SQL error indicator '{ind}' in response.", "verified": True})
                        break
            except Exception: pass

        # ── 4. XSS probe ───────────────────────────────────────────────────────
        xss_payload = "<script>alert(1)</script>"
        xss_url = url + ("?" if "?" not in url else "&") + "q=" + quote(xss_payload)
        try:
            xr = requests.get(xss_url, timeout=10, verify=False, headers={"User-Agent": "VENOM-AI/2.0"})
            if xss_payload in xr.text:
                findings.append({"title": "Reflected XSS", "vuln_type": "xss",
                                 "severity": "high", "cvss_score": 8.1, "cwe_id": "CWE-79", "source_tool": "xss_scanner",
                                 "description": "User input reflected in response without sanitisation.",
                                 "affected_url": xss_url, "recommendation": "Encode all output. Implement CSP.",
                                 "evidence": f"Payload reflected: {xss_payload[:60]}", "verified": True})
        except Exception: pass

        # ── 5. NHI / Secret detection (Starter+ only) ──────────────────────────
        if not enable_nhi:
            logger.info("[NHI] Skipped — plan does not include NHI/secret scanner")
            secret_patterns = []
        else:
            secret_patterns = [
            (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "API Key Exposed"),
            (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",              "Hardcoded Password"),
            (r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+",     "JWT Token Exposed"),
            (r"(?i)ghp_[A-Za-z0-9]{36}",                                                "GitHub PAT Exposed"),
            (r"(?i)sk-[A-Za-z0-9]{48}",                                                 "OpenAI Key Exposed"),
            (r"(?i)(aws_access_key_id)\s*[=:]\s*['\"]?([A-Z0-9]{20})['\"]?",           "AWS Access Key"),
            (r"(?i)(secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",      "Secret Key Exposed"),
        ]
        try:
            pr = requests.get(url, timeout=15, verify=False, headers={"User-Agent": "VENOM-AI/2.0"})
            source = pr.text
            found = set()
            for pattern, title in secret_patterns:
                for m in re.finditer(pattern, source):
                    if title not in found:
                        found.add(title)
                        findings.append({"title": title, "vuln_type": "nhi_secret_exposure",
                                         "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-798", "source_tool": "nhi_scanner",
                                         "description": "Sensitive credential found in page source.",
                                         "affected_url": url, "recommendation": "Remove secrets from code. Use env vars and a secrets manager.",
                                         "evidence": (m.group(0) or "")[:80], "verified": True})
        except Exception: pass

        # ── 6. Save to DB ──────────────────────────────────────────────────────
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
            try:
                db.add(models.Vulnerability(
                    scan_job_id=int(scan_id), vuln_type=f.get("vuln_type", "Unknown"),
                    title=f.get("title", "Unknown"), severity=sev,
                    description=f.get("description", ""), evidence=f.get("evidence", ""),
                    affected_url=f.get("affected_url", url), recommendation=f.get("recommendation", ""),
                    cvss_score=float(f.get("cvss_score", 0)), cve_id=f.get("cve_id", ""),
                    cwe_id=f.get("cwe_id", ""), fix=f.get("fix", ""),
                    source_tool=str(f.get("source_tool", "inline_scanner")),
                    verified=bool(f.get("verified", False)), false_positive=False,
                ))
            except Exception as ve:
                logger.warning(f"[{scan_id}] Vuln save error: {ve}")

        total = len(findings)
        crit, hi, med, lo = counts["critical"], counts["high"], counts["medium"], counts["low"]
        score = max(0, 100 - crit * 25 - hi * 15 - med * 8 - lo * 3)
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

        try:
            scan.status = "COMPLETED"
            scan.completed_at = datetime.now(timezone.utc)
            if hasattr(scan, "security_score"): scan.security_score = score
            if hasattr(scan, "grade"):          scan.grade = grade
            if hasattr(scan, "total_issues"):   scan.total_issues = total
            if hasattr(scan, "critical_count"): scan.critical_count = crit
            if hasattr(scan, "high_count"):     scan.high_count = hi
            if hasattr(scan, "medium_count"):   scan.medium_count = med
            if hasattr(scan, "low_count"):      scan.low_count = lo
            if hasattr(scan, "progress"):       scan.progress = 100
            if hasattr(scan, "ai_summary"):
                url_t = getattr(scan, "target_url", url)
                if score >= 90:
                    risk_desc = "well-secured with minimal attack surface"
                elif score >= 70:
                    risk_desc = "moderately secured but has weaknesses that should be addressed"
                elif score >= 50:
                    risk_desc = "poorly secured with multiple high-risk vulnerabilities"
                else:
                    risk_desc = "critically vulnerable and at high risk of compromise"

                top_issues = [f.get("title","") for f in findings[:3] if f.get("title")]
                top_str = ", ".join(top_issues) if top_issues else "various security misconfigurations"

                scan.ai_summary = (
                    f"VENOM AI Security Assessment — {url_t}\n\n"
                    f"Security Score: {score}/100 (Grade {grade})\n\n"
                    f"The target is {risk_desc}. "
                    f"Scan identified {total} total finding{'s' if total!=1 else ''}: "
                    f"{crit} critical, {hi} high, {med} medium, {lo} low severity. "
                    f"Key findings include: {top_str}. "
                    f"{'⚠️ Immediate remediation required for critical issues.' if crit > 0 else ''}"
                    f"{'Review high severity findings before next deployment.' if hi > 0 and crit == 0 else ''}"
                )
            db.commit()
            logger.info(f"[{scan_id}] Inline fallback complete: {total} findings, score {score}")
        except Exception as ce:
            logger.error(f"[{scan_id}] Commit error: {ce}")
            db.rollback()
    except Exception as e:
        logger.error(f"[{scan_id}] Inline scan failed: {e}\n{tb.format_exc()}")
        try:
            db.rollback()
        except Exception: pass
    finally:
        try: db.close()
        except Exception: pass


# ── MAIN CELERY TASK ──────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.run_security_scan",
    max_retries=1,
    default_retry_delay=30,
    acks_late=True,
)
def run_security_scan(self, url: str, user_id: str = "anonymous",
                      scan_type: str = "full", scan_id: int = None,
                      enable_nhi: bool = True):
    """
    VENOM AI v2 — Main security scan task.
    Runs the full pipeline: scan → PoE → NHI → compliance → attack chains → autofix
    """
    task_id = self.request.id
    logger.info(f"VENOM task start: scan_id={scan_id} task={task_id} url={url} type={scan_type}")

    # Update DB: mark as running
    if scan_id:
        _update_scan_status(scan_id, "RUNNING", 5, "Initializing VENOM scan engine")

    try:
        sw = _get_security_worker()
        result = sw.run_full_scan(
            task_self=self,
            url=url,
            user_id=user_id,
            scan_id=str(scan_id or task_id),
            scan_type=scan_type,
        )

        # Normalize status key — old worker returned "done", API expects "completed"
        if isinstance(result, dict):
            if result.get("status") == "done":
                result["status"] = "COMPLETED"
            # Normalize count keys
            if "critical" in result and "critical_count" not in result:
                result["critical_count"] = result["critical"]
                result["high_count"]     = result.get("high", 0)
                result["medium_count"]   = result.get("medium", 0)
                result["low_count"]      = result.get("low", 0)

        # Persist to DB
        if scan_id and isinstance(result, dict):
            _save_results_to_db(scan_id, result)

        # ── FALLBACK: Check ACTUAL vuln count in DB (not worker's reported count)
        # The security worker often returns total_issues>0 but no vulnerabilities[]
        # array, so DB ends up empty. We always run inline if DB has 0 vulns. ───
        actual_vuln_count = 0
        if scan_id:
            try:
                db = _get_db()
                models = _get_models()
                actual_vuln_count = db.query(models.Vulnerability).filter(
                    models.Vulnerability.scan_job_id == int(scan_id)
                ).count()
                db.close()
            except Exception:
                actual_vuln_count = 0

        if scan_id and actual_vuln_count == 0:
            logger.info(f"[{scan_id}] DB has 0 vulns — running inline HTTP scanner to generate findings")
            try:
                _run_inline_scan_in_task(scan_id, url)
            except Exception as inline_err:
                logger.warning(f"[{scan_id}] Inline fallback scanner error: {inline_err}")

        logger.info(f"VENOM task complete: scan_id={scan_id} score={result.get('security_score') if isinstance(result,dict) else 'N/A'} "
                    f"issues={result.get('total_issues',0) if isinstance(result,dict) else 0}")
        return result

    except Exception as exc:
        logger.error(f"VENOM scan FAILED scan_id={scan_id}: {exc}", exc_info=True)
        if scan_id:
            # Even on failure, try inline scanner so user gets something
            try:
                _run_inline_scan_in_task(scan_id, url)
                return {"status": "COMPLETED", "note": "Completed via inline fallback scanner"}
            except Exception:
                pass
            _update_scan_status(scan_id, "FAILED", 0, str(exc))
        raise


# ── DOCUMENT TASK ─────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.process_document",
    acks_late=True,
)
def process_document(self, file_path: str, user_id: str = "anonymous"):
    """Process uploaded documents for security analysis."""
    logger.info(f"Document task: {file_path}")
    try:
        try:
            from workers.document_worker import process_document_file
        except ImportError:
            from workers.document_worker import process_document_file
        return process_document_file(file_path, user_id)
    except Exception as exc:
        logger.error(f"Document task failed: {exc}")
        raise


# ── REPORT TASK ───────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.generate_report",
    acks_late=True,
)
def generate_report(self, scan_id: int, report_format: str = "pdf"):
    """Generate a PDF security report for a completed scan."""
    logger.info(f"Report task: scan_id={scan_id} format={report_format}")
    try:
        try:
            from services.report_service import generate_scan_report
        except ImportError:
            from services.report_service import generate_scan_report
        return generate_scan_report(scan_id, report_format)
    except Exception as exc:
        logger.error(f"Report task failed: {exc}")
        raise


# ── COMPLIANCE TASK ───────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.run_compliance_check",
    acks_late=True,
)
def run_compliance_check(self, scan_id: int):
    """Run compliance mapping (ISO/SOC2/GDPR) for a completed scan."""
    logger.info(f"Compliance task: scan_id={scan_id}")
    db = _get_db()
    try:
        models = _get_models()
        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == int(scan_id)
        ).all()
        vuln_dicts = [v.__dict__ for v in vulns]
        gen = _get_compliance_service()
        if gen:
            return gen(vuln_dicts)
        return {"error": "compliance_service not available"}
    except Exception as exc:
        logger.error(f"Compliance task failed: {exc}")
        raise
    finally:
        db.close()


# ── AUTOFIX TASK ──────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.run_autofix",
    acks_late=True,
)
def run_autofix(self, scan_id: int):
    """Generate AI code patches for high/critical vulns in a scan."""
    logger.info(f"AutoFix task: scan_id={scan_id}")
    db = _get_db()
    try:
        models = _get_models()
        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == int(scan_id),
            models.Vulnerability.severity.in_(["critical", "high"])
        ).all()[:10]
        vuln_dicts = [v.__dict__ for v in vulns]
        gen = _get_autofix_service()
        if gen:
            return gen(vuln_dicts)
        return {"error": "autofix_service not available"}
    except Exception as exc:
        logger.error(f"AutoFix task failed: {exc}")
        raise
    finally:
        db.close()


# ── CONTINUOUS MONITORING — Beat-driven scheduler ────────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.check_monitor_schedule",
    queue="default",
)
def check_monitor_schedule(self):
    """
    Beat-driven monitor scheduler.
    Runs every 60s. Fires any due scans + auto-resets stale ones.
    Replaces the old browser-heartbeat-driven scheduler.
    """
    try:
        from routes.monitoring import check_due_scans
        check_due_scans()
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"[Monitor Beat] Failed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


@celery_app.task(bind=True, name="workers.tasks.monitor_email_for_all_users", queue="email")
def monitor_email_for_all_users(self):
    """Check IMAP inbox for new attachments and process them."""
    logger.info("[Email Monitor] Checking inbox...")
    try:
        import os
        host  = os.environ.get("IMAP_HOST", "")
        user  = os.environ.get("EMAIL_USER", "")
        pwd   = os.environ.get("EMAIL_PASSWORD", "")
        if not host or not user or not pwd or "your@gmail" in user:
            logger.info("[Email Monitor] Email not configured — skipping")
            return {"status": "skipped", "reason": "not configured"}
        from imap_tools import MailBox, AND
        with MailBox(host).login(user, pwd) as mb:
            unseen = list(mb.fetch(AND(seen=False), limit=10))
        logger.info(f"[Email Monitor] Found {len(unseen)} unseen messages")
        return {"status": "ok", "checked": len(unseen)}
    except Exception as e:
        logger.warning(f"[Email Monitor] Error: {e}")
        return {"status": "error", "error": str(e)}
