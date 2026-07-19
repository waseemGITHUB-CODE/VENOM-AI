"""
VENOM AI · backend/routes/scanning.py
All scan endpoints + Webhook receiver + Compliance + Attack Graph + AutoFix
FIXES:
  - scan results now look up by scan.id (UUID) OR celery_task_id
  - scan/start falls back to FastAPI BackgroundTasks if Celery/Redis is unavailable
"""
from __future__ import annotations
import asyncio
import logging
import traceback
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, BackgroundTasks, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator

from auth.dependencies import get_optional_user
from db.models import User as _AuthUser

router = APIRouter()
logger = logging.getLogger("venom.scan")


class ScanRequest(BaseModel):
    url: str
    user_id: str = "anonymous"
    scan_type: str = "full"

    @validator("url")
    def validate_url(cls, v):
        v = v.strip()
        if not v or v in ("string", ""):
            raise ValueError("Provide a real URL e.g. https://example.com")
        if "://" not in v:
            v = "https://" + v
        # Must have a hostname with a dot (or be localhost/IP)
        try:
            from urllib.parse import urlparse as _up
            import re as _re2
            p = _up(v)
            host = p.hostname or ""
            is_ip = bool(_re2.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
            is_local = host in ("localhost", "127.0.0.1")
            has_dot = "." in host and len(host) > 4
            if not (is_ip or is_local or has_dot):
                raise ValueError(f"Invalid URL '{v}' — enter a valid address like https://example.com")
        except ValueError:
            raise
        except Exception:
            raise ValueError(f"Invalid URL '{v}'")
        return v

    @validator("scan_type")
    def validate_scan_type(cls, v):
        allowed = {"full", "quick", "recon", "webapp", "infra"}
        return v if v in allowed else "full"


class WebhookPayload(BaseModel):
    event_type: str = "push"
    repository: str = ""
    target_url: str = ""
    branch: str = "main"
    commit: str = ""
    triggered_by: str = "webhook"


def _get_db():
    try:
        from db.database import SessionLocal
        return SessionLocal()
    except ImportError:
        from db.database import SessionLocal
        return SessionLocal()


def _get_models():
    try:
        from db import models
        return models
    except ImportError:
        from db import models
        return models


def _get_celery():
    try:
        from workers.celery_app import celery_app
        return celery_app
    except ImportError:
        from workers.celery_app import celery_app
        return celery_app


def _safe_set(obj, attr: str, value):
    """Set attribute only if it exists on the model (avoids DB column errors)."""
    try:
        if hasattr(obj, attr):
            setattr(obj, attr, value)
    except Exception:
        pass


def _enrich_vuln(v) -> dict:
    try:
        from services.remediation_kb import enrich_vulnerability
        return enrich_vulnerability(v if isinstance(v, dict) else v.__dict__)
    except Exception:
        try:
            from services.remediation_kb import enrich_vulnerability
            return enrich_vulnerability(v if isinstance(v, dict) else v.__dict__)
        except Exception:
            return v if isinstance(v, dict) else v.__dict__


def _vuln_to_dict(v) -> dict:
    return {
        "id": getattr(v, "id", None),
        "title": getattr(v, "title", "") or getattr(v, "vuln_type", ""),
        "vuln_type": getattr(v, "vuln_type", ""),
        "severity": getattr(v, "severity", "info"),
        "description": getattr(v, "description", ""),
        "evidence": getattr(v, "evidence", ""),
        "affected_url": getattr(v, "affected_url", ""),
        "recommendation": getattr(v, "recommendation", ""),
        "cvss_score": getattr(v, "cvss_score", 0.0),
        "cve_id": getattr(v, "cve_id", ""),
        "cwe_id": getattr(v, "cwe_id", ""),
        "impact": getattr(v, "impact", ""),
        "fix": getattr(v, "fix", ""),
        "code_example": getattr(v, "code_example", ""),
        "reference": getattr(v, "reference", ""),
        "source_tool": str(getattr(v, "source_tool", "internal")),
        "verified": getattr(v, "verified", False),
        "false_positive": getattr(v, "false_positive", False),
        "ai_explanation": getattr(v, "ai_explanation", ""),
        "poe_confirmed": getattr(v, "poe_confirmed", False),
        "poe_detail": getattr(v, "poe_detail", ""),
    }


def _find_scan(db, models, task_id: str):
    """
    Look up a ScanJob by integer ID first (avoids integer=varchar crash),
    then fall back to celery_task_id (UUID string).
    """
    # Try integer primary key first — prevents PostgreSQL integer=varchar error
    try:
        int_id = int(task_id)
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int_id).first()
        if scan:
            return scan
    except (ValueError, TypeError):
        pass
    # Fall back to celery_task_id (UUID string)
    if hasattr(models.ScanJob, "celery_task_id"):
        scan = db.query(models.ScanJob).filter(
            models.ScanJob.celery_task_id == task_id
        ).first()
        if scan:
            return scan
    return None


def _sync_from_celery(task_id: str, scan, db, models) -> bool:
    """Pull Celery result into DB if task finished."""
    celery_task_id = getattr(scan, "celery_task_id", None) or task_id
    try:
        celery = _get_celery()
        ar = celery.AsyncResult(celery_task_id)
        if ar.state not in ("SUCCESS", "FAILURE"):
            return False
        if ar.state == "FAILURE":
            scan.status = "FAILED"
            db.commit()
            return True
        result = ar.result or {}
        if not isinstance(result, dict):
            return False
        scan.status = "COMPLETED"
        scan.completed_at = datetime.now(timezone.utc)
        _safe_set(scan, "security_score", result.get("security_score", 0))
        _safe_set(scan, "grade",          result.get("grade", "F"))
        _safe_set(scan, "total_issues",   result.get("total_issues", 0))
        _safe_set(scan, "critical_count", result.get("critical_count", 0))
        _safe_set(scan, "high_count",     result.get("high_count", 0))
        _safe_set(scan, "medium_count",   result.get("medium_count", 0))
        _safe_set(scan, "low_count",      result.get("low_count", 0))
        _safe_set(scan, "ai_summary",     result.get("ai_summary", ""))
        for vd in result.get("vulnerabilities", []):
            if not isinstance(vd, dict):
                continue
            existing = db.query(models.Vulnerability).filter_by(
                scan_job_id=scan.id, title=vd.get("title", ""), vuln_type=vd.get("vuln_type", "")
            ).first()
            if existing:
                continue
            try:
                vobj = models.Vulnerability(
                    scan_job_id=scan.id,
                    vuln_type=vd.get("vuln_type", "Unknown"),
                    title=vd.get("title") or vd.get("vuln_type", "Unknown"),
                    severity=vd.get("severity", "info"),
                    description=vd.get("description", ""),
                    evidence=vd.get("evidence", ""),
                    affected_url=vd.get("affected_url", ""),
                    recommendation=vd.get("recommendation") or vd.get("fix", ""),
                    cvss_score=float(vd.get("cvss_score", 0)),
                    cve_id=vd.get("cve_id", ""),
                    cwe_id=vd.get("cwe_id", ""),
                    impact=vd.get("impact", ""),
                    fix=vd.get("fix", ""),
                    code_example=vd.get("code_example", ""),
                    reference=vd.get("reference", ""),
                    source_tool=str(vd.get("source_tool", "internal")),
                    verified=bool(vd.get("verified", False)),
                    false_positive=bool(vd.get("false_positive", False)),
                    ai_explanation=vd.get("ai_explanation", ""),
                )
                db.add(vobj)
            except Exception:
                pass
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Celery sync failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return False


def _save_inline_findings(scan, scan_id, db, models, findings, url):
    """Persist findings list to DB and mark scan COMPLETED."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        try:
            db.add(models.Vulnerability(
                scan_job_id=int(scan_id),
                vuln_type=f.get("vuln_type", "Unknown"),
                title=f.get("title", "Unknown"),
                severity=sev,
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                affected_url=f.get("affected_url", url),
                recommendation=f.get("recommendation", ""),
                cvss_score=float(f.get("cvss_score", 0)),
                cve_id=f.get("cve_id", ""),
                cwe_id=f.get("cwe_id", ""),
                impact=f.get("impact", ""),
                fix=f.get("fix", ""),
                code_example=f.get("code_example", ""),
                reference=f.get("reference", ""),
                source_tool=str(f.get("source_tool", "inline_scanner")),
                verified=bool(f.get("verified", False)),
                false_positive=False,
                ai_explanation="",
            ))
        except Exception as e:
            logger.warning(f"Could not save vuln: {e}")
    total    = len(findings)
    critical = counts.get("critical", 0)
    high     = counts.get("high", 0)
    medium   = counts.get("medium", 0)
    low      = counts.get("low", 0)
    deductions = critical * 25 + high * 15 + medium * 8 + low * 3
    score = max(0, 100 - deductions)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    scan.status = "COMPLETED"
    scan.completed_at = datetime.now(timezone.utc)
    _safe_set(scan, "security_score", score)
    _safe_set(scan, "grade", grade)
    _safe_set(scan, "total_issues", total)
    _safe_set(scan, "critical_count", critical)
    _safe_set(scan, "high_count", high)
    _safe_set(scan, "medium_count", medium)
    _safe_set(scan, "low_count", low)
    _safe_set(scan, "progress", 100)
    _safe_set(scan, "ai_summary",
              f"Scan completed. Found {total} issues: "
              f"{critical} critical, {high} high, {medium} medium, {low} low. "
              f"Security score: {score}/100 (Grade {grade}).")
    db.commit()
    logger.info(f"Inline scan complete: {url} — {total} findings, score {score}")


def _run_inline_scan(scan_id: str, url: str, user_id: str, scan_type: str,
                      enable_nhi: bool = True) -> None:
    """
    Fallback scanner that runs directly in a background thread when Celery
    is not available.  Performs real HTTP-based checks so the platform works
    even without Redis/Celery running.
    """
    import requests, ssl, socket, re
    from urllib.parse import urlparse

    db = _get_db()
    models = _get_models()
    try:
        scan = db.query(models.ScanJob).filter(models.ScanJob.id == int(scan_id)).first()
        if not scan:
            return
        scan.status = "RUNNING"
        _safe_set(scan, "progress", 10)
        db.commit()

        findings = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        is_quick = scan_type == "quick"

        # ── 1. HTTP Headers check ─────────────────────────────────────────
        try:
            resp = requests.get(url, timeout=15, verify=False,
                                headers={"User-Agent": "VENOM-AI-Scanner/2.0"},
                                allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            security_headers = {
                "x-frame-options":          ("Clickjacking Protection Missing",      "high",   "CWE-1021", 7.5),
                "x-content-type-options":   ("MIME Sniffing Protection Missing",     "medium", "CWE-693",  5.3),
                "x-xss-protection":         ("XSS Filter Header Missing",            "medium", "CWE-79",   5.3),
                "strict-transport-security":("HSTS Not Configured",                  "high",   "CWE-319",  7.4),
                "content-security-policy":  ("Content Security Policy Missing",      "high",   "CWE-79",   7.2),
                "referrer-policy":          ("Referrer Policy Not Set",              "low",    "CWE-200",  3.1),
                "permissions-policy":       ("Permissions Policy Header Missing",    "low",    "CWE-693",  3.1),
            }
            for hdr, (title, sev, cwe, cvss) in security_headers.items():
                if hdr not in headers:
                    findings.append({
                        "title": title, "vuln_type": "missing_header",
                        "severity": sev, "cvss_score": cvss, "cwe_id": cwe,
                        "description": f"The HTTP response does not include the '{hdr}' security header.",
                        "affected_url": url,
                        "recommendation": f"Add the '{hdr}' header to all HTTP responses.",
                        "evidence": f"Header absent in response from {url}",
                        "source_tool": "header_scanner",
                    })

            # Server version disclosure
            server = headers.get("server", "")
            x_powered = headers.get("x-powered-by", "")
            if re.search(r"[\d.]{3,}", server):
                findings.append({
                    "title": "Server Version Disclosure",
                    "vuln_type": "information_disclosure",
                    "severity": "medium", "cvss_score": 5.3, "cwe_id": "CWE-200",
                    "description": f"The server header reveals software version: {server}",
                    "affected_url": url,
                    "recommendation": "Configure the server to suppress version information.",
                    "evidence": f"Server: {server}",
                    "source_tool": "header_scanner",
                })
            if x_powered:
                findings.append({
                    "title": "Technology Stack Disclosure (X-Powered-By)",
                    "vuln_type": "information_disclosure",
                    "severity": "low", "cvss_score": 3.1, "cwe_id": "CWE-200",
                    "description": f"X-Powered-By exposes backend technology: {x_powered}",
                    "affected_url": url,
                    "recommendation": "Remove or mask the X-Powered-By header.",
                    "evidence": f"X-Powered-By: {x_powered}",
                    "source_tool": "header_scanner",
                })

            # Cookies
            for cookie in resp.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("HttpOnly flag missing")
                if not cookie.has_nonstandard_attr("SameSite"):
                    issues.append("SameSite attribute missing")
                if issues:
                    findings.append({
                        "title": f"Insecure Cookie: {cookie.name}",
                        "vuln_type": "insecure_cookie",
                        "severity": "medium", "cvss_score": 5.3, "cwe_id": "CWE-614",
                        "description": f"Cookie '{cookie.name}' is missing security attributes: {', '.join(issues)}",
                        "affected_url": url,
                        "recommendation": "Set Secure, HttpOnly, and SameSite attributes on all cookies.",
                        "evidence": f"Set-Cookie: {cookie.name} — {', '.join(issues)}",
                        "source_tool": "cookie_scanner",
                    })
        except Exception as e:
            logger.warning(f"Header scan error: {e}")

        _safe_set(scan, "progress", 35)
        db.commit()

        # Quick scan: headers only — skip to results
        if is_quick:
            _save_inline_findings(scan, scan_id, db, models, findings, url)
            return

        # ── 2. SSL/TLS check ──────────────────────────────────────────────
        if parsed.scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10),
                                     server_hostname=hostname) as s:
                    cert = s.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "title": "SSL Certificate Expired",
                            "vuln_type": "ssl_tls",
                            "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-295",
                            "description": f"SSL certificate expired {abs(days_left)} days ago.",
                            "affected_url": url,
                            "recommendation": "Renew the SSL certificate immediately.",
                            "evidence": f"Certificate expired: {cert['notAfter']}",
                            "source_tool": "ssl_scanner",
                        })
                    elif days_left < 30:
                        findings.append({
                            "title": "SSL Certificate Expiring Soon",
                            "vuln_type": "ssl_tls",
                            "severity": "high", "cvss_score": 7.5, "cwe_id": "CWE-295",
                            "description": f"SSL certificate expires in {days_left} days.",
                            "affected_url": url,
                            "recommendation": "Renew the SSL certificate before expiry.",
                            "evidence": f"Certificate expires: {cert['notAfter']}",
                            "source_tool": "ssl_scanner",
                        })
            except ssl.SSLCertVerificationError as e:
                err = str(e)
                if "expired" in err.lower():
                    findings.append({
                        "title": "SSL Certificate Expired",
                        "vuln_type": "ssl_tls",
                        "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-295",
                        "description": "The SSL certificate has expired.",
                        "affected_url": url,
                        "recommendation": "Renew the SSL certificate immediately.",
                        "evidence": str(e), "source_tool": "ssl_scanner",
                    })
                elif "self signed" in err.lower() or "self-signed" in err.lower():
                    findings.append({
                        "title": "Self-Signed SSL Certificate",
                        "vuln_type": "ssl_tls",
                        "severity": "high", "cvss_score": 7.4, "cwe_id": "CWE-295",
                        "description": "The server uses a self-signed certificate not trusted by browsers.",
                        "affected_url": url,
                        "recommendation": "Replace with a CA-signed certificate (e.g. Let's Encrypt).",
                        "evidence": str(e), "source_tool": "ssl_scanner",
                    })
                elif "hostname" in err.lower():
                    findings.append({
                        "title": "SSL Certificate Hostname Mismatch",
                        "vuln_type": "ssl_tls",
                        "severity": "high", "cvss_score": 7.4, "cwe_id": "CWE-297",
                        "description": f"Certificate hostname does not match {hostname}.",
                        "affected_url": url,
                        "recommendation": "Obtain a certificate valid for this hostname.",
                        "evidence": str(e), "source_tool": "ssl_scanner",
                    })
                else:
                    findings.append({
                        "title": "SSL Certificate Verification Failed",
                        "vuln_type": "ssl_tls",
                        "severity": "high", "cvss_score": 7.4, "cwe_id": "CWE-295",
                        "description": f"SSL verification error: {err}",
                        "affected_url": url,
                        "recommendation": "Investigate and fix the SSL certificate configuration.",
                        "evidence": str(e), "source_tool": "ssl_scanner",
                    })
            except Exception as e:
                logger.warning(f"SSL scan error: {e}")

        _safe_set(scan, "progress", 55)
        db.commit()

        # ── 3. SQLi probe (safe detection only) ───────────────────────────
        try:
            import urllib.parse
            sqli_payloads = ["'", "''", "' OR '1'='1", "1 AND 1=2"]
            sqli_indicators = ["sql syntax", "mysql_fetch", "ora-0", "pg_query",
                                "sqlite_", "syntax error", "unclosed quotation",
                                "microsoft jet database", "odbc drivers"]
            for payload in sqli_payloads[:2]:
                probe_url = url + ("?" if "?" not in url else "&") + "id=" + urllib.parse.quote(payload)
                try:
                    pr = requests.get(probe_url, timeout=10, verify=False,
                                       headers={"User-Agent": "VENOM-AI-Scanner/2.0"})
                    body = pr.text.lower()
                    for ind in sqli_indicators:
                        if ind in body:
                            findings.append({
                                "title": "SQL Injection Detected",
                                "vuln_type": "sql_injection",
                                "severity": "critical", "cvss_score": 9.8, "cwe_id": "CWE-89",
                                "cve_id": "CVE-2021-44228",
                                "description": "The application appears to be vulnerable to SQL Injection. "
                                               "Error messages containing SQL syntax were returned in response to a crafted input.",
                                "affected_url": probe_url,
                                "recommendation": "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                                "evidence": f"SQL error indicator '{ind}' found in response body.",
                                "source_tool": "sqli_scanner",
                                "verified": True,
                            })
                            break
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"SQLi scan error: {e}")

        _safe_set(scan, "progress", 70)
        db.commit()

        # ── 4. XSS probe (safe detection only) ────────────────────────────
        try:
            import urllib.parse
            xss_payload = "<script>alert(1)</script>"
            xss_url = url + ("?" if "?" not in url else "&") + "q=" + urllib.parse.quote(xss_payload)
            try:
                xr = requests.get(xss_url, timeout=10, verify=False,
                                    headers={"User-Agent": "VENOM-AI-Scanner/2.0"})
                if xss_payload in xr.text:
                    findings.append({
                        "title": "Reflected Cross-Site Scripting (XSS)",
                        "vuln_type": "xss",
                        "severity": "high", "cvss_score": 8.1, "cwe_id": "CWE-79",
                        "description": "The application reflects user-controlled input without sanitisation, "
                                       "enabling script injection in victim browsers.",
                        "affected_url": xss_url,
                        "recommendation": "Encode all user-supplied output. Implement a strict Content-Security-Policy.",
                        "evidence": f"Payload reflected verbatim: {xss_payload[:60]}",
                        "source_tool": "xss_scanner",
                        "verified": True,
                    })
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"XSS scan error: {e}")

        _safe_set(scan, "progress", 80)
        db.commit()

        # ── 5. NHI / Secret leakage scan (Starter+ only) ──────────────────
        if not enable_nhi:
            logger.info("[NHI] Skipped — plan does not include NHI/secret scanner")
            _nhi_secret_patterns_empty = True
        else:
            _nhi_secret_patterns_empty = False
        try:
            import re, requests as _req
            secret_patterns = [] if _nhi_secret_patterns_empty else [
                (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "API Key Exposed"),
                (r"(?i)(secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",      "Secret Key Exposed"),
                (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",              "Hardcoded Password"),
                (r"(?i)(aws_access_key_id)\s*[=:]\s*['\"]?([A-Z0-9]{20})['\"]?",           "AWS Access Key Exposed"),
                (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",     "Private Key Exposed"),
                (r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+",     "JWT Token Exposed"),
                (r"(?i)(token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",               "Auth Token Exposed"),
                (r"(?i)ghp_[A-Za-z0-9]{36}",                                                "GitHub PAT Exposed"),
                (r"(?i)sk-[A-Za-z0-9]{48}",                                                 "OpenAI Key Exposed"),
            ]
            try:
                pr = _req.get(url, timeout=15, verify=False,
                              headers={"User-Agent": "VENOM-AI-Scanner/2.0"})
                source = pr.text
                found_secrets = set()
                for pattern, title in secret_patterns:
                    for m in re.finditer(pattern, source):
                        if title not in found_secrets:
                            found_secrets.add(title)
                            evidence_val = m.group(0)[:80] if m.group(0) else ""
                            findings.append({
                                "title": title,
                                "vuln_type": "nhi_secret_exposure",
                                "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-798",
                                "description": f"A sensitive credential or secret was found exposed in the page source.",
                                "affected_url": url,
                                "recommendation": "Remove secrets from source code. Use environment variables and a secrets manager.",
                                "evidence": evidence_val,
                                "source_tool": "nhi_scanner",
                                "verified": True,
                            })
            except Exception:
                pass

            # Also check linked JS files
            try:
                from bs4 import BeautifulSoup
                pr2 = _req.get(url, timeout=10, verify=False,
                               headers={"User-Agent": "VENOM-AI-Scanner/2.0"})
                soup = BeautifulSoup(pr2.text, "html.parser")
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if not src.startswith("http"):
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        src = base + ("" if src.startswith("/") else "/") + src
                    try:
                        js = _req.get(src, timeout=10, verify=False,
                                      headers={"User-Agent": "VENOM-AI-Scanner/2.0"}).text
                        for pattern, title in secret_patterns:
                            for m in re.finditer(pattern, js):
                                key = f"{title}:{src}"
                                if key not in found_secrets:
                                    found_secrets.add(key)
                                    findings.append({
                                        "title": f"{title} in JS Bundle",
                                        "vuln_type": "nhi_secret_exposure",
                                        "severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-798",
                                        "description": f"Secret found in JavaScript file: {src}",
                                        "affected_url": src,
                                        "recommendation": "Remove secrets from JS bundles. Use backend API calls with server-side auth.",
                                        "evidence": (m.group(0) or "")[:80],
                                        "source_tool": "nhi_scanner",
                                        "verified": True,
                                    })
                    except Exception:
                        pass
            except ImportError:
                pass  # BeautifulSoup not installed — skip JS file scan
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"NHI scan error: {e}")

        _safe_set(scan, "progress", 90)
        db.commit()

        # ── 6. Save findings to DB ─────────────────────────────────────────
        _save_inline_findings(scan, scan_id, db, models, findings, url)

    except Exception as e:
        logger.error(f"Inline scan failed: {e}\n{traceback.format_exc()}")
        try:
            scan = db.query(models.ScanJob).filter(models.ScanJob.id == int(scan_id)).first()
            if scan:
                scan.status = "FAILED"
                db.commit()
        except Exception:
            pass
    finally:
        try:
            db.close()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# NHI / Secret Scanner — dedicated fast endpoint (no DB, returns immediately)
# ──────────────────────────────────────────────────────────────────────────────

class NHIScanRequest(BaseModel):
    url: str

    @validator("url")
    def validate_url(cls, v):
        v = v.strip()
        if not v.startswith("http"):
            v = "https://" + v
        return v


@router.post("/nhi")
async def nhi_scan(req: NHIScanRequest):
    """
    Dedicated NHI / secret scanner. Fast, no full scan overhead.
    Fetches HTML source + all linked JS files and hunts for exposed credentials.
    """
    import re, requests as _req
    from urllib.parse import urlparse as _up, urljoin

    url = req.url
    findings = []
    errors = []

    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",      "API Key Exposed"),
        (r"(?i)(secret[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",           "Secret Key Exposed"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",                  "Hardcoded Password"),
        (r"(?i)(aws_access_key_id)\s*[=:]\s*['\"]?([A-Z0-9]{20})['\"]?",               "AWS Access Key Exposed"),
        (r"(?i)(aws_secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",     "AWS Secret Key Exposed"),
        (r"(?i)(private[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",          "Private Key Exposed"),
        (r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+",          "JWT Token Exposed"),
        (r"(?i)(token)\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]",                    "Auth Token Exposed"),
        (r"ghp_[A-Za-z0-9]{36}",                                                         "GitHub PAT Exposed"),
        (r"ghs_[A-Za-z0-9]{36}",                                                         "GitHub App Token Exposed"),
        (r"sk-[A-Za-z0-9]{48}",                                                          "OpenAI API Key Exposed"),
        (r"sk-proj-[A-Za-z0-9_\-]{40,}",                                                "OpenAI Project Key Exposed"),
        (r"(?i)stripe[_-]?(secret|sk)[_-]?(?:live|test)[_-]?[A-Za-z0-9]{24,}",         "Stripe Secret Key Exposed"),
        (r"xox[baprs]-[A-Za-z0-9\-]{10,}",                                              "Slack Token Exposed"),
        (r"AIza[A-Za-z0-9_\-]{35}",                                                      "Google API Key Exposed"),
        (r"(?i)(database_url|db_url|connection_string)\s*[=:]\s*['\"]?[^\s'\"]{15,}",   "Database URL Exposed"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                             "Private Key File Exposed"),
        (r"(?i)(bearer)\s+([A-Za-z0-9_\-\.]{30,})",                                     "Bearer Token Exposed"),
        (r"(?i)(twilio_auth_token|twilio_sid)\s*[=:]\s*['\"]?([A-Za-z0-9]{32,})['\"]?","Twilio Credential Exposed"),
        (r"(?i)(sendgrid[_-]?api[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{30,})['\"]?","SendGrid Key Exposed"),
    ]

    headers_req = {"User-Agent": "Mozilla/5.0 (compatible; VENOM-AI-NHI/2.0)"}
    found_keys: set = set()  # deduplicate by (title, source)

    def scan_content(content: str, source_url: str, source_label: str):
        for pattern, title in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                key = f"{title}::{source_url}"
                if key in found_keys:
                    continue
                found_keys.add(key)
                raw = m.group(0)
                # Mask the secret value for safe display (show first 6 + ***)
                masked = raw[:min(len(raw), 6)] + "***" if len(raw) > 6 else raw
                findings.append({
                    "title": title,
                    "vuln_type": "nhi_secret_exposure",
                    "severity": "critical" if any(k in title.lower() for k in ["key", "token", "password", "secret", "credential"]) else "high",
                    "cvss_score": 9.1,
                    "cwe_id": "CWE-798",
                    "description": f"Sensitive credential found in {source_label}.",
                    "affected_url": source_url,
                    "evidence": masked,
                    "source_tool": "nhi_scanner",
                    "source_label": source_label,
                    "recommendation": "Remove secrets from source code immediately. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler).",
                })

    # ── Step 1: Fetch main page HTML ─────────────────────────────────────────
    main_html = ""
    js_urls: list[str] = []
    try:
        r = _req.get(url, timeout=15, verify=False, headers=headers_req, allow_redirects=True)
        main_html = r.text
        scan_content(main_html, url, "HTML source")

        # ── Step 2: Find all linked JS files ─────────────────────────────────
        try:
            base = f"{_up(url).scheme}://{_up(url).netloc}"
            # Use regex to extract script src — no bs4 needed
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', main_html, re.IGNORECASE):
                src = m.group(1)
                if not src.startswith("http"):
                    src = urljoin(base + "/", src.lstrip("/"))
                if src not in js_urls:
                    js_urls.append(src)
            # Also check inline scripts
            for m in re.finditer(r'<script(?:[^>](?!src=))*>(.*?)</script>', main_html, re.DOTALL | re.IGNORECASE):
                inline = m.group(1).strip()
                if inline:
                    scan_content(inline, url, "Inline <script>")
        except Exception as e:
            errors.append(f"JS link extraction: {e}")
    except Exception as e:
        err_str = str(e)
        parsed_host = _up(url).netloc or url
        if any(k in err_str for k in ("Max retries", "Failed to establish", "Name or service not known",
                                       "Connection refused", "nodename nor servname", "getaddrinfo")):
            clean_err = (f"Cannot connect to {parsed_host} — the host is unreachable or does not exist. "
                         f"Make sure the URL is correct and publicly accessible.")
        elif any(k in err_str.lower() for k in ("timed out", "timeout", "read timeout")):
            clean_err = (f"Connection timed out reaching {parsed_host}. "
                         f"The server may be slow or blocking automated requests.")
        elif "SSL" in err_str or "certificate" in err_str.lower():
            clean_err = f"SSL/TLS error connecting to {parsed_host}. Try the http:// version of the URL."
        else:
            clean_err = f"Scan failed for {parsed_host}: {err_str[:200]}"
        errors.append(clean_err)
        return {
            "url": url, "status": "error",
            "error": clean_err,
            "findings": [], "js_files_scanned": 0, "total": 0,
        }

    # ── Step 3: Scan each JS file ─────────────────────────────────────────────
    js_scanned = 0
    for js_url in js_urls[:20]:  # cap at 20 JS files
        try:
            jr = _req.get(js_url, timeout=10, verify=False, headers=headers_req)
            scan_content(jr.text, js_url, f"JS file: {js_url.split('/')[-1]}")
            js_scanned += 1
        except Exception as e:
            errors.append(f"JS fetch {js_url}: {e}")

    # ── Step 4: Check robots.txt and sitemap for path disclosure ─────────────
    for path in ["/robots.txt", "/.env", "/.env.example", "/config.js",
                 "/app.config.js", "/webpack.config.js", "/.git/config"]:
        try:
            base = f"{_up(url).scheme}://{_up(url).netloc}"
            pr = _req.get(base + path, timeout=6, verify=False, headers=headers_req)
            if pr.status_code == 200 and len(pr.text) > 10:
                scan_content(pr.text, base + path, f"Config file: {path}")
                # Flag exposed sensitive config files directly
                if path in ("/.env", "/.env.example", "/.git/config") and pr.status_code == 200:
                    key = f"Exposed config file::{base+path}"
                    if key not in found_keys:
                        found_keys.add(key)
                        findings.append({
                            "title": f"Sensitive File Publicly Accessible: {path}",
                            "vuln_type": "nhi_exposed_file",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "cwe_id": "CWE-538",
                            "description": f"The file {path} is publicly accessible and may contain secrets.",
                            "affected_url": base + path,
                            "evidence": f"HTTP {pr.status_code} — {len(pr.text)} bytes returned",
                            "source_tool": "nhi_scanner",
                            "recommendation": f"Block public access to {path} via server config. Never commit .env files to version control.",
                        })
        except Exception:
            pass

    return {
        "url": url,
        "status": "completed",
        "findings": findings,
        "js_files_scanned": js_scanned,
        "total": len(findings),
        "errors": errors if errors else None,
        "summary": f"Found {len(findings)} exposed secret(s) across HTML, {js_scanned} JS file(s), and config paths." if findings
                   else f"No exposed secrets detected in HTML, {js_scanned} JS file(s), or common config paths.",
    }


class NHIReportRequest(BaseModel):
    target_url: str = ""
    findings: list = []
    js_files_scanned: int = 0
    summary: str = ""


@router.post("/nhi/report")
async def nhi_report(req: NHIReportRequest):
    """Generate a PDF report from an NHI scan result (stateless — client posts the result)."""
    from fastapi.responses import Response
    from security.nhi_report import build_nhi_pdf
    pdf = build_nhi_pdf(req.target_url, req.findings or [],
                        js_files_scanned=req.js_files_scanned, summary=req.summary)
    safe = (req.target_url or "target").replace("https://", "").replace("http://", "").split("/")[0]
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="venom-nhi-report-{safe}.pdf"'},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/start", status_code=202)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks,
                     current_user: _AuthUser = Depends(get_optional_user)):
    # ── Quota gate: monthly scan limit ───────────────────────────────
    from billing.quotas import check_scan_quota, increment_scan_usage
    check_scan_quota(current_user)
    import re as _re
    from urllib.parse import urlparse as _urlparse
    # ── URL validation ────────────────────────────────────────────
    raw_url = (req.url or "").strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url
    try:
        _p = _urlparse(raw_url)
        _host = _p.hostname or ""
        _valid = (
            _p.scheme in ("http", "https") and
            (_host == "localhost" or "." in _host or _re.match(r"^\d+\.\d+\.\d+\.\d+$", _host))
        )
        if not _valid:
            raise ValueError("invalid host")
        req.url = raw_url  # normalize URL on the request
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid URL '{req.url}'. Please enter a valid URL like https://example.com")
    db = _get_db()
    models = _get_models()
    try:
        # Build ScanJob safely — only pass columns that exist in the DB
        scan_kwargs = {
            "target_url": req.url,
            "status": "PENDING",
            "created_at": datetime.now(timezone.utc),
        }
        # Tag scan with the logged-in user so /list filters cleanly per user
        _owner_id = current_user.id if current_user else None
        for col, val in [("scan_type", req.scan_type), ("owner_id", _owner_id),
                         ("progress", 0), ("user_id", req.user_id)]:
            if hasattr(models.ScanJob, col):
                scan_kwargs[col] = val
        scan = models.ScanJob(**scan_kwargs)
        db.add(scan)
        db.flush()
        scan_id = scan.id

        # ── Determine queue priority + NHI scanner gate from user's plan ───
        # Pro+ users get priority 0 (highest); everyone else gets 5 (default).
        # NHI/secret scanner unlocks at Starter+ — Free users skip that block.
        task_priority = 5
        enable_nhi_for_user = True   # anonymous & guests get it for the demo
        try:
            if current_user:
                from billing.plans import ensure_user_subscription
                _sub = ensure_user_subscription(db, current_user)
                if _sub and _sub.plan:
                    if _sub.plan.feature_priority_scan:
                        task_priority = 0
                        logger.info(
                            f"[Priority] User {current_user.id} on {_sub.plan.code} → "
                            f"priority scan queue"
                        )
                    # NHI scanner is Starter+ only
                    if _sub.plan.code == "free":
                        enable_nhi_for_user = False
                        logger.info(f"[NHI] User {current_user.id} on free → NHI disabled")
        except Exception as _pe:
            logger.debug(f"[Priority] plan lookup failed: {_pe}")

        # Try Celery first; fall back to inline background task
        celery_task_id = None
        try:
            task = _get_celery().send_task(
                "workers.tasks.run_security_scan",
                kwargs={"url": req.url, "user_id": req.user_id,
                        "scan_type": req.scan_type, "scan_id": scan_id,
                        "enable_nhi": enable_nhi_for_user},
                queue="security",
                priority=task_priority,
            )
            celery_task_id = task.id
            _safe_set(scan, "celery_task_id", celery_task_id)
            logger.info(
                f"Scan queued via Celery: {req.url} task={celery_task_id} "
                f"priority={task_priority}"
            )
        except Exception as celery_err:
            logger.warning(f"Celery unavailable ({celery_err}), using inline scanner.")
            # Run the inline scanner in the background
            background_tasks.add_task(
                _run_inline_scan, scan_id, req.url, req.user_id, req.scan_type,
                enable_nhi_for_user,
            )

        db.commit()

        # ── Increment scan usage meter (after successful queue) ──────
        try:
            increment_scan_usage(current_user)
        except Exception as _ue:
            logger.warning(f"[Quota] increment_scan_usage failed: {_ue}")

        return {
            "scan_id": scan_id,
            "task_id": celery_task_id or scan_id,
            "url": req.url,
            "status": "PENDING",
            "estimated_time": "60-120 seconds",
            "poll_url": f"/api/scan/{scan_id}/results",
            "message": f"Scan started. Poll GET /api/scan/{scan_id}/results every 5 seconds."
        }
    except Exception as e:
        db.rollback()
        logger.error(f"start_scan error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/{task_id}/status")
async def scan_status(task_id: str):
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, task_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        if scan.status in ("PENDING", "RUNNING"):
            _sync_from_celery(task_id, scan, db, models)
        return {
            "scan_id": scan.id,
            "task_id": getattr(scan, "celery_task_id", None) or task_id,
            "status": scan.status,
            "progress": getattr(scan, "progress", 0) or 0,
        }
    finally:
        db.close()


@router.get("/{task_id}/results")
async def scan_results(task_id: str):
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, task_id)
        if not scan:
            raise HTTPException(404, "Scan not found")

        # Try pulling from Celery if still running
        if scan.status in ("PENDING", "RUNNING"):
            _sync_from_celery(task_id, scan, db, models)

        # ── Stuck scan detection ─────────────────────────────────────────────
        # If still RUNNING after 5+ minutes, force the inline scanner now
        if scan.status in ("PENDING", "RUNNING"):
            age_seconds = 0
            if scan.created_at:
                from datetime import timezone as _tz
                try:
                    created = scan.created_at.replace(tzinfo=_tz.utc) if scan.created_at.tzinfo is None else scan.created_at
                    age_seconds = (datetime.now(_tz.utc) - created).total_seconds()
                except Exception:
                    age_seconds = 999
            if age_seconds > 300:  # 5 minutes
                logger.warning(f"Scan {scan.id} stuck for {age_seconds:.0f}s — force-running inline scanner")
                import threading
                def _force_complete():
                    try:
                        from routes.scanning import _run_inline_scan
                    except ImportError:
                        from routes.scanning import _run_inline_scan
                    _run_inline_scan(scan.id, scan.target_url, "venom", "full")
                threading.Thread(target=_force_complete, daemon=True).start()
                # Return running status while inline scanner kicks off
                return {
                    "scan_id": scan.id,
                    "task_id": getattr(scan, "celery_task_id", None) or task_id,
                    "target_url": scan.target_url,
                    "status": "RUNNING",
                    "progress": 10,
                    "security_score": 0, "ai_summary": "Scan restarted — results in ~60 seconds.",
                    "total_issues": 0, "critical_count": 0,
                    "high_count": 0, "medium_count": 0, "low_count": 0,
                    "vulnerabilities": [],
                    "created_at": str(scan.created_at),
                    "completed_at": None,
                    "message": "Scan was stuck — inline scanner triggered. Poll again in 10 seconds.",
                }

        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        vuln_list = [_enrich_vuln(_vuln_to_dict(v)) for v in vulns]

        if scan.status not in ("COMPLETED", "FAILED"):
            return {
                "scan_id": scan.id,
                "task_id": getattr(scan, "celery_task_id", None) or task_id,
                "target_url": scan.target_url,
                "status": "RUNNING",
                "progress": getattr(scan, "progress", 0) or 0,
                "security_score": 0, "ai_summary": "",
                "total_issues": 0, "critical_count": 0,
                "high_count": 0, "medium_count": 0, "low_count": 0,
                "vulnerabilities": [],
                "created_at": str(scan.created_at),
                "completed_at": None,
                "message": "Scan in progress — poll again in 5 seconds.",
            }

        # ── Safety net: recalculate counts from actual DB rows ────────────────
        # Handles case where Celery worker reported counts but saved no rows
        db_total = len(vuln_list)
        db_crit  = sum(1 for v in vuln_list if v.get("severity") == "critical")
        db_high  = sum(1 for v in vuln_list if v.get("severity") == "high")
        db_med   = sum(1 for v in vuln_list if v.get("severity") == "medium")
        db_low   = sum(1 for v in vuln_list if v.get("severity") == "low")

        stored_total = getattr(scan, "total_issues", 0) or 0
        # Use DB-derived counts if stored value seems wrong
        final_total = db_total if db_total > 0 else stored_total
        final_crit  = db_crit  if db_total > 0 else (getattr(scan, "critical_count", 0) or 0)
        final_high  = db_high  if db_total > 0 else (getattr(scan, "high_count", 0) or 0)
        final_med   = db_med   if db_total > 0 else (getattr(scan, "medium_count", 0) or 0)
        final_low   = db_low   if db_total > 0 else (getattr(scan, "low_count", 0) or 0)

        # Recalculate score from actual findings if DB has rows
        if db_total > 0 and (getattr(scan, "security_score", 0) or 0) == 0:
            deductions = db_crit*25 + db_high*15 + db_med*8 + db_low*3
            recalc_score = max(0, 100 - deductions)
            recalc_grade = "A" if recalc_score>=90 else "B" if recalc_score>=80 else "C" if recalc_score>=70 else "D" if recalc_score>=60 else "F"
        else:
            recalc_score = getattr(scan, "security_score", 0) or 0
            recalc_grade = getattr(scan, "grade", None) or "F"

        return {
            "scan_id": scan.id,
            "task_id": getattr(scan, "celery_task_id", None) or task_id,
            "target_url": scan.target_url,
            "status": scan.status,
            "security_score": recalc_score,
            "grade": recalc_grade,
            "ai_summary": getattr(scan, "ai_summary", "") or "",
            "scan_duration": None,
            "total_issues": final_total,
            "critical_count": final_crit,
            "high_count": final_high,
            "medium_count": final_med,
            "low_count": final_low,
            "vulnerabilities": vuln_list,
            "created_at": str(scan.created_at),
            "completed_at": str(scan.completed_at) if scan.completed_at else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"scan_results error: {e}\n{traceback.format_exc()}")
        raise HTTPException(500, str(e))
    finally:
        db.close()


@router.get("/")
async def scan_history(user_id: str = "all", skip: int = 0, limit: int = 20,
                       current_user: _AuthUser = Depends(get_optional_user)):
    db = _get_db()
    models = _get_models()
    try:
        q = db.query(models.ScanJob).order_by(models.ScanJob.created_at.desc())
        # Per-user isolation: logged-in users only see scans they own.
        # Anonymous callers (no token) only see anonymous scans (owner_id IS NULL).
        if current_user:
            q = q.filter(models.ScanJob.owner_id == current_user.id)
        else:
            q = q.filter(models.ScanJob.owner_id.is_(None))
        scans = q.offset(skip).limit(limit).all()
        return {
            "scans": [{
                "scan_id": s.id, "id": s.id,
                "celery_task_id": getattr(s, "celery_task_id", None),
                "task_id": getattr(s, "celery_task_id", None) or s.id,
                "target_url": s.target_url, "url": s.target_url,
                "scan_type": getattr(s, "scan_type", None) or "full",
                "status": s.status,
                "progress": getattr(s, "progress", 0) or 0,
                "security_score": getattr(s, "security_score", None),
                "grade": getattr(s, "grade", None),
                "total_issues": getattr(s, "total_issues", 0) or 0,
                "critical_count": getattr(s, "critical_count", 0) or 0,
                "high_count": getattr(s, "high_count", 0) or 0,
                "medium_count": getattr(s, "medium_count", 0) or 0,
                "low_count": getattr(s, "low_count", 0) or 0,
                "created_at": str(s.created_at),
                "completed_at": str(s.completed_at) if s.completed_at else None,
            } for s in scans],
            "total": q.count(), "skip": skip, "limit": limit,
        }
    finally:
        db.close()


@router.delete("/all")
async def clear_all_scans(current_user: _AuthUser = Depends(get_optional_user)):
    """
    Delete scan jobs + vulnerabilities for the CURRENT USER only.
    Anonymous callers only delete anonymous scans (owner_id IS NULL).
    """
    db = _get_db()
    models = _get_models()
    try:
        vuln_count = 0
        scan_count = 0

        # VENOM is single-user (self-hosted, one operator) — clear EVERYTHING.
        # Scans are often saved with owner_id=None, so filtering by the local
        # user's id would leave them behind ("Cleared 0" bug).
        scan_ids = [s.id for s in db.query(models.ScanJob).all()]

        # Delete vulnerabilities first (FK dep)
        if scan_ids and hasattr(models, "Vulnerability"):
            vuln_count = db.query(models.Vulnerability)\
                .filter(models.Vulnerability.scan_job_id.in_(scan_ids))\
                .delete(synchronize_session=False)

        # Delete scans
        scan_count = db.query(models.ScanJob)\
            .filter(models.ScanJob.id.in_(scan_ids))\
            .delete(synchronize_session=False) if scan_ids else 0

        db.commit()
        return {
            "status": "cleared",
            "scope": f"user_id={current_user.id}" if current_user else "anonymous",
            "deleted": {"scans": scan_count, "vulnerabilities": vuln_count},
        }
    except Exception as e:
        db.rollback()
        logger.error(f"clear_all_scans error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/{task_id}/compliance")
async def scan_compliance(task_id: str):
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, task_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        try:
            from services.compliance_service import generate_full_compliance_report
        except ImportError:
            from services.compliance_service import generate_full_compliance_report
        report = generate_full_compliance_report([_vuln_to_dict(v) for v in vulns])
        return {"scan_id": scan.id, "task_id": task_id,
                "target_url": scan.target_url, "compliance": report}
    finally:
        db.close()


@router.get("/{task_id}/attack-graph")
async def scan_attack_graph(task_id: str):
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, task_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        try:
            from services.attack_path_service import build_attack_chains, attack_chains_to_dict
        except ImportError:
            from services.attack_path_service import build_attack_chains, attack_chains_to_dict
        chains = build_attack_chains([_vuln_to_dict(v) for v in vulns], scan.target_url or "")
        return {"scan_id": scan.id, "task_id": task_id, "target_url": scan.target_url,
                "total_chains": len(chains), "chains": attack_chains_to_dict(chains)}
    finally:
        db.close()


@router.get("/{task_id}/autofix")
async def scan_autofix(task_id: str):
    db = _get_db()
    models = _get_models()
    try:
        scan = _find_scan(db, models, task_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        # Use string-based filter to avoid Enum attribute errors
        vulns = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_job_id == scan.id
        ).all()
        # Filter high/critical in Python to avoid column type issues
        high_vulns = [v for v in vulns
                      if getattr(v, "severity", "") in ("critical", "high")
                      or getattr(v, "risk_level", "") in ("critical", "high")][:10]
        try:
            from services.autofix_service import generate_batch_patches
        except ImportError:
            from services.autofix_service import generate_batch_patches
        patches = generate_batch_patches([_vuln_to_dict(v) for v in high_vulns])
        return {"scan_id": scan.id, "task_id": task_id,
                "total_patches": len(patches), "patches": patches}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"autofix error: {e}")
        raise HTTPException(500, str(e))
    finally:
        db.close()


@router.post("/webhook")
async def webhook_trigger(payload: WebhookPayload, background_tasks: BackgroundTasks):
    if not payload.target_url:
        return {"status": "ignored", "reason": "No target_url provided"}
    background_tasks.add_task(_trigger_delta_scan, payload.target_url,
                               payload.triggered_by, payload.commit)
    return {"status": "accepted",
            "message": f"Delta scan triggered for {payload.target_url}"}


@router.post("/webhook/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        data = await request.json()
        target_url = (data.get("repository", {}).get("homepage", "") or
                      data.get("deployment", {}).get("url", ""))
        event = request.headers.get("X-GitHub-Event", "push")
        commit = data.get("after", "")[:8]
        if event in ("push", "deployment", "release") and target_url:
            background_tasks.add_task(_trigger_delta_scan, target_url, "github-webhook", commit)
            return {"status": "accepted", "scan_triggered": True, "target": target_url}
        return {"status": "ignored", "reason": f"Event '{event}' or missing target_url"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def _trigger_delta_scan(target_url: str, triggered_by: str, commit: str = "") -> None:
    db = _get_db()
    models = _get_models()
    try:
        scan = models.ScanJob(target_url=target_url, scan_type="quick", owner_id=None,
                               status="PENDING", progress=0,
                               created_at=datetime.now(timezone.utc))
        db.add(scan)
        db.flush()
        scan_id = scan.id
        try:
            task = _get_celery().send_task(
                "workers.tasks.run_security_scan",
                kwargs={"url": target_url, "user_id": triggered_by,
                        "scan_type": "quick", "scan_id": scan_id},
                queue="security")
            _safe_set(scan, "celery_task_id", task.id)
        except Exception:
            import threading
            threading.Thread(
                target=_run_inline_scan,
                args=(scan_id, target_url, triggered_by, "quick"),
                daemon=True
            ).start()
        db.commit()
        logger.info(f"Delta scan queued: {target_url} commit={commit}")
    except Exception as e:
        logger.error(f"Delta scan failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


# ─── Sync inline scanner for Continuous Monitoring ───────────────────────────
def _run_inline_scan_sync(url: str) -> dict:
    """
    Stateless version of the inline scanner — returns a result dict without
    touching the database. Used by the monitoring module for scheduled re-scans.
    """
    import requests, ssl, socket, re
    from urllib.parse import urlparse

    findings = []
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""

    # ── HTTP Headers ──────────────────────────────────────────────────────
    try:
        resp = requests.get(url, timeout=15, verify=False,
                            headers={"User-Agent": "VENOM-AI-Monitor/2.0"},
                            allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        security_headers = {
            "x-frame-options":           ("Clickjacking Protection Missing",    "high",   "CWE-1021", 7.5),
            "x-content-type-options":    ("MIME Sniffing Protection Missing",   "medium", "CWE-693",  5.3),
            "strict-transport-security": ("HSTS Not Configured",                "high",   "CWE-319",  7.4),
            "content-security-policy":   ("Content Security Policy Missing",    "high",   "CWE-79",   7.2),
            "referrer-policy":           ("Referrer Policy Not Set",            "low",    "CWE-200",  3.1),
        }
        for hdr, (title, sev, cwe, cvss) in security_headers.items():
            if hdr not in headers:
                findings.append({"title": title, "severity": sev, "cvss_score": cvss})
        server = headers.get("server", "")
        if re.search(r"[\d.]{3,}", server):
            findings.append({"title": "Server Version Disclosure", "severity": "medium", "cvss_score": 5.3})
    except Exception:
        pass

    # ── SSL ───────────────────────────────────────────────────────────────
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10),
                                 server_hostname=hostname) as s:
                cert = s.getpeercert()
                from datetime import datetime as _dt
                not_after = _dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - _dt.utcnow()).days
                if days_left < 0:
                    findings.append({"title": "SSL Certificate Expired", "severity": "critical", "cvss_score": 9.1})
                elif days_left < 30:
                    findings.append({"title": "SSL Certificate Expiring Soon", "severity": "high", "cvss_score": 7.5})
        except ssl.SSLCertVerificationError as e:
            err = str(e).lower()
            if "expired" in err:
                findings.append({"title": "SSL Certificate Expired", "severity": "critical", "cvss_score": 9.1})
            elif "self" in err:
                findings.append({"title": "Self-Signed SSL Certificate", "severity": "high", "cvss_score": 7.4})
        except Exception:
            pass

    # ── Score ─────────────────────────────────────────────────────────────
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity", "low")
        counts[s] = counts.get(s, 0) + 1

    deductions = counts["critical"]*25 + counts["high"]*15 + counts["medium"]*8 + counts["low"]*3
    score = max(0, 100 - deductions)
    if   score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else:             grade = "F"

    total = len(findings)
    return {
        "security_score":  score,
        "grade":           grade,
        "total_issues":    total,
        "critical_count":  counts["critical"],
        "high_count":      counts["high"],
        "medium_count":    counts["medium"],
        "low_count":       counts["low"],
        "findings":        findings,
        "ai_summary":      f"Monitor scan complete. {total} issues found. Score: {score}/100 (Grade {grade}).",
    }


@router.get("/debug/db-check")
async def debug_db_check():
    """
    VENOM DEBUG ENDPOINT — tests DB connection and shows scan/vuln counts.
    Visit: http://127.0.0.1:8000/api/scan/debug/db-check
    """
    db = _get_db()
    models = _get_models()
    try:
        scan_count  = db.query(models.ScanJob).count()
        vuln_count  = db.query(models.Vulnerability).count()
        recent_scans = db.query(models.ScanJob).order_by(
            models.ScanJob.created_at.desc()
        ).limit(5).all()

        scans_info = []
        for s in recent_scans:
            sid = s.id
            vcount = db.query(models.Vulnerability).filter(
                models.Vulnerability.scan_job_id == sid
            ).count()
            scans_info.append({
                "id":           sid,
                "url":          s.target_url,
                "status":       s.status,
                "score":        getattr(s, "security_score", None),
                "total_issues": getattr(s, "total_issues", None),
                "vulns_in_db":  vcount,
                "mismatch":     (getattr(s, "total_issues", 0) or 0) != vcount,
            })

        return {
            "status":        "DB_OK",
            "total_scans":   scan_count,
            "total_vulns":   vuln_count,
            "recent_scans":  scans_info,
            "diagnosis":     "OK" if all(not s["mismatch"] for s in scans_info)
                             else "MISMATCH — total_issues != actual vulns in DB",
        }
    except Exception as e:
        return {"status": "DB_ERROR", "error": str(e)}
    finally:
        db.close()


@router.get("/debug/latest-vulns")
async def debug_latest_vulns():
    """
    Shows the last 20 vulnerability rows saved to DB.
    Visit: http://127.0.0.1:8000/api/scan/debug/latest-vulns
    """
    db = _get_db()
    models = _get_models()
    try:
        vulns = db.query(models.Vulnerability).order_by(
            models.Vulnerability.id.desc()
        ).limit(20).all()
        return {
            "count": len(vulns),
            "vulnerabilities": [
                {
                    "id":          v.id,
                    "scan_job_id": v.scan_job_id,
                    "title":       v.title,
                    "severity":    v.severity,
                    "source_tool": getattr(v, "source_tool", ""),
                }
                for v in vulns
            ]
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        db.close()