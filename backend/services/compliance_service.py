"""
VENOM AI · backend/services/compliance_service.py
Maps vulnerability findings to ISO 27001 / SOC 2 / GDPR controls
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import logging

logger = logging.getLogger("venom.compliance")


@dataclass
class ComplianceControl:
    id: str
    name: str
    framework: str
    description: str
    status: str = "unknown"   # pass / fail / partial / unknown
    failing_vulns: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ComplianceReport:
    framework: str
    score: int                   # 0-100
    grade: str                   # A-F
    controls: List[ComplianceControl] = field(default_factory=list)
    total_controls: int = 0
    passing: int = 0
    failing: int = 0
    partial: int = 0


# ─── ISO 27001 Control Mapping ────────────────────────────────────────────────

ISO_CONTROLS = [
    ("A.5.1.1",  "Information security policies",             ["policy"]),
    ("A.6.1.2",  "Segregation of duties",                    ["privilege", "admin"]),
    ("A.9.1.1",  "Access control policy",                    ["auth", "login", "access"]),
    ("A.9.4.2",  "Secure log-on procedures",                 ["brute", "default", "credential"]),
    ("A.9.4.3",  "Password management",                      ["weak password", "plain text", "hash"]),
    ("A.10.1.1", "Cryptographic controls (TLS/SSL)",         ["ssl", "tls", "certificate", "cipher"]),
    ("A.12.2.1", "Controls against malware",                 ["injection", "xss", "rce", "command"]),
    ("A.12.4.1", "Event logging",                            ["log", "monitor"]),
    ("A.12.6.1", "Management of technical vulnerabilities",  ["outdated", "cve", "patch"]),
    ("A.13.1.1", "Network controls",                         ["port", "firewall", "exposure"]),
    ("A.13.2.1", "Information transfer policies",            ["cors", "header", "csp"]),
    ("A.14.1.2", "Securing application services",            ["api", "endpoint", "http"]),
    ("A.14.2.5", "Secure system engineering principles",     ["traversal", "lfi", "ssrf", "idor"]),
    ("A.16.1.2", "Reporting information security events",    ["incident"]),
    ("A.18.1.3", "Protection of records",                    ["data", "pii", "leak"]),
]

# ─── SOC 2 Control Mapping ────────────────────────────────────────────────────

SOC2_CONTROLS = [
    ("CC1.1",  "COSO principle: Commitment to integrity",          ["sql", "injection", "tampering"]),
    ("CC6.1",  "Logical access controls",                         ["auth", "login", "access", "password"]),
    ("CC6.2",  "Authentication prior to access",                  ["brute", "bypass", "credential"]),
    ("CC6.3",  "Role-based access",                               ["privilege", "admin", "idor"]),
    ("CC6.6",  "Restricts logical access from outside",          ["cors", "port", "exposure"]),
    ("CC6.7",  "Restrict transmission of data",                  ["ssl", "tls", "cleartext"]),
    ("CC7.1",  "Detection and monitoring of changes",            ["hash", "integrity"]),
    ("CC7.2",  "System monitoring",                              ["log", "monitor", "alert"]),
    ("CC7.3",  "Evaluate and communicate security events",       ["incident", "breach"]),
    ("CC8.1",  "Change management processes",                    ["outdated", "patch", "version"]),
    ("CC9.1",  "Risk identification and mitigation",             ["cve", "critical", "high"]),
    ("A1.2",   "Environmental protections — HTTPS",              ["http ", "insecure", "certificate"]),
    ("C1.1",   "Confidentiality policy",                         ["data", "pii", "exposure", "leak"]),
    ("PI1.1",  "Processing integrity completeness",              ["xss", "injection", "manipulation"]),
    ("PI1.4",  "Outputs complete and accurate",                  ["rce", "command", "api"]),
]

# ─── GDPR Article Mapping ─────────────────────────────────────────────────────

GDPR_CONTROLS = [
    ("Art.5",   "Principles of data processing",                 ["data", "pii", "personal"]),
    ("Art.17",  "Right to erasure — secure deletion",           ["data", "storage", "backup"]),
    ("Art.25",  "Data protection by design and by default",     ["xss", "injection", "traversal"]),
    ("Art.32",  "Security of processing",                       ["ssl", "tls", "encryption", "auth"]),
    ("Art.33",  "Breach notification capability",               ["log", "monitor", "alert"]),
    ("Art.35",  "Data protection impact assessment",            ["critical", "high", "sensitive"]),
    ("Art.28",  "Processor agreements — API security",          ["api", "key", "token", "secret"]),
    ("Art.44",  "Transfers to third countries",                 ["cors", "third-party", "cdn"]),
    ("Art.83",  "Conditions for imposing fines",                ["critical", "breach", "incident"]),
]


def _vuln_matches_keywords(vuln: dict, keywords: List[str]) -> bool:
    text = " ".join([
        str(vuln.get("title", "")),
        str(vuln.get("description", "")),
        str(vuln.get("vuln_type", "")),
        str(vuln.get("cwe_id", "")),
    ]).lower()
    return any(kw in text for kw in keywords)


def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 55: return "D"
    return "F"


def map_to_iso27001(vulnerabilities: List[dict]) -> ComplianceReport:
    controls = []
    for ctrl_id, ctrl_name, keywords in ISO_CONTROLS:
        failing = [v.get("title", v.get("vuln_type", "")) for v in vulnerabilities if _vuln_matches_keywords(v, keywords)]
        critical_fails = [v for v in vulnerabilities if _vuln_matches_keywords(v, keywords) and v.get("severity") in ("critical", "high")]
        if critical_fails:
            status = "fail"
        elif failing:
            status = "partial"
        else:
            status = "pass"
        controls.append(ComplianceControl(
            id=ctrl_id, name=ctrl_name, framework="ISO 27001",
            description=f"Control {ctrl_id}: {ctrl_name}",
            status=status, failing_vulns=failing[:3],
            remediation="Remediate all associated vulnerabilities to achieve compliance."
        ))
    passing = sum(1 for c in controls if c.status == "pass")
    failing_count = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    total = len(controls)
    score = int(((passing + partial * 0.5) / total) * 100) if total else 0
    return ComplianceReport(
        framework="ISO 27001", score=score, grade=_score_to_grade(score),
        controls=controls, total_controls=total,
        passing=passing, failing=failing_count, partial=partial
    )


def map_to_soc2(vulnerabilities: List[dict]) -> ComplianceReport:
    controls = []
    for ctrl_id, ctrl_name, keywords in SOC2_CONTROLS:
        failing = [v.get("title", v.get("vuln_type", "")) for v in vulnerabilities if _vuln_matches_keywords(v, keywords)]
        critical_fails = [v for v in vulnerabilities if _vuln_matches_keywords(v, keywords) and v.get("severity") in ("critical", "high")]
        status = "fail" if critical_fails else "partial" if failing else "pass"
        controls.append(ComplianceControl(
            id=ctrl_id, name=ctrl_name, framework="SOC 2 Type II",
            description=f"Trust Service Criteria {ctrl_id}: {ctrl_name}",
            status=status, failing_vulns=failing[:3],
            remediation="Address all failing controls to achieve SOC 2 certification."
        ))
    passing = sum(1 for c in controls if c.status == "pass")
    failing_count = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    total = len(controls)
    score = int(((passing + partial * 0.5) / total) * 100) if total else 0
    return ComplianceReport(
        framework="SOC 2 Type II", score=score, grade=_score_to_grade(score),
        controls=controls, total_controls=total,
        passing=passing, failing=failing_count, partial=partial
    )


def map_to_gdpr(vulnerabilities: List[dict]) -> ComplianceReport:
    controls = []
    for ctrl_id, ctrl_name, keywords in GDPR_CONTROLS:
        failing = [v.get("title", v.get("vuln_type", "")) for v in vulnerabilities if _vuln_matches_keywords(v, keywords)]
        critical_fails = [v for v in vulnerabilities if _vuln_matches_keywords(v, keywords) and v.get("severity") in ("critical", "high")]
        status = "fail" if critical_fails else "partial" if failing else "pass"
        controls.append(ComplianceControl(
            id=ctrl_id, name=ctrl_name, framework="GDPR",
            description=f"GDPR {ctrl_id}: {ctrl_name}",
            status=status, failing_vulns=failing[:3],
            remediation="Ensure all data protection controls meet GDPR requirements."
        ))
    passing = sum(1 for c in controls if c.status == "pass")
    failing_count = sum(1 for c in controls if c.status == "fail")
    partial = sum(1 for c in controls if c.status == "partial")
    total = len(controls)
    score = int(((passing + partial * 0.5) / total) * 100) if total else 0
    return ComplianceReport(
        framework="GDPR", score=score, grade=_score_to_grade(score),
        controls=controls, total_controls=total,
        passing=passing, failing=failing_count, partial=partial
    )


def generate_full_compliance_report(vulnerabilities: List[dict]) -> dict:
    iso = map_to_iso27001(vulnerabilities)
    soc = map_to_soc2(vulnerabilities)
    gdpr = map_to_gdpr(vulnerabilities)
    overall = int((iso.score + soc.score + gdpr.score) / 3)

    def report_to_dict(r: ComplianceReport) -> dict:
        return {
            "framework": r.framework,
            "score": r.score,
            "grade": r.grade,
            "total_controls": r.total_controls,
            "passing": r.passing,
            "failing": r.failing,
            "partial": r.partial,
            "controls": [
                {
                    "id": c.id, "name": c.name, "status": c.status,
                    "failing_vulns": c.failing_vulns, "remediation": c.remediation
                } for c in r.controls
            ]
        }

    return {
        "overall_score": overall,
        "overall_grade": _score_to_grade(overall),
        "iso_27001": report_to_dict(iso),
        "soc2": report_to_dict(soc),
        "gdpr": report_to_dict(gdpr),
        "total_vulnerabilities": len(vulnerabilities),
        "critical_count": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
        "high_count": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
    }
