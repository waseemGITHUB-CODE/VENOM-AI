"""
VENOM AI · backend/services/attack_path_service.py
Correlates scan findings into visual Attack Chains with Blast Radius analysis.
Every scan with at least one vulnerability will produce at least one chain.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import logging

logger = logging.getLogger("venom.attack_path")


@dataclass
class AttackNode:
    id: str
    label: str
    node_type: str           # attacker | vulnerability | asset
    severity: str = "info"
    detail: str = ""
    cve: str = ""
    blast_radius: int = 0


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    technique: str
    confidence: float = 1.0
    is_chain: bool = False


@dataclass
class AttackChain:
    id: str
    title: str
    description: str
    nodes: List[AttackNode] = field(default_factory=list)
    edges: List[AttackEdge] = field(default_factory=list)
    severity: str = "high"
    blast_radius: int = 0
    steps: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


# ─── MITRE ATT&CK Technique Mapping ──────────────────────────────────────────

VULN_TO_MITRE = {
    # Injection / Execution
    "sql injection":        ("T1190", "Exploit Public-Facing Application"),
    "sqli":                 ("T1190", "Exploit Public-Facing Application"),
    "xss":                  ("T1059.007", "JavaScript Execution"),
    "cross-site scripting": ("T1059.007", "JavaScript Execution"),
    "cross site scripting": ("T1059.007", "JavaScript Execution"),
    "ssti":                 ("T1059",    "Command and Scripting Interpreter"),
    "template injection":   ("T1059",    "Command and Scripting Interpreter"),
    "command injection":    ("T1059",    "Command and Scripting Interpreter"),
    "rce":                  ("T1059",    "Command and Scripting Interpreter"),
    "code execution":       ("T1059",    "Command and Scripting Interpreter"),
    "xxe":                  ("T1083",    "File and Directory Discovery"),
    # Auth / Access control
    "idor":                 ("T1078", "Valid Accounts"),
    "broken auth":          ("T1078", "Valid Accounts"),
    "authentication":       ("T1078", "Valid Accounts"),
    "broken access":        ("T1078", "Valid Accounts"),
    "privilege":            ("T1134", "Access Token Manipulation"),
    # Credential / session
    "credential":           ("T1552", "Unsecured Credentials"),
    "api key":              ("T1552.001", "Credentials in Files"),
    "secret":               ("T1552.001", "Credentials in Files"),
    "token":                ("T1552",   "Unsecured Credentials"),
    "leaked":               ("T1552",   "Unsecured Credentials"),
    "cookie":               ("T1539",   "Steal Web Session Cookie"),
    "session":              ("T1539",   "Steal Web Session Cookie"),
    "insecure cookie":      ("T1539",   "Steal Web Session Cookie"),
    # Network / Discovery
    "open port":            ("T1046", "Network Service Discovery"),
    "exposed service":      ("T1046", "Network Service Discovery"),
    "port":                 ("T1046", "Network Service Discovery"),
    "ssrf":                 ("T1090", "Proxy via Internal Network"),
    "lfi":                  ("T1083", "File and Directory Discovery"),
    "rfi":                  ("T1105", "Ingress Tool Transfer"),
    "path traversal":       ("T1083", "File and Directory Discovery"),
    "directory traversal":  ("T1083", "File and Directory Discovery"),
    "open redirect":        ("T1189", "Drive-by Compromise"),
    # Collection
    "csrf":                 ("T1185", "Browser Session Hijacking"),
    "cors":                 ("T1185", "Browser Session Hijacking"),
    "clickjack":            ("T1185", "Browser Session Hijacking"),
    "clickjacking":         ("T1185", "Browser Session Hijacking"),
    # Defense evasion / Info disclosure
    "missing header":       ("T1036", "Masquerading / Missing Controls"),
    "security header":      ("T1036", "Masquerading / Missing Controls"),
    "content-security":     ("T1036", "Masquerading / Missing Controls"),
    "x-frame":              ("T1036", "Masquerading / Missing Controls"),
    "information disclosure":("T1082","System Information Discovery"),
    "information_disclosure":("T1082","System Information Discovery"),
    "tech stack":           ("T1082", "System Information Discovery"),
    "server version":       ("T1082", "System Information Discovery"),
    "error message":        ("T1082", "System Information Discovery"),
    # SSL / Crypto
    "ssl":                  ("T1557", "Adversary-in-the-Middle"),
    "tls":                  ("T1557", "Adversary-in-the-Middle"),
    "certificate":          ("T1557", "Adversary-in-the-Middle"),
    "weak cipher":          ("T1557", "Adversary-in-the-Middle"),
    # Software / CVE
    "outdated":             ("T1190", "Exploit Public-Facing Application"),
    "vulnerable version":   ("T1190", "Exploit Public-Facing Application"),
    "cve":                  ("T1190", "Exploit Public-Facing Application"),
    "outdated software":    ("T1190", "Exploit Public-Facing Application"),
    # Reconnaissance
    "recon":                ("T1592", "Gather Victim Host Information"),
    "fingerprint":          ("T1592", "Gather Victim Host Information"),
    "banner":               ("T1592", "Gather Victim Host Information"),
}

BLAST_RADIUS_MAP = {
    "critical": 50,
    "high":     25,
    "medium":   10,
    "low":       3,
    "info":      1,
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _get_mitre(vuln: dict) -> Tuple[str, str]:
    """Find the best-matching MITRE technique for a vulnerability."""
    text = " ".join([
        vuln.get("title", ""),
        vuln.get("vuln_type", ""),
        vuln.get("description", ""),
    ]).lower()
    # Longer keyword matches first (more specific wins)
    for keyword in sorted(VULN_TO_MITRE, key=len, reverse=True):
        if keyword in text:
            return VULN_TO_MITRE[keyword]
    return "T1190", "Exploit Public-Facing Application"


def _chain_label(v1: dict, v2: dict) -> Optional[str]:
    """Return a human-readable chain label if v1 can pivot to v2, else None."""
    t1 = (v1.get("title", "") + " " + v1.get("vuln_type", "")).lower()
    t2 = (v2.get("title", "") + " " + v2.get("vuln_type", "")).lower()
    s1, s2 = v1.get("severity", "low"), v2.get("severity", "low")

    # Specific pivot patterns
    if any(x in t1 for x in ["port", "service", "banner"]) and \
       any(x in t2 for x in ["auth", "login", "brute", "credential"]):
        return "Port Exposure → Service Exploitation"

    if any(x in t1 for x in ["key", "secret", "token", "credential", "api key", "leaked"]) and \
       any(x in t2 for x in ["auth", "access", "idor", "account", "privilege"]):
        return "Credential Leak → Account Takeover"

    if any(x in t1 for x in ["traversal", "lfi", "path"]) and \
       any(x in t2 for x in ["secret", "key", "credential", "config", "password"]):
        return "Path Traversal → Credential Extraction"

    if "ssrf" in t1 and any(x in t2 for x in ["internal", "port", "service", "rce"]):
        return "SSRF → Internal Network Pivot"

    if any(x in t1 for x in ["sql", "injection", "sqli"]) and \
       any(x in t2 for x in ["data", "pii", "database", "dump", "exfil"]):
        return "SQL Injection → Data Exfiltration"

    if "xss" in t1 and any(x in t2 for x in ["session", "cookie", "auth", "csrf", "token"]):
        return "XSS → Session Hijacking"

    if any(x in t1 for x in ["cors", "csrf", "clickjack"]) and \
       any(x in t2 for x in ["auth", "account", "privilege", "data", "session"]):
        return "CSRF/CORS → Cross-Origin Attack"

    if any(x in t1 for x in ["information", "disclosure", "banner", "version", "fingerprint"]) and \
       any(x in t2 for x in ["cve", "outdated", "vulnerable", "exploit", "injection"]):
        return "Reconnaissance → Targeted Exploitation"

    if any(x in t1 for x in ["ssl", "tls", "certificate", "cipher"]) and \
       any(x in t2 for x in ["session", "credential", "cookie", "token", "auth"]):
        return "TLS Weakness → Credential Interception"

    if any(x in t1 for x in ["header", "csp", "x-frame", "hsts"]) and \
       any(x in t2 for x in ["xss", "clickjack", "inject", "script"]):
        return "Missing Headers → Client-Side Attack"

    if any(x in t1 for x in ["redirect", "open redirect"]) and \
       any(x in t2 for x in ["phish", "credential", "token", "auth", "account"]):
        return "Open Redirect → Phishing / Token Theft"

    # Generic severity-based chains
    if s1 in ("critical", "high") and s2 in ("critical", "high"):
        return "Multi-Vector High-Severity Attack"

    if s1 in ("critical", "high") and s2 == "medium":
        return "High-Impact Vulnerability Chain"

    if s1 == "medium" and s2 == "medium":
        return "Combined Medium-Risk Exposure"

    return None


def build_attack_chains(vulnerabilities: List[dict], target_url: str) -> List[AttackChain]:
    if not vulnerabilities:
        return []

    chains: List[AttackChain] = []
    chain_id = 0
    used: set = set()

    # Sort highest severity first
    ordered = sorted(
        vulnerabilities,
        key=lambda v: SEV_ORDER.get(v.get("severity", "info"), 4)
    )

    # ── Pass 1: find semantic chains between vulnerability pairs ─────────────
    for i, v1 in enumerate(ordered):
        if i in used:
            continue
        for j, v2 in enumerate(ordered[i + 1:], i + 1):
            if j in used:
                continue
            label = _chain_label(v1, v2)
            if not label:
                continue

            chain_id += 1
            mid1, mname1 = _get_mitre(v1)
            mid2, mname2 = _get_mitre(v2)
            br = (BLAST_RADIUS_MAP.get(v1.get("severity", "low"), 3) +
                  BLAST_RADIUS_MAP.get(v2.get("severity", "low"), 3))

            sev = "critical" if (v1.get("severity") == "critical" or
                                 v2.get("severity") == "critical") else v1.get("severity", "high")

            attacker = AttackNode(
                id=f"atk-{chain_id}", label="External Attacker",
                node_type="attacker", severity="critical")
            node1 = AttackNode(
                id=f"v1-{i}-{chain_id}",
                label=(v1.get("title") or v1.get("vuln_type") or "Vulnerability")[:30],
                node_type="vulnerability", severity=v1.get("severity", "high"),
                detail=v1.get("description", ""), cve=v1.get("cve_id", ""),
                blast_radius=BLAST_RADIUS_MAP.get(v1.get("severity", "low"), 3))
            node2 = AttackNode(
                id=f"v2-{j}-{chain_id}",
                label=(v2.get("title") or v2.get("vuln_type") or "Vulnerability")[:30],
                node_type="vulnerability", severity=v2.get("severity", "medium"),
                detail=v2.get("description", ""), cve=v2.get("cve_id", ""),
                blast_radius=BLAST_RADIUS_MAP.get(v2.get("severity", "low"), 3))
            asset = AttackNode(
                id=f"asset-{chain_id}",
                label=_short_url(target_url) or "Target Asset",
                node_type="asset", severity=sev,
                detail=target_url, blast_radius=br)

            chains.append(AttackChain(
                id=f"chain-{chain_id}",
                title=label,
                description=f"Attacker leverages {node1.label} to pivot via {node2.label} and compromise target.",
                nodes=[attacker, node1, node2, asset],
                edges=[
                    AttackEdge(attacker.id, node1.id, mname1, confidence=0.9),
                    AttackEdge(node1.id, node2.id, label[:40], confidence=0.8, is_chain=True),
                    AttackEdge(node2.id, asset.id, mname2, confidence=0.85),
                ],
                severity=sev,
                blast_radius=br,
                steps=[
                    f"1. Attacker identifies {node1.label} on {_short_url(target_url)}",
                    f"2. Exploits via {mname1} ({mid1})",
                    f"3. Pivots: {label}",
                    f"4. Leverages {node2.label} — {mname2} ({mid2})",
                    f"5. Full compromise of target asset",
                ],
                mitre_techniques=[mid1, mid2],
            ))
            used.add(i)
            used.add(j)
            if len(chains) >= 6:
                break
        if len(chains) >= 6:
            break

    # ── Pass 2: standalone chains for every unused critical/high vuln ────────
    for i, v in enumerate(ordered):
        if i in used:
            continue
        sev = v.get("severity", "info")
        if sev not in ("critical", "high"):
            continue
        if len(chains) >= 8:
            break

        chain_id += 1
        mid, mname = _get_mitre(v)
        br = BLAST_RADIUS_MAP.get(sev, 3)
        atk_id  = f"atk-s-{chain_id}"
        vuln_id = f"v-s-{chain_id}"
        ast_id  = f"asset-s-{chain_id}"

        chains.append(AttackChain(
            id=f"chain-solo-{chain_id}",
            title=f"{(v.get('title') or v.get('vuln_type') or 'Vulnerability')[:45]}",
            description="Single high/critical severity vulnerability provides direct exploitation path.",
            nodes=[
                AttackNode(atk_id,  "External Attacker", "attacker",     "critical"),
                AttackNode(vuln_id, (v.get("title") or v.get("vuln_type") or "Vulnerability")[:30],
                           "vulnerability", sev, v.get("description", ""), blast_radius=br),
                AttackNode(ast_id,  _short_url(target_url) or "Target Asset",
                           "asset", sev, target_url, blast_radius=br),
            ],
            edges=[
                AttackEdge(atk_id, vuln_id, mname, confidence=0.95),
                AttackEdge(vuln_id, ast_id, "Direct Asset Compromise", confidence=0.9),
            ],
            severity=sev,
            blast_radius=br,
            steps=[
                f"1. Attacker identifies {v.get('title', 'vulnerability')} on {_short_url(target_url)}",
                f"2. Exploits using {mname} ({mid})",
                "3. Direct unauthorized access to target asset",
            ],
            mitre_techniques=[mid],
        ))
        used.add(i)

    # ── Pass 3: fallback — if still empty, generate chains for top-N vulns ───
    # Guarantees the graph is never blank when there ARE scan results.
    if not chains:
        for i, v in enumerate(ordered[:8]):
            chain_id += 1
            sev = v.get("severity", "medium")
            mid, mname = _get_mitre(v)
            br = BLAST_RADIUS_MAP.get(sev, 3)
            atk_id  = f"atk-f-{chain_id}"
            vuln_id = f"v-f-{chain_id}"
            ast_id  = f"asset-f-{chain_id}"

            chains.append(AttackChain(
                id=f"chain-fb-{chain_id}",
                title=(v.get("title") or v.get("vuln_type") or "Security Finding")[:50],
                description="Security vulnerability identified during scan that may be leveraged by an attacker.",
                nodes=[
                    AttackNode(atk_id,  "External Attacker", "attacker", "critical"),
                    AttackNode(vuln_id, (v.get("title") or v.get("vuln_type") or "Vulnerability")[:30],
                               "vulnerability", sev, v.get("description", ""), blast_radius=br),
                    AttackNode(ast_id,  _short_url(target_url) or "Target Asset",
                               "asset", sev, target_url, blast_radius=br),
                ],
                edges=[
                    AttackEdge(atk_id, vuln_id, mname, confidence=0.8),
                    AttackEdge(vuln_id, ast_id, "Potential Asset Impact", confidence=0.7),
                ],
                severity=sev,
                blast_radius=br,
                steps=[
                    f"1. Attacker discovers {v.get('title', 'vulnerability')}",
                    f"2. Potential exploitation via {mname} ({mid})",
                    "3. Risk of unauthorized access or data exposure",
                ],
                mitre_techniques=[mid],
            ))

    return chains


def _short_url(url: str) -> str:
    """Strip protocol and path — return just the hostname."""
    if not url:
        return ""
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0][:25]


def attack_chains_to_dict(chains: List[AttackChain]) -> List[dict]:
    result = []
    for chain in chains:
        result.append({
            "id":               chain.id,
            "title":            chain.title,
            "description":      chain.description,
            "severity":         chain.severity,
            "blast_radius":     chain.blast_radius,
            "steps":            chain.steps,
            "mitre_techniques": chain.mitre_techniques,
            "nodes": [
                {
                    "id":           n.id,
                    "label":        n.label,
                    "type":         n.node_type,
                    "severity":     n.severity,
                    "detail":       n.detail,
                    "blast_radius": n.blast_radius,
                }
                for n in chain.nodes
            ],
            "edges": [
                {
                    "source":     e.source_id,
                    "target":     e.target_id,
                    "technique":  e.technique,
                    "confidence": e.confidence,
                    "is_chain":   e.is_chain,
                }
                for e in chain.edges
            ],
        })
    return result
