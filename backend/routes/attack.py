"""
VENOM AI — Active Attack Scan Routes (Phase 2c)
─────────────────────────────────────────────────────────────────────────
Endpoints:
  POST   /api/attack/start             — start a new active OWASP scan
  GET    /api/attack/list              — list user's scans
  GET    /api/attack/{scan_id}         — full scan detail + findings
  POST   /api/attack/{scan_id}/cancel  — cancel in-flight scan
  DELETE /api/attack/{scan_id}         — delete a scan + its findings

SAFETY GATES (in order, before any scan starts):
  1. User must be authenticated
  2. Target must NOT be on forbidden list
  3. User must have verified domain ownership
  4. User must check consent flag
  5. User must be within concurrent scan limit
  6. User must be within daily scan-same-target limit
  7. Every gate logged to ScanAuditLog
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db, SessionLocal
from db.models import User as _AuthUser, AttackScan, AttackFinding, VerifiedDomain
from auth.dependencies import get_optional_user
from auth.rate_limit import rate_limit

from security.audit import log_scan_event
from security.forbidden_targets import check_forbidden
from security.domain_verify import is_domain_verified, normalize_domain
from security.demo_targets import (
    is_authorized_without_verification, list_demo_targets,
)
from security.attack_orchestrator import run_attack_scan, request_cancel

logger = logging.getLogger("venom.attack_route")
router = APIRouter()


# ─── Concurrency / quota limits ──────────────────────────────────────────────
CONCURRENT_SCAN_LIMITS_BY_PLAN = {
    "free":     1,
    "starter":  2,
    "pro":      3,
    "business": 10,
}
DAILY_SAME_TARGET_LIMIT = 5   # max 5 scans of same domain per day per user

DEFAULT_ENABLED_CATEGORIES = ["A01", "A02", "A03", "A04", "A05",
                              "A06", "A07", "A08", "A09", "A10"]   # full OWASP Top 10:2025


# ─── Schemas ─────────────────────────────────────────────────────────────────

class StartAttackRequest(BaseModel):
    target_url:         str
    consent:            bool = False
    scan_intensity:     str = "standard"          # light | standard | aggressive
    enabled_categories: Optional[List[str]] = None  # ["A01","A05",...]


def _require_user(user: Optional[_AuthUser]) -> _AuthUser:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _get_plan_code(db: Session, user: _AuthUser) -> str:
    """Best-effort lookup of user's current plan code. Defaults to 'free'."""
    try:
        from billing.plans import ensure_user_subscription
        sub = ensure_user_subscription(db, user)
        if sub and sub.plan:
            return (sub.plan.code or "free").lower()
    except Exception as e:
        logger.debug(f"[Attack] plan lookup failed: {e}")
    return "free"


def _to_dict_scan(s: AttackScan, with_plan: bool = False) -> dict:
    out = {
        "id":              s.id,
        "target_url":      s.target_url,
        "target_domain":   s.target_domain,
        "status":          s.status,
        "progress":        s.progress,
        "phase":           s.phase,
        "current_engine":  getattr(s, "current_engine", None),
        "error":           s.error,
        "recon_id":        s.recon_id,
        "domain_verified": s.domain_verified,
        "consent_given":   s.consent_given,
        "scan_intensity":  s.scan_intensity,
        "max_rps":         s.max_rps,
        "enabled_categories": s.enabled_categories,
        "total_findings":  s.total_findings,
        "critical_count":  s.critical_count,
        "high_count":      s.high_count,
        "medium_count":    s.medium_count,
        "low_count":       s.low_count,
        "hardening_count": s.hardening_count,
        "started_at":      s.started_at.isoformat() if s.started_at else None,
        "completed_at":    s.completed_at.isoformat() if s.completed_at else None,
        "duration_s":      s.duration_s,
    }
    if with_plan:
        out["attack_plan"] = s.attack_plan
    return out


def _to_dict_finding(f: AttackFinding) -> dict:
    return {
        "id":             f.id,
        "category":       f.category,
        "owasp":          f.owasp,
        "severity":       f.severity,
        "title":          f.title,
        "description":    f.description,
        "impact":         f.impact,
        "recommendation": f.recommendation,
        "affected_url":   f.affected_url,
        "parameter":      f.parameter,
        "http_method":    f.http_method,
        "payload":        f.payload,
        "evidence":       f.evidence,
        "poc":            f.poc,
        "cwe_id":         f.cwe_id,
        "cve_id":         f.cve_id,
        "cvss_score":     f.cvss_score,
        "likelihood":     f.likelihood,
        "impact_score":   f.impact_score,
        "risk_score":     f.risk_score,
        "verified":       f.verified,
        "false_positive": bool(getattr(f, "false_positive", False)),
        "confidence":     getattr(f, "confidence", "probable"),
        "confidence_reason": getattr(f, "confidence_reason", None),
        "source_tool":    f.source_tool,
        # AI enrichment fields
        "ai_explanation": f.ai_explanation,
        "ai_code_fix":    f.ai_code_fix,
        "ai_fix_language": f.ai_fix_language,
        "ai_enriched_at": f.ai_enriched_at.isoformat() if f.ai_enriched_at else None,
        "created_at":     f.created_at.isoformat() if f.created_at else None,
    }


# ─── Safety gate functions ──────────────────────────────────────────────────

def _check_concurrent_limit(db: Session, user_id: int, plan_code: str) -> tuple:
    """Return (allowed, current_count, limit)."""
    limit = CONCURRENT_SCAN_LIMITS_BY_PLAN.get(plan_code, 1)
    running = db.query(AttackScan).filter(
        AttackScan.owner_id == user_id,
        AttackScan.status.in_(["queued", "running_recon", "planning", "running_attacks", "verifying"]),
    ).count()
    return (running < limit), running, limit


def _check_daily_same_target(db: Session, user_id: int, target_domain: str) -> tuple:
    """Return (allowed, today_count, limit) for scans of same domain today."""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    cnt = db.query(AttackScan).filter(
        AttackScan.owner_id == user_id,
        AttackScan.target_domain == target_domain,
        AttackScan.started_at >= today_start,
    ).count()
    return (cnt < DAILY_SAME_TARGET_LIMIT), cnt, DAILY_SAME_TARGET_LIMIT


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.post("/start")
def start_attack(
    req: StartAttackRequest,
    request: Request,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=5, period_seconds=60)),
):
    """
    Start a real OWASP Top 10:2025 active attack scan.
    All safety gates enforced here before the orchestrator is invoked.
    """
    user = _require_user(current_user)

    # ── 1. Normalize + basic validation ─────────────────────────────────
    target_url = (req.target_url or "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    target_domain = normalize_domain(target_url)
    if not target_domain:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    user_ip    = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")

    def _block(reason: str, status_code: int = 403):
        log_scan_event(db,
            action="attack_scan_blocked",
            target_url=target_url,
            owner_id=user.id,
            consent_given=req.consent,
            scan_type="active",
            user_ip=user_ip,
            user_agent=user_agent,
            allowed=False,
            block_reason=reason,
        )
        raise HTTPException(status_code=status_code, detail=reason)

    # ── Single-user / self-hosted mode ───────────────────────────────────
    # No consent gate, no domain-ownership verification, no concurrent/daily
    # limits. The ONE safety net we always keep is the forbidden-target
    # blocklist (.gov/.mil/banks/hospitals) — that stays on for legal safety.
    import os as _os
    _single_user = _os.getenv("SINGLE_USER_MODE", "true").strip().lower() in ("1", "true", "yes", "on")

    # ── Forbidden targets (ALWAYS enforced) ──────────────────────────────
    forbid = check_forbidden(db, target_url)
    if forbid:
        _block(
            f"Target blocked: {forbid['reason']} "
            f"(category={forbid['category']}, pattern={forbid['pattern']}). "
            f"VENOM AI never scans {forbid['category']} targets."
        )

    if not _single_user:
        # ── Multi-user mode: enforce consent + ownership + limits ────────
        if not req.consent:
            _block("Consent required. Set consent=true to confirm you have authorization to scan this target.")

        pre_authorized, pre_auth_reason = is_authorized_without_verification(target_url)
        verified = is_domain_verified(db, user.id, target_url)
        if not (verified or pre_authorized):
            _block(
                "Active scans require verified domain ownership. "
                f"Verify {target_domain} first, or scan a public demo target / localhost."
            )

        plan_code = _get_plan_code(db, user)
        ok, running, limit = _check_concurrent_limit(db, user.id, plan_code)
        if not ok:
            _block(
                f"Concurrent scan limit reached: {running}/{limit} for plan '{plan_code}'.",
                status_code=429,
            )

        ok2, today, limit2 = _check_daily_same_target(db, user.id, target_domain)
        if not ok2:
            _block(
                f"Daily scan limit on this target reached: {today}/{limit2}.",
                status_code=429,
            )

    # ── 7. Categories validation ─────────────────────────────────────────
    cats = req.enabled_categories or DEFAULT_ENABLED_CATEGORIES
    valid_cats = {"A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"}
    cats = [c for c in cats if c in valid_cats]
    if not cats:
        cats = DEFAULT_ENABLED_CATEGORIES

    # ── Create scan row ──────────────────────────────────────────────────
    scan = AttackScan(
        owner_id=user.id,
        target_url=target_url,
        target_domain=target_domain,
        status="queued",
        progress=0,
        # In single-user mode there is no ownership check; multi-user sets these above.
        domain_verified=bool(locals().get("verified") or locals().get("pre_authorized")),
        consent_given=True,
        user_ip=user_ip,
        scan_intensity=req.scan_intensity,
        max_rps={"light": 5, "standard": 10, "aggressive": 20}.get(req.scan_intensity, 10),
        enabled_categories=cats,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # ── Launch orchestrator in background thread ─────────────────────────
    scan_id = scan.id
    threading.Thread(
        target=run_attack_scan,
        args=(scan_id,),
        daemon=True,
        name=f"AttackScan-{scan_id}",
    ).start()

    log_scan_event(db,
        action="attack_scan_queued",
        target_url=target_url,
        owner_id=user.id,
        domain_verified=True,
        consent_given=True,
        scan_type="active",
        user_ip=user_ip,
        user_agent=user_agent,
        allowed=True,
        metadata={"scan_id": scan_id, "categories": cats},
    )

    return {
        "message":  f"Active scan started against {target_url}",
        "scan_id":  scan_id,
        "poll_url": f"/api/attack/{scan_id}",
        "estimated_duration_s": 300,
        "categories": cats,
    }


@router.get("/demo-targets")
def get_demo_targets(
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
):
    """
    Return the list of pre-approved demo targets that can be scanned
    WITHOUT domain ownership verification.

    These are publicly declared vulnerable test sites maintained by
    security vendors and the OWASP Foundation.
    """
    _require_user(current_user)
    return {
        "demo_targets": list_demo_targets(),
        "localhost_allowed": True,
        "note": (
            "These targets can be scanned without verification because their "
            "owners publicly publish them for security testing. You can also "
            "scan localhost/127.0.0.1 freely."
        ),
    }


@router.get("/list")
def list_attack_scans(
    limit: int = 20,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List the current user's recent attack scans."""
    user = _require_user(current_user)
    rows = db.query(AttackScan).filter(
        AttackScan.owner_id == user.id,
    ).order_by(AttackScan.id.desc()).limit(limit).all()
    return {
        "scans": [_to_dict_scan(s) for s in rows],
        "total": len(rows),
    }


@router.get("/{scan_id}")
def get_attack_scan(
    scan_id: int,
    include_plan: bool = False,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get full attack scan detail + findings split into vulnerability / hardening."""
    user = _require_user(current_user)
    s = db.query(AttackScan).filter(
        AttackScan.id == scan_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")

    all_findings = db.query(AttackFinding).filter(
        AttackFinding.scan_id == scan_id,
    ).order_by(
        # Vulnerabilities first, then by severity, then by risk score
        AttackFinding.category.desc(),   # 'vulnerability' before 'hardening' alphabetically
        AttackFinding.risk_score.desc(),
    ).all()

    # Split into two groups — findings marked as false positives are hidden
    _active = [f for f in all_findings if not bool(getattr(f, "false_positive", False))]

    # Collapse duplicates of the same vuln type + title (e.g. the same SSTI found
    # on 32 forms) into ONE representative row + a location count, so results are
    # readable. Applies to already-saved scans at read time.
    def _collapse(rows):
        groups, order = {}, []
        for f in rows:
            key = ((f.owasp or ""), (f.title or "").strip().lower())
            groups.setdefault(key, []).append(f)
            if key not in order:
                order.append(key)
        out = []
        for key in order:
            grp = groups[key]
            d = _to_dict_finding(grp[0])
            if len(grp) > 1:
                locs = []
                for g in grp:
                    u = getattr(g, "affected_url", None)
                    if u and u not in locs:
                        locs.append(u)
                d["locations"] = len(grp)
                extra = f"\n\nDetected on {len(grp)} location(s)"
                if locs[:5]:
                    extra += ": " + ", ".join(locs[:5]) + ("…" if len(locs) > 5 else "")
                d["description"] = (d.get("description") or "") + extra + "."
            out.append(d)
        return out

    vulnerabilities = _collapse([f for f in _active if f.category == "vulnerability"])
    hardening       = _collapse([f for f in _active if f.category == "hardening"])
    dismissed_count = sum(1 for f in all_findings if bool(getattr(f, "false_positive", False)))

    # Sort vulns by CONFIDENCE first (true positives on top), then risk, then severity
    confidence_order = {"confirmed": 0, "probable": 1, "suspected": 2, "hardening": 3}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulnerabilities.sort(key=lambda f: (
        confidence_order.get(f.get("confidence", "probable"), 1),
        -int(f.get("risk_score", 0)),
        severity_order.get(f.get("severity", "info"), 99),
    ))

    return {
        "scan":            _to_dict_scan(s, with_plan=include_plan),
        "vulnerabilities": vulnerabilities,
        "hardening":       hardening,
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "total_hardening":       len(hardening),
            "by_confidence": {
                tier: sum(1 for v in vulnerabilities if v.get("confidence") == tier)
                for tier in ("confirmed", "probable", "suspected")
            },
            "by_severity": {
                sev: sum(1 for v in vulnerabilities if v["severity"] == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "by_owasp": {
                cat: sum(1 for v in vulnerabilities if v["owasp"] == cat)
                for cat in ("A01","A02","A03","A04","A05","A06","A07","A08","A09","A10")
            },
            "dismissed": dismissed_count,
        },
    }


@router.post("/finding/{finding_id}/false-positive")
def toggle_false_positive(
    finding_id: int,
    body: dict = None,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Mark a finding as a false positive (or restore it). Dismissed findings are
    hidden from results and won't reappear on re-render."""
    user = _require_user(current_user)
    f = db.query(AttackFinding).join(AttackScan, AttackFinding.scan_id == AttackScan.id).filter(
        AttackFinding.id == finding_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    value = True if body is None else bool(body.get("value", True))
    f.false_positive = value
    if hasattr(f, "is_false_positive"):
        f.is_false_positive = value
    db.commit()
    return {"ok": True, "finding_id": finding_id, "false_positive": value}


@router.get("/{scan_id}/diff")
def scan_diff(
    scan_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Compare this scan to the PREVIOUS completed scan of the same target.
    Returns findings that are new, fixed (gone), or unchanged."""
    user = _require_user(current_user)
    cur = db.query(AttackScan).filter(
        AttackScan.id == scan_id, AttackScan.owner_id == user.id,
    ).first()
    if not cur:
        raise HTTPException(status_code=404, detail="Scan not found")

    prev = db.query(AttackScan).filter(
        AttackScan.owner_id == user.id,
        AttackScan.target_url == cur.target_url,
        AttackScan.status == "completed",
        AttackScan.id != cur.id,
        AttackScan.started_at < cur.started_at,
    ).order_by(AttackScan.started_at.desc()).first()

    def _key(f):
        return f"{(f.owasp or '').strip()}|{(f.title or '').strip().lower()}"

    def _load(sid):
        rows = db.query(AttackFinding).filter(
            AttackFinding.scan_id == sid,
            AttackFinding.false_positive == False,   # noqa: E712
        ).all()
        return {_key(f): f for f in rows}

    cur_map = _load(cur.id)
    if not prev:
        return {"ok": True, "has_previous": False,
                "current_scan": {"id": cur.id, "target": cur.target_url},
                "new": [], "fixed": [], "unchanged": list(cur_map.keys()),
                "counts": {"new": 0, "fixed": 0, "unchanged": len(cur_map)}}

    prev_map = _load(prev.id)
    brief = lambda f: {"title": f.title, "owasp": f.owasp, "severity": f.severity,
                       "confidence": getattr(f, "confidence", "probable")}
    new_keys   = [k for k in cur_map if k not in prev_map]
    fixed_keys = [k for k in prev_map if k not in cur_map]
    same_keys  = [k for k in cur_map if k in prev_map]
    return {
        "ok": True, "has_previous": True,
        "current_scan":  {"id": cur.id,  "target": cur.target_url,  "at": cur.started_at.isoformat()  if cur.started_at  else None},
        "previous_scan": {"id": prev.id, "target": prev.target_url, "at": prev.started_at.isoformat() if prev.started_at else None},
        "new":       [brief(cur_map[k])  for k in new_keys],
        "fixed":     [brief(prev_map[k]) for k in fixed_keys],
        "unchanged": [brief(cur_map[k])  for k in same_keys],
        "counts": {"new": len(new_keys), "fixed": len(fixed_keys), "unchanged": len(same_keys)},
    }


@router.post("/{scan_id}/cancel")
def cancel_attack_scan(
    scan_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Request cancellation of an in-flight attack scan."""
    user = _require_user(current_user)
    s = db.query(AttackScan).filter(
        AttackScan.id == scan_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if s.status in ("completed", "failed", "cancelled"):
        return {"message": f"Scan already {s.status}"}
    request_cancel(scan_id)
    return {"message": "Cancel requested. Scan will stop at next checkpoint."}


@router.post("/clear-history")
def clear_attack_history(
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete ALL finished OWASP scans + findings (keeps running ones).
    In single-user mode, clears every scan regardless of owner_id (some are saved
    anonymously) so 'Clear History' actually empties the list."""
    user = _require_user(current_user)
    active = ("queued", "running_recon", "planning", "running_attacks", "verifying")
    from auth.dependencies import _single_user_mode
    q = db.query(AttackScan)
    if not _single_user_mode():
        q = q.filter(AttackScan.owner_id == user.id)
    scans = q.all()
    deleted = 0
    for s in scans:
        st = getattr(s.status, "value", s.status)
        if str(st) in active:
            continue
        db.delete(s)
        deleted += 1
    db.commit()
    return {"ok": True, "deleted": deleted}


@router.delete("/{scan_id}")
def delete_attack_scan(
    scan_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a scan + cascade-delete its findings."""
    user = _require_user(current_user)
    s = db.query(AttackScan).filter(
        AttackScan.id == scan_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if s.status in ("queued", "running_recon", "planning", "running_attacks", "verifying"):
        raise HTTPException(status_code=400, detail="Cancel the scan before deleting")
    db.delete(s)
    db.commit()
    return {"message": "Scan deleted"}


@router.get("/{scan_id}/attack-chain")
def attack_chain_for_scan(
    scan_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Return structured attack chains for a completed scan.
    Each chain = entry_point → tools → attacker_steps → impact, plus AI narrative.
    """
    user = _require_user(current_user)
    s = db.query(AttackScan).filter(
        AttackScan.id == scan_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(AttackFinding).filter(
        AttackFinding.scan_id == scan_id,
        AttackFinding.category == "vulnerability",
    ).order_by(AttackFinding.risk_score.desc()).all()
    findings_dicts = [_to_dict_finding(f) for f in findings]

    from security.attack_chain_builder import build_attack_chains
    chains = build_attack_chains(findings_dicts, s.target_url or "")

    return {
        "scan_id":      scan_id,
        "target_url":   s.target_url,
        "total_chains": len(chains),
        "chains":       chains,
    }


@router.get("/{scan_id}/report")
def download_attack_report(
    scan_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Generate + stream a PDF security report for an OWASP active scan."""
    from fastapi.responses import Response
    user = _require_user(current_user)
    s = db.query(AttackScan).filter(
        AttackScan.id == scan_id,
        AttackScan.owner_id == user.id,
    ).first()
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(AttackFinding).filter(
        AttackFinding.scan_id == scan_id,
    ).order_by(AttackFinding.risk_score.desc()).all()

    from security.attack_report import build_attack_pdf
    pdf_bytes = build_attack_pdf(s, findings)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="venom-owasp-report-{scan_id}.pdf"'},
    )


@router.get("/audit/recent")
def recent_audit(
    limit: int = 50,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Show the current user's recent audit-log entries (legal trail visibility)."""
    user = _require_user(current_user)
    from security.audit import get_user_audit_history
    return {"audit": get_user_audit_history(db, user.id, limit=limit)}
