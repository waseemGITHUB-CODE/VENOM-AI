"""
VENOM AI — Reconnaissance Routes (Phase 2a)
─────────────────────────────────────────────────────────────────────────
Endpoints:
  POST /api/recon/start            — start a recon scan against a target
  GET  /api/recon/{recon_id}       — get recon results (status + findings)
  GET  /api/recon/list             — list all recons by current user

SAFETY:
  - Forbidden targets are blocked
  - All recon attempts logged to ScanAuditLog (legal trail)
  - Free plan can recon any URL (recon is passive — no attacks fired)
  - For ACTIVE scans (Phase 2b+), domain ownership verification is required
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db, SessionLocal
from db.models import (
    User as _AuthUser, ReconResult, DiscoveredEndpoint,
    DiscoveredForm, DetectedTech,
)
from auth.dependencies import get_optional_user
from auth.rate_limit import rate_limit

from security.recon_engine import run_recon
from security.forbidden_targets import check_forbidden
from security.audit import log_scan_event
from security.domain_verify import normalize_domain

logger = logging.getLogger("venom.recon_route")
router = APIRouter()


# ─── Schemas ─────────────────────────────────────────────────────────────────

class StartReconRequest(BaseModel):
    target_url: str
    consent:    bool = False   # user must check "I have permission"


def _require_user(user: Optional[_AuthUser]) -> _AuthUser:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _to_dict_endpoint(e: DiscoveredEndpoint) -> dict:
    return {
        "id":           e.id,
        "url":          e.url,
        "http_method":  e.http_method,
        "status_code":  e.status_code,
        "content_type": e.content_type,
        "response_size": e.response_size,
        "kind":         e.kind,
        "is_authenticated": e.is_authenticated,
        "parameters":   e.parameters,
        "headers":      e.headers,
    }


def _to_dict_form(f: DiscoveredForm) -> dict:
    return {
        "id":              f.id,
        "page_url":        f.page_url,
        "action":          f.action,
        "method":          f.method,
        "enctype":         f.enctype,
        "inputs":          f.inputs,
        "has_csrf_token":  f.has_csrf_token,
        "csrf_field_name": f.csrf_field_name,
        "purpose":         f.purpose,
    }


def _to_dict_tech(t: DetectedTech) -> dict:
    return {
        "name":       t.name,
        "version":    t.version,
        "category":   t.category,
        "confidence": t.confidence,
        "evidence":   t.evidence,
    }


def _to_dict_recon(r: ReconResult) -> dict:
    return {
        "id":           r.id,
        "target_url":   r.target_url,
        "status":       r.status,
        "progress":     r.progress,
        "total_urls":   r.total_urls,
        "total_forms":  r.total_forms,
        "total_endpoints": r.total_endpoints,
        "auth_method":  r.auth_method,
        "stack_summary": r.stack_summary,
        "error":        r.error,
        "started_at":   r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
    }


# ─── Routes ──────────────────────────────────────────────────────────────────

def _run_recon_in_thread(target_url: str, owner_id: Optional[int]):
    """Run recon in a background thread with its own DB session."""
    db = SessionLocal()
    try:
        run_recon(db, target_url, owner_id=owner_id)
    except Exception as e:
        logger.error(f"[Recon Thread] failed for {target_url}: {e}")
    finally:
        db.close()


@router.post("/start")
def start_recon(
    req: StartReconRequest,
    request: Request,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=10, period_seconds=60)),
):
    """
    Start a recon scan. Recon is PASSIVE (only HTTP GETs, no attacks)
    so it doesn't require domain ownership — but it does require:
      - Consent flag (user acknowledges responsibility)
      - Target not on forbidden list
      - Authentication
    """
    user = _require_user(current_user)

    target_url = (req.target_url or "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    domain = normalize_domain(target_url)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    if not req.consent:
        # Log the blocked attempt
        log_scan_event(
            db,
            action="recon_blocked",
            target_url=target_url,
            owner_id=user.id,
            consent_given=False,
            scan_type="recon",
            user_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            allowed=False,
            block_reason="consent_not_given",
        )
        raise HTTPException(
            status_code=403,
            detail="You must confirm authorization to scan this target. Set consent=true.",
        )

    # ── Forbidden targets check ─────────────────────────────────────────
    forbid = check_forbidden(db, target_url)
    if forbid:
        log_scan_event(
            db,
            action="recon_blocked",
            target_url=target_url,
            owner_id=user.id,
            consent_given=True,
            scan_type="recon",
            user_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            allowed=False,
            block_reason=f"forbidden_target:{forbid['category']}",
        )
        raise HTTPException(
            status_code=403,
            detail=(f"Target blocked: {forbid['reason']} "
                    f"(matched {forbid['pattern']}, category={forbid['category']}). "
                    f"VENOM AI will not scan {forbid['category']} targets."),
        )

    # ── Audit: scan started ─────────────────────────────────────────────
    log_scan_event(
        db,
        action="recon_started",
        target_url=target_url,
        owner_id=user.id,
        consent_given=True,
        scan_type="recon",
        user_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        allowed=True,
    )

    # ── Fire recon in background thread ─────────────────────────────────
    threading.Thread(
        target=_run_recon_in_thread,
        args=(target_url, user.id),
        daemon=True,
    ).start()

    return {
        "message":    f"Recon started for {target_url}",
        "target_url": target_url,
        "status":     "running",
        "poll_url":   "/api/recon/latest",
    }


@router.get("/latest")
def latest_recon(
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Return the most recent recon for this user (for polling after start)."""
    user = _require_user(current_user)
    r = db.query(ReconResult).filter(
        ReconResult.owner_id == user.id
    ).order_by(ReconResult.id.desc()).first()
    if not r:
        raise HTTPException(status_code=404, detail="No recon found")
    return _to_dict_recon(r)


@router.get("/list")
def list_recons(
    limit: int = 20,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all of this user's past recon scans."""
    user = _require_user(current_user)
    rows = db.query(ReconResult).filter(
        ReconResult.owner_id == user.id
    ).order_by(ReconResult.id.desc()).limit(limit).all()
    return {
        "recons": [_to_dict_recon(r) for r in rows],
        "total":  len(rows),
    }


@router.get("/{recon_id}")
def get_recon(
    recon_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get full recon results (summary + endpoints + forms + tech)."""
    user = _require_user(current_user)
    r = db.query(ReconResult).filter(
        ReconResult.id == recon_id,
        ReconResult.owner_id == user.id,
    ).first()
    if not r:
        raise HTTPException(status_code=404, detail="Recon not found")

    endpoints = db.query(DiscoveredEndpoint).filter(
        DiscoveredEndpoint.recon_id == r.id
    ).order_by(DiscoveredEndpoint.id.asc()).all()
    forms = db.query(DiscoveredForm).filter(
        DiscoveredForm.recon_id == r.id
    ).all()
    techs = db.query(DetectedTech).filter(
        DetectedTech.recon_id == r.id
    ).all()

    return {
        "recon":     _to_dict_recon(r),
        "endpoints": [_to_dict_endpoint(e) for e in endpoints],
        "forms":     [_to_dict_form(f) for f in forms],
        "tech":      [_to_dict_tech(t) for t in techs],
    }


@router.delete("/{recon_id}")
def delete_recon(
    recon_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a recon record + cascade-delete its endpoints/forms/tech."""
    user = _require_user(current_user)
    r = db.query(ReconResult).filter(
        ReconResult.id == recon_id,
        ReconResult.owner_id == user.id,
    ).first()
    if not r:
        raise HTTPException(status_code=404, detail="Recon not found")
    db.delete(r)
    db.commit()
    return {"message": "Recon deleted"}
