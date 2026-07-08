"""
VENOM AI — Scan Audit Log
─────────────────────────────────────────────────────────────────────────
Records every scan attempt for legal protection.

Captures: WHO scanned WHAT, WHEN, was it authorized?
If a user is accused of unauthorized scanning, these logs are evidence:
  - The user clicked the consent button
  - They had verified domain ownership (or not)
  - We blocked or allowed the request

Keep these logs forever. Never auto-delete.
"""
from __future__ import annotations
import logging
from typing import Optional
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy.orm import Session

logger = logging.getLogger("venom.audit")


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return url[:255]


def log_scan_event(
    db: Session,
    *,
    action: str,                # scan_started | scan_completed | scan_blocked | recon_started | etc.
    target_url: str,
    owner_id: Optional[int] = None,
    domain_verified: bool = False,
    consent_given: bool = False,
    scan_type: Optional[str] = None,
    user_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    allowed: bool = True,
    block_reason: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Persist an audit log entry. Never raises — audit failures must not block scans.
    """
    try:
        from db.models import ScanAuditLog
        entry = ScanAuditLog(
            owner_id        = owner_id,
            action          = action,
            target_url      = target_url[:1000],
            target_domain   = _extract_domain(target_url)[:255],
            domain_verified = domain_verified,
            consent_given   = consent_given,
            scan_type       = scan_type,
            user_ip         = user_ip[:45] if user_ip else None,
            user_agent      = (user_agent or "")[:500],
            allowed         = allowed,
            block_reason    = (block_reason or "")[:200] if block_reason else None,
            metadata_json   = metadata,
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.error(f"[Audit] log_scan_event failed (non-fatal): {e}")
        try:
            db.rollback()
        except Exception:
            pass


def get_user_audit_history(db: Session, owner_id: int, limit: int = 100) -> list:
    """Fetch recent audit entries for a user."""
    try:
        from db.models import ScanAuditLog
        rows = db.query(ScanAuditLog).filter(
            ScanAuditLog.owner_id == owner_id
        ).order_by(ScanAuditLog.created_at.desc()).limit(limit).all()
        return [{
            "id":            r.id,
            "action":        r.action,
            "target_url":    r.target_url,
            "target_domain": r.target_domain,
            "domain_verified": r.domain_verified,
            "consent_given": r.consent_given,
            "scan_type":     r.scan_type,
            "allowed":       r.allowed,
            "block_reason":  r.block_reason,
            "created_at":    r.created_at.isoformat() if r.created_at else None,
        } for r in rows]
    except Exception as e:
        logger.error(f"[Audit] get_user_audit_history failed: {e}")
        return []
