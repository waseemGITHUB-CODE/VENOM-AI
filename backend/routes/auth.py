"""
VENOM AI — routes/auth.py
Single-user account endpoints: view/update profile, delete account.

VENOM runs single-user by default (SINGLE_USER_MODE=true) — there is no
login/signup system. get_current_user always resolves to the one local
account (see auth/dependencies.py).
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from db.database import get_db
from db.models import User

router = APIRouter()
logger = logging.getLogger("venom.auth")


# ══════════════════════════════════════════════════════════════════════════════
# Schemas
# ══════════════════════════════════════════════════════════════════════════════
class UpdateProfileRequest(BaseModel):
    full_name:    Optional[str] = Field(default=None, max_length=255)
    company_name: Optional[str] = Field(default=None, max_length=255)
    avatar_url:   Optional[str] = Field(default=None, max_length=1000)


class DeleteAccountRequest(BaseModel):
    confirm: str = ""    # must be the literal string "DELETE" to actually delete


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════
def _user_to_dict(u: User) -> dict:
    return {
        "id":           u.id,
        "email":        u.email,
        "full_name":    u.full_name,
        "company_name": u.company_name,
        "avatar_url":   u.avatar_url,
        "is_admin":     u.is_admin,
        "is_verified":  u.is_verified,
        "created_at":   u.created_at.isoformat() if u.created_at else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════
@router.get("/me")
def me(user: User = Depends(get_current_user)):
    """Return the current (local) user."""
    return _user_to_dict(user)


@router.patch("/me")
def update_me(
    req: UpdateProfileRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update the current user's profile."""
    if req.full_name    is not None: user.full_name    = req.full_name.strip() or None
    if req.company_name is not None: user.company_name = req.company_name.strip() or None
    if req.avatar_url   is not None: user.avatar_url   = req.avatar_url.strip()   or None
    db.commit()
    db.refresh(user)
    return _user_to_dict(user)


@router.post("/delete-account")
def delete_account(
    req: DeleteAccountRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Permanently delete the current user account and all associated data:
    scans, vulnerabilities, monitors, chat sessions, reports, subscription.

    Requires `{"confirm": "DELETE"}` body for explicit opt-in.
    """
    if req.confirm != "DELETE":
        raise HTTPException(400, "Confirmation required. POST {\"confirm\":\"DELETE\"}.")

    user_id = user.id
    user_email = user.email
    try:
        from db import models as _m
        try:
            db.query(_m.Vulnerability).filter(
                _m.Vulnerability.scan_job_id.in_(
                    db.query(_m.ScanJob.id).filter(_m.ScanJob.owner_id == user_id)
                )
            ).delete(synchronize_session=False)
        except Exception: pass
        for model_name in [
            "ScanJob", "MonitorTarget", "MonitorAlert", "Report",
            "PaymentEvent", "Subscription", "UsageMeter",
            "RefreshToken", "ApiKey", "EmailToken",
        ]:
            mdl = getattr(_m, model_name, None)
            if not mdl: continue
            try:
                for fk in ("user_id", "owner_id"):
                    if hasattr(mdl, fk):
                        db.query(mdl).filter(getattr(mdl, fk) == user_id).delete(
                            synchronize_session=False)
                        break
            except Exception as _e:
                logger.warning(f"[delete-account] {model_name} sweep failed: {_e}")
        db.query(User).filter(User.id == user_id).delete(synchronize_session=False)
        db.commit()
        logger.info(f"[delete-account] User {user_id} ({user_email}) permanently deleted.")
        return {"ok": True, "deleted": True}
    except Exception as e:
        db.rollback()
        logger.error(f"[delete-account] failed for user {user_id}: {e}")
        raise HTTPException(500, f"Failed to delete account: {e}")
