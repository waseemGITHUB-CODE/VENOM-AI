"""
VENOM AI — auth/dependencies.py
FastAPI dependencies for auth-protected routes.

────────────────────────────────────────────────────────────────────────────
SINGLE-USER MODE (open-source / self-hosted default)
────────────────────────────────────────────────────────────────────────────
When SINGLE_USER_MODE is enabled (the default), VENOM runs as a local,
single-user tool — no login, no email verification. Every request is
automatically attributed to one fixed local user, so scan ownership and
history still work exactly as before.

Set SINGLE_USER_MODE=false in .env to re-enable the full multi-user login
system (useful if a small team shares one instance).
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from auth.security import decode_access_token
from db.database import get_db
from db.models import User


# ── Mode flag ────────────────────────────────────────────────────────────────
def _single_user_mode() -> bool:
    return os.getenv("SINGLE_USER_MODE", "true").strip().lower() in ("1", "true", "yes", "on")


LOCAL_USER_EMAIL = "local@venom.local"
LOCAL_USER_NAME  = "Local User"


def get_or_create_local_user(db: Session) -> User:
    """Return the fixed single-user account, creating it on first use."""
    user = db.query(User).filter(User.email == LOCAL_USER_EMAIL).first()
    if user:
        return user
    user = User(
        email=LOCAL_USER_EMAIL,
        username="local",
        full_name=LOCAL_USER_NAME,
        hashed_pass=None,          # no password — never logs in
        is_active=True,
        is_verified=True,          # verification is disabled in single-user mode
        is_admin=True,             # local owner has full control
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── Token helpers (multi-user mode) ──────────────────────────────────────────
def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ── Dependencies ─────────────────────────────────────────────────────────────
def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    """
    Require an authenticated user.
    In single-user mode this always returns the local user (no token needed).
    In multi-user mode it validates the JWT and 401s if missing/invalid.
    """
    if _single_user_mode():
        return get_or_create_local_user(db)

    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = _extract_bearer(authorization)
    if not token:
        raise creds_exc
    payload = decode_access_token(token)
    if not payload:
        raise creds_exc
    try:
        user_id = int(payload.get("sub", 0))
    except (TypeError, ValueError):
        raise creds_exc
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise creds_exc
    return user


def get_optional_user(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """
    Return the current user, or None.
    In single-user mode this always returns the local user (never None),
    so scan history / ownership is consistent everywhere.
    """
    if _single_user_mode():
        return get_or_create_local_user(db)

    token = _extract_bearer(authorization)
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    try:
        user_id = int(payload.get("sub", 0))
    except (TypeError, ValueError):
        return None
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.is_active:
        return user
    return None


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    """Require admin. In single-user mode the local user is always admin."""
    if _single_user_mode():
        return user
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def get_verified_user(user: User = Depends(get_current_user)) -> User:
    """Require a verified account. In single-user mode verification is skipped."""
    if _single_user_mode():
        return user
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")
    return user
