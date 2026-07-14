"""
VENOM AI — auth/dependencies.py
FastAPI dependencies for auth-protected routes.

VENOM is a self-hosted, single-user tool — there is no login, no email
verification, no multi-user accounts. Every request is automatically
attributed to one fixed local user, so scan ownership and history work
consistently everywhere.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from db.database import get_db
from db.models import User
from fastapi import Depends


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
        hashed_pass=None,
        is_active=True,
        is_verified=True,
        is_admin=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_current_user(db: Session = Depends(get_db)) -> User:
    """Return the local user (always succeeds — single-user mode)."""
    return get_or_create_local_user(db)


def get_optional_user(db: Session = Depends(get_db)) -> User:
    """Return the local user (never None — single-user mode)."""
    return get_or_create_local_user(db)


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    """The local owner always has admin rights."""
    return user


def get_verified_user(user: User = Depends(get_current_user)) -> User:
    """The local owner is always considered verified."""
    return user
