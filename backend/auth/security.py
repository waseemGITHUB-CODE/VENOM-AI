"""
VENOM AI — auth/security.py
Password hashing (bcrypt via passlib) + JWT encode/decode + token hashing.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings

# ── Password hashing ──────────────────────────────────────────────────────────
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Bcrypt-hash a plaintext password."""
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time verify a plaintext password against a bcrypt hash."""
    if not plain or not hashed:
        return False
    try:
        return _pwd_context.verify(plain, hashed)
    except Exception:
        return False


# ── JWT — access tokens ───────────────────────────────────────────────────────
def create_access_token(subject: str, extra: Optional[dict] = None) -> str:
    """
    Encode a short-lived access JWT.
    `subject` is the user id (stringified).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub":  str(subject),
        "iat":  int(now.timestamp()),
        "exp":  int((now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate an access token. Returns payload dict or None."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ── JWT — refresh tokens ──────────────────────────────────────────────────────
def create_refresh_token(subject: str) -> tuple[str, datetime]:
    """
    Encode a long-lived refresh JWT.
    Returns (token, expiry_datetime).
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub":  str(subject),
        "iat":  int(now.timestamp()),
        "exp":  int(exp.timestamp()),
        "type": "refresh",
        "jti":  secrets.token_urlsafe(16),  # unique id — useful for revoke
    }
    token = jwt.encode(payload, settings.JWT_REFRESH_SECRET, algorithm=settings.ALGORITHM)
    return token, exp


def decode_refresh_token(token: str) -> Optional[dict]:
    """Decode and validate a refresh token. Returns payload dict or None."""
    try:
        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload
    except JWTError:
        return None


# ── Token hashing (refresh tokens & email tokens stored as SHA-256) ───────────
def hash_token(token: str) -> str:
    """SHA-256 hash a token for DB storage. Constant length, fast verify."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_url_token(nbytes: int = 32) -> str:
    """Generate a URL-safe random token (for verify-email, password-reset links)."""
    return secrets.token_urlsafe(nbytes)
