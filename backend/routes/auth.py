"""
VENOM AI — routes/auth.py
Complete auth API: signup / login / logout / refresh / me / verify-email /
forgot-password / reset-password / change-password / Google OAuth.

All endpoints are JSON. JWTs are returned in the response body; the frontend
stores them (we don't use cookies so this works cleanly with the static frontend
served from a separate origin).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from auth.rate_limit import rate_limit

from auth.dependencies import get_current_user
from auth.disposable_domains import is_disposable_email
from auth.email_sender import (
    send_login_alert_email,
    send_password_reset_email,
    send_verification_email,
    send_welcome_email,
)
from auth.oauth import (
    build_google_auth_url,
    exchange_code_for_userinfo,
    is_google_oauth_enabled,
)
from auth.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    generate_url_token,
    hash_password,
    hash_token,
    verify_password,
)
from core.config import settings
from db.database import get_db
from db.models import AuthToken, RefreshToken, User

router = APIRouter()
logger = logging.getLogger("venom.auth")


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════
class SignupRequest(BaseModel):
    email:        EmailStr
    password:     str = Field(min_length=8, max_length=128)
    full_name:    Optional[str] = Field(default=None, max_length=255)
    company_name: Optional[str] = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    user:          dict


class RefreshRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str = Field(min_length=8, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(min_length=8, max_length=128)


class UpdateProfileRequest(BaseModel):
    full_name:    Optional[str] = Field(default=None, max_length=255)
    company_name: Optional[str] = Field(default=None, max_length=255)
    avatar_url:   Optional[str] = Field(default=None, max_length=1000)


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
        "oauth_provider": u.oauth_provider,
        "created_at":   u.created_at.isoformat() if u.created_at else None,
    }


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def _issue_tokens(db: Session, user: User, request: Request) -> dict:
    """Create access + refresh tokens. Persist refresh token (hashed) for revocation."""
    access = create_access_token(user.id)
    refresh, refresh_exp = create_refresh_token(user.id)
    db.add(RefreshToken(
        user_id    = user.id,
        token_hash = hash_token(refresh),
        user_agent = request.headers.get("user-agent", "")[:500],
        ip_address = _client_ip(request)[:45],
        expires_at = refresh_exp.replace(tzinfo=None),
    ))
    db.commit()
    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "user":          _user_to_dict(user),
    }


def _make_email_token(db: Session, user: User, purpose: str, hours: int) -> str:
    """Create a single-use URL token for verify-email / password-reset."""
    raw = generate_url_token(32)
    db.add(AuthToken(
        user_id    = user.id,
        token_hash = hash_token(raw),
        purpose    = purpose,
        expires_at = datetime.utcnow() + timedelta(hours=hours),
    ))
    db.commit()
    return raw


def _consume_email_token(db: Session, raw_token: str, purpose: str) -> Optional[User]:
    """Validate + atomically consume a verify-email / reset-password token."""
    if not raw_token:
        return None
    record = db.query(AuthToken).filter(
        AuthToken.token_hash == hash_token(raw_token),
        AuthToken.purpose    == purpose,
        AuthToken.used_at.is_(None),
        AuthToken.expires_at  > datetime.utcnow(),
    ).first()
    if not record:
        return None
    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        return None
    record.used_at = datetime.utcnow()
    db.commit()
    return user


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/signup", status_code=201)
def signup(
    req: SignupRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=3, period_seconds=60)),   # 3 signups/min per IP
):
    """Create a new account. Sends verification email. Returns tokens immediately."""
    email = req.email.lower().strip()

    # ── Reject disposable / temporary email providers ────────────────────────
    if is_disposable_email(email):
        raise HTTPException(
            status_code=422,
            detail="Disposable/temporary email addresses are not allowed. "
                   "Please use a real email — Gmail, Outlook, Yahoo, ProtonMail, "
                   "or a work email all work fine.",
        )

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = User(
        email        = email,
        hashed_pass  = hash_password(req.password),
        full_name    = (req.full_name or "").strip() or None,
        company_name = (req.company_name or "").strip() or None,
        is_active    = True,
        is_verified  = False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Fire verification email (non-blocking — log on failure, don't error)
    try:
        token = _make_email_token(db, user, "email_verify", settings.EMAIL_TOKEN_EXPIRE_HOURS)
        verify_url = f"{settings.FRONTEND_URL}/verify-email.html?token={token}"
        send_verification_email(user.email, user.full_name or user.email, verify_url)
    except Exception as e:
        logger.warning(f"[signup] verification email failed for {user.email}: {e}")

    return _issue_tokens(db, user, request)


@router.post("/login")
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=5, period_seconds=60)),   # 5 attempts/min per IP
):
    """Email + password login."""
    email = req.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if not user or not user.hashed_pass or not verify_password(req.password, user.hashed_pass):
        # Generic message to prevent user enumeration
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is disabled. Contact support.")

    user.last_login_at = datetime.utcnow()
    user.last_login_ip = _client_ip(request)[:45]
    db.commit()
    db.refresh(user)
    return _issue_tokens(db, user, request)


@router.post("/refresh")
def refresh(req: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange a refresh token for a fresh access token (and rotates the refresh token)."""
    payload = decode_refresh_token(req.refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    # Confirm token is still in DB and not revoked
    record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(req.refresh_token),
        RefreshToken.revoked_at.is_(None),
        RefreshToken.expires_at > datetime.utcnow(),
    ).first()
    if not record:
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired.")

    user = db.query(User).filter(User.id == record.user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    # Rotate: revoke the old, issue new pair
    record.revoked_at = datetime.utcnow()
    db.commit()
    return _issue_tokens(db, user, request)


@router.post("/logout")
def logout(req: RefreshRequest, db: Session = Depends(get_db)):
    """Revoke a refresh token (so it can't be used again)."""
    record = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hash_token(req.refresh_token),
        RefreshToken.revoked_at.is_(None),
    ).first()
    if record:
        record.revoked_at = datetime.utcnow()
        db.commit()
    return {"ok": True}


@router.post("/logout-all")
def logout_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke ALL refresh tokens for the current user (sign out from every device)."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()})
    db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    """Return the currently authenticated user."""
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


# ── Email verification ────────────────────────────────────────────────────────
@router.post("/verify-email")
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    """Confirm an email-verification token. Marks user as verified + sends welcome email."""
    user = _consume_email_token(db, req.token, "email_verify")
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link.")
    if not user.is_verified:
        user.is_verified = True
        db.commit()
        try:
            send_welcome_email(user.email, user.full_name or user.email, settings.FRONTEND_URL)
        except Exception:
            pass
    return {"ok": True, "user": _user_to_dict(user)}


@router.post("/resend-verification")
def resend_verification(
    req: ResendVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=3, period_seconds=60)),   # 3 resends/min per IP
):
    """Resend the verification link. Always returns success to prevent enumeration."""
    user = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if user and not user.is_verified:
        try:
            token = _make_email_token(db, user, "email_verify", settings.EMAIL_TOKEN_EXPIRE_HOURS)
            verify_url = f"{settings.FRONTEND_URL}/verify-email.html?token={token}"
            send_verification_email(user.email, user.full_name or user.email, verify_url)
        except Exception as e:
            logger.warning(f"[resend-verification] {e}")
    return {"ok": True, "detail": "If an unverified account exists for this email, a new link has been sent."}


# ── Password reset ────────────────────────────────────────────────────────────
@router.post("/forgot-password")
def forgot_password(
    req: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=3, period_seconds=60)),   # 3 resets/min per IP
):
    """Send a password-reset email. Always returns success to prevent enumeration."""
    user = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if user and user.is_active:
        try:
            token = _make_email_token(db, user, "password_reset", settings.RESET_TOKEN_EXPIRE_HOURS)
            reset_url = f"{settings.FRONTEND_URL}/reset-password.html?token={token}"
            send_password_reset_email(user.email, user.full_name or user.email, reset_url)
        except Exception as e:
            logger.warning(f"[forgot-password] {e}")
    return {"ok": True, "detail": "If an account exists for this email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Set a new password using a reset token."""
    user = _consume_email_token(db, req.token, "password_reset")
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link.")
    user.hashed_pass = hash_password(req.new_password)
    # Revoke all refresh tokens — force re-login everywhere
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at.is_(None),
    ).update({"revoked_at": datetime.utcnow()})
    db.commit()
    return {"ok": True}


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change password while logged in (requires current password)."""
    if not user.hashed_pass or not verify_password(req.current_password, user.hashed_pass):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    user.hashed_pass = hash_password(req.new_password)
    db.commit()
    return {"ok": True}


# ── Delete Account ────────────────────────────────────────────────────────────
class DeleteAccountRequest(BaseModel):
    confirm: str = ""    # must be the literal string "DELETE" to actually delete


@router.post("/delete-account")
def delete_account(
    req: DeleteAccountRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Permanently delete the current user account and all associated data:
    - Scans, vulnerabilities, monitors
    - Chat sessions, reports, subscription
    - Refresh tokens / API keys

    Requires `{"confirm": "DELETE"}` body for explicit opt-in.
    """
    if req.confirm != "DELETE":
        raise HTTPException(400, "Confirmation required. POST {\"confirm\":\"DELETE\"}.")

    user_id = user.id
    user_email = user.email
    try:
        # Cascade-delete every table that references the user.
        # If FK ondelete=CASCADE is set this is cheap; otherwise we sweep manually.
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
                # Most tables use user_id or owner_id
                for fk in ("user_id", "owner_id"):
                    if hasattr(mdl, fk):
                        db.query(mdl).filter(getattr(mdl, fk) == user_id).delete(
                            synchronize_session=False)
                        break
            except Exception as _e:
                logger.warning(f"[delete-account] {model_name} sweep failed: {_e}")
        # Finally the user row itself
        db.query(User).filter(User.id == user_id).delete(synchronize_session=False)
        db.commit()
        logger.info(f"[delete-account] User {user_id} ({user_email}) permanently deleted.")
        return {"ok": True, "deleted": True}
    except Exception as e:
        db.rollback()
        logger.error(f"[delete-account] failed for user {user_id}: {e}")
        raise HTTPException(500, f"Failed to delete account: {e}")


# ── Google OAuth ──────────────────────────────────────────────────────────────
@router.get("/google")
def google_login():
    """Redirect to Google's consent screen."""
    if not is_google_oauth_enabled():
        raise HTTPException(status_code=503, detail="Google OAuth is not configured on this server.")
    return RedirectResponse(build_google_auth_url())


@router.get("/google/callback")
def google_callback(code: str, request: Request, db: Session = Depends(get_db)):
    """
    Google redirects here with ?code=... We exchange it, find or create the user,
    then redirect to the frontend with the access + refresh tokens in the URL hash.
    The frontend reads the hash, stores tokens, and removes the hash.
    """
    if not is_google_oauth_enabled():
        raise HTTPException(status_code=503, detail="Google OAuth is not configured.")

    info = exchange_code_for_userinfo(code)
    if not info or not info.get("email"):
        raise HTTPException(status_code=400, detail="Google sign-in failed — please try again.")

    email      = info["email"].lower().strip()
    google_sub = info.get("sub")
    name       = info.get("name") or email.split("@")[0]
    picture    = info.get("picture")
    g_verified = bool(info.get("email_verified", False))

    user = db.query(User).filter(User.email == email).first()
    if user:
        # Link existing account to Google
        if not user.oauth_provider:
            user.oauth_provider = "google"
            user.oauth_id       = google_sub
        if not user.avatar_url and picture:
            user.avatar_url = picture
        if g_verified and not user.is_verified:
            user.is_verified = True
    else:
        # New user via Google
        user = User(
            email          = email,
            hashed_pass    = None,             # OAuth only — no password
            full_name      = name,
            avatar_url     = picture,
            is_active      = True,
            is_verified    = g_verified,
            oauth_provider = "google",
            oauth_id       = google_sub,
        )
        db.add(user)

    user.last_login_at = datetime.utcnow()
    user.last_login_ip = _client_ip(request)[:45]
    db.commit()
    db.refresh(user)

    tokens = _issue_tokens(db, user, request)
    redirect = (
        f"{settings.FRONTEND_URL}/oauth-callback.html"
        f"#access_token={tokens['access_token']}"
        f"&refresh_token={tokens['refresh_token']}"
    )
    return RedirectResponse(redirect)


# ── Discovery ─────────────────────────────────────────────────────────────────
@router.get("/providers")
def auth_providers():
    """Tells the frontend which login methods are enabled."""
    return {
        "email":  True,
        "google": is_google_oauth_enabled(),
    }
