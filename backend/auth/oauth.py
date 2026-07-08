"""
VENOM AI — auth/oauth.py
Google OAuth 2.0 flow — pure-stdlib + httpx (no extra deps).

Flow:
  1. GET  /api/auth/google           → redirects to Google
  2. GET  /api/auth/google/callback  → exchanges code, creates/links user, redirects to frontend with token
"""
from __future__ import annotations

import logging
import secrets
from typing import Optional
from urllib.parse import urlencode

import httpx

from core.config import settings

logger = logging.getLogger("venom.auth.oauth")

GOOGLE_AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL    = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def is_google_oauth_enabled() -> bool:
    return bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET)


def build_google_auth_url(state: Optional[str] = None) -> str:
    """Return the URL the user should be redirected to to start Google login."""
    if state is None:
        state = secrets.token_urlsafe(24)
    params = {
        "client_id":     settings.GOOGLE_CLIENT_ID,
        "redirect_uri":  settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid email profile",
        "access_type":   "online",
        "prompt":        "select_account",
        "state":         state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def exchange_code_for_userinfo(code: str) -> Optional[dict]:
    """
    Exchange an authorization code for an access token, then fetch the user's
    Google profile. Returns dict with keys: sub, email, email_verified, name, picture.
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            tr = client.post(GOOGLE_TOKEN_URL, data={
                "code":          code,
                "client_id":     settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri":  settings.GOOGLE_REDIRECT_URI,
                "grant_type":    "authorization_code",
            })
            if tr.status_code != 200:
                logger.warning(f"[Google] token exchange failed: {tr.status_code} {tr.text[:200]}")
                return None
            access_token = tr.json().get("access_token")
            if not access_token:
                return None

            ur = client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if ur.status_code != 200:
                logger.warning(f"[Google] userinfo failed: {ur.status_code}")
                return None
            return ur.json()
    except Exception as e:
        logger.error(f"[Google] OAuth error: {e}")
        return None
