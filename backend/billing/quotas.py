"""
VENOM AI · backend/billing/quotas.py  —  OPEN SOURCE EDITION
─────────────────────────────────────────────────────────────────────────
In the open-source, self-hosted VENOM there are NO plans, NO quotas, and
NO payments. Every feature is unlimited for everyone.

This module keeps the SAME function signatures the route handlers import,
but every check is now a no-op that never blocks. This means the 6 route
files that call these functions keep working untouched.

If you ever want to re-introduce limits (e.g. for a shared team instance),
this is the single place to add them.
"""
from __future__ import annotations

import logging
from typing import Optional

from db import models

logger = logging.getLogger("venom.quotas")


# ── Scan quota ─ unlimited ──────────────────────────────────────────────────
def check_scan_quota(user: Optional[models.User]) -> None:
    """No-op — scans are unlimited in the open-source edition."""
    return None


def increment_scan_usage(user: Optional[models.User]) -> None:
    """No-op — no usage metering in the open-source edition."""
    return None


# ── Chat quota ─ unlimited ──────────────────────────────────────────────────
def check_chat_quota(user: Optional[models.User]) -> None:
    """No-op — AI chat is unlimited (user supplies their own Groq API key)."""
    return None


def increment_chat_usage(user: Optional[models.User]) -> None:
    """No-op."""
    return None


# ── Monitor quota ─ unlimited ───────────────────────────────────────────────
def check_monitor_quota(user: Optional[models.User], current_count: int = 0) -> None:
    """No-op — monitor as many targets as you like."""
    return None


# ── Feature gate ─ everything unlocked ──────────────────────────────────────
def require_feature(user: Optional[models.User], feature: str) -> None:
    """No-op — all features (PDF reports, priority, API, etc.) are unlocked."""
    return None


# ── Usage snapshot ─ returns an 'unlimited' shape for the UI ────────────────
def get_usage_snapshot(user: Optional[models.User]) -> dict:
    """
    Returns a static 'unlimited' snapshot so any UI that reads plan/usage
    data keeps rendering without a billing backend.
    """
    return {
        "plan": {
            "code": "open-source",
            "name": "Open Source (Unlimited)",
            "price_inr_paise": 0,
            "price_usd_cents": 0,
            "features": {
                "pdf_reports":   True,
                "priority_scan": True,
                "api_access":    True,
                "custom_domain": True,
            },
        },
        "quotas": {
            "scan_monthly": -1,   # -1 = unlimited
            "monitor":      -1,
            "chat_daily":   -1,
        },
        "usage": {
            "scans_used":   0,
            "chats_used":   0,
            "period_start": None,
            "chat_day":     None,
        },
        "subscription": {
            "status":               "active",
            "current_period_end":   None,
            "cancel_at_period_end": False,
        },
    }
