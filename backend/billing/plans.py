"""
VENOM AI · backend/billing/plans.py  —  OPEN SOURCE EDITION
─────────────────────────────────────────────────────────────────────────
The open-source, self-hosted VENOM has NO paid tiers. There is exactly one
plan — "Open Source" — with every quota unlimited and every feature enabled.

We keep the Plan/Subscription tables (and these helper signatures) so the
rest of the codebase keeps working untouched; they just always resolve to
the single unlimited plan.
"""
from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from db import models

logger = logging.getLogger("venom.plans")


# Single unlimited plan. -1 / huge numbers = effectively unlimited.
OPEN_SOURCE_PLAN: dict = {
    "code": "open-source",
    "name": "Open Source (Unlimited)",
    "description": "Self-hosted VENOM AI — every feature unlocked, no limits.",
    "price_inr_paise": 0,
    "price_usd_cents": 0,
    "sort_order": 0,
    "scan_quota_monthly":    100_000_000,
    "monitor_quota":         100_000_000,
    "chat_quota_daily":      100_000_000,
    "feature_pdf_reports":   True,
    "feature_priority_scan": True,
    "feature_api_access":    True,
    "feature_custom_domain": True,
}


def seed_plans(db: Session) -> None:
    """Upsert the single open-source plan on startup. Idempotent."""
    existing = db.query(models.Plan).filter(models.Plan.code == "open-source").first()
    if existing:
        for k, v in OPEN_SOURCE_PLAN.items():
            setattr(existing, k, v)
    else:
        db.add(models.Plan(**OPEN_SOURCE_PLAN))
    db.commit()
    logger.info("[Plans] Seeded open-source unlimited plan")


def get_free_plan(db: Session) -> Optional[models.Plan]:
    """Returns the single open-source plan (name kept for backward compat)."""
    plan = db.query(models.Plan).filter(models.Plan.code == "open-source").first()
    if not plan:
        seed_plans(db)
        plan = db.query(models.Plan).filter(models.Plan.code == "open-source").first()
    return plan


def get_plan_by_code(db: Session, code: str) -> Optional[models.Plan]:
    """All codes resolve to the single open-source plan."""
    return get_free_plan(db)


def ensure_user_subscription(db: Session, user: models.User) -> models.Subscription:
    """
    Every user is on the unlimited open-source plan. Create the subscription
    row if it doesn't exist yet.
    """
    sub = (
        db.query(models.Subscription)
        .filter(models.Subscription.user_id == user.id)
        .filter(models.Subscription.status.in_(["active", "trialing", "past_due"]))
        .order_by(models.Subscription.created_at.desc())
        .first()
    )
    if sub:
        return sub

    plan = get_free_plan(db)
    if not plan:
        raise RuntimeError("Open-source plan not seeded — call seed_plans() at startup")

    sub = models.Subscription(
        user_id=user.id,
        plan_id=plan.id,
        status="active",
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    logger.info(f"[Plans] Created unlimited subscription for user {user.id}")
    return sub
