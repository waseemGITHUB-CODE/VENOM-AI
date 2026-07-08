"""
VENOM AI · backend/routes/dashboard.py
Real-time dashboard statistics API.

Aggregates BOTH data sources:
  • ScanJob / Vulnerability      → legacy passive scans
  • AttackScan / AttackFinding   → new OWASP Top 10:2025 active scans
so the dashboard counts always match what the scanner actually found.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from auth.dependencies import get_optional_user
from db.models import User as _AuthUser

router = APIRouter()
logger = logging.getLogger("venom.dashboard")


def _get_db():
    from db.database import SessionLocal
    return SessionLocal()


def _get_models():
    from db import models
    return models


def _scope_scanjob(query, models, current_user):
    if current_user:
        return query.filter(models.ScanJob.owner_id == current_user.id)
    return query.filter(models.ScanJob.owner_id.is_(None))


def _scope_attackscan(query, models, current_user):
    # AttackScan always has a non-null owner_id (auth required).
    if current_user:
        return query.filter(models.AttackScan.owner_id == current_user.id)
    # Anonymous callers see no active scans.
    return query.filter(models.AttackScan.id.is_(None))


@router.get("/stats")
async def dashboard_stats(current_user: _AuthUser = Depends(get_optional_user)):
    """Combined dashboard statistics across passive + active scans (current user only)."""
    db = _get_db()
    models = _get_models()
    try:
        # ── Legacy passive scans (ScanJob) ───────────────────────────────
        pq = db.query(models.ScanJob).order_by(models.ScanJob.created_at.desc())
        pq = _scope_scanjob(pq, models, current_user)
        passive = pq.all()

        # ── New active scans (AttackScan) ────────────────────────────────
        active = []
        if hasattr(models, "AttackScan"):
            aq = db.query(models.AttackScan).order_by(models.AttackScan.started_at.desc())
            aq = _scope_attackscan(aq, models, current_user)
            active = aq.all()

        # ── Unified scan counts ──────────────────────────────────────────
        p_completed = [s for s in passive if s.status == "completed"]
        p_running   = [s for s in passive if s.status == "running"]
        p_failed    = [s for s in passive if s.status == "failed"]

        a_completed = [s for s in active if s.status == "completed"]
        a_running   = [s for s in active if s.status in
                       ("queued", "running_recon", "planning", "running_attacks", "verifying")]
        a_failed    = [s for s in active if s.status in ("failed", "cancelled")]

        total_scans     = len(passive) + len(active)
        completed_count = len(p_completed) + len(a_completed)
        running_count   = len(p_running) + len(a_running)
        failed_count    = len(p_failed) + len(a_failed)

        # ── Security score (passive scans carry a stored score) ──────────
        scores = [s.security_score for s in p_completed if s.security_score is not None]
        avg_score = round(sum(scores) / len(scores)) if scores else 0
        min_score = min(scores) if scores else 0
        max_score = max(scores) if scores else 0

        # ── Vulnerability counts (BOTH sources) ──────────────────────────
        total_vulns    = sum(s.total_issues or 0 for s in p_completed) + \
                         sum(s.total_findings or 0 for s in a_completed)
        total_critical = sum(s.critical_count or 0 for s in p_completed) + \
                         sum(s.critical_count or 0 for s in a_completed)
        total_high     = sum(s.high_count or 0 for s in p_completed) + \
                         sum(s.high_count or 0 for s in a_completed)
        total_medium   = sum(s.medium_count or 0 for s in p_completed) + \
                         sum(s.medium_count or 0 for s in a_completed)
        total_low      = sum(s.low_count or 0 for s in p_completed) + \
                         sum(s.low_count or 0 for s in a_completed)

        # ── Trend (last 7 days vs previous 7) across both sources ────────
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        two_weeks_ago = now - timedelta(days=14)

        def _dt(s, attr):
            v = getattr(s, attr, None)
            if not v:
                return None
            return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

        recent = sum(1 for s in passive if (_dt(s, "created_at") or now) >= week_ago) + \
                 sum(1 for s in active if (_dt(s, "started_at") or now) >= week_ago)
        prev = sum(1 for s in passive
                   if (d := _dt(s, "created_at")) and two_weeks_ago <= d < week_ago) + \
               sum(1 for s in active
                   if (d := _dt(s, "started_at")) and two_weeks_ago <= d < week_ago)

        # ── Threat level ─────────────────────────────────────────────────
        if total_critical > 0:
            threat_level = "CRITICAL"
        elif total_high > 0:
            threat_level = "HIGH"
        elif total_medium > 0:
            threat_level = "MEDIUM"
        elif total_scans > 0:
            threat_level = "LOW"
        else:
            threat_level = "UNKNOWN"

        # ── Most-targeted URLs (both sources) ────────────────────────────
        url_counts = {}
        for s in passive:
            if s.target_url:
                url_counts[s.target_url] = url_counts.get(s.target_url, 0) + 1
        for s in active:
            if s.target_url:
                url_counts[s.target_url] = url_counts.get(s.target_url, 0) + 1
        top_targets = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total_scans":          total_scans,
            "completed_scans":      completed_count,
            "running_scans":        running_count,
            "failed_scans":         failed_count,
            "avg_security_score":   avg_score,
            "min_score":            min_score,
            "max_score":            max_score,
            "total_vulnerabilities": total_vulns,
            "critical_count":       total_critical,
            "high_count":           total_high,
            "medium_count":         total_medium,
            "low_count":            total_low,
            "threat_level":         threat_level,
            "scans_last_7_days":    recent,
            "scans_prev_7_days":    prev,
            "top_targets":          [{"url": u, "scan_count": c} for u, c in top_targets],
            "last_updated":         now.isoformat(),
        }
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        db.close()


@router.get("/recent-vulns")
async def recent_vulnerabilities(limit: int = 20,
                                 current_user: _AuthUser = Depends(get_optional_user)):
    """Most recent critical/high findings across BOTH passive + active scans."""
    db = _get_db()
    models = _get_models()
    try:
        out = []

        # ── New active findings (AttackFinding) — scoped to user's scans ──
        if hasattr(models, "AttackFinding") and hasattr(models, "AttackScan") and current_user:
            a_findings = (
                db.query(models.AttackFinding)
                .join(models.AttackScan, models.AttackFinding.scan_id == models.AttackScan.id)
                .filter(models.AttackScan.owner_id == current_user.id)
                .filter(models.AttackFinding.category == "vulnerability")
                .filter(models.AttackFinding.severity.in_(["critical", "high"]))
                .order_by(models.AttackFinding.id.desc())
                .limit(limit)
                .all()
            )
            for v in a_findings:
                out.append({
                    "id":            f"a{v.id}",
                    "title":         v.title,
                    "severity":      v.severity,
                    "affected_url":  v.affected_url,
                    "cwe_id":        v.cwe_id,
                    "owasp":         v.owasp,
                    "scan_id":       v.scan_id,
                    "poe_confirmed": bool(v.verified),
                    "source":        "active",
                })

        # ── Legacy passive vulns (Vulnerability) — top up to `limit` ─────
        if len(out) < limit and hasattr(models, "Vulnerability"):
            remaining = limit - len(out)
            p_vulns = (
                db.query(models.Vulnerability)
                .filter(models.Vulnerability.severity.in_(["critical", "high"]))
                .order_by(models.Vulnerability.id.desc())
                .limit(remaining)
                .all()
            )
            for v in p_vulns:
                out.append({
                    "id":            f"p{v.id}",
                    "title":         v.title or v.vuln_type,
                    "severity":      v.severity,
                    "affected_url":  v.affected_url,
                    "cwe_id":        v.cwe_id,
                    "owasp":         None,
                    "scan_id":       v.scan_job_id,
                    "poe_confirmed": bool(getattr(v, "poe_confirmed", False)),
                    "source":        "passive",
                })

        return {"vulnerabilities": out[:limit], "total": len(out[:limit])}
    except Exception as e:
        logger.error(f"recent-vulns error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        db.close()


@router.get("/timeline")
async def scan_timeline(days: int = 30,
                        current_user: _AuthUser = Depends(get_optional_user)):
    """Daily scan count for the timeline chart (passive + active combined)."""
    db = _get_db()
    models = _get_models()
    try:
        now = datetime.now(timezone.utc)
        result = []
        for d in range(days - 1, -1, -1):
            day = now - timedelta(days=d)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)

            pq = db.query(models.ScanJob).filter(
                models.ScanJob.created_at >= day_start,
                models.ScanJob.created_at < day_end)
            if current_user:
                pq = pq.filter(models.ScanJob.owner_id == current_user.id)
            else:
                pq = pq.filter(models.ScanJob.owner_id.is_(None))
            count = pq.count()

            if hasattr(models, "AttackScan") and current_user:
                aq = db.query(models.AttackScan).filter(
                    models.AttackScan.started_at >= day_start,
                    models.AttackScan.started_at < day_end,
                    models.AttackScan.owner_id == current_user.id)
                count += aq.count()

            result.append({"date": day_start.strftime("%Y-%m-%d"), "scans": count})
        return {"timeline": result, "days": days}
    except Exception as e:
        logger.error(f"timeline error: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        db.close()
