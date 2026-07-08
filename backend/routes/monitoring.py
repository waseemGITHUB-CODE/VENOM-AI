"""
VENOM AI — Continuous Monitoring Route (DB-persisted)

KEY CHANGES (Phase 1):
  - All monitor state stored in PostgreSQL (was in-memory dict, lost on restart)
  - All alerts stored in DB (was in-memory list)
  - Celery Beat task runs every 60s — scans run even when browser is closed
  - Alerts are desktop-only — no email notifications
  - _trigger_scan() always creates its OWN DB session (safe from any thread)
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import models
from db.database import get_db, SessionLocal
from auth.dependencies import get_optional_user
from db.models import User as _AuthUser, MonitorTarget, MonitorAlert
from billing.quotas import check_monitor_quota

logger = logging.getLogger(__name__)
router = APIRouter()


INTERVAL_MINUTES = {
    "five_min":   5,
    "thirty_min": 30,
    "hourly":     60,
    "daily":      1440,
    "weekly":     10080,
}


# ─── Pydantic schemas ─────────────────────────────────────────────────────────
class AddMonitorRequest(BaseModel):
    target_url:  str
    interval:    str = "daily"
    alert_on_drop: bool = True
    alert_on_new:  bool = True


class TargetRequest(BaseModel):
    target_url: str


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _next_scan_time(interval: str) -> datetime:
    mins = INTERVAL_MINUTES.get(interval, 1440)
    return _now_utc() + timedelta(minutes=mins)


def _owner_id_of(user: Optional[_AuthUser]) -> Optional[int]:
    return user.id if user else None


def _monitor_to_dict(m: MonitorTarget) -> dict:
    """Convert a MonitorTarget row to the dict shape the frontend expects."""
    return {
        "id":              m.id,
        "target_url":      m.target_url,
        "interval":        m.interval,
        "alert_on_drop":   m.alert_on_drop,
        "alert_on_new":    m.alert_on_new,
        "enabled":         m.enabled,
        "status":          m.status or "idle",
        "last_scan_at":    m.last_scan_at.isoformat() if m.last_scan_at else None,
        "next_scan_at":    m.next_scan_at.isoformat() if m.next_scan_at else None,
        "last_score":      m.last_score,
        "last_grade":      m.last_grade,
        "last_vuln_count": m.last_vuln_count or 0,
        "alert_count":     m.alert_count or 0,
        "progress":        m.progress or 0,
        "added_at":        m.added_at.isoformat() if m.added_at else None,
    }


def _alert_to_dict(a: MonitorAlert) -> dict:
    return {
        "id":         a.id,
        "target_url": a.target_url,
        "type":       a.alert_type,
        "message":    a.message,
        "old_score":  a.old_score,
        "new_score":  a.new_score,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "read":       a.read,
    }


def _add_alert_db(db: Session, owner_id: Optional[int], target_url: str,
                  alert_type: str, message: str,
                  old_score: Optional[int] = None,
                  new_score: Optional[int] = None) -> MonitorAlert:
    """Persist an alert. Caller must commit."""
    alert = MonitorAlert(
        owner_id=owner_id,
        target_url=target_url,
        alert_type=alert_type,
        message=message,
        old_score=old_score,
        new_score=new_score,
        read=False,
    )
    db.add(alert)
    return alert


# ─── Scan trigger (runs in daemon thread) ────────────────────────────────────
def _trigger_scan(monitor_id: int):
    """
    Fire a scan for a monitored target by its DB ID.
    ALWAYS creates its own DB session — safe to call from any thread.
    """
    db = SessionLocal()
    try:
        entry = db.query(MonitorTarget).filter(MonitorTarget.id == monitor_id).first()
        if not entry or not entry.target_url:
            return

        target_url = entry.target_url
        owner_id   = entry.owner_id

        entry.status       = "scanning"
        entry.last_scan_at = _now_utc()
        db.commit()

        celery_used = False
        result      = {}

        # ── Try Celery (fire-and-wait, max 2 min) ─────────────────────────
        try:
            import time
            from workers.celery_app import celery_app

            scan_job = models.ScanJob(
                target_url=target_url,
                status="PENDING",
                scan_type="monitor",
                owner_id=owner_id,
            )
            db.add(scan_job)
            db.flush()
            scan_id = scan_job.id

            task = celery_app.send_task(
                "workers.tasks.run_security_scan",
                kwargs={"url": target_url, "user_id": "monitor",
                        "scan_type": "quick", "scan_id": scan_id},
                queue="security",
            )
            entry.celery_task_id = task.id
            entry.scan_job_id    = scan_id
            db.commit()
            celery_used = True
            logger.info(f"[Monitor] Celery task queued for {target_url}: {task.id}")

            # Poll max 2 minutes
            for _ in range(24):
                time.sleep(5)
                try:
                    db.expire(scan_job)
                    db.refresh(scan_job)
                except Exception:
                    db.close()
                    db = SessionLocal()
                    scan_job = db.query(models.ScanJob).filter(
                        models.ScanJob.id == scan_id).first()
                    if scan_job is None:
                        break
                if scan_job.status in ("COMPLETED", "FAILED"):
                    break
                # Re-fetch entry to update progress
                entry = db.query(MonitorTarget).filter(MonitorTarget.id == monitor_id).first()
                if entry:
                    entry.progress = getattr(scan_job, "progress", 0) or 0
                    db.commit()

            result = {
                "security_score": getattr(scan_job, "security_score", 0) or 0,
                "grade":          getattr(scan_job, "grade", "F") or "F",
                "total_issues":   getattr(scan_job, "total_issues", 0) or 0,
            }
        except Exception as celery_err:
            logger.warning(f"[Monitor] Celery path failed ({celery_err}) — inline scan")
            celery_used = False

        # ── Inline scanner fallback ────────────────────────────────────────
        if not celery_used:
            try:
                from routes.scanning import _run_inline_scan_sync
                result = _run_inline_scan_sync(target_url)
            except Exception as inline_err:
                logger.error(f"[Monitor] Inline scan failed for {target_url}: {inline_err}")
                result = {"security_score": 0, "grade": "F", "total_issues": 0}

        # ── Reload entry, evaluate results, fire alerts ──────────────────
        entry = db.query(MonitorTarget).filter(MonitorTarget.id == monitor_id).first()
        if not entry:
            return

        new_score = result.get("security_score", 0)
        new_grade = result.get("grade", "F")
        new_vulns = result.get("total_issues", 0)
        old_score = entry.last_score

        if old_score is not None:
            if entry.alert_on_drop and new_score < old_score:
                diff = old_score - new_score
                _add_alert_db(
                    db, owner_id, target_url, "score_drop",
                    f"Security score dropped {diff} pts ({old_score} → {new_score})",
                    old_score=old_score, new_score=new_score,
                )
                entry.alert_count = (entry.alert_count or 0) + 1

            if entry.alert_on_new and new_vulns > (entry.last_vuln_count or 0):
                delta = new_vulns - (entry.last_vuln_count or 0)
                _add_alert_db(
                    db, owner_id, target_url, "new_vuln",
                    f"{delta} new vulnerability(ies) detected on {target_url}",
                    old_score=old_score, new_score=new_score,
                )
                entry.alert_count = (entry.alert_count or 0) + 1

        entry.last_score      = new_score
        entry.last_grade      = new_grade
        entry.last_vuln_count = new_vulns
        entry.next_scan_at    = _next_scan_time(entry.interval)
        entry.status          = "idle"
        entry.progress        = 0
        db.commit()

    except Exception as exc:
        logger.error(f"[Monitor] Scan failed for monitor {monitor_id}: {exc}", exc_info=True)
        try:
            entry = db.query(MonitorTarget).filter(MonitorTarget.id == monitor_id).first()
            if entry:
                _add_alert_db(db, entry.owner_id, entry.target_url, "scan_error",
                              f"Scan failed: {str(exc)[:120]}")
                entry.status       = "error"
                entry.next_scan_at = _next_scan_time(entry.interval)
                db.commit()
        except Exception:
            db.rollback()
    finally:
        try:
            db.close()
        except Exception:
            pass


# ─── Public scheduler (called by Celery Beat) ────────────────────────────────
_STALE_SCAN_MINUTES = 15

def check_due_scans():
    """
    Called by Celery Beat every 60s.
    - Fires due scans in daemon threads.
    - Auto-resets scans stuck in 'scanning' for >15 minutes.
    """
    db = SessionLocal()
    try:
        now = _now_utc()
        stale_cutoff = now - timedelta(minutes=_STALE_SCAN_MINUTES)

        # Auto-reset stale scans
        stale = db.query(MonitorTarget).filter(
            MonitorTarget.status == "scanning",
            MonitorTarget.last_scan_at < stale_cutoff,
        ).all()
        for s in stale:
            logger.warning(f"[Monitor] Stale scan reset for {s.target_url}")
            s.status       = "error"
            s.next_scan_at = _next_scan_time(s.interval)
            _add_alert_db(db, s.owner_id, s.target_url, "scan_error",
                          "Scan timed out and was automatically reset")
        if stale:
            db.commit()

        # Find due scans
        due = db.query(MonitorTarget).filter(
            MonitorTarget.enabled == True,
            MonitorTarget.status != "scanning",
            MonitorTarget.next_scan_at <= now,
        ).all()

        for m in due:
            t = threading.Thread(target=_trigger_scan, args=(m.id,), daemon=True)
            t.start()
            logger.info(f"[Monitor] Triggered scan for {m.target_url} (monitor_id={m.id})")
    except Exception as e:
        logger.error(f"[Monitor] check_due_scans failed: {e}", exc_info=True)
    finally:
        db.close()


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("/list")
def list_monitors(current_user: Optional[_AuthUser] = Depends(get_optional_user),
                  db: Session = Depends(get_db)):
    """Return all monitored targets for the current user."""
    owner_id = _owner_id_of(current_user)

    q = db.query(MonitorTarget)
    if owner_id is not None:
        q = q.filter(MonitorTarget.owner_id == owner_id)
    else:
        q = q.filter(MonitorTarget.owner_id.is_(None))

    monitors = q.all()
    # Sort: currently scanning first, then by last scan time
    monitors.sort(key=lambda m: (
        0 if (m.status == "scanning") else 1,
        m.last_scan_at or datetime.min,
    ), reverse=True)

    monitors_list = [_monitor_to_dict(m) for m in monitors]
    return {
        "monitors": monitors_list,
        "total":    len(monitors_list),
        "active":   sum(1 for m in monitors if m.enabled),
        "scanning": sum(1 for m in monitors if m.status == "scanning"),
    }


@router.post("/add")
def add_monitor(req: AddMonitorRequest,
                current_user: Optional[_AuthUser] = Depends(get_optional_user),
                db: Session = Depends(get_db)):
    """Add a target to continuous monitoring."""
    owner_id = _owner_id_of(current_user)
    import re
    from urllib.parse import urlparse as _urlparse

    url = req.target_url.strip().rstrip("/")
    if not url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        parsed = _urlparse(url)
        host = parsed.hostname or ""
        valid = (
            parsed.scheme in ("http", "https") and
            (host == "localhost" or "." in host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host))
        )
        if not valid:
            raise ValueError("bad host")
    except Exception:
        raise HTTPException(status_code=400,
                            detail=f"Invalid URL: '{req.target_url}'. Use https://example.com")

    # If user already has this target, just update settings
    existing = db.query(MonitorTarget).filter(
        MonitorTarget.target_url == url,
        MonitorTarget.owner_id == owner_id,
    ).first()
    if existing:
        existing.interval      = req.interval
        existing.alert_on_drop = req.alert_on_drop
        existing.alert_on_new  = req.alert_on_new
        existing.enabled       = True
        db.commit()
        return {"message": f"Monitor updated for {url}", "monitor": _monitor_to_dict(existing)}

    # ── Quota gate: monitor target limit ────────────────────────────────
    current_count = db.query(MonitorTarget).filter(MonitorTarget.owner_id == owner_id).count()
    check_monitor_quota(current_user, current_count=current_count)

    new_monitor = MonitorTarget(
        owner_id=owner_id,
        target_url=url,
        interval=req.interval,
        alert_on_drop=req.alert_on_drop,
        alert_on_new=req.alert_on_new,
        enabled=True,
        status="idle",
        next_scan_at=_next_scan_time(req.interval),
        last_vuln_count=0,
        alert_count=0,
    )
    db.add(new_monitor)
    db.commit()
    db.refresh(new_monitor)

    # First scan in a daemon thread — response returns instantly
    monitor_id = new_monitor.id
    threading.Thread(target=_trigger_scan, args=(monitor_id,), daemon=True).start()

    return {"message": f"Now monitoring {url}", "monitor": _monitor_to_dict(new_monitor)}


def _find_monitor(db: Session, target_url: str, owner_id: Optional[int]) -> MonitorTarget:
    """Find a monitor row for this user, tolerating trailing-slash differences."""
    url = target_url.strip().rstrip("/")
    candidates = [url, url + "/"]
    q = db.query(MonitorTarget).filter(
        MonitorTarget.target_url.in_(candidates),
        MonitorTarget.owner_id == owner_id,
    )
    m = q.first()
    if not m:
        raise HTTPException(status_code=404, detail=f"Monitor not found for: {target_url}")
    return m


@router.post("/remove")
def remove_monitor(req: TargetRequest,
                   current_user: Optional[_AuthUser] = Depends(get_optional_user),
                   db: Session = Depends(get_db)):
    """Remove a target from monitoring."""
    owner_id = _owner_id_of(current_user)
    m = _find_monitor(db, req.target_url, owner_id)
    url = m.target_url
    db.delete(m)
    db.commit()
    return {"message": f"Removed monitor for {url}"}


@router.post("/toggle")
def toggle_monitor(req: TargetRequest,
                   current_user: Optional[_AuthUser] = Depends(get_optional_user),
                   db: Session = Depends(get_db)):
    """Enable or disable a monitor."""
    owner_id = _owner_id_of(current_user)
    m = _find_monitor(db, req.target_url, owner_id)
    m.enabled = not m.enabled
    db.commit()
    state = "enabled" if m.enabled else "paused"
    return {"message": f"Monitor {state}", "enabled": m.enabled}


@router.post("/reset")
def reset_monitor(req: TargetRequest,
                  current_user: Optional[_AuthUser] = Depends(get_optional_user),
                  db: Session = Depends(get_db)):
    """Force-reset a scan stuck in 'scanning' or 'error' state back to 'idle'."""
    owner_id = _owner_id_of(current_user)
    m = _find_monitor(db, req.target_url, owner_id)
    old_status = m.status or "idle"
    m.status       = "idle"
    m.next_scan_at = _next_scan_time(m.interval)
    m.progress     = 0
    db.commit()
    logger.info(f"[Monitor] Force-reset {m.target_url} from '{old_status}' → 'idle'")
    return {"message": "Monitor reset to idle", "status": "idle"}


@router.post("/scan-now")
def scan_now(req: TargetRequest,
             current_user: Optional[_AuthUser] = Depends(get_optional_user),
             db: Session = Depends(get_db)):
    """Manually trigger an immediate scan for a monitored target."""
    owner_id = _owner_id_of(current_user)
    m = _find_monitor(db, req.target_url, owner_id)
    if m.status == "scanning":
        return {"message": "Scan already in progress"}
    monitor_id = m.id
    threading.Thread(target=_trigger_scan, args=(monitor_id,), daemon=True).start()
    return {"message": f"Scan triggered for {m.target_url}"}


@router.get("/alerts")
def get_alerts(unread_only: bool = False,
               current_user: Optional[_AuthUser] = Depends(get_optional_user),
               db: Session = Depends(get_db)):
    """Return alert history for the current user."""
    owner_id = _owner_id_of(current_user)

    q = db.query(MonitorAlert)
    if owner_id is not None:
        q = q.filter(MonitorAlert.owner_id == owner_id)
    else:
        q = q.filter(MonitorAlert.owner_id.is_(None))
    if unread_only:
        q = q.filter(MonitorAlert.read == False)

    alerts = q.order_by(MonitorAlert.created_at.desc()).limit(200).all()
    total  = db.query(MonitorAlert).filter(
        MonitorAlert.owner_id == owner_id if owner_id is not None
        else MonitorAlert.owner_id.is_(None)
    ).count()
    unread = db.query(MonitorAlert).filter(
        MonitorAlert.read == False,
        MonitorAlert.owner_id == owner_id if owner_id is not None
        else MonitorAlert.owner_id.is_(None)
    ).count()
    return {
        "alerts": [_alert_to_dict(a) for a in alerts],
        "total":  total,
        "unread": unread,
    }


@router.post("/alerts/mark-read")
def mark_all_read(current_user: Optional[_AuthUser] = Depends(get_optional_user),
                  db: Session = Depends(get_db)):
    """Mark all alerts as read for the current user."""
    owner_id = _owner_id_of(current_user)
    q = db.query(MonitorAlert).filter(MonitorAlert.read == False)
    if owner_id is not None:
        q = q.filter(MonitorAlert.owner_id == owner_id)
    else:
        q = q.filter(MonitorAlert.owner_id.is_(None))
    for a in q.all():
        a.read = True
    db.commit()
    return {"message": "All alerts marked as read"}


@router.delete("/alerts/{alert_id}")
def delete_alert(alert_id: int,
                 current_user: Optional[_AuthUser] = Depends(get_optional_user),
                 db: Session = Depends(get_db)):
    """Delete a specific alert (only from the current user's bucket)."""
    owner_id = _owner_id_of(current_user)
    q = db.query(MonitorAlert).filter(MonitorAlert.id == alert_id)
    if owner_id is not None:
        q = q.filter(MonitorAlert.owner_id == owner_id)
    else:
        q = q.filter(MonitorAlert.owner_id.is_(None))
    a = q.first()
    if a:
        db.delete(a)
        db.commit()
    return {"message": "Alert deleted"}


@router.get("/events")
async def alert_events(current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """
    SSE stream — pushes new monitoring alerts to the browser in real-time.
    Each user only sees their own alerts.
    """
    import asyncio, json as _json
    from fastapi.responses import StreamingResponse as _SR

    owner_id = _owner_id_of(current_user)

    async def generator():
        # Track the highest alert id we've already sent
        db = SessionLocal()
        try:
            q = db.query(MonitorAlert)
            if owner_id is not None:
                q = q.filter(MonitorAlert.owner_id == owner_id)
            else:
                q = q.filter(MonitorAlert.owner_id.is_(None))
            latest = q.order_by(MonitorAlert.id.desc()).first()
            last_seen_id = latest.id if latest else 0
        finally:
            db.close()

        keep_alive_interval = 25
        elapsed = 0
        while True:
            await asyncio.sleep(1)
            elapsed += 1

            # Fresh DB session each tick (safe + cheap)
            db = SessionLocal()
            try:
                q = db.query(MonitorAlert).filter(MonitorAlert.id > last_seen_id)
                if owner_id is not None:
                    q = q.filter(MonitorAlert.owner_id == owner_id)
                else:
                    q = q.filter(MonitorAlert.owner_id.is_(None))
                new = q.order_by(MonitorAlert.id.asc()).all()
                if new:
                    last_seen_id = max(a.id for a in new)
                    for alert in new:
                        payload = _json.dumps({
                            "id":         alert.id,
                            "type":       alert.alert_type,
                            "message":    alert.message,
                            "target_url": alert.target_url,
                            "old_score":  alert.old_score,
                            "new_score":  alert.new_score,
                            "created_at": alert.created_at.isoformat() if alert.created_at else None,
                        })
                        yield f"event: alert\ndata: {payload}\n\n"
            finally:
                db.close()

            if elapsed >= keep_alive_interval:
                elapsed = 0
                yield ": keep-alive\n\n"

    return _SR(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/heartbeat")
def heartbeat(current_user: Optional[_AuthUser] = Depends(get_optional_user),
              db: Session = Depends(get_db)):
    """
    Lightweight heartbeat — returns user's monitor + alert counts.
    Scheduler runs via Celery Beat now, so we no longer need to tick from here.
    """
    owner_id = _owner_id_of(current_user)

    q = db.query(MonitorTarget)
    if owner_id is not None:
        q = q.filter(MonitorTarget.owner_id == owner_id)
    else:
        q = q.filter(MonitorTarget.owner_id.is_(None))
    monitors = q.all()

    qa = db.query(MonitorAlert).filter(MonitorAlert.read == False)
    if owner_id is not None:
        qa = qa.filter(MonitorAlert.owner_id == owner_id)
    else:
        qa = qa.filter(MonitorAlert.owner_id.is_(None))
    unread = qa.count()

    return {
        "monitors":      len(monitors),
        "active":        sum(1 for m in monitors if m.enabled),
        "unread_alerts": unread,
        "scanning_now":  [m.target_url for m in monitors if m.status == "scanning"],
    }
