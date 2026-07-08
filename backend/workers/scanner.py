"""
Scanner Routes — /api/scan
──────────────────────────────────────────────────────────────────
  POST /scan                    kick off a new scan
  GET  /scan/{task_id}/results  ← UUID lookup (what you were hitting)
  GET  /scan/{task_id}/status   lightweight polling
  GET  /scans                   list all user scans
  GET  /scans/{scan_id}         full scan by integer DB id
──────────────────────────────────────────────────────────────────
FIXES vs original:
  1. Added /scan/{task_id}/results  — UUID lookup by celery_task_id
  2. Added _try_sync_from_celery()  — pulls result if Celery done
  3. _save_vulnerabilities()        — writes Vulnerability rows to DB
  4. start_scan passes scan_type + user_id to Celery task
"""
from typing import List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.auth import get_current_user
from db.database import get_db
from db.models import ScanJob, TaskStatus, User, Vulnerability, RiskLevel
from workers.tasks import run_security_scan

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────

class ScanIn(BaseModel):
    url:       str
    scan_type: str = "full"   # full | quick | recon | webapp | infra


class VulnOut(BaseModel):
    id:             int
    title:          str
    severity:       str
    category:       Optional[str] = None
    description:    Optional[str] = None
    evidence:       Optional[str] = None
    recommendation: Optional[str] = None
    ai_explanation: Optional[str] = None
    cvss_score:     Optional[float] = None
    source_tool:    Optional[str] = None

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    scan_id:         int
    task_id:         Optional[str] = None
    target_url:      str
    status:          str
    security_score:  Optional[int] = 0
    grade:           Optional[str] = None
    ai_summary:      Optional[str] = None
    scan_duration:   Optional[float] = None
    total_issues:    int = 0
    critical_count:  int = 0
    high_count:      int = 0
    medium_count:    int = 0
    low_count:       int = 0
    vulnerabilities: List[VulnOut] = []
    created_at:      str
    completed_at:    Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────

_RISK_MAP = {
    "critical": RiskLevel.CRITICAL,
    "high":     RiskLevel.HIGH,
    "medium":   RiskLevel.MEDIUM,
    "low":      RiskLevel.LOW,
    "info":     RiskLevel.LOW,
}

def _sev(v: Vulnerability) -> str:
    raw = v.risk_level
    return raw.value if hasattr(raw, "value") else (raw or "medium")

def _status_str(s: ScanJob) -> str:
    raw = s.status
    return raw.value if hasattr(raw, "value") else (raw or "pending")

def _vuln_out(v: Vulnerability) -> VulnOut:
    return VulnOut(
        id             = v.id,
        title          = v.title,
        severity       = _sev(v),
        category       = v.category,
        description    = v.description,
        evidence       = v.evidence,
        recommendation = v.recommendation,
        ai_explanation = v.ai_explanation,
        cvss_score     = v.cvss_score,
        source_tool    = getattr(v, "source_tool", "internal"),
    )

def _scan_out(s: ScanJob) -> ScanOut:
    vulns = s.vulnerabilities or []
    counts = {"critical":0,"high":0,"medium":0,"low":0}
    for v in vulns:
        sev = _sev(v).lower()
        if sev in counts:
            counts[sev] += 1
    return ScanOut(
        scan_id        = s.id,
        task_id        = s.celery_task_id,
        target_url     = s.target_url,
        status         = _status_str(s),
        security_score = s.security_score or 0,
        grade          = getattr(s, "grade", None),
        ai_summary     = s.ai_summary,
        scan_duration  = s.scan_duration,
        total_issues   = len(vulns),
        critical_count = counts["critical"],
        high_count     = counts["high"],
        medium_count   = counts["medium"],
        low_count      = counts["low"],
        vulnerabilities= [_vuln_out(v) for v in vulns],
        created_at     = str(s.created_at),
        completed_at   = str(s.completed_at) if s.completed_at else None,
    )


def _save_vulnerabilities(db: Session, scan_id: int, vuln_list: list) -> None:
    """Write vulnerability dicts/objects from security_worker into DB."""
    db.query(Vulnerability).filter(
        Vulnerability.scan_job_id == scan_id
    ).delete()
    for v in vuln_list:
        if hasattr(v, "to_dict"):
            v = v.to_dict()
        sev  = str(v.get("severity", "medium")).lower()
        risk = _RISK_MAP.get(sev, RiskLevel.MEDIUM)
        db.add(Vulnerability(
            scan_job_id    = scan_id,
            title          = v.get("title",          "Unknown Finding"),
            description    = v.get("description",    ""),
            risk_level     = risk,
            category       = v.get("vuln_type",      "other"),
            evidence       = (v.get("evidence",      "") or "")[:2000],
            ai_explanation = v.get("ai_explanation",  ""),
            recommendation = v.get("recommendation",  ""),
            cvss_score     = float(v.get("cvss_score", 0.0) or 0.0),
        ))
    db.commit()


def _try_sync_from_celery(scan: ScanJob, db: Session) -> None:
    """Pull finished Celery result into DB if task is done but DB not updated."""
    try:
        from celery.result import AsyncResult
        from workers.celery_app import celery_app

        result = AsyncResult(scan.celery_task_id, app=celery_app)

        if result.state == "SUCCESS" and result.result:
            r = result.result
            scan.status         = TaskStatus.COMPLETED
            scan.security_score = r.get("security_score", 0)
            scan.ai_summary     = r.get("ai_summary",     "")
            scan.scan_duration  = r.get("duration_s",     0.0)
            scan.completed_at   = datetime.now(timezone.utc)
            vulns = r.get("vulnerabilities", [])
            if vulns:
                _save_vulnerabilities(db, scan.id, vulns)
            else:
                db.commit()

        elif result.state == "FAILURE":
            scan.status = TaskStatus.FAILED
            db.commit()

        elif result.state == "STARTED" and _status_str(scan) == "pending":
            scan.status = TaskStatus.RUNNING
            db.commit()

    except Exception as e:
        import logging
        logging.getLogger("cyberplatform").warning(
            f"Celery sync failed for {scan.celery_task_id}: {e}"
        )


# ── Routes ───────────────────────────────────────────────────────

@router.post("/scan", status_code=202)
def start_scan(
    body: ScanIn,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    url  = body.url if "://" in body.url else f"https://{body.url}"
    scan = ScanJob(owner_id=user.id, target_url=url, status=TaskStatus.PENDING)
    db.add(scan); db.commit(); db.refresh(scan)

    task = run_security_scan.delay(
        scan.id, url,
        scan_type=body.scan_type,
        user_id=str(user.id),
    )
    scan.celery_task_id = task.id
    db.commit()

    return {
        "scan_id":  scan.id,
        "task_id":  task.id,
        "status":   "pending",
        "message":  f"Scan started. Poll: GET /api/scan/{task.id}/results",
    }


@router.get("/scan/{task_id}/results")
def get_results_by_task_id(
    task_id: str,
    db:      Session = Depends(get_db),
    user:    User    = Depends(get_current_user),
):
    """Main polling endpoint — use the task_id UUID from POST /scan."""
    scan = (
        db.query(ScanJob)
          .filter(ScanJob.celery_task_id == task_id,
                  ScanJob.owner_id       == user.id)
          .first()
    )
    if not scan:
        raise HTTPException(
            404,
            detail=f"No scan found with task_id '{task_id}'. "
                   "Use the task_id returned by POST /api/scan."
        )

    # Sync from Celery if still pending
    if _status_str(scan) in ("pending", "running"):
        _try_sync_from_celery(scan, db)
        db.refresh(scan)

    out    = _scan_out(scan)
    status = out.status

    return {
        "scan_id":         out.scan_id,
        "task_id":         task_id,
        "status":          status,
        "security_score":  out.security_score,
        "grade":           out.grade or "N/A",
        "total_issues":    out.total_issues,
        "critical_count":  out.critical_count,
        "high_count":      out.high_count,
        "medium_count":    out.medium_count,
        "low_count":       out.low_count,
        "ai_summary":      out.ai_summary or "",
        "scan_duration":   out.scan_duration,
        "vulnerabilities": [v.model_dump() for v in out.vulnerabilities],
        "completed_at":    out.completed_at,
        "message": (
            "Scan in progress — poll again in 5 seconds."
            if status in ("pending", "running")
            else "Scan complete."
        ),
    }


@router.get("/scan/{task_id}/status")
def get_status_by_task_id(
    task_id: str,
    db:      Session = Depends(get_db),
    user:    User    = Depends(get_current_user),
):
    """Lightweight status check — no vulnerability list returned."""
    scan = (
        db.query(ScanJob)
          .filter(ScanJob.celery_task_id == task_id,
                  ScanJob.owner_id       == user.id)
          .first()
    )
    if not scan:
        raise HTTPException(404, f"No scan found with task_id='{task_id}'")

    if _status_str(scan) in ("pending", "running"):
        _try_sync_from_celery(scan, db)
        db.refresh(scan)

    return {
        "scan_id":        scan.id,
        "task_id":        task_id,
        "status":         _status_str(scan),
        "security_score": scan.security_score or 0,
        "vuln_count":     len(scan.vulnerabilities) if scan.vulnerabilities else 0,
        "completed_at":   str(scan.completed_at) if scan.completed_at else None,
    }


@router.get("/scans")
def list_scans(
    limit: int     = 20,
    db:    Session = Depends(get_db),
    user:  User    = Depends(get_current_user),
):
    rows = (
        db.query(ScanJob)
          .filter(ScanJob.owner_id == user.id)
          .order_by(ScanJob.created_at.desc())
          .limit(limit).all()
    )
    return [_scan_out(s) for s in rows]


@router.get("/scans/{scan_id}")
def get_scan_by_id(
    scan_id: int,
    db:      Session = Depends(get_db),
    user:    User    = Depends(get_current_user),
):
    s = (
        db.query(ScanJob)
          .filter(ScanJob.id == scan_id,
                  ScanJob.owner_id == user.id)
          .first()
    )
    if not s:
        raise HTTPException(404, "Scan not found")
    return _scan_out(s)
