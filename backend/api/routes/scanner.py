"""
Scanner Routes — /api/scanner
  POST /scan             kick off a new scan
  GET  /scans            list user's scans
  GET  /scans/{id}       get full scan with vulnerabilities
  GET  /scans/{id}/status lightweight polling
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.auth import get_current_user
from db.database import get_db
from db.models import ScanJob, User, Vulnerability
from workers.tasks import run_security_scan

router = APIRouter()


class ScanIn(BaseModel):
    url: str


class VulnOut(BaseModel):
    id:             int
    title:          str
    risk_level:     str
    category:       Optional[str]
    description:    Optional[str]
    ai_explanation: Optional[str]
    recommendation: Optional[str]
    cvss_score:     Optional[float]
    evidence:       Optional[str]
    class Config: from_attributes = True


class ScanOut(BaseModel):
    id:              int
    target_url:      str
    status:          str
    security_score:  Optional[int]
    ai_summary:      Optional[str]
    scan_duration:   Optional[float]
    vulnerabilities: List[VulnOut] = []
    created_at:      str
    completed_at:    Optional[str]


def _vuln_out(v: Vulnerability) -> VulnOut:
    return VulnOut(
        id=v.id, title=v.title,
        risk_level=v.risk_level.value if hasattr(v.risk_level, "value") else v.risk_level,
        category=v.category, description=v.description,
        ai_explanation=v.ai_explanation, recommendation=v.recommendation,
        cvss_score=v.cvss_score, evidence=v.evidence,
    )


def _scan_out(s: ScanJob) -> ScanOut:
    return ScanOut(
        id=s.id, target_url=s.target_url,
        status=s.status.value if hasattr(s.status, "value") else s.status,
        security_score=s.security_score, ai_summary=s.ai_summary,
        scan_duration=s.scan_duration,
        vulnerabilities=[_vuln_out(v) for v in (s.vulnerabilities or [])],
        created_at=str(s.created_at),
        completed_at=str(s.completed_at) if s.completed_at else None,
    )


@router.post("/scan", status_code=202)
def start_scan(
    body: ScanIn,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    url  = body.url if "://" in body.url else f"https://{body.url}"
    scan = ScanJob(owner_id=user.id, target_url=url)
    db.add(scan); db.commit(); db.refresh(scan)
    task = run_security_scan.delay(scan.id, url)
    scan.celery_task_id = task.id; db.commit()
    return {"scan_id": scan.id, "task_id": task.id, "status": "pending",
            "message": f"Scan started for {url}"}


@router.get("/scans")
def list_scans(limit: int = 20, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(ScanJob)
          .filter(ScanJob.owner_id == user.id)
          .order_by(ScanJob.created_at.desc())
          .limit(limit).all()
    )
    return [_scan_out(s) for s in rows]


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    s = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not s: raise HTTPException(404, "Scan not found")
    return _scan_out(s)


@router.get("/scans/{scan_id}/status")
def scan_status(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    s = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.owner_id == user.id).first()
    if not s: raise HTTPException(404, "Scan not found")
    return {
        "scan_id":       s.id,
        "status":        s.status.value if hasattr(s.status, "value") else s.status,
        "security_score":s.security_score,
        "vuln_count":    len(s.vulnerabilities) if s.vulnerabilities else 0,
        "completed_at":  str(s.completed_at) if s.completed_at else None,
    }
