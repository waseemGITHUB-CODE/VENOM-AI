"""
Dashboard Routes — /api/dashboard
  GET /stats            aggregated platform numbers
  GET /recent-activity  latest 10 events across all modules
  GET /security-trend   last N scan scores for chart
"""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from core.auth import get_current_user
from db.database import get_db
from db.models import Document, Report, ScanJob, User, Vulnerability

router = APIRouter()


@router.get("/stats")
def stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    uid = user.id

    total_scans     = db.query(ScanJob).filter(ScanJob.owner_id == uid).count()
    completed_scans = db.query(ScanJob).filter(ScanJob.owner_id == uid, ScanJob.status == "completed").count()
    running_scans   = db.query(ScanJob).filter(ScanJob.owner_id == uid, ScanJob.status == "running").count()

    total_docs     = db.query(Document).filter(Document.owner_id == uid).count()
    processed_docs = db.query(Document).filter(Document.owner_id == uid, Document.status == "completed").count()

    total_reports = db.query(Report).filter(Report.owner_id == uid).count()

    total_vulns = (
        db.query(func.count(Vulnerability.id))
          .join(ScanJob, Vulnerability.scan_job_id == ScanJob.id)
          .filter(ScanJob.owner_id == uid)
          .scalar() or 0
    )
    critical_vulns = (
        db.query(func.count(Vulnerability.id))
          .join(ScanJob, Vulnerability.scan_job_id == ScanJob.id)
          .filter(ScanJob.owner_id == uid, Vulnerability.risk_level == "critical")
          .scalar() or 0
    )

    avg_score = (
        db.query(func.avg(ScanJob.security_score))
          .filter(ScanJob.owner_id == uid, ScanJob.status == "completed")
          .scalar()
    )

    return {
        "scans": {
            "total": total_scans, "completed": completed_scans, "running": running_scans,
        },
        "documents": {"total": total_docs, "processed": processed_docs},
        "reports":   total_reports,
        "vulnerabilities": {"total": total_vulns, "critical": critical_vulns},
        "average_security_score": round(float(avg_score), 1) if avg_score else None,
    }


@router.get("/recent-activity")
def recent_activity(limit: int = 10, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    uid = user.id
    events = []

    for s in db.query(ScanJob).filter(ScanJob.owner_id == uid).order_by(ScanJob.created_at.desc()).limit(5).all():
        events.append({
            "type": "scan", "id": s.id,
            "title": f"Security scan — {s.target_url}",
            "status": s.status.value if hasattr(s.status, "value") else s.status,
            "score": s.security_score, "time": str(s.created_at),
        })

    for d in db.query(Document).filter(Document.owner_id == uid).order_by(Document.created_at.desc()).limit(5).all():
        events.append({
            "type": "document", "id": d.id,
            "title": f"Document — {d.filename}",
            "status": d.status.value if hasattr(d.status, "value") else d.status,
            "doc_type": d.doc_type.value if hasattr(d.doc_type, "value") else d.doc_type,
            "time": str(d.created_at),
        })

    for r in db.query(Report).filter(Report.owner_id == uid).order_by(Report.created_at.desc()).limit(3).all():
        events.append({
            "type": "report", "id": r.id,
            "title": r.title, "time": str(r.created_at),
        })

    events.sort(key=lambda x: x["time"], reverse=True)
    return events[:limit]


@router.get("/security-trend")
def security_trend(n: int = 10, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(ScanJob)
          .filter(ScanJob.owner_id == user.id, ScanJob.status == "completed",
                  ScanJob.security_score.isnot(None))
          .order_by(ScanJob.created_at.desc())
          .limit(n).all()
    )
    return [
        {"date": str(s.created_at.date()), "score": s.security_score, "url": s.target_url}
        for s in reversed(rows)
    ]
