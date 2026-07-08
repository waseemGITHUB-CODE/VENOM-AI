"""
Reports Routes — /api/reports
  POST /generate        generate a PDF report
  GET  /                list user's reports
  GET  /{id}            get report data
  GET  /{id}/download   download PDF file
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from core.auth import get_current_user
from db.database import get_db
from db.models import Report, ScanJob, User
from services.report_service import generate_invoice_report, generate_security_report

router = APIRouter()


class GenerateIn(BaseModel):
    scan_job_id: Optional[int] = None
    report_type: str           = "security_audit"


@router.post("/generate", status_code=201)
def generate(
    body: GenerateIn,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    if body.report_type == "security_audit":
        if body.scan_job_id:
            scan = db.query(ScanJob).filter(
                ScanJob.id == body.scan_job_id, ScanJob.owner_id == user.id
            ).first()
            if not scan:
                raise HTTPException(404, "Scan not found")
        else:
            scan = (
                db.query(ScanJob)
                  .filter(ScanJob.owner_id == user.id, ScanJob.status == "completed")
                  .order_by(ScanJob.created_at.desc())
                  .first()
            )
            if not scan:
                raise HTTPException(404, "No completed scans found. Run a scan first.")
        report = generate_security_report(scan, user, db)

    elif body.report_type == "invoice_batch":
        report = generate_invoice_report(user, db)

    else:
        raise HTTPException(400, f"Unknown report_type: {body.report_type}")

    return {"report_id": report.id, "title": report.title, "message": "Report generated"}


@router.get("/")
def list_reports(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(Report)
          .filter(Report.owner_id == user.id)
          .order_by(Report.created_at.desc())
          .limit(50).all()
    )
    return [
        {"id": r.id, "title": r.title, "report_type": r.report_type,
         "created_at": str(r.created_at), "has_pdf": bool(r.pdf_path)}
        for r in rows
    ]


@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    r = db.query(Report).filter(Report.id == report_id, Report.owner_id == user.id).first()
    if not r: raise HTTPException(404, "Report not found")
    return {
        "id": r.id, "title": r.title, "report_type": r.report_type,
        "executive_summary": r.executive_summary, "content": r.content,
        "created_at": str(r.created_at),
    }


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    r = db.query(Report).filter(Report.id == report_id, Report.owner_id == user.id).first()
    if not r or not r.pdf_path:
        raise HTTPException(404, "PDF not found")
    ext      = ".html" if r.pdf_path.endswith(".html") else ".pdf"
    media    = "text/html" if ext == ".html" else "application/pdf"
    filename = r.title.replace(" ", "_").replace("/", "-") + ext
    return FileResponse(r.pdf_path, media_type=media, filename=filename)
