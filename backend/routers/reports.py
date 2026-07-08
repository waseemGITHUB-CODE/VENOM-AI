"""Reports API Router"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db
from services.ai_service import AIService

router = APIRouter()

class ReportRequest(BaseModel):
    report_type: str   # security_audit | document_extract | executive | automation
    scan_id: Optional[str] = None
    document_id: Optional[str] = None
    title: Optional[str] = "Untitled Report"

@router.post("/generate")
async def generate_report(request: ReportRequest, db: Session = Depends(get_db)):
    """Generate a PDF report from scan or document data."""
    ai = AIService()

    if request.report_type == "security_audit":
        # TODO: fetch scan data from DB
        sample_data = {
            "target": "example.com",
            "score": 72,
            "vulnerabilities": [
                {"title": "Missing HSTS", "severity": "high"},
                {"title": "Open port 3306", "severity": "high"},
            ]
        }
        executive_summary = ai.generate_executive_summary(sample_data)
        recommendations   = ai.generate_recommendations(sample_data["vulnerabilities"])

        return {
            "report_id": "new-report-id",
            "title": request.title,
            "type": "security_audit",
            "sections": {
                "executive_summary": executive_summary,
                "recommendations": recommendations,
            },
            "status": "generated",
            "pdf_url": None  # TODO: render to PDF with weasyprint/reportlab
        }

    return {"status": "report_type not implemented yet", "type": request.report_type}

@router.get("/")
async def list_reports(db: Session = Depends(get_db)):
    return {"reports": []}
