"""Dashboard API Router — aggregated stats for the frontend"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return aggregated platform stats for the dashboard."""
    # TODO: compute real stats from DB
    return {
        "total_scans": 12,
        "scans_this_week": 3,
        "avg_security_score": 74.5,
        "total_documents": 8,
        "documents_processed": 7,
        "total_reports": 5,
        "active_jobs": 1,
        "recent_scans": [
            {"url": "example.com", "score": 82, "date": "2025-01-10", "status": "completed"},
            {"url": "testsite.org", "score": 61, "date": "2025-01-09", "status": "completed"},
        ],
        "recent_documents": [
            {"name": "Invoice_Jan.pdf", "type": "invoice", "date": "2025-01-10", "status": "completed"},
        ],
        "score_trend": [
            {"date": "Jan 5", "score": 68},
            {"date": "Jan 7", "score": 72},
            {"date": "Jan 10", "score": 74},
        ]
    }

@router.get("/activity")
async def get_recent_activity(db: Session = Depends(get_db)):
    """Return recent platform activity feed."""
    return {
        "activities": [
            {"type": "scan",     "message": "Security scan completed for example.com", "time": "2 min ago"},
            {"type": "document", "message": "Invoice extracted: $4,200.00 from Acme Corp", "time": "1 hr ago"},
            {"type": "report",   "message": "Security audit report generated",           "time": "3 hr ago"},
        ]
    }
