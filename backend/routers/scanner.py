"""
Scanner API Router
POST /api/scanner/start  — start a website scan
GET  /api/scanner/{id}   — get scan status/results
GET  /api/scanner/       — list user's scans
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import uuid, datetime

from database import get_db

router = APIRouter()

class ScanRequest(BaseModel):
    url: str
    include_port_scan: bool = True
    include_ssl_check: bool = True

class ScanStatusResponse(BaseModel):
    scan_id: str
    url: str
    status: str
    security_score: Optional[float]
    message: str

@router.post("/start", response_model=ScanStatusResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Initiate a website security scan (runs in background)."""
    # Validate URL format
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = str(uuid.uuid4())

    # Add to background task queue
    background_tasks.add_task(_run_scan_task, scan_id, url, db)

    return ScanStatusResponse(
        scan_id=scan_id,
        url=url,
        status="queued",
        security_score=None,
        message=f"Scan queued for {url}. This typically takes 30-60 seconds."
    )

@router.get("/{scan_id}")
async def get_scan_result(scan_id: str, db: Session = Depends(get_db)):
    """Get scan results by ID. Returns status if still running."""
    # In production: fetch from DB
    return {
        "scan_id": scan_id,
        "status": "completed",
        "message": "Fetch from database in production"
    }

@router.get("/")
async def list_scans(db: Session = Depends(get_db)):
    """List all scans for the current user."""
    return {"scans": [], "message": "Connect auth to filter by user"}

async def _run_scan_task(scan_id: str, url: str, db):
    """Background task that runs the actual scan."""
    from workers.scanner import SecurityScanner
    scanner = SecurityScanner()
    try:
        result = await scanner.run_full_scan(url, scan_id)
        # TODO: Save result to DB scan_jobs and scan_results tables
        print(f"[SCAN COMPLETE] {scan_id}: score={result.get('security_score')}")
    except Exception as e:
        print(f"[SCAN ERROR] {scan_id}: {e}")
