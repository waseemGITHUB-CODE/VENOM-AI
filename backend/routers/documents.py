"""
Documents API Router
POST /api/documents/upload  — upload and process a document
GET  /api/documents/        — list documents
GET  /api/documents/{id}    — get document with extracted data
"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List
import uuid, os, shutil, datetime

from database import get_db
from config import settings

router = APIRouter()

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".csv", ".docx", ".xlsx"}

@router.post("/upload")
async def upload_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Upload a document for AI processing and data extraction."""
    # Validate extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type {ext} not supported. Allowed: {ALLOWED_EXTENSIONS}")

    # Check file size
    contents = await file.read()
    size_kb = len(contents) / 1024
    if size_kb > settings.MAX_FILE_SIZE_MB * 1024:
        raise HTTPException(413, f"File too large. Max {settings.MAX_FILE_SIZE_MB}MB")

    # Save to upload directory
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    doc_id   = str(uuid.uuid4())
    filename = f"{doc_id}{ext}"
    filepath = os.path.join(settings.UPLOAD_DIR, filename)

    with open(filepath, "wb") as f:
        f.write(contents)

    # Queue background processing
    background_tasks.add_task(_process_document_task, doc_id, filepath, file.filename, db)

    return {
        "document_id": doc_id,
        "filename": file.filename,
        "size_kb": round(size_kb, 2),
        "status": "processing",
        "message": "Document uploaded. AI extraction in progress. Check back in a few seconds."
    }

@router.get("/")
async def list_documents(db: Session = Depends(get_db)):
    """Return all documents for the current user."""
    # TODO: filter by authenticated user
    return {"documents": [], "total": 0}

@router.get("/{document_id}")
async def get_document(document_id: str, db: Session = Depends(get_db)):
    """Get a single document with all extracted data."""
    # TODO: fetch from DB
    return {"document_id": document_id, "status": "fetch from DB in production"}

async def _process_document_task(doc_id: str, filepath: str, original_name: str, db):
    """Background task that runs the document processor."""
    from workers.document_processor import DocumentProcessor
    processor = DocumentProcessor()
    try:
        result = processor.route_file(filepath, original_name)
        print(f"[DOCPROC DONE] {doc_id}: type={result.get('doc_type')}")
        # TODO: Save result to documents + extracted_data tables in DB
    except Exception as e:
        print(f"[DOCPROC ERROR] {doc_id}: {e}")
