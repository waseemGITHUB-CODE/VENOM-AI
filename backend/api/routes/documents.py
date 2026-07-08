"""
Documents Routes — /api/documents
  POST /upload          upload file → queue AI processing
  GET  /               list all user docs
  GET  /{id}           get document + extracted data
  GET  /{id}/status    lightweight polling
  DELETE /{id}         delete document
"""
import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from core.auth import get_current_user
from core.config import settings
from db.database import get_db
from db.models import DocType, Document, TaskStatus, User
from workers.tasks import process_document

router = APIRouter()

_ALLOWED_EXTS = {".pdf", ".docx", ".doc", ".txt", ".png", ".jpg", ".jpeg"}


class DocOut(BaseModel):
    id:             int
    filename:       str
    doc_type:       str
    status:         str
    file_size:      Optional[int]
    extracted_data: Optional[dict]
    summary:        Optional[str]
    created_at:     str
    processed_at:   Optional[str]


def _doc_out(d: Document) -> DocOut:
    return DocOut(
        id=d.id, filename=d.filename,
        doc_type=d.doc_type.value if hasattr(d.doc_type, "value") else d.doc_type,
        status=d.status.value if hasattr(d.status, "value") else d.status,
        file_size=d.file_size, extracted_data=d.extracted_data,
        summary=d.summary, created_at=str(d.created_at),
        processed_at=str(d.processed_at) if d.processed_at else None,
    )


@router.post("/upload", status_code=202)
async def upload_document(
    file:     UploadFile = File(...),
    doc_type: str        = Form(default="other"),
    db:       Session    = Depends(get_db),
    user:     User       = Depends(get_current_user),
):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in _ALLOWED_EXTS:
        raise HTTPException(400, f"Unsupported file type: {ext}")

    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_FILE_SIZE_MB} MB limit")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    safe_name = f"{user.id}_{file.filename or 'upload'}"
    file_path = os.path.join(settings.UPLOAD_DIR, safe_name)
    with open(file_path, "wb") as f:
        f.write(content)

    try:
        dt = DocType(doc_type)
    except ValueError:
        dt = DocType.OTHER

    doc = Document(
        owner_id=user.id, filename=file.filename, file_path=file_path,
        file_size=len(content), doc_type=dt, status=TaskStatus.RUNNING,
    )
    db.add(doc); db.commit(); db.refresh(doc)

    task = process_document.delay(doc.id)
    doc.celery_task_id = task.id
    db.commit()

    return {"document_id": doc.id, "task_id": task.id, "status": "processing",
            "message": "Document uploaded and queued for AI processing"}


@router.get("/")
def list_docs(limit: int = 20, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(Document)
          .filter(Document.owner_id == user.id)
          .order_by(Document.created_at.desc())
          .limit(limit).all()
    )
    return [_doc_out(d) for d in rows]


@router.get("/{doc_id}")
def get_doc(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    d = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not d: raise HTTPException(404, "Document not found")
    return _doc_out(d)


@router.get("/{doc_id}/status")
def doc_status(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    d = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not d: raise HTTPException(404, "Document not found")
    return {"document_id": d.id,
            "status": d.status.value if hasattr(d.status, "value") else d.status}


@router.delete("/{doc_id}")
def delete_doc(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    d = db.query(Document).filter(Document.id == doc_id, Document.owner_id == user.id).first()
    if not d: raise HTTPException(404, "Document not found")
    if d.file_path and os.path.exists(d.file_path):
        os.remove(d.file_path)
    db.delete(d); db.commit()
    return {"status": "deleted"}
