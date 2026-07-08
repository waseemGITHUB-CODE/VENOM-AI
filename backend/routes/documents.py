from fastapi import APIRouter, UploadFile, File, Form, HTTPException
import uuid, os
from pathlib import Path

router = APIRouter()
UPLOAD_DIR = Path("uploads/documents")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED = {"application/pdf","application/msword","image/jpeg","image/png","text/plain"}

@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    user_id: str = Form("anonymous"),
    doc_category: str = Form("auto")
):
    if file.content_type not in ALLOWED:
        raise HTTPException(400, f"File type not allowed: {file.content_type}")
    doc_id = str(uuid.uuid4())
    ext = Path(file.filename).suffix
    save_path = UPLOAD_DIR / f"{doc_id}{ext}"
    content = await file.read()
    if len(content) > 50*1024*1024:
        raise HTTPException(413, "File too large. Max 50MB.")
    with open(save_path, "wb") as f:
        f.write(content)
    # In production: dispatch celery_app.send_task("workers.document_worker.process_document", ...)
    task_id = str(uuid.uuid4())
    return {"document_id": doc_id, "filename": file.filename,
            "task_id": task_id, "status": "processing",
            "message": "Document uploaded. AI is analyzing it now."}

@router.get("/{doc_id}/status")
async def doc_status(doc_id: str):
    return {"document_id": doc_id, "status": "processing"}

@router.get("/{doc_id}/extracted")
async def get_extracted(doc_id: str):
    return {"document_id": doc_id, "fields": {}, "summary": ""}

@router.get("/")
async def list_docs(user_id: str = "all", skip: int = 0, limit: int = 20):
    return {"documents": [], "total": 0}