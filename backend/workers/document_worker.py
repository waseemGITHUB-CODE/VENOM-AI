"""
workers/document_worker.py
Document Processing Automation Worker

Workflow:
  File uploaded → Celery task → AI reads → Extract fields → Store in DB → Update status
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional

# In production these are real imports:
# from celery import Task
# from workers.celery_app import celery_app
# from groq import Groq
# import pdfplumber, pytesseract

logger = logging.getLogger(__name__)


# ── Celery Task Registration ──────────────────────────────────
# @celery_app.task(bind=True, name="workers.document_worker.process_document", max_retries=3)
def process_document(task_self, file_path: str, doc_id: str,
                     user_id: str, doc_category: str = "auto"):
    """
    Main document processing entry point.
    Called by Celery worker when a file is uploaded.
    """
    logger.info(f"Processing document: {doc_id}, category: {doc_category}")

    try:
        # Step 1: Update status → processing
        update_doc_status(doc_id, "processing", progress=10)

        # Step 2: Detect document type if auto
        if doc_category == "auto":
            doc_category = detect_document_type(file_path)
        logger.info(f"Document category: {doc_category}")
        update_doc_status(doc_id, "processing", progress=25)

        # Step 3: Extract raw text from file
        raw_text = extract_text(file_path)
        if not raw_text:
            raise ValueError("Could not extract text from document")
        update_doc_status(doc_id, "processing", progress=45)

        # Step 4: AI extraction based on category
        extracted_fields = extract_with_ai(raw_text, doc_category)
        update_doc_status(doc_id, "processing", progress=75)

        # Step 5: AI summary
        summary = generate_summary(raw_text, doc_category)
        update_doc_status(doc_id, "processing", progress=90)

        # Step 6: Store results in DB
        store_extracted_data(doc_id, extracted_fields, summary)
        update_doc_status(doc_id, "done", progress=100)

        logger.info(f"Document {doc_id} processed successfully")
        return {"status": "done", "doc_id": doc_id, "fields": extracted_fields}

    except Exception as e:
        logger.error(f"Document processing failed: {e}", exc_info=True)
        update_doc_status(doc_id, "failed")
        # In production: task_self.retry(exc=e, countdown=60)
        raise


# ── Text Extraction ────────────────────────────────────────────
def extract_text(file_path: str) -> str:
    """Extract raw text from PDF, DOCX, image, or plain text."""
    path = Path(file_path)
    ext  = path.suffix.lower()

    if ext == ".pdf":
        return extract_pdf_text(file_path)
    elif ext in (".docx", ".doc"):
        return extract_docx_text(file_path)
    elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".bmp"):
        return extract_image_text(file_path)  # OCR
    elif ext == ".txt":
        return path.read_text(encoding="utf-8", errors="ignore")
    else:
        raise ValueError(f"Unsupported file type: {ext}")


def extract_pdf_text(file_path: str) -> str:
    """
    Extract text from PDF using pdfplumber (layered PDF).
    Falls back to pytesseract OCR for scanned/image PDFs.
    """
    # In production:
    # import pdfplumber
    # with pdfplumber.open(file_path) as pdf:
    #     text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    # if not text.strip():
    #     text = ocr_pdf(file_path)  # OCR fallback
    # return text
    return "[PDF text extracted here]"


def extract_docx_text(file_path: str) -> str:
    # In production:
    # from docx import Document
    # doc = Document(file_path)
    # return "\n".join(para.text for para in doc.paragraphs)
    return "[DOCX text extracted here]"


def extract_image_text(file_path: str) -> str:
    """OCR via pytesseract."""
    # In production:
    # from PIL import Image
    # import pytesseract
    # return pytesseract.image_to_string(Image.open(file_path))
    return "[OCR text extracted here]"


# ── Document Type Detection ────────────────────────────────────
CATEGORY_KEYWORDS = {
    "invoice":  ["invoice", "bill", "total amount", "due date", "payment", "vat", "tax"],
    "contract": ["agreement", "contract", "parties", "clause", "terms", "effective date"],
    "report":   ["report", "summary", "findings", "analysis", "results", "conclusion"],
    "form":     ["form", "application", "fill", "field", "signature", "date of birth"],
}

def detect_document_type(file_path: str) -> str:
    """Detect document category from content keywords."""
    try:
        text = extract_text(file_path).lower()
        scores = {cat: sum(1 for kw in kws if kw in text)
                  for cat, kws in CATEGORY_KEYWORDS.items()}
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "general"
    except Exception:
        return "general"


# ── AI Extraction ──────────────────────────────────────────────
EXTRACTION_PROMPTS = {
    "invoice": """
Extract the following fields from this invoice text.
Return ONLY valid JSON with these exact keys:
{
  "company_name": "",
  "vendor_name": "",
  "invoice_number": "",
  "invoice_date": "",
  "due_date": "",
  "invoice_amount": 0.0,
  "tax_amount": 0.0,
  "currency": "USD",
  "line_items": [],
  "payment_terms": ""
}
If a field is not found, use null.
Invoice text:
""",
    "contract": """
Extract these fields from the contract text as JSON:
{
  "contract_title": "",
  "party_1": "",
  "party_2": "",
  "effective_date": "",
  "expiry_date": "",
  "contract_value": null,
  "key_obligations": [],
  "termination_clause": "",
  "governing_law": ""
}
Contract text:
""",
    "report": """
Extract these fields from the report as JSON:
{
  "report_title": "",
  "author": "",
  "date": "",
  "key_findings": [],
  "recommendations": [],
  "executive_summary": ""
}
Report text:
""",
    "general": """
Extract all key information from this document as JSON.
Include any names, dates, amounts, reference numbers, and important facts.
Return as: {"fields": {"key": "value", ...}, "summary": "brief summary"}
Document text:
""",
}

def extract_with_ai(text: str, category: str) -> dict:
    """
    Use Groq/OpenAI to extract structured fields from document text.
    In production this calls the actual LLM API.
    """
    prompt = EXTRACTION_PROMPTS.get(category, EXTRACTION_PROMPTS["general"])
    full_prompt = prompt + "\n\n" + text[:8000]  # 8k char limit

    # In production:
    # from groq import Groq
    # client = Groq(api_key=os.environ["GROQ_API_KEY"])
    # response = client.chat.completions.create(
    #     model="llama3-70b-8192",
    #     messages=[
    #         {"role": "system", "content": "You are a document data extraction expert. Always return valid JSON only."},
    #         {"role": "user", "content": full_prompt}
    #     ],
    #     temperature=0.1,
    #     max_tokens=1000,
    # )
    # raw = response.choices[0].message.content.strip()
    # return json.loads(raw)

    # Mock return for development:
    if category == "invoice":
        return {
            "company_name": "Acme Corp",
            "vendor_name": "Supplier Ltd",
            "invoice_number": "INV-2024-001",
            "invoice_date": "2024-01-15",
            "due_date": "2024-02-15",
            "invoice_amount": 5250.00,
            "tax_amount": 250.00,
            "currency": "USD",
        }
    return {"extracted": True, "category": category}


def generate_summary(text: str, category: str) -> str:
    """Generate a 2-3 sentence AI summary of the document."""
    # In production: call LLM with summarization prompt
    return f"This {category} document has been processed and key fields extracted."


# ── Database Operations ────────────────────────────────────────
def update_doc_status(doc_id: str, status: str, progress: int = 0):
    """Update document processing status in DB."""
    # In production: UPDATE documents SET status=... WHERE id=...
    logger.info(f"Doc {doc_id}: {status} ({progress}%)")


def store_extracted_data(doc_id: str, fields: dict, summary: str):
    """Store extracted fields in extracted_data table."""
    # In production: INSERT INTO extracted_data (document_id, ...) VALUES (...)
    logger.info(f"Storing extracted data for doc {doc_id}")
