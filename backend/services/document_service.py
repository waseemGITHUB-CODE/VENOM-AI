"""
Document Processing Service
─────────────────────────────────────────────────────────────────────
Pipeline:
  file_path → extract_text() → ai_extract_fields() → ai_summarize()
  → return { extracted_data, summary }
─────────────────────────────────────────────────────────────────────
Supports: .pdf  .docx  .doc  .txt
"""
import json
import os

import pdfplumber
from groq import Groq

from core.config import settings

_groq = Groq(api_key=settings.GROQ_API_KEY)


# ══════════════════════════════════════════════════════════════════════
# TEXT EXTRACTION
# ══════════════════════════════════════════════════════════════════════

def _extract_pdf(path: str) -> str:
    text = ""
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text += t + "\n"
    return text.strip()


def _extract_docx(path: str) -> str:
    import docx
    doc  = docx.Document(path)
    return "\n".join(p.text for p in doc.paragraphs if p.text.strip())


def _extract_txt(path: str) -> str:
    with open(path, "r", errors="ignore") as f:
        return f.read()


def extract_text(file_path: str) -> str:
    """Route to the correct extractor based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        return _extract_pdf(file_path)
    elif ext in (".docx", ".doc"):
        return _extract_docx(file_path)
    elif ext == ".txt":
        return _extract_txt(file_path)
    return ""


# ══════════════════════════════════════════════════════════════════════
# AI EXTRACTION PROMPTS
# ══════════════════════════════════════════════════════════════════════

_INVOICE_PROMPT = """\
You are a document data-extraction AI. Extract structured fields from the
invoice text below and return ONLY valid JSON — no markdown fences,
no explanations, just the JSON object.

Required schema:
{
  "company_name":   string | null,
  "invoice_number": string | null,
  "invoice_amount": number | null,
  "invoice_date":   string | null,
  "due_date":       string | null,
  "currency":       string | null,
  "vendor_address": string | null,
  "tax_amount":     number | null,
  "line_items": [
    {"description": string, "quantity": number, "unit_price": number, "total": number}
  ]
}
Set any field to null if not found. Return ONLY the JSON."""

_GENERAL_PROMPT = """\
You are a document data-extraction AI. Extract the most important structured
information from the document below and return ONLY valid JSON.

Include these fields where present:
  document_type, main_parties, key_dates, key_amounts, obligations, summary

Return ONLY valid JSON — no markdown, no preamble."""

_SUMMARY_PROMPT = """\
Summarize this business document in 2–3 concise sentences.
Cover: document type, who it's from, key amounts or dates, and any action required.
Be professional and direct."""


# ══════════════════════════════════════════════════════════════════════
# AI CALLS
# ══════════════════════════════════════════════════════════════════════

def _call_groq(system: str, user_text: str, max_tokens: int = 1024, temperature: float = 0.1) -> str:
    resp = _groq.chat.completions.create(
        model=settings.GROQ_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user_text},
        ],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    return resp.choices[0].message.content.strip()


def ai_extract_invoice(text: str) -> dict:
    raw = _call_groq(_INVOICE_PROMPT, f"INVOICE TEXT:\n{text[:6000]}")
    raw = raw.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"parse_error": True, "raw": raw[:500]}


def ai_extract_general(text: str) -> dict:
    raw = _call_groq(_GENERAL_PROMPT, f"DOCUMENT TEXT:\n{text[:6000]}")
    raw = raw.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"parse_error": True, "raw": raw[:500]}


def ai_summarize(text: str) -> str:
    try:
        return _call_groq(_SUMMARY_PROMPT, f"DOCUMENT:\n{text[:4000]}", max_tokens=256, temperature=0.4)
    except Exception as e:
        return f"Summary unavailable: {e}"


# ══════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════

def process_document_file(file_path: str, doc_type: str) -> dict:
    """
    Full processing pipeline.

    Returns:
      { "extracted_data": dict, "summary": str }
    """
    text = extract_text(file_path)
    if not text:
        return {
            "extracted_data": {"error": "Could not extract text from this file."},
            "summary": "Unable to process document — no extractable text found.",
        }

    summary   = ai_summarize(text)
    extracted = ai_extract_invoice(text) if doc_type == "invoice" else ai_extract_general(text)

    return {"extracted_data": extracted, "summary": summary}
