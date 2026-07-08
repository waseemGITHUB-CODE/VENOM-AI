"""
Document Processing Worker
Handles: PDF text extraction, AI-powered data extraction, classification, storage
"""
import os
import datetime
from pathlib import Path
from typing import Optional

from services.ai_service import AIService

class DocumentProcessor:
    def __init__(self):
        self.ai = AIService()

    def extract_text_from_pdf(self, file_path: str) -> str:
        """Extract raw text from a PDF file using PyMuPDF (fitz)."""
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(file_path)
            text = ""
            for page in doc:
                text += page.get_text("text") + "\n"
            doc.close()
            return text.strip()
        except ImportError:
            return self._extract_with_pdfplumber(file_path)
        except Exception as e:
            return f"[PDF extraction error: {str(e)}]"

    def _extract_with_pdfplumber(self, file_path: str) -> str:
        """Fallback PDF extractor using pdfplumber."""
        try:
            import pdfplumber
            text = ""
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    text += (page.extract_text() or "") + "\n"
            return text.strip()
        except Exception as e:
            return f"[pdfplumber error: {str(e)}]"

    def process_document(self, file_path: str, original_filename: str) -> dict:
        """
        Full document processing pipeline:
        1. Extract raw text
        2. Classify document type
        3. Extract structured data via AI
        4. Generate summary
        Returns structured result dict.
        """
        print(f"[DOCPROC] Processing: {original_filename}")

        # Step 1: Extract raw text
        raw_text = self.extract_text_from_pdf(file_path)
        if not raw_text or raw_text.startswith("[PDF"):
            return {
                "status": "failed",
                "error": "Could not extract text from document",
                "filename": original_filename
            }

        print(f"[DOCPROC] Extracted {len(raw_text)} characters")

        # Step 2: Classify
        doc_type = self.ai.classify_document(raw_text)
        print(f"[DOCPROC] Classified as: {doc_type}")

        # Step 3: Extract structured data
        extracted = self.ai.extract_invoice_data(raw_text)

        # Step 4: Generate summary
        summary = self.ai.summarize_document(raw_text)

        return {
            "status": "completed",
            "filename": original_filename,
            "doc_type": doc_type,
            "raw_text": raw_text,
            "summary": summary,
            "extracted": extracted,
            "processed_at": datetime.datetime.utcnow().isoformat(),
            "char_count": len(raw_text),
        }

    def process_text_file(self, file_path: str, original_filename: str) -> dict:
        """Process plain text, CSV, or other text-based documents."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_text = f.read()
        except Exception as e:
            return {"status": "failed", "error": str(e)}

        doc_type = self.ai.classify_document(raw_text)
        extracted = self.ai.extract_invoice_data(raw_text)
        summary = self.ai.summarize_document(raw_text)

        return {
            "status": "completed",
            "filename": original_filename,
            "doc_type": doc_type,
            "raw_text": raw_text,
            "summary": summary,
            "extracted": extracted,
            "processed_at": datetime.datetime.utcnow().isoformat(),
        }

    def route_file(self, file_path: str, original_filename: str) -> dict:
        """Route file to correct processor based on extension."""
        ext = Path(original_filename).suffix.lower()
        if ext == ".pdf":
            return self.process_document(file_path, original_filename)
        elif ext in {".txt", ".csv", ".md", ".json"}:
            return self.process_text_file(file_path, original_filename)
        else:
            return {
                "status": "failed",
                "error": f"Unsupported file type: {ext}",
                "filename": original_filename
            }
