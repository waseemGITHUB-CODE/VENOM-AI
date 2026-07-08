"""
AI Service — LLM integration for document extraction, explanations, and report generation.
Uses Groq (fast, free) with OpenAI as fallback.
"""
import json
import re
from typing import Optional
from config import settings

try:
    from groq import Groq
    GROQ_AVAILABLE = bool(settings.GROQ_API_KEY)
except ImportError:
    GROQ_AVAILABLE = False

MODEL = "llama3-70b-8192"

class AIService:
    def __init__(self):
        if GROQ_AVAILABLE:
            self.client = Groq(api_key=settings.GROQ_API_KEY)
        else:
            self.client = None

    def _call(self, system: str, user: str, max_tokens: int = 1500) -> str:
        """Make a synchronous LLM call."""
        if not self.client:
            return "[AI service not configured. Set GROQ_API_KEY in .env]"
        try:
            resp = self.client.chat.completions.create(
                model=MODEL,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user}
                ]
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            return f"[AI error: {str(e)}]"

    # ── DOCUMENT EXTRACTION ───────────────────────────────────────────────────

    def extract_invoice_data(self, raw_text: str) -> dict:
        """
        Extract structured invoice fields from raw PDF text.
        Returns a dict with company_name, invoice_number, invoice_amount, etc.
        """
        system = """You are a document data extraction engine.
Extract structured data from invoice/document text.
Respond ONLY with valid JSON. No markdown, no explanation.
JSON schema:
{
  "doc_type": "invoice|contract|report|form|unknown",
  "company_name": "...",
  "vendor_name": "...",
  "invoice_number": "...",
  "invoice_amount": 0.00,
  "invoice_date": "YYYY-MM-DD or original format",
  "due_date": "YYYY-MM-DD or original format",
  "line_items": [{"description": "...", "qty": 1, "unit_price": 0.00, "total": 0.00}],
  "extra_fields": {}
}
Use null for missing fields. Never guess amounts."""

        raw = self._call(system, f"Extract data from this document:\n\n{raw_text[:4000]}")
        # Strip markdown code fences if present
        raw = re.sub(r"```json|```", "", raw).strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"doc_type": "unknown", "raw_response": raw}

    def summarize_document(self, raw_text: str) -> str:
        """Generate a concise AI summary of any document."""
        system = """You are a professional document analyst.
Write a concise 2-3 sentence summary of the document.
State the document type, key parties, and main purpose or amounts."""
        return self._call(system, f"Summarize:\n\n{raw_text[:3000]}")

    def classify_document(self, raw_text: str) -> str:
        """Classify document type: invoice, contract, report, form, or unknown."""
        system = """Classify the document type.
Respond with exactly ONE word: invoice, contract, report, form, or unknown."""
        return self._call(system, raw_text[:1000], max_tokens=10).lower().strip()

    # ── SECURITY ANALYSIS ─────────────────────────────────────────────────────

    def explain_vulnerability(self, vuln_title: str, description: str, evidence: str = "") -> str:
        """Explain a security vulnerability in plain, non-technical language."""
        system = """You are a cybersecurity expert who explains vulnerabilities to non-technical clients.
Be clear, concise, and practical. Use this structure:
**What it is:** (1 sentence)
**Why it matters:** (1-2 sentences, business impact)
**How to fix it:** (2-3 numbered steps)
Keep it under 200 words."""
        prompt = f"Vulnerability: {vuln_title}\nDescription: {description}\nEvidence: {evidence}"
        return self._call(system, prompt)

    async def explain_security_topic(self, question: str) -> str:
        """Answer a general cybersecurity question in plain language."""
        system = """You are Nova, a friendly cybersecurity assistant on a professional IT platform.
Answer questions clearly for both technical and non-technical users.
Format with markdown for clarity. Keep responses practical and actionable."""
        return self._call(system, question)

    def generate_security_score_explanation(self, score: float, issues: list) -> str:
        """Generate an AI explanation of the overall security score."""
        system = """You are a cybersecurity consultant writing a client-facing score explanation.
Be professional but approachable. Mention the score, main issues, and urgency."""
        issue_list = "\n".join([f"- {i}" for i in issues])
        prompt = f"Security Score: {score}/100\n\nIssues Found:\n{issue_list}"
        return self._call(system, prompt)

    # ── REPORT GENERATION ─────────────────────────────────────────────────────

    def generate_executive_summary(self, scan_data: dict) -> str:
        """Generate a non-technical executive summary of a security audit."""
        system = """You are a senior cybersecurity consultant writing an executive summary for a board/management audience.
Structure:
1. Overview (2 sentences)
2. Key Findings (3 bullet points)
3. Risk Level Assessment
4. Immediate Priorities (3 items)
5. Conclusion
Use professional language. Avoid deep technical jargon."""
        return self._call(system, f"Scan data:\n{json.dumps(scan_data, indent=2)[:3000]}", max_tokens=800)

    def generate_technical_report_section(self, vuln_data: list) -> str:
        """Generate detailed technical findings section."""
        system = """You are a penetration tester writing a technical findings section.
For each vulnerability provide:
- CVE reference if applicable
- CVSS score interpretation
- Attack scenario
- Step-by-step remediation
Be precise and technical."""
        return self._call(system, f"Vulnerabilities:\n{json.dumps(vuln_data, indent=2)[:3000]}", max_tokens=1200)

    def generate_recommendations(self, issues: list) -> str:
        """Generate prioritized security recommendations."""
        system = """You are a cybersecurity consultant providing remediation recommendations.
Prioritize by: Critical → High → Medium → Low.
For each: state the fix, estimated effort (Low/Medium/High), and business justification."""
        return self._call(system, f"Issues:\n{json.dumps(issues, indent=2)[:2000]}", max_tokens=800)
