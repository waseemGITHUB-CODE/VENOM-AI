"""
CyberBot Service — The Central AI Brain
─────────────────────────────────────────────────────────────────────
Responsibilities:
  1. Receive free-text user messages
  2. Detect intent with local pattern matching (fast, no API cost)
  3. Call Groq LLaMA3 for full natural-language response
  4. Parse structured <action> blocks from AI response
  5. Return { reply, intent, action } to the API route
─────────────────────────────────────────────────────────────────────
"""
import json
import re
from enum import Enum
from typing import Optional

from groq import Groq

from core.config import settings


# ══════════════════════════════════════════════════════════════════════
# INTENTS
# ══════════════════════════════════════════════════════════════════════

class Intent(str, Enum):
    SCAN_WEBSITE      = "scan_website"
    ANALYZE_DOCUMENT  = "analyze_document"
    GENERATE_REPORT   = "generate_report"
    SHOW_DASHBOARD    = "show_dashboard"
    SHOW_SCAN_RESULTS = "show_scan_results"
    EXPLAIN_VULN      = "explain_vulnerability"
    INVOICE_SUMMARY   = "invoice_summary"
    GENERAL_SECURITY  = "general_security"
    UNKNOWN           = "unknown"


# ══════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are VENOM AI — a STRICTLY CYBERSECURITY-FOCUSED assistant for
the VENOM AI platform. You ONLY answer questions about cybersecurity, application
security, network security, ethical hacking, vulnerabilities, secure coding, threat
intelligence, OWASP / MITRE ATT&CK, compliance (ISO 27001, SOC2, GDPR, HIPAA, PCI-DSS),
DevSecOps, incident response, malware analysis, OSINT, and operating this platform.

╔════════════════════════════════════════════════════════════════════╗
║  HARD SCOPE RULE — READ EVERY TIME                                 ║
╠════════════════════════════════════════════════════════════════════╣
║  If a user asks ANYTHING outside cybersecurity / this platform —   ║
║  cooking, sports, jokes, relationships, general programming, math, ║
║  history, weather, code that is NOT security-related, etc. —       ║
║  you MUST politely refuse in ONE short paragraph (≤ 40 words):     ║
║                                                                    ║
║    "I'm VENOM AI — I only help with cybersecurity, vulnerability   ║
║    assessment, and platform tasks. I can't help with that topic.   ║
║    Ask me about scans, vulnerabilities, compliance, or hardening   ║
║    your systems instead."                                          ║
║                                                                    ║
║  Do NOT answer the off-topic question in any form. Do NOT add      ║
║  trivia, do NOT 'just this once'. NEVER break this rule.           ║
╚════════════════════════════════════════════════════════════════════╝

YOUR CAPABILITIES (within the cybersecurity scope above):
1. Trigger website security scans
2. Analyze uploaded security-related documents (audit reports, pentest reports,
   SBOMs, security policies, certificates)
3. Generate professional PDF security reports
4. Explain security vulnerabilities in plain English (with depth — be detailed
   when the topic is cyber-technical)
5. Answer cybersecurity best-practice questions thoroughly
6. Show dashboard stats and scan history

WHEN A USER REQUESTS AN ACTION (only for cyber/platform tasks), append a JSON
action block at the END of your reply:

<action>
{"intent": "scan_website", "parameters": {"url": "https://example.com"}}
</action>

AVAILABLE INTENTS:
- scan_website          → {"url": "https://..."}
- analyze_document      → {"document_id": 123}
- generate_report       → {"scan_job_id": 123, "report_type": "security_audit"}
- show_dashboard        → {}
- show_scan_results     → {"scan_job_id": 123}
- explain_vulnerability → {"topic": "XSS"}
- general_security      → {}

RESPONSE STYLE:
- Cyber-technical questions: GO DEEP. Be detailed, include examples, CVE refs,
  payloads, mitigations, code snippets. Don't be brief on real security topics.
- Off-topic questions: ONE short refusal paragraph, no exceptions.
- Use **bold** for key terms, numbered lists for steps, bullet lists for items.
- Professional, never condescending.
- Always end real answers with a clear next-step suggestion."""


# ══════════════════════════════════════════════════════════════════════
# FAST LOCAL PATTERN MATCHING (runs before AI API call)
# ══════════════════════════════════════════════════════════════════════

_PATTERNS: dict[Intent, list[str]] = {
    Intent.SCAN_WEBSITE: [
        r"scan\s+(my\s+)?(website|site|domain|url)",
        r"(check|audit|test)\s+(my\s+)?(website|site|security)",
        r"vulnerability\s+(scan|check|test|audit)",
        r"pentest|penetration\s+test",
        r"scan\s+https?://",
    ],
    Intent.ANALYZE_DOCUMENT: [
        r"(analyze|process|read|extract|parse)\s+(this|the|my)?\s*(document|file|pdf|invoice|contract)",
        r"(what|what's)\s+(is\s+)?(in|inside)\s+(this|the|my)",
    ],
    Intent.GENERATE_REPORT: [
        r"(generate|create|make|build|produce|give\s+me)\s+(a\s+)?(security\s+|audit\s+)?report",
        r"(export|download|prepare)\s+(a\s+)?report",
    ],
    Intent.SHOW_DASHBOARD: [
        r"\bdashboard\b",
        r"show\s+(me\s+)?(my\s+)?(stats|statistics|overview|summary)",
        r"what('s|s)?\s+(going\s+on|happening|my\s+status)",
    ],
    Intent.SHOW_SCAN_RESULTS: [
        r"(show|see|view|get)\s+(my\s+)?(scan\s+)?results",
        r"(last|latest|recent|previous)\s+scan",
        r"scan\s+(history|results|output)",
    ],
    Intent.EXPLAIN_VULN: [
        r"(explain|what\s+is|tell\s+me\s+about)\s+.*(vuln|vulnerability|sql\s+injection|xss|csrf|ssrf|rce|lfi)",
        r"how\s+(dangerous|serious|bad|critical)\s+is",
    ],
    Intent.INVOICE_SUMMARY: [
        r"invoice\s+(summary|report|data|list|batch)",
        r"(summarize|list)\s+(all\s+)?(my\s+)?invoices",
        r"accounting\s+(report|summary|export)",
    ],
}


def detect_intent(message: str) -> Intent:
    """Fast regex-based intent detection — runs locally with zero latency."""
    msg = message.lower()
    for intent, patterns in _PATTERNS.items():
        for pat in patterns:
            if re.search(pat, msg):
                return intent
    return Intent.UNKNOWN


def extract_url(message: str) -> Optional[str]:
    """Pull any URL from the message text."""
    m = re.search(r'https?://[^\s]+', message)
    if m:
        return m.group(0).rstrip('.,)')
    # Bare domain fallback
    m = re.search(r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:[a-z]{2,})(?:/[^\s]*)?)\b', message.lower())
    if m:
        return f"https://{m.group(0)}"
    return None


def _extract_action(text: str) -> Optional[dict]:
    """Parse <action>{...}</action> block from AI reply."""
    m = re.search(r'<action>\s*(\{.*?\})\s*</action>', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return None


def _clean_reply(text: str) -> str:
    """Remove the action block from user-visible reply."""
    return re.sub(r'\s*<action>.*?</action>', '', text, flags=re.DOTALL).strip()


# ══════════════════════════════════════════════════════════════════════
# MAIN CYBERBOT CLASS
# ══════════════════════════════════════════════════════════════════════

class CyberBot:
    def __init__(self):
        self._client = Groq(api_key=settings.GROQ_API_KEY)

    async def process_message(
        self,
        message: str,
        conversation_history: list,
        user_context: Optional[dict] = None,
    ) -> dict:
        """
        Process one user message.

        Returns:
          {
            "reply":  str,          ← clean text shown to user
            "intent": str,          ← detected workflow intent
            "action": dict | None,  ← structured action to trigger
          }
        """
        # 1 ── Fast local detection (no API cost)
        local_intent = detect_intent(message)

        # 2 ── Build messages list for AI
        sys_content = SYSTEM_PROMPT
        if user_context:
            sys_content += f"\n\nCurrent user context: {json.dumps(user_context)}"

        messages = [{"role": "system", "content": sys_content}]
        messages += (conversation_history or [])[-10:]   # keep last 10 turns
        messages.append({"role": "user", "content": message})

        # 3 ── Call Groq API
        try:
            resp = self._client.chat.completions.create(
                model=settings.GROQ_MODEL,
                messages=messages,
                max_tokens=1024,
                temperature=0.65,
            )
            raw_reply = resp.choices[0].message.content or ""
        except Exception as exc:
            raw_reply = f"I'm having trouble connecting to my AI backend right now ({exc}). Please try again."

        # 4 ── Parse action block
        action = _extract_action(raw_reply)
        reply  = _clean_reply(raw_reply)

        # 5 ── Resolve final intent
        intent = Intent.UNKNOWN
        if action and "intent" in action:
            try:
                intent = Intent(action["intent"])
            except ValueError:
                intent = local_intent
        elif local_intent != Intent.UNKNOWN:
            intent = local_intent
            # Auto-inject URL if scan was detected but AI didn't add action block
            if intent == Intent.SCAN_WEBSITE and not action:
                url = extract_url(message)
                if url:
                    action = {"intent": "scan_website", "parameters": {"url": url}}

        return {"reply": reply, "intent": intent.value, "action": action}
