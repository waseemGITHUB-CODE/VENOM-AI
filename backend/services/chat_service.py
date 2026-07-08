"""
Chat Service — Intent Detection + Workflow Dispatch
"""
from typing import Optional
import re
from services.ai_service import AIService

INTENT_MAP = {
    "scan_website": ["scan", "vuln", "security audit", "pentest", "check website", "audit", "port scan"],
    "analyze_document": ["analyze", "invoice", "extract", "process file", "read pdf", "document", "contract"],
    "generate_report": ["report", "generate report", "security report", "summary", "findings", "pdf report"],
    "show_dashboard": ["dashboard", "show results", "my scans", "history", "analytics", "overview"],
    "explain_vulnerability": ["explain", "what is", "what does", "cve", "owasp", "xss", "sqli", "csrf"],
    "email_automation": ["email", "inbox", "automate email", "monitor inbox"],
    "general_help": ["help", "what can you do", "commands", "capabilities", "how do i"],
}

RESPONSES = {
    "scan_website": {
        "reply": "🔍 **Website Security Scan**\n\nI'll scan the target for vulnerabilities including:\n• Security headers\n• SSL/TLS configuration\n• Open ports\n• CMS detection\n• Common web vulnerabilities\n\nPlease enter the URL you want to scan below, or click **Start Scan** in the Scanner tab.",
        "action": "open_scanner",
        "follow_up": ["Enter a URL to scan", "View past scan results", "Generate a security report"]
    },
    "analyze_document": {
        "reply": "📄 **Document Analysis**\n\nI can extract structured data from:\n• **Invoices** — company name, amounts, dates\n• **Contracts** — parties, terms, dates\n• **Reports** — key findings, summaries\n• **Forms** — all field data\n\nPlease upload your PDF or document using the upload button.",
        "action": "open_upload",
        "follow_up": ["Upload a PDF document", "View extracted documents", "Generate accounting report"]
    },
    "generate_report": {
        "reply": "📊 **Report Generation**\n\nI can generate:\n• **Security Audit Report** — full vulnerability findings with risk scores\n• **Executive Summary** — non-technical overview for management\n• **Document Extraction Report** — structured invoice/contract data\n• **Automation Report** — workflow results summary\n\nWhich type of report would you like?",
        "action": "open_reports",
        "follow_up": ["Security audit report", "Executive summary", "Document extraction report"]
    },
    "show_dashboard": {
        "reply": "📈 **Your Dashboard**\n\nNavigating to your dashboard where you can see:\n• Recent security scans and scores\n• Processed documents\n• Automation job status\n• Security trends\n\nOpening dashboard now...",
        "action": "navigate",
        "action_data": {"path": "/dashboard"},
        "follow_up": ["View scan history", "View documents", "View reports"]
    },
    "email_automation": {
        "reply": "📧 **Email Automation Setup**\n\nI can monitor your inbox and automatically:\n• Detect invoice attachments\n• Extract company names, amounts, dates\n• Store data in the database\n• Generate accounting reports\n\nTo set this up, I'll need your email credentials (IMAP). Go to **Settings → Email Integration** to configure.",
        "action": "open_settings",
        "action_data": {"tab": "email"},
        "follow_up": ["Configure email settings", "View email automation logs", "Test email connection"]
    },
    "general_help": {
        "reply": "👋 **Welcome to CyberPlatform!**\n\nI'm your AI assistant. Here's what I can do:\n\n🔍 **Security Scanning**\n→ *\"Scan my website for vulnerabilities\"*\n→ *\"Run a security audit on example.com\"*\n\n📄 **Document Processing**\n→ *\"Analyze this invoice\"*\n→ *\"Extract data from this PDF\"*\n\n📊 **Reports**\n→ *\"Generate a security report\"*\n→ *\"Create an executive summary\"*\n\n📧 **Email Automation**\n→ *\"Automate my email inbox\"*\n\n📈 **Dashboard**\n→ *\"Show my dashboard\"*\n→ *\"View scan history\"*",
        "action": None,
        "follow_up": ["Scan a website", "Upload a document", "Generate a report", "View dashboard"]
    }
}

class ChatService:
    def __init__(self, db):
        self.db = db
        self.ai = AIService()

    def detect_intent(self, message: str) -> str:
        """Simple keyword-based intent detection with AI fallback."""
        msg = message.lower().strip()

        # Check each intent's keywords
        for intent, keywords in INTENT_MAP.items():
            for kw in keywords:
                if kw in msg:
                    return intent

        # URL detection → auto-trigger scan
        url_pattern = r'https?://[^\s]+'
        if re.search(url_pattern, msg):
            return "scan_website"

        # Default to general help
        return "general_help"

    async def handle_intent(self, intent: str, message: str, context: Optional[dict]) -> dict:
        """Route the detected intent to the correct handler."""

        base = RESPONSES.get(intent, RESPONSES["general_help"])

        # For explain_vulnerability — use AI to generate a real answer
        if intent == "explain_vulnerability":
            ai_reply = await self.ai.explain_security_topic(message)
            return {
                "reply": ai_reply,
                "intent": intent,
                "action": None,
                "action_data": None,
                "follow_up": ["Scan a website for this vulnerability", "Generate a report", "View dashboard"]
            }

        # For scan_website — extract URL if present in message
        if intent == "scan_website":
            url_match = re.search(r'https?://[^\s]+', message)
            action_data = {"url": url_match.group(0)} if url_match else {}
            return {
                "reply": base["reply"],
                "intent": intent,
                "action": base["action"],
                "action_data": action_data,
                "follow_up": base.get("follow_up")
            }

        return {
            "reply": base["reply"],
            "intent": intent,
            "action": base.get("action"),
            "action_data": base.get("action_data"),
            "follow_up": base.get("follow_up")
        }
