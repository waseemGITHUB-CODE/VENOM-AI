"""
Chatbot Controller — Intent Detection & Workflow Routing
The central intelligence that parses user commands and triggers the correct automation.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import json

from database import get_db
from services.ai_service import AIService
from services.chat_service import ChatService

router = APIRouter()

# ── SCHEMAS ──────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    context: Optional[dict] = None  # e.g. {"document_id": "...", "scan_id": "..."}

class ChatResponse(BaseModel):
    reply: str
    intent: str
    action: Optional[str] = None
    action_data: Optional[dict] = None
    follow_up: Optional[list] = None

# ── INTENT DEFINITIONS ────────────────────────────────────────────────────────

INTENTS = {
    "scan_website": {
        "keywords": ["scan", "vulnerability", "security audit", "pentest", "check website", "audit site"],
        "action": "trigger_scan",
        "description": "Triggers a website vulnerability scan"
    },
    "analyze_document": {
        "keywords": ["analyze", "document", "invoice", "extract", "process file", "read pdf"],
        "action": "trigger_document",
        "description": "Processes and extracts data from uploaded documents"
    },
    "generate_report": {
        "keywords": ["report", "generate report", "security report", "summary", "findings"],
        "action": "trigger_report",
        "description": "Generates a professional security or automation report"
    },
    "show_dashboard": {
        "keywords": ["dashboard", "show results", "my scans", "history", "analytics"],
        "action": "navigate_dashboard",
        "description": "Navigates to the dashboard"
    },
    "explain_vulnerability": {
        "keywords": ["explain", "what is", "what does", "vulnerability", "risk", "cve"],
        "action": "explain",
        "description": "AI explains a security vulnerability in plain language"
    },
    "email_automation": {
        "keywords": ["email", "inbox", "automate email", "monitor inbox", "email processing"],
        "action": "trigger_email",
        "description": "Sets up email monitoring and automation"
    },
    "general_help": {
        "keywords": ["help", "what can you do", "commands", "capabilities"],
        "action": "show_help",
        "description": "Shows available commands and capabilities"
    },
}

# ── ROUTER ────────────────────────────────────────────────────────────────────

@router.post("/message", response_model=ChatResponse)
async def chat(request: ChatRequest, db: Session = Depends(get_db)):
    """
    Main chatbot endpoint. Detects intent and routes to the correct workflow.
    """
    svc = ChatService(db)
    intent = svc.detect_intent(request.message)
    response = await svc.handle_intent(intent, request.message, request.context)
    return response

@router.get("/intents")
def list_intents():
    """Returns all supported chatbot commands."""
    return {
        "intents": [
            {
                "name": k,
                "description": v["description"],
                "example_keywords": v["keywords"][:3]
            }
            for k, v in INTENTS.items()
        ]
    }
