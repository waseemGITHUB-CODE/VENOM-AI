"""
Chatbot Routes — /api/chatbot
  POST /message                      send message, get AI reply + triggered action
  GET  /sessions                     list user's sessions
  GET  /sessions/{id}/messages       get all messages in session
  DELETE /sessions/{id}              delete session
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.auth import get_current_user
from db.database import get_db
from db.models import (
    ChatMessage, ChatSession, Document, ScanJob, TaskStatus, User
)
from services.chatbot_service import CyberBot
from workers.tasks import process_document, run_security_scan

router   = APIRouter()
cyberbot = CyberBot()


# ── Schemas ────────────────────────────────────────────────────────────────────

class ChatIn(BaseModel):
    message:    str
    session_id: Optional[int] = None


class MessageOut(BaseModel):
    session_id:   int
    message_id:   int
    reply:        str
    intent:       str
    action:       Optional[dict]
    action_taken: Optional[str]


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/message", response_model=MessageOut)
async def send_message(
    body: ChatIn,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    # 1 ── Session resolution
    if body.session_id:
        session = db.query(ChatSession).filter(
            ChatSession.id == body.session_id,
            ChatSession.owner_id == user.id,
        ).first()
        if not session:
            raise HTTPException(404, "Session not found")
    else:
        session = ChatSession(owner_id=user.id)
        db.add(session); db.commit(); db.refresh(session)

    # 2 ── Build conversation history for AI
    prev_msgs = (
        db.query(ChatMessage)
          .filter(ChatMessage.session_id == session.id)
          .order_by(ChatMessage.created_at)
          .limit(20)
          .all()
    )
    history = [{"role": m.role, "content": m.content} for m in prev_msgs]

    # 3 ── User context blob
    user_ctx = {
        "username":    user.username,
        "company":     user.company_name or "",
        "scan_count":  db.query(ScanJob).filter(ScanJob.owner_id == user.id).count(),
        "doc_count":   db.query(Document).filter(Document.owner_id == user.id).count(),
    }

    # 4 ── AI processing
    result = await cyberbot.process_message(
        message=body.message,
        conversation_history=history,
        user_context=user_ctx,
    )

    # 5 ── Save user message
    user_msg = ChatMessage(
        session_id=session.id, role="user",
        content=body.message, intent=result["intent"],
    )
    db.add(user_msg)

    # 6 ── Execute triggered action
    action_taken  = None
    extra_context = ""
    action        = result.get("action")

    if action:
        intent = action.get("intent", "")
        params = action.get("parameters", {})

        if intent == "scan_website" and params.get("url"):
            url  = params["url"]
            scan = ScanJob(owner_id=user.id, target_url=url)
            db.add(scan); db.commit(); db.refresh(scan)
            task = run_security_scan.delay(scan.id, url)
            scan.celery_task_id = task.id
            db.commit()
            action_taken  = f"triggered:scan_job:{scan.id}"
            extra_context = (
                f"\n\n✅ **Scan started** for `{url}` — Scan ID **#{scan.id}**.\n"
                "Check the **Scanner** tab for live progress."
            )

        elif intent == "analyze_document":
            doc_id = params.get("document_id")
            if doc_id:
                doc = db.query(Document).filter(
                    Document.id == doc_id, Document.owner_id == user.id
                ).first()
                if doc:
                    task = process_document.delay(doc.id)
                    doc.celery_task_id = task.id
                    doc.status         = TaskStatus.RUNNING
                    db.commit()
                    action_taken  = f"triggered:document:{doc.id}"
                    extra_context = f"\n\n✅ **Processing started** for document #{doc.id}."

        elif intent == "generate_report":
            extra_context = "\n\n📄 Head to **Reports** tab and click **Generate** to create your PDF."

        elif intent == "show_dashboard":
            extra_context = "\n\n📊 Opening your **Dashboard** now."

    # 7 ── Save AI message
    final_reply = result["reply"] + extra_context
    ai_msg = ChatMessage(
        session_id=session.id, role="assistant",
        content=final_reply, intent=result["intent"],
        action_taken=action_taken,
    )
    db.add(ai_msg)

    # 8 ── Auto-title session on first message
    if len(prev_msgs) == 0:
        words = body.message.split()
        session.title = " ".join(words[:6]) + ("…" if len(words) > 6 else "")
        db.add(session)

    db.commit()

    return MessageOut(
        session_id=session.id,
        message_id=ai_msg.id,
        reply=final_reply,
        intent=result["intent"],
        action=action,
        action_taken=action_taken,
    )


@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(ChatSession)
          .filter(ChatSession.owner_id == user.id)
          .order_by(ChatSession.created_at.desc())
          .limit(50).all()
    )
    return [{"id": s.id, "title": s.title, "created_at": str(s.created_at)} for s in rows]


@router.get("/sessions/{session_id}/messages")
def get_messages(
    session_id: int,
    db:  Session = Depends(get_db),
    user: User   = Depends(get_current_user),
):
    sess = db.query(ChatSession).filter(
        ChatSession.id == session_id, ChatSession.owner_id == user.id
    ).first()
    if not sess:
        raise HTTPException(404, "Session not found")
    msgs = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at).all()
    return [{"id": m.id, "role": m.role, "content": m.content,
             "intent": m.intent, "created_at": str(m.created_at)} for m in msgs]


@router.delete("/sessions/{session_id}")
def delete_session(
    session_id: int,
    db:  Session = Depends(get_db),
    user: User   = Depends(get_current_user),
):
    sess = db.query(ChatSession).filter(
        ChatSession.id == session_id, ChatSession.owner_id == user.id
    ).first()
    if not sess:
        raise HTTPException(404, "Session not found")
    db.delete(sess); db.commit()
    return {"status": "deleted"}
