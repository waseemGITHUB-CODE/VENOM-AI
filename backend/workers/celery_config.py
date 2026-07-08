"""
workers/celery_app.py  —  Celery Task Queue Configuration
"""
from celery import Celery
import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "cyberplatform",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "backend.workers.document_worker",
        "backend.workers.security_worker",
        "backend.workers.report_worker",
        "backend.workers.email_worker",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "workers.security_worker.*":  {"queue": "security"},
        "workers.document_worker.*":  {"queue": "documents"},
        "workers.report_worker.*":    {"queue": "reports"},
        "workers.email_worker.*":     {"queue": "email"},
    },
)

# ─────────────────────────────────────────────────────────────────────
# workers/email_worker.py  —  Email Automation Worker
# ─────────────────────────────────────────────────────────────────────
"""
Email Automation Workflow:
  Monitor inbox → Detect new email → Find attachments → Process invoice → Store → Report
"""

import email
import imaplib
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


# @celery_app.task(name="workers.email_worker.check_inbox")
def check_inbox(company_id: str, email_address: str, password: str,
                imap_server: str, imap_port: int = 993):
    """Poll email inbox for new messages with attachments."""
    logger.info(f"Checking inbox: {email_address}")

    try:
        mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        mail.login(email_address, password)
        mail.select("inbox")

        # Search for unread emails
        _, msg_ids = mail.search(None, "(UNSEEN)")

        processed = 0
        for msg_id in msg_ids[0].split():
            _, msg_data = mail.fetch(msg_id, "(RFC822)")
            email_message = email.message_from_bytes(msg_data[0][1])

            result = process_email_message(email_message, company_id)
            if result:
                mail.store(msg_id, "+FLAGS", "\\Seen")
                processed += 1

        mail.close()
        mail.logout()
        logger.info(f"Processed {processed} emails for {email_address}")
        return {"processed": processed}

    except Exception as e:
        logger.error(f"Email check failed: {e}", exc_info=True)
        raise


def process_email_message(msg, company_id: str) -> bool:
    """Process a single email message."""
    sender  = msg.get("From", "")
    subject = msg.get("Subject", "")
    received = msg.get("Date", "")

    logger.info(f"Processing email: From={sender}, Subject={subject}")

    # Check for attachments
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disp = str(part.get("Content-Disposition", ""))

        if "attachment" in content_disp:
            filename = part.get_filename()
            payload  = part.get_payload(decode=True)

            if filename and payload:
                detected_type = detect_attachment_type(filename, content_type)

                if detected_type in ("invoice", "receipt", "pdf"):
                    # Save attachment and dispatch to document worker
                    file_path = save_attachment(filename, payload, company_id)
                    doc_id    = save_email_record(company_id, sender, subject, filename)

                    # Dispatch document processing
                    # celery_app.send_task(
                    #     "workers.document_worker.process_document",
                    #     args=[file_path, doc_id, company_id, "invoice"]
                    # )
                    logger.info(f"Dispatched invoice processing: {filename}")
                    return True

    return False


def detect_attachment_type(filename: str, content_type: str) -> str:
    """Detect what kind of attachment this is."""
    name_lower = filename.lower()
    if any(kw in name_lower for kw in ["invoice", "inv", "bill", "receipt"]):
        return "invoice"
    if content_type == "application/pdf":
        return "pdf"
    return "unknown"


def save_attachment(filename: str, payload: bytes, company_id: str) -> str:
    """Save email attachment to disk."""
    import uuid
    from pathlib import Path
    save_dir = Path(f"uploads/email/{company_id}")
    save_dir.mkdir(parents=True, exist_ok=True)
    file_id   = str(uuid.uuid4())
    save_path = save_dir / f"{file_id}_{filename}"
    save_path.write_bytes(payload)
    return str(save_path)


def save_email_record(company_id: str, sender: str, subject: str, filename: str) -> str:
    """Store email processing record in DB."""
    import uuid
    doc_id = str(uuid.uuid4())
    # In production: INSERT INTO processed_emails ...
    logger.info(f"Saved email record: {doc_id}")
    return doc_id


# ─────────────────────────────────────────────────────────────────────
# Celery Beat Schedule — Periodic Tasks
# ─────────────────────────────────────────────────────────────────────
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    # Check all company inboxes every 5 minutes
    "check-all-inboxes": {
        "task": "workers.email_worker.check_all_company_inboxes",
        "schedule": crontab(minute="*/5"),
    },
    # Clean up old task logs daily
    "cleanup-task-logs": {
        "task": "workers.celery_app.cleanup_old_tasks",
        "schedule": crontab(hour=2, minute=0),  # 2am UTC
    },
}
