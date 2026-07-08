"""
╔══════════════════════════════════════════════════════════════════╗
║  CyberPlatform  ·  backend/workers/celery_app.py                ║
║  Celery Application — fully self-contained, no import errors    ║
╠══════════════════════════════════════════════════════════════════╣
║  FIXES:                                                          ║
║  1. Removed worker_max_memory_per_child (requires psutil)        ║
║  2. Removed task_soft_time_limit (no SIGUSR1 on Windows)         ║
║  3. Added broker_connection_retry_on_startup = True              ║
║  4. Safe import paths for both project root and backend/         ║
╚══════════════════════════════════════════════════════════════════╝

USAGE
─────
  # Start worker (all queues):
  py -3.12 -m celery -A backend.workers.celery_app worker --loglevel=info -Q security,documents,reports,default

  # Start Beat scheduler:
  py -3.12 -m celery -A backend.workers.celery_app beat --loglevel=info

  # Monitor with Flower:
  py -3.12 -m celery -A backend.workers.celery_app flower --port=5555
"""
from __future__ import annotations

import os
import sys
import logging

# ── Path fix ────────────────────────────────────────────────────────────────
_this_dir    = os.path.dirname(os.path.abspath(__file__))   # .../backend/workers
_backend_dir = os.path.dirname(_this_dir)                   # .../backend
_project_dir = os.path.dirname(_backend_dir)                # .../cyberplatform
for _p in (_backend_dir, _project_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("cyberplatform.celery")


# ── Settings loader ─────────────────────────────────────────────────────────
def _load_settings() -> dict:
    try:
        from core.config import settings
        return {
            "broker":  settings.CELERY_BROKER_URL,
            "backend": settings.CELERY_RESULT_BACKEND,
        }
    except ImportError:
        pass

    try:
        from core.config import settings
        return {
            "broker":  settings.CELERY_BROKER_URL,
            "backend": settings.CELERY_RESULT_BACKEND,
        }
    except ImportError:
        pass

    logger.warning("[celery_app] Config import failed. Falling back to environment variables.")
    return {
        "broker":  os.environ.get("CELERY_BROKER_URL",     "redis://localhost:6379/0"),
        "backend": os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
    }


_cfg = _load_settings()

# ── Celery application ──────────────────────────────────────────────────────
from celery import Celery
from celery.schedules import crontab

celery_app = Celery(
    "cyberplatform",
    broker  = _cfg["broker"],
    backend = _cfg["backend"],
    include = [
        "workers.tasks",
        "workers.security_worker",
        "workers.document_worker",
        "workers.report_worker",
    ],
)

# ── Configuration ───────────────────────────────────────────────────────────
celery_app.conf.update(
    # Serialization
    task_serializer   = "json",
    result_serializer = "json",
    accept_content    = ["json"],
    result_expires    = 3600,

    # Timezone
    timezone   = "UTC",
    enable_utc = True,

    # Reliability
    task_track_started           = True,
    task_acks_late               = True,
    task_reject_on_worker_lost   = True,
    worker_prefetch_multiplier   = 1,

    # Retries
    task_max_retries             = 3,
    task_default_retry_delay     = 30,

    # Results
    result_backend_transport_options = {
        "retry_policy": {"timeout": 5.0},
        "master_name":  None,
    },

    # Worker — NOTE: worker_max_memory_per_child REMOVED (requires psutil on Windows)
    worker_max_tasks_per_child   = 50,

    # Task time limit — NOTE: task_soft_time_limit REMOVED (no SIGUSR1 on Windows)
    task_time_limit = 600,   # 10 min hard kill

    # Windows fix — retry broker connection on startup
    broker_connection_retry_on_startup = True,

    # ── Redis priority support — required for paid-tier priority scans ──
    # Redis sorts higher priority first when both are present.
    broker_transport_options = {
        "priority_steps":   list(range(10)),
        "sep":              ":",
        "queue_order_strategy": "priority",
    },
    task_default_priority = 5,    # mid-priority default
)

# ── Queue routing ────────────────────────────────────────────────────────────
celery_app.conf.task_queues = {
    "security":  {"exchange": "security",  "routing_key": "security"},
    "documents": {"exchange": "documents", "routing_key": "documents"},
    "reports":   {"exchange": "reports",   "routing_key": "reports"},
    "email":     {"exchange": "email",     "routing_key": "email"},
    "default":   {"exchange": "default",   "routing_key": "default"},
}

celery_app.conf.task_default_queue       = "default"
celery_app.conf.task_default_exchange    = "default"
celery_app.conf.task_default_routing_key = "default"

celery_app.conf.task_routes = {
    "workers.tasks.run_security_scan":           {"queue": "security"},
    "workers.security_worker.run_full_scan":     {"queue": "security"},
    "workers.tasks.process_document":            {"queue": "documents"},
    "workers.document_worker.*":                 {"queue": "documents"},
    "workers.report_worker.*":                   {"queue": "reports"},
    "workers.tasks.monitor_email_for_all_users": {"queue": "email"},
    "workers.tasks.monitor_single_inbox":        {"queue": "email"},
    "workers.tasks.check_monitor_schedule":      {"queue": "default"},
}

# ── Beat schedule ────────────────────────────────────────────────────────────
celery_app.conf.beat_schedule = {
    # Continuous Monitoring scheduler — replaces browser-heartbeat tick.
    # Runs every 60s, scans due targets even when no user is logged in.
    "monitor-due-scans": {
        "task":     "workers.tasks.check_monitor_schedule",
        "schedule": 60,
        "options":  {"queue": "default"},
    },
    # Email inbox check (skipped if IMAP not configured)
    "monitor-email-inbox": {
        "task":     "workers.tasks.monitor_email_for_all_users",
        "schedule": 300,
        "options":  {"queue": "email"},
    },
}


# ── Signals ─────────────────────────────────────────────────────────────────
from celery.signals import worker_ready, worker_shutdown, task_failure, task_success

@worker_ready.connect
def on_worker_ready(sender=None, **kwargs):
    logger.info("=" * 60)
    logger.info("  CyberPlatform Celery Worker READY")
    logger.info(f"  Broker:  {_cfg['broker']}")
    logger.info(f"  Backend: {_cfg['backend']}")
    logger.info("=" * 60)

@worker_shutdown.connect
def on_worker_shutdown(sender=None, **kwargs):
    logger.info("[Worker] Shutting down — releasing resources")

@task_failure.connect
def on_task_failure(sender=None, task_id=None, exception=None,
                    traceback=None, **kwargs):
    logger.error(f"[Task FAILED] task_id={task_id}  "
                 f"task={getattr(sender, 'name', 'unknown')}  "
                 f"error={exception}")

@task_success.connect
def on_task_success(sender=None, result=None, **kwargs):
    logger.info(f"[Task OK]     task={getattr(sender, 'name', 'unknown')}  "
                f"result_keys={list(result.keys()) if isinstance(result, dict) else type(result).__name__}")