"""
VENOM AI — backend/db/models.py
Complete schema with ALL columns used by scanner, tasks, and API routes.
"""
import enum
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float,
    ForeignKey, Integer, JSON, String, Text,
)
from sqlalchemy.orm import relationship

try:
    from db.database import Base
except ImportError:
    from db.database import Base


# ══════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════

class TaskStatus(str, enum.Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"

class RiskLevel(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class DocType(str, enum.Enum):
    INVOICE  = "invoice"
    CONTRACT = "contract"
    REPORT   = "report"
    FORM     = "form"
    OTHER    = "other"


# ══════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════

class User(Base):
    __tablename__ = "users"

    id           = Column(Integer, primary_key=True, index=True)
    email        = Column(String(255), unique=True, index=True, nullable=False)
    username     = Column(String(100), unique=True, index=True, nullable=True)
    full_name    = Column(String(255), nullable=True)
    avatar_url   = Column(String(1000), nullable=True)

    # Password — nullable so OAuth-only users (no password) are allowed
    hashed_pass  = Column(String(255), nullable=True)

    # Account state
    company_name = Column(String(255))
    is_active    = Column(Boolean, default=True,  nullable=False)
    is_admin     = Column(Boolean, default=False, nullable=False)
    is_verified  = Column(Boolean, default=False, nullable=False)  # email verified?

    # OAuth (Google)
    oauth_provider = Column(String(50),  nullable=True)   # 'google' or None
    oauth_id       = Column(String(255), nullable=True, index=True)

    # Activity tracking
    last_login_at  = Column(DateTime, nullable=True)
    last_login_ip  = Column(String(45), nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    documents     = relationship("Document",    back_populates="owner", cascade="all, delete-orphan")
    scan_jobs     = relationship("ScanJob",     back_populates="owner", cascade="all, delete-orphan")
    reports       = relationship("Report",      back_populates="owner", cascade="all, delete-orphan")
    chat_sessions = relationship("ChatSession", back_populates="owner", cascade="all, delete-orphan")
    email_jobs    = relationship("EmailJob",    back_populates="owner", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    auth_tokens    = relationship("AuthToken",    back_populates="user", cascade="all, delete-orphan")
    subscriptions = relationship("Subscription", back_populates="user", cascade="all, delete-orphan")
    usage_meters  = relationship("UsageMeter",   back_populates="user", cascade="all, delete-orphan")
    monitor_targets = relationship("MonitorTarget", back_populates="owner", cascade="all, delete-orphan")
    monitor_alerts  = relationship("MonitorAlert",  back_populates="owner", cascade="all, delete-orphan")
    verified_domains = relationship("VerifiedDomain", back_populates="owner", cascade="all, delete-orphan")
    audit_logs       = relationship("ScanAuditLog",   back_populates="owner", cascade="all, delete-orphan")
    attack_scans     = relationship("AttackScan",     back_populates="owner", cascade="all, delete-orphan")


# ══════════════════════════════════════════════════════
# AUTH TOKENS (refresh tokens, email verify, password reset)
# ══════════════════════════════════════════════════════

class RefreshToken(Base):
    """Refresh tokens — stored hashed so we can revoke them server-side."""
    __tablename__ = "refresh_tokens"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash  = Column(String(255), unique=True, index=True, nullable=False)
    user_agent  = Column(String(500), nullable=True)
    ip_address  = Column(String(45),  nullable=True)
    expires_at  = Column(DateTime, nullable=False)
    revoked_at  = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")


class AuthToken(Base):
    """
    Single-use tokens for email verification and password reset.
    `purpose` = 'email_verify' | 'password_reset'.
    """
    __tablename__ = "auth_tokens"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash  = Column(String(255), unique=True, index=True, nullable=False)
    purpose     = Column(String(50), nullable=False, index=True)
    expires_at  = Column(DateTime, nullable=False)
    used_at     = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="auth_tokens")


# ══════════════════════════════════════════════════════
# DOCUMENTS
# ══════════════════════════════════════════════════════

class Document(Base):
    __tablename__ = "documents"

    id             = Column(Integer, primary_key=True, index=True)
    owner_id       = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename       = Column(String(500), nullable=False)
    file_path      = Column(String(1000))
    file_size      = Column(Integer)
    doc_type       = Column(Enum(DocType), default=DocType.OTHER)
    status         = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    extracted_data = Column(JSON)
    summary        = Column(Text)
    celery_task_id = Column(String(255))
    created_at     = Column(DateTime, default=datetime.utcnow)
    processed_at   = Column(DateTime)

    owner        = relationship("User",        back_populates="documents")
    invoice_data = relationship("InvoiceData", back_populates="document",
                                uselist=False, cascade="all, delete-orphan")


class InvoiceData(Base):
    __tablename__ = "invoice_data"

    id             = Column(Integer, primary_key=True, index=True)
    document_id    = Column(Integer, ForeignKey("documents.id"), nullable=False)
    company_name   = Column(String(255))
    invoice_number = Column(String(100))
    invoice_amount = Column(Float)
    invoice_date   = Column(String(50))
    due_date       = Column(String(50))
    currency       = Column(String(10), default="USD")
    vendor_address = Column(Text)
    tax_amount     = Column(Float)
    line_items     = Column(JSON)
    created_at     = Column(DateTime, default=datetime.utcnow)

    document = relationship("Document", back_populates="invoice_data")


# ══════════════════════════════════════════════════════
# SECURITY SCANNING — ScanJob
# ══════════════════════════════════════════════════════

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id             = Column(Integer, primary_key=True, index=True)
    owner_id       = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_url     = Column(String(1000), nullable=False)
    status         = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    celery_task_id = Column(String(255), index=True)

    # Scan config
    scan_type      = Column(String(50), default="full")

    # Progress tracking
    progress       = Column(Integer, default=0)

    # Results summary
    security_score = Column(Integer, default=0)
    grade          = Column(String(2))
    total_issues   = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    low_count      = Column(Integer, default=0)

    # AI & metadata
    ai_summary     = Column(Text)
    scan_duration  = Column(Float)
    raw_results    = Column(JSON)

    # Timestamps
    started_at     = Column(DateTime)
    completed_at   = Column(DateTime)
    created_at     = Column(DateTime, default=datetime.utcnow)

    owner           = relationship("User",          back_populates="scan_jobs")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_job",
                                   cascade="all, delete-orphan")
    reports         = relationship("Report",        back_populates="scan_job")


# ══════════════════════════════════════════════════════
# SECURITY SCANNING — Vulnerability
# ══════════════════════════════════════════════════════

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id          = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False, index=True)

    # Core finding
    title        = Column(String(500), nullable=False, default="Unknown")
    vuln_type    = Column(String(100))
    category     = Column(String(100))
    severity     = Column(String(20), default="info")
    risk_level   = Column(String(20), default="medium")

    # Target
    affected_url = Column(String(1000))
    evidence     = Column(Text)

    # Detail
    description    = Column(Text)
    impact         = Column(Text)
    recommendation = Column(Text)
    fix            = Column(Text)
    code_example   = Column(Text)
    reference      = Column(String(1000))
    references     = Column(JSON)

    # AI
    ai_explanation = Column(Text)
    ai_risk_level  = Column(String(20))

    # Scoring
    cvss_score = Column(Float, default=0.0)
    cve_id     = Column(String(50))
    cwe_id     = Column(String(20))

    # Tool & verification
    source_tool       = Column(String(50), default="venom")
    verified          = Column(Boolean, default=False)
    is_verified       = Column(Boolean, default=False)
    false_positive    = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)

    # Proof-of-Exploit
    poe_confirmed = Column(Boolean, default=False)
    poe_detail    = Column(Text, default="")
    poe_attempted = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan_job = relationship("ScanJob", back_populates="vulnerabilities")


# ══════════════════════════════════════════════════════
# REPORTS
# ══════════════════════════════════════════════════════

class Report(Base):
    __tablename__ = "reports"

    id                = Column(Integer, primary_key=True, index=True)
    owner_id          = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_job_id       = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    title             = Column(String(500), nullable=False)
    report_type       = Column(String(50))
    executive_summary = Column(Text)
    content           = Column(JSON)
    pdf_path          = Column(String(1000))
    created_at        = Column(DateTime, default=datetime.utcnow)

    owner    = relationship("User",    back_populates="reports")
    scan_job = relationship("ScanJob", back_populates="reports")


# ══════════════════════════════════════════════════════
# EMAIL MONITORING
# ══════════════════════════════════════════════════════

class EmailJob(Base):
    __tablename__ = "email_jobs"

    id              = Column(Integer, primary_key=True, index=True)
    owner_id        = Column(Integer, ForeignKey("users.id"), nullable=False)
    sender          = Column(String(255))
    subject         = Column(String(500))
    received_at     = Column(DateTime)
    has_attachment  = Column(Boolean, default=False)
    attachment_name = Column(String(255))
    status          = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    document_id     = Column(Integer, ForeignKey("documents.id"), nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="email_jobs")


# ══════════════════════════════════════════════════════
# CHATBOT
# ══════════════════════════════════════════════════════

class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id         = Column(Integer, primary_key=True, index=True)
    owner_id   = Column(Integer, ForeignKey("users.id"), nullable=False)
    title      = Column(String(255), default="New Conversation")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner    = relationship("User",        back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session",
                            cascade="all, delete-orphan",
                            order_by="ChatMessage.created_at")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, ForeignKey("chat_sessions.id"), nullable=False)
    role         = Column(String(20), nullable=False)
    content      = Column(Text, nullable=False)
    intent       = Column(String(100))
    action_taken = Column(String(255))
    created_at   = Column(DateTime, default=datetime.utcnow)

    session = relationship("ChatSession", back_populates="messages")


# ══════════════════════════════════════════════════════
# BILLING & SUBSCRIPTIONS
# ══════════════════════════════════════════════════════

class Plan(Base):
    """A subscription tier — Free, Pro, Business, etc."""
    __tablename__ = "plans"

    id              = Column(Integer, primary_key=True, index=True)
    code            = Column(String(50),  unique=True, index=True, nullable=False)  # "free" | "pro" | "business"
    name            = Column(String(100), nullable=False)
    description     = Column(Text)

    # Pricing (paise — Razorpay's unit; ₹999 → 99900)
    price_inr_paise = Column(Integer, default=0,  nullable=False)
    price_usd_cents = Column(Integer, default=0,  nullable=False)
    billing_period  = Column(String(20), default="monthly")  # monthly | yearly
    is_active       = Column(Boolean,    default=True, nullable=False)
    sort_order      = Column(Integer,    default=0)

    # Razorpay plan IDs (created on first checkout, cached here)
    razorpay_plan_id_inr = Column(String(100), nullable=True)
    razorpay_plan_id_usd = Column(String(100), nullable=True)

    # Quotas
    scan_quota_monthly    = Column(Integer, default=5,   nullable=False)
    monitor_quota         = Column(Integer, default=1,   nullable=False)
    chat_quota_daily      = Column(Integer, default=50,  nullable=False)

    # Feature flags
    feature_pdf_reports   = Column(Boolean, default=False, nullable=False)
    feature_priority_scan = Column(Boolean, default=False, nullable=False)
    feature_api_access    = Column(Boolean, default=False, nullable=False)
    feature_custom_domain = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    subscriptions = relationship("Subscription", back_populates="plan")


class Subscription(Base):
    """A user's current subscription record."""
    __tablename__ = "subscriptions"

    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    plan_id     = Column(Integer, ForeignKey("plans.id"), nullable=False)

    # Lifecycle: trialing | active | past_due | cancelled | expired | paused
    status      = Column(String(30), default="active", nullable=False, index=True)

    # Razorpay identifiers
    razorpay_subscription_id = Column(String(100), nullable=True, index=True)
    razorpay_customer_id     = Column(String(100), nullable=True)

    # Billing period
    current_period_start = Column(DateTime, nullable=True)
    current_period_end   = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean,  default=False)
    cancelled_at         = Column(DateTime, nullable=True)
    trial_ends_at        = Column(DateTime, nullable=True)

    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="subscriptions")
    plan = relationship("Plan", back_populates="subscriptions")


class UsageMeter(Base):
    """
    Tracks usage in the current billing period.
    One row per (user, period_start). Resets monthly for scans, daily for chats.
    """
    __tablename__ = "usage_meters"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # Period markers
    period_start = Column(DateTime, nullable=False, index=True)  # start of current month
    chat_day     = Column(String(10), nullable=False, index=True)  # 'YYYY-MM-DD' for daily reset

    # Counters
    scans_used  = Column(Integer, default=0, nullable=False)
    chats_used  = Column(Integer, default=0, nullable=False)

    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="usage_meters")


# ══════════════════════════════════════════════════════
# CONTINUOUS MONITORING (DB-persisted, not in-memory)
# ══════════════════════════════════════════════════════

class MonitorTarget(Base):
    """A URL the user wants continuously monitored."""
    __tablename__ = "monitor_targets"

    id              = Column(Integer, primary_key=True, index=True)
    owner_id        = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    target_url      = Column(String(1000), nullable=False, index=True)
    interval        = Column(String(20),   default="daily",  nullable=False)
    alert_on_drop   = Column(Boolean,      default=True,     nullable=False)
    alert_on_new    = Column(Boolean,      default=True,     nullable=False)
    enabled         = Column(Boolean,      default=True,     nullable=False, index=True)

    # Last scan state
    status          = Column(String(20),   default="idle")    # idle | scanning | error
    last_scan_at    = Column(DateTime,     nullable=True)
    next_scan_at    = Column(DateTime,     nullable=True, index=True)
    last_score      = Column(Integer,      nullable=True)
    last_grade      = Column(String(2),    nullable=True)
    last_vuln_count = Column(Integer,      default=0)
    alert_count     = Column(Integer,      default=0)
    progress        = Column(Integer,      default=0)

    # Celery linkage
    celery_task_id  = Column(String(255),  nullable=True)
    scan_job_id     = Column(Integer,      nullable=True)

    added_at        = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="monitor_targets")


class MonitorAlert(Base):
    """An alert fired by the monitor (score drop, new vuln, scan error)."""
    __tablename__ = "monitor_alerts"

    id          = Column(Integer, primary_key=True, index=True)
    owner_id    = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    target_url  = Column(String(1000), nullable=False)
    alert_type  = Column(String(30),   nullable=False)   # score_drop | new_vuln | scan_error
    message     = Column(Text,         nullable=False)
    old_score   = Column(Integer,      nullable=True)
    new_score   = Column(Integer,      nullable=True)
    read        = Column(Boolean,      default=False, nullable=False, index=True)

    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    owner = relationship("User", back_populates="monitor_alerts")


# ══════════════════════════════════════════════════════
# DOMAIN VERIFICATION (Phase 2a) — proof of ownership before active scans
# ══════════════════════════════════════════════════════

class VerifiedDomain(Base):
    """
    A domain the user has proven they own.
    Required before VENOM allows active (attack-based) scans against it.
    """
    __tablename__ = "verified_domains"

    id              = Column(Integer, primary_key=True, index=True)
    owner_id        = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    domain          = Column(String(255), nullable=False, index=True)        # e.g. example.com
    verification_token = Column(String(64), nullable=False, unique=True)     # secret per domain
    verified        = Column(Boolean, default=False, nullable=False, index=True)
    verified_via    = Column(String(20), nullable=True)   # dns_txt | file | well_known | meta_tag
    verified_at     = Column(DateTime, nullable=True)
    last_check_at   = Column(DateTime, nullable=True)
    last_check_error = Column(Text, nullable=True)

    # ── Re-verification tracking ────────────────────────────────────────
    # We re-check ownership periodically. If verification proof disappears
    # (e.g. user removes the DNS TXT record), we revoke active-scan rights.
    revoked_at      = Column(DateTime, nullable=True)

    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="verified_domains")


# ══════════════════════════════════════════════════════
# RECONNAISSANCE RESULTS (Phase 2a) — output of crawler/fingerprinter
# ══════════════════════════════════════════════════════

class ReconResult(Base):
    """
    Top-level recon record for a target.
    One row per recon scan; sub-tables hold the discovered details.
    """
    __tablename__ = "recon_results"

    id            = Column(Integer, primary_key=True, index=True)
    owner_id      = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    target_url    = Column(String(1000), nullable=False)
    status        = Column(String(20),   default="running")   # running | completed | failed
    progress      = Column(Integer,      default=0)

    # Summary counts
    total_urls     = Column(Integer, default=0)
    total_forms    = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)

    # Detected stack snapshot
    stack_summary = Column(JSON,    nullable=True)  # { "framework": "Django", "lang": "Python", ... }
    auth_method   = Column(String(50), nullable=True)  # jwt | session_cookie | basic | oauth | none

    # Raw notes
    error         = Column(Text, nullable=True)

    started_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at  = Column(DateTime, nullable=True)

    endpoints = relationship("DiscoveredEndpoint", back_populates="recon", cascade="all, delete-orphan")
    forms     = relationship("DiscoveredForm",     back_populates="recon", cascade="all, delete-orphan")
    techs     = relationship("DetectedTech",       back_populates="recon", cascade="all, delete-orphan")


class DiscoveredEndpoint(Base):
    """A URL/endpoint discovered during recon."""
    __tablename__ = "discovered_endpoints"

    id          = Column(Integer, primary_key=True, index=True)
    recon_id    = Column(Integer, ForeignKey("recon_results.id"), nullable=False, index=True)

    url         = Column(String(1500), nullable=False)
    http_method = Column(String(10),   default="GET")
    status_code = Column(Integer,      nullable=True)
    content_type = Column(String(100), nullable=True)
    response_size = Column(Integer,    nullable=True)

    # Categorization
    kind        = Column(String(30), default="page")  # page | api | static | redirect | error
    is_authenticated = Column(Boolean, default=False)

    # For API endpoints
    parameters  = Column(JSON, nullable=True)   # ["id", "page", "q"]
    headers     = Column(JSON, nullable=True)   # selected interesting response headers

    found_at    = Column(DateTime, default=datetime.utcnow, nullable=False)

    recon = relationship("ReconResult", back_populates="endpoints")


class DiscoveredForm(Base):
    """An HTML form discovered during recon (input vector for active attacks)."""
    __tablename__ = "discovered_forms"

    id        = Column(Integer, primary_key=True, index=True)
    recon_id  = Column(Integer, ForeignKey("recon_results.id"), nullable=False, index=True)

    page_url  = Column(String(1500), nullable=False)
    action    = Column(String(1500), nullable=True)
    method    = Column(String(10),   default="POST")
    enctype   = Column(String(100),  nullable=True)

    # All input fields as JSON: [{"name": "email", "type": "email", "required": true}, ...]
    inputs    = Column(JSON, nullable=False)

    has_csrf_token = Column(Boolean, default=False)
    csrf_field_name = Column(String(100), nullable=True)

    purpose   = Column(String(50), nullable=True)   # login | signup | search | contact | comment | other
    found_at  = Column(DateTime, default=datetime.utcnow, nullable=False)

    recon = relationship("ReconResult", back_populates="forms")


class DetectedTech(Base):
    """A piece of technology detected on the target (framework, lib, server, etc.)."""
    __tablename__ = "detected_tech"

    id       = Column(Integer, primary_key=True, index=True)
    recon_id = Column(Integer, ForeignKey("recon_results.id"), nullable=False, index=True)

    name       = Column(String(100), nullable=False)        # "Django", "React", "nginx"
    version    = Column(String(50),  nullable=True)
    category   = Column(String(50),  nullable=False)        # framework | language | server | cdn | analytics | js_lib
    confidence = Column(Integer,     default=80)            # 0-100

    evidence   = Column(Text, nullable=True)                # where we detected it

    recon = relationship("ReconResult", back_populates="techs")


# ══════════════════════════════════════════════════════
# SECURITY GUARDRAILS (Phase 2a) — audit logs + forbidden targets
# ══════════════════════════════════════════════════════

class ScanAuditLog(Base):
    """
    Legal audit trail of every scan attempt.
    Records: who, what target, when, was it authorized?
    Critical for legal defense if a complaint is filed.
    """
    __tablename__ = "scan_audit_logs"

    id            = Column(Integer, primary_key=True, index=True)
    owner_id      = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    action        = Column(String(50), nullable=False, index=True)   # scan_started | scan_completed | scan_blocked | recon_started
    target_url    = Column(String(1000), nullable=False)
    target_domain = Column(String(255),  nullable=False, index=True)

    # Authorization context
    domain_verified = Column(Boolean, default=False)         # was domain ownership proven?
    consent_given   = Column(Boolean, default=False)         # did user click consent?
    scan_type     = Column(String(50), nullable=True)        # passive | active | full

    # Request context
    user_ip       = Column(String(45),  nullable=True)
    user_agent    = Column(String(500), nullable=True)

    # Result
    allowed       = Column(Boolean, default=True, nullable=False)
    block_reason  = Column(String(200), nullable=True)       # if blocked, why

    # Extra context (request count, payloads sent, etc.)
    metadata_json = Column(JSON, nullable=True)

    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    owner = relationship("User", back_populates="audit_logs")


class ForbiddenTarget(Base):
    """
    Targets VENOM will NEVER scan, no matter who asks.
    Used to block government, military, banks, etc.
    """
    __tablename__ = "forbidden_targets"

    id       = Column(Integer, primary_key=True, index=True)
    pattern  = Column(String(255), nullable=False, unique=True, index=True)
    # pattern can be: exact domain "example.gov", suffix "*.gov", or substring "::bank::"

    category = Column(String(50), nullable=False)            # government | military | financial | healthcare | education | other
    reason   = Column(String(500), nullable=False)
    added_by = Column(String(100), nullable=True)            # admin email
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


# ══════════════════════════════════════════════════════
# ACTIVE ATTACK SCAN (Phase 2b/2c) — OWASP Top 10:2025 attack runner
# ══════════════════════════════════════════════════════

class AttackScan(Base):
    """
    A full active attack scan: recon → AI plan → attack engines → findings.
    Replaces the old passive 'ScanJob' model for OWASP Top 10:2025 testing.
    """
    __tablename__ = "attack_scans"

    id              = Column(Integer, primary_key=True, index=True)
    owner_id        = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url      = Column(String(1000), nullable=False)
    target_domain   = Column(String(255), nullable=False, index=True)

    # State machine
    status          = Column(String(30), default="queued", nullable=False, index=True)
    # queued | running_recon | planning | running_attacks | verifying | completed | failed | cancelled
    progress        = Column(Integer, default=0)
    phase           = Column(String(200), nullable=True)   # human-readable current phase
    current_engine  = Column(String(30), nullable=True)    # A01 | A02 | A04 | A05 | enrichment | done
    error           = Column(Text, nullable=True)

    # Linkage
    recon_id        = Column(Integer, ForeignKey("recon_results.id"), nullable=True)

    # Plan from AI (stored for transparency)
    attack_plan     = Column(JSON, nullable=True)

    # Authorization context (legal)
    domain_verified = Column(Boolean, default=False, nullable=False)
    consent_given   = Column(Boolean, default=False, nullable=False)
    user_ip         = Column(String(45), nullable=True)

    # Configuration
    scan_intensity  = Column(String(20), default="standard")   # light | standard | aggressive
    max_rps         = Column(Integer, default=10)
    enabled_categories = Column(JSON, nullable=True)   # list of "A01", "A05", etc.

    # Summary counts (computed at end)
    total_findings    = Column(Integer, default=0)
    critical_count    = Column(Integer, default=0)
    high_count        = Column(Integer, default=0)
    medium_count      = Column(Integer, default=0)
    low_count         = Column(Integer, default=0)
    hardening_count   = Column(Integer, default=0)   # informational best-practice issues
    requests_sent     = Column(Integer, default=0)

    # Timing
    started_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at    = Column(DateTime, nullable=True)
    duration_s      = Column(Float, nullable=True)

    owner    = relationship("User", back_populates="attack_scans")
    findings = relationship("AttackFinding", back_populates="scan", cascade="all, delete-orphan")


class AttackFinding(Base):
    """
    A single finding from an attack engine.
    Cleanly separated into category='vulnerability' (exploitable) or
    'hardening' (best-practice missing).
    """
    __tablename__ = "attack_findings"

    id             = Column(Integer, primary_key=True, index=True)
    scan_id        = Column(Integer, ForeignKey("attack_scans.id"), nullable=False, index=True)

    # Classification (KEY: hardening vs vulnerability — separate views in UI)
    category       = Column(String(20), nullable=False, index=True)   # vulnerability | hardening
    owasp          = Column(String(10), nullable=False, index=True)   # A01..A10 or "hardening"
    severity       = Column(String(20), nullable=False, index=True)   # critical | high | medium | low | info

    title          = Column(String(500), nullable=False)
    description    = Column(Text, nullable=True)
    impact         = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)

    # Exploit detail
    affected_url   = Column(String(1500), nullable=True)
    parameter      = Column(String(200), nullable=True)
    http_method    = Column(String(10), default="GET")
    payload        = Column(Text, nullable=True)
    evidence       = Column(Text, nullable=True)
    poc            = Column(Text, nullable=True)

    # Classification helpers
    cwe_id         = Column(String(20), nullable=True)
    cve_id         = Column(String(50), nullable=True)
    cvss_score     = Column(Float, default=0.0)

    # Risk matrix (Phase 2h)
    likelihood     = Column(Integer, default=3)        # 1-5
    impact_score   = Column(Integer, default=3)        # 1-5
    risk_score     = Column(Integer, default=9)        # likelihood × impact (1-25)

    # Verification
    verified       = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    # Confidence tier: confirmed | probable | suspected | hardening
    confidence         = Column(String(20), default="probable", index=True)
    confidence_reason  = Column(Text, nullable=True)

    source_tool    = Column(String(50), default="venom_active")

    request_sample  = Column(Text, nullable=True)
    response_sample = Column(Text, nullable=True)

    # AI enrichment (Phase 2d) — plain English + working code fix
    ai_explanation  = Column(Text, nullable=True)        # plain-English explanation for non-experts
    ai_code_fix     = Column(Text, nullable=True)        # actual code snippet to apply
    ai_fix_language = Column(String(40), nullable=True)  # python | javascript | php | etc.
    ai_enriched_at  = Column(DateTime, nullable=True)

    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("AttackScan", back_populates="findings")


class PaymentEvent(Base):
    """Audit log of every Razorpay webhook + checkout event."""
    __tablename__ = "payment_events"

    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    event_type   = Column(String(100), nullable=False, index=True)   # subscription.activated, payment.captured, etc.
    razorpay_id  = Column(String(100), nullable=True, index=True)
    amount_paise = Column(Integer, nullable=True)
    currency     = Column(String(10), nullable=True)
    status       = Column(String(30), nullable=True)
    raw_payload  = Column(JSON,    nullable=True)
    processed    = Column(Boolean, default=False, nullable=False)
    created_at   = Column(DateTime, default=datetime.utcnow, nullable=False)