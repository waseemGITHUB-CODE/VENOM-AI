from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Enum as SAEnum, JSON, Float
from sqlalchemy.dialects.postgresql import UUID
from database import Base
import uuid, datetime, enum

class JobType(str, enum.Enum):
    document_processing = "document_processing"
    website_scan        = "website_scan"
    report_generation   = "report_generation"
    email_automation    = "email_automation"
    workflow            = "workflow"

class JobStatus(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"

class AutomationJob(Base):
    __tablename__ = "automation_jobs"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    job_type     = Column(SAEnum(JobType))
    status       = Column(SAEnum(JobStatus), default=JobStatus.pending)
    input_data   = Column(JSON)
    output_data  = Column(JSON)
    error_msg    = Column(Text)
    progress_pct = Column(Float, default=0)
    created_at   = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
