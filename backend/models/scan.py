from sqlalchemy import Column, String, DateTime, Text, Float, Integer, ForeignKey, Enum as SAEnum, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import uuid, datetime, enum

class ScanStatus(str, enum.Enum):
    queued    = "queued"
    running   = "running"
    completed = "completed"
    failed    = "failed"

class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id       = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    target_url     = Column(String, nullable=False)
    status         = Column(SAEnum(ScanStatus), default=ScanStatus.queued)
    security_score = Column(Float)
    started_at     = Column(DateTime)
    completed_at   = Column(DateTime)
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

    owner           = relationship("User", back_populates="scan_jobs")
    result          = relationship("ScanResult", back_populates="scan_job", uselist=False)
    vulnerabilities = relationship("Vulnerability", back_populates="scan_job")

class ScanResult(Base):
    __tablename__ = "scan_results"
    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id      = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"))
    headers_score    = Column(Float)
    ssl_score        = Column(Float)
    ports_score      = Column(Float)
    cms_score        = Column(Float)
    open_ports       = Column(JSON)
    headers_found    = Column(JSON)
    headers_missing  = Column(JSON)
    ssl_details      = Column(JSON)
    cms_detected     = Column(String)
    ai_summary       = Column(Text)
    raw_data         = Column(JSON)

    scan_job = relationship("ScanJob", back_populates="result")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id    = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"))
    title          = Column(String, nullable=False)
    severity       = Column(SAEnum(SeverityLevel))
    description    = Column(Text)
    ai_explanation = Column(Text)
    recommendation = Column(Text)
    cvss_score     = Column(Float)
    evidence       = Column(Text)
    fixed          = Column(Boolean, default=False)

    scan_job = relationship("ScanJob", back_populates="vulnerabilities")
