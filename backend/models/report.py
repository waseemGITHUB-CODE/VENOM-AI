from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Enum as SAEnum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import uuid, datetime, enum

class ReportType(str, enum.Enum):
    security_audit   = "security_audit"
    document_extract = "document_extract"
    automation       = "automation"
    executive        = "executive"

class Report(Base):
    __tablename__ = "reports"
    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    title       = Column(String, nullable=False)
    report_type = Column(SAEnum(ReportType))
    content_json= Column(JSON)
    pdf_path    = Column(String)
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="reports")
