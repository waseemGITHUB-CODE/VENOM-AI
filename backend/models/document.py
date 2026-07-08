from sqlalchemy import Column, String, DateTime, Text, Float, ForeignKey, Enum as SAEnum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import uuid, datetime, enum

class DocStatus(str, enum.Enum):
    pending    = "pending"
    processing = "processing"
    completed  = "completed"
    failed     = "failed"

class DocType(str, enum.Enum):
    invoice  = "invoice"
    contract = "contract"
    report   = "report"
    form     = "form"
    unknown  = "unknown"

class Document(Base):
    __tablename__ = "documents"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    filename     = Column(String, nullable=False)
    file_path    = Column(String)
    doc_type     = Column(SAEnum(DocType), default=DocType.unknown)
    status       = Column(SAEnum(DocStatus), default=DocStatus.pending)
    file_size_kb = Column(Float)
    raw_text     = Column(Text)
    ai_summary   = Column(Text)
    created_at   = Column(DateTime, default=datetime.datetime.utcnow)
    processed_at = Column(DateTime)

    owner     = relationship("User", back_populates="documents")
    extracted = relationship("ExtractedData", back_populates="document", uselist=False)

class ExtractedData(Base):
    __tablename__ = "extracted_data"
    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id    = Column(UUID(as_uuid=True), ForeignKey("documents.id"))
    company_name   = Column(String)
    invoice_number = Column(String)
    invoice_amount = Column(Float)
    invoice_date   = Column(String)
    vendor_name    = Column(String)
    due_date       = Column(String)
    line_items     = Column(JSON)
    extra_fields   = Column(JSON)

    document = relationship("Document", back_populates="extracted")
