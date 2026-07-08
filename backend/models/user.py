from sqlalchemy import Column, String, DateTime, Boolean, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import uuid, datetime, enum

class UserRole(str, enum.Enum):
    admin = "admin"
    client = "client"
    analyst = "analyst"

class User(Base):
    __tablename__ = "users"
    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email        = Column(String, unique=True, nullable=False, index=True)
    full_name    = Column(String)
    hashed_pw    = Column(String, nullable=False)
    role         = Column(SAEnum(UserRole), default=UserRole.client)
    is_active    = Column(Boolean, default=True)
    company_name = Column(String)
    created_at   = Column(DateTime, default=datetime.datetime.utcnow)

    documents  = relationship("Document", back_populates="owner")
    scan_jobs  = relationship("ScanJob",  back_populates="owner")
    reports    = relationship("Report",   back_populates="owner")
