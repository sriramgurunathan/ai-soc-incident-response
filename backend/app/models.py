import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    department = Column(String(50), default="Engineering")
    role = Column(String(50), default="Staff Member")
    clearance_level = Column(String(20), default="Confidential")
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    must_reset_password = Column(Boolean, default=False)
    failed_login_count = Column(Integer, default=0)
    last_failed_at = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    password_history = relationship("PasswordHistory", back_populates="user", cascade="all, delete-orphan")
    password_requests = relationship("PasswordResetRequestModel", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        return self.role == "Admin"

    @property
    def is_soc(self) -> bool:
        return self.department == "Cybersecurity SOC" or self.role in ["Admin", "Lead SOC Analyst", "Senior SOC Specialist", "SOC Analyst"]

class PasswordHistory(Base):
    __tablename__ = "password_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="password_history")

class PasswordResetRequestModel(Base):
    __tablename__ = "password_reset_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    username = Column(String(50), nullable=False, index=True)
    new_password_hash = Column(String(255), nullable=False)
    status = Column(String(20), default="PENDING")  # PENDING, APPROVED, REJECTED
    reviewed_by = Column(String(50), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="password_requests")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    username = Column(String(50), nullable=True, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    user_agent = Column(Text, nullable=True)
    severity = Column(String(20), default="INFO")
    details = Column(Text, nullable=True)

class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_number = Column(String(20), unique=True, index=True, nullable=False)
    title = Column(String(150), nullable=False)
    attack_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="HIGH")
    status = Column(String(20), default="OPEN")
    risk_score = Column(Integer, default=50)
    mitre_technique = Column(String(50), nullable=True)
    username = Column(String(50), nullable=True)
    source_ip = Column(String(45), nullable=True)
    evidence_data = Column(Text, nullable=True)
    ai_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    reason = Column(String(255), nullable=False)
    incident_id = Column(String(36), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class Document(Base):
    __tablename__ = "documents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(150), nullable=False)
    classification = Column(String(20), default="Confidential")
    department = Column(String(50), default="All")
    description = Column(Text, nullable=True)
    file_name = Column(String(100), nullable=False)
    content_snippet = Column(Text, nullable=True)
    restricted = Column(Boolean, default=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String(36), nullable=True)
    username = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=True)
    source_ip = Column(String(45), nullable=False)
    outcome = Column(String(20), default="SUCCESS")
