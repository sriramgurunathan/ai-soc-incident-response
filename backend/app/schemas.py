from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    is_locked: bool = False
    must_reset_password: bool = False
    message: str
    user: Optional[dict] = None

class PasswordResetRequest(BaseModel):
    username: str
    current_password: Optional[str] = None
    new_password: str
    confirm_password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    department: str
    role: str
    clearance_level: str
    is_active: bool
    is_locked: bool
    must_reset_password: bool
    failed_login_count: int
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class IncidentResponse(BaseModel):
    id: str
    incident_number: str
    title: str
    attack_type: str
    severity: str
    status: str
    risk_score: int
    mitre_technique: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    evidence_data: Optional[str] = None
    ai_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class EventResponse(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    username: Optional[str] = None
    source_ip: str
    severity: str
    details: Optional[str] = None

    class Config:
        from_attributes = True

class ContainmentAction(BaseModel):
    action: str
    target: str
    reason: Optional[str] = "SOC Analyst manual containment action"

class SimulateRequest(BaseModel):
    scenario: str
    target_user: Optional[str] = "john.doe"
    source_ip: Optional[str] = "192.168.1.105"
