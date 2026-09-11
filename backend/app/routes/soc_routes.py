import json
import uuid
import asyncio
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..database import get_db
from ..models import SecurityIncident, SecurityEvent, BlockedIP, User, AuditLog, PasswordResetRequestModel, PasswordHistory
from ..schemas import ContainmentAction, LoginRequest, LoginResponse
from ..auth import (
    verify_password, 
    hash_password, 
    create_access_token, 
    get_current_user, 
    require_soc_analyst, 
    require_soc_admin
)
from ..detection_engine import record_security_event
from .websocket_routes import ws_manager

router = APIRouter(prefix="/api/v1/soc", tags=["SOC Analyst Console"])

class CoworkerCreate(BaseModel):
    username: str
    full_name: str
    email: str
    role: str = "SOC Analyst"
    clearance_level: str = "Secret"
    password: str

class CoworkerUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    clearance_level: Optional[str] = None
    is_locked: Optional[bool] = None
    new_password: Optional[str] = None

# ==================== SOC AUTHENTICATION ====================
@router.post("/auth/login")
async def soc_login(payload: LoginRequest, db: Session = Depends(get_db)):
    uname = (payload.username or "").strip()
    user = db.query(User).filter(
        (User.username.ilike(uname)) | (User.email.ilike(uname))
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SOC credentials."
        )

    # Check password
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SOC credentials."
        )

    # Enforce SOC / Admin clearance check!
    if not user.is_soc:
        record_security_event(
            db=db,
            event_type="UNAUTHORIZED_SOC_ACCESS_ATTEMPT",
            username=user.username,
            source_ip="SOC-GATEWAY",
            user_agent="SOC-Portal-UI",
            severity="HIGH",
            details={"reason": "Non-SOC employee attempted login to SOC operations console"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: User '{user.username}' does not hold SOC security clearance. Only SOC Administrators and Analysts are permitted."
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SOC Account Quarantined. Contact Lead Administrator."
        )

    token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
            "department": user.department,
            "is_admin": user.is_admin,
            "is_soc": user.is_soc
        }
    }

@router.get("/auth/me")
async def get_soc_me(current_user: User = Depends(require_soc_analyst)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "role": current_user.role,
        "department": current_user.department,
        "clearance_level": current_user.clearance_level,
        "is_admin": current_user.is_admin,
        "is_soc": current_user.is_soc
    }

# ==================== CO-WORKER MANAGEMENT (ADMIN ONLY) ====================
@router.get("/coworkers")
async def list_coworkers(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst)
):
    """
    List all SOC team members & administrators.
    """
    soc_users = (
        db.query(User)
        .filter((User.department == "Cybersecurity SOC") | (User.role == "Admin"))
        .all()
    )
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role,
            "department": u.department,
            "clearance_level": u.clearance_level,
            "is_active": u.is_active,
            "is_locked": u.is_locked,
            "is_admin": u.is_admin,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None
        }
        for u in soc_users
    ]

@router.post("/coworkers", status_code=status.HTTP_201_CREATED)
async def create_coworker(
    payload: CoworkerCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_soc_admin)
):
    """
    Admin adds a new SOC co-worker.
    """
    existing = db.query(User).filter((User.username == payload.username) | (User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists.")

    new_user = User(
        id=str(uuid.uuid4()),
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        department="Cybersecurity SOC",
        role=payload.role,
        clearance_level=payload.clearance_level,
        password_hash=hash_password(payload.password),
        is_active=True,
        is_locked=False,
        must_reset_password=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    record_security_event(
        db=db,
        event_type="SOC_COWORKER_CREATED",
        username=admin_user.username,
        source_ip="ADMIN-CONSOLE",
        user_agent="SOC-Admin-UI",
        severity="INFO",
        details={"created_user": new_user.username, "role": new_user.role}
    )

    return {
        "success": True,
        "message": f"Co-worker '{new_user.full_name}' ({new_user.username}) created successfully.",
        "user_id": new_user.id
    }

@router.put("/coworkers/{user_id}")
async def update_coworker(
    user_id: str,
    payload: CoworkerUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_soc_admin)
):
    """
    Admin updates a SOC co-worker's details, role, or password.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Co-worker not found.")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.role is not None:
        user.role = payload.role
    if payload.clearance_level is not None:
        user.clearance_level = payload.clearance_level
    if payload.is_locked is not None:
        user.is_locked = payload.is_locked
    if payload.new_password:
        user.password_hash = hash_password(payload.new_password)
        user.must_reset_password = False

    user.updated_at = datetime.utcnow()
    db.commit()

    record_security_event(
        db=db,
        event_type="SOC_COWORKER_UPDATED",
        username=admin_user.username,
        source_ip="ADMIN-CONSOLE",
        user_agent="SOC-Admin-UI",
        severity="INFO",
        details={"updated_user": user.username, "role": user.role}
    )

    return {"success": True, "message": f"Co-worker '{user.username}' updated successfully."}

@router.delete("/coworkers/{user_id}")
async def delete_coworker(
    user_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_soc_admin)
):
    """
    Admin deletes a SOC co-worker.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Co-worker not found.")

    if user.username == "admin" or user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete the primary administrative account.")

    deleted_username = user.username
    db.delete(user)
    db.commit()

    record_security_event(
        db=db,
        event_type="SOC_COWORKER_DELETED",
        username=admin_user.username,
        source_ip="ADMIN-CONSOLE",
        user_agent="SOC-Admin-UI",
        severity="HIGH",
        details={"deleted_user": deleted_username}
    )

    return {"success": True, "message": f"Co-worker '{deleted_username}' deleted successfully."}

# ==================== EMERGENCY LOCKOUT CONTROLS (ADMIN ONLY) ====================
@router.post("/actions/emergency-lockdown")
async def emergency_lockdown_all_employees(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_soc_admin)
):
    """
    Admin locks ALL regular employees from logging in immediately (Emergency Quarantine).
    Excludes SOC personnel and admin.
    """
    non_soc_users = (
        db.query(User)
        .filter(User.department != "Cybersecurity SOC", User.role != "Admin")
        .all()
    )
    locked_count = 0
    for u in non_soc_users:
        u.is_locked = True
        u.must_reset_password = True
        locked_count += 1

    db.commit()

    record_security_event(
        db=db,
        event_type="EMERGENCY_LOCKDOWN_TRIGGERED",
        username=admin_user.username,
        source_ip="ADMIN-CONSOLE",
        user_agent="SOC-Admin-UI",
        severity="CRITICAL",
        details={"locked_accounts_count": locked_count}
    )

    return {
        "success": True,
        "message": f"EMERGENCY LOCKDOWN ACTIVE: {locked_count} employee accounts have been quarantined from logging in.",
        "quarantined_count": locked_count
    }

@router.post("/actions/emergency-unlock")
async def emergency_unlock_all_employees(
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_soc_admin)
):
    """
    Admin lifts the emergency lockdown for all employees.
    """
    non_soc_users = (
        db.query(User)
        .filter(User.department != "Cybersecurity SOC", User.role != "Admin")
        .all()
    )
    unlocked_count = 0
    for u in non_soc_users:
        u.is_locked = False
        u.failed_login_count = 0
        unlocked_count += 1

    db.commit()

    record_security_event(
        db=db,
        event_type="EMERGENCY_LOCKDOWN_LIFTED",
        username=admin_user.username,
        source_ip="ADMIN-CONSOLE",
        user_agent="SOC-Admin-UI",
        severity="INFO",
        details={"unlocked_accounts_count": unlocked_count}
    )

    return {
        "success": True,
        "message": f"EMERGENCY LOCKDOWN LIFTED: {unlocked_count} employee accounts have been unlocked.",
        "unlocked_count": unlocked_count
    }

# ==================== INCIDENT & EVENT TELEMETRY ====================
@router.get("/incidents")
async def list_incidents(
    status_filter: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityIncident)
    if status_filter and status_filter != "ALL":
        query = query.filter(SecurityIncident.status == status_filter)
    
    incidents = query.order_by(desc(SecurityIncident.created_at)).limit(limit).all()
    results = []
    for inc in incidents:
        results.append({
            "id": inc.id,
            "incident_number": inc.incident_number,
            "title": inc.title,
            "attack_type": inc.attack_type,
            "severity": inc.severity,
            "status": inc.status,
            "risk_score": inc.risk_score,
            "mitre_technique": inc.mitre_technique,
            "username": inc.username,
            "source_ip": inc.source_ip,
            "evidence_data": json.loads(inc.evidence_data) if inc.evidence_data else {},
            "ai_summary": json.loads(inc.ai_summary) if inc.ai_summary else {},
            "created_at": inc.created_at.isoformat()
        })
    return results

@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {
        "id": inc.id,
        "incident_number": inc.incident_number,
        "title": inc.title,
        "attack_type": inc.attack_type,
        "severity": inc.severity,
        "status": inc.status,
        "risk_score": inc.risk_score,
        "mitre_technique": inc.mitre_technique,
        "username": inc.username,
        "source_ip": inc.source_ip,
        "evidence_data": json.loads(inc.evidence_data) if inc.evidence_data else {},
        "ai_summary": json.loads(inc.ai_summary) if inc.ai_summary else {},
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat()
    }

@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, new_status: str, db: Session = Depends(get_db)):
    inc = db.query(SecurityIncident).filter(SecurityIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    inc.status = new_status
    inc.updated_at = datetime.utcnow()
    db.commit()
    return {"success": True, "incident_number": inc.incident_number, "status": inc.status}

@router.get("/events")
async def list_security_events(limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit).all()
    return [
        {
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat(),
            "event_type": ev.event_type,
            "username": ev.username,
            "source_ip": ev.source_ip,
            "severity": ev.severity,
            "details": json.loads(ev.details) if ev.details else {}
        }
        for ev in events
    ]

@router.get("/stats")
async def get_soc_stats(db: Session = Depends(get_db)):
    total_events = db.query(SecurityEvent).count()
    active_incidents = db.query(SecurityIncident).filter(SecurityIncident.status.in_(["OPEN", "INVESTIGATING"])).count()
    critical_incidents = db.query(SecurityIncident).filter(SecurityIncident.severity == "CRITICAL").count()
    locked_accounts = db.query(User).filter(User.is_locked == True).count()
    blocked_ips_count = db.query(BlockedIP).filter(BlockedIP.is_active == True).count()
    soc_team_count = db.query(User).filter((User.department == "Cybersecurity SOC") | (User.role == "Admin")).count()

    return {
        "total_security_events": total_events,
        "active_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "quarantined_accounts": locked_accounts,
        "blocked_perimeter_ips": blocked_ips_count,
        "soc_team_members": soc_team_count,
        "sensor_status": "ONLINE",
        "detection_engine_mode": "ACTIVE_DEFENSE",
        "mitre_coverage": ["T1110.001"]
    }

@router.post("/containment")
async def execute_containment_action(action: ContainmentAction, db: Session = Depends(get_db)):
    if action.action == "lock_account":
        user = db.query(User).filter(User.username == action.target).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User {action.target} not found.")
        user.is_locked = True
        user.must_reset_password = True
        db.commit()
        record_security_event(db, "MANUAL_ACCOUNT_LOCK", action.target, "SOC-CONSOLE", "Analyst-UI", "HIGH", {"reason": action.reason})
        return {"success": True, "message": f"Account {action.target} has been quarantined."}

    elif action.action == "unlock_account":
        user = db.query(User).filter(User.username == action.target).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User {action.target} not found.")
        user.is_locked = False
        user.failed_login_count = 0
        db.commit()
        record_security_event(db, "MANUAL_ACCOUNT_UNLOCK", action.target, "SOC-CONSOLE", "Analyst-UI", "INFO", {"reason": action.reason})
        return {"success": True, "message": f"Account {action.target} has been unlocked."}

    elif action.action == "force_password_reset":
        user = db.query(User).filter(User.username == action.target).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User {action.target} not found.")
        user.must_reset_password = True
        db.commit()
        record_security_event(db, "FORCE_PASSWORD_RESET_FLAGGED", action.target, "SOC-CONSOLE", "Analyst-UI", "MEDIUM", {"reason": action.reason})
        return {"success": True, "message": f"Mandatory password reset flag set for {action.target}."}

    elif action.action == "block_ip":
        existing = db.query(BlockedIP).filter(BlockedIP.ip_address == action.target).first()
        if not existing:
            block = BlockedIP(
                ip_address=action.target,
                reason=action.reason or "SOC Analyst perimeter drop rule",
                is_active=True
            )
            db.add(block)
        else:
            existing.is_active = True
        db.commit()
        record_security_event(db, "FIREWALL_IP_BLOCKED", None, action.target, "SOC-CONSOLE", "HIGH", {"reason": action.reason})
        return {"success": True, "message": f"IP {action.target} has been blocked at perimeter firewall."}

    elif action.action == "unblock_ip":
        existing = db.query(BlockedIP).filter(BlockedIP.ip_address == action.target).first()
        if existing:
            existing.is_active = False
            db.commit()
        record_security_event(db, "FIREWALL_IP_UNBLOCKED", None, action.target, "SOC-CONSOLE", "INFO", {"reason": action.reason})
        return {"success": True, "message": f"IP {action.target} has been unblocked."}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown containment action: {action.action}")

@router.get("/threat-hunt")
async def threat_hunt_query(
    query: str = Query(..., description="Search keyword"),
    db: Session = Depends(get_db)
):
    keyword = f"%{query}%"
    events = (
        db.query(SecurityEvent)
        .filter(
            (SecurityEvent.username.ilike(keyword)) |
            (SecurityEvent.source_ip.ilike(keyword)) |
            (SecurityEvent.event_type.ilike(keyword)) |
            (SecurityEvent.severity.ilike(keyword))
        )
        .order_by(desc(SecurityEvent.timestamp))
        .limit(100)
        .all()
    )
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "username": e.username,
            "source_ip": e.source_ip,
            "severity": e.severity,
            "details": json.loads(e.details) if e.details else {}
        }
        for e in events
    ]

# ==================== PASSWORD RESET APPROVAL WORKFLOW ====================
@router.get("/password-requests")
async def list_password_requests(
    current_user: User = Depends(require_soc_analyst),
    db: Session = Depends(get_db)
):
    """
    Returns pending and recent employee password reset requests.
    Accessible to Admin and SOC Co-Workers.
    """
    requests = (
        db.query(PasswordResetRequestModel)
        .order_by(desc(PasswordResetRequestModel.created_at))
        .limit(100)
        .all()
    )
    results = []
    for r in requests:
        target_user = db.query(User).filter(User.id == r.user_id).first()
        results.append({
            "id": r.id,
            "user_id": r.user_id,
            "username": r.username,
            "full_name": target_user.full_name if target_user else r.username,
            "department": target_user.department if target_user else "Unknown",
            "role": target_user.role if target_user else "Employee",
            "is_locked": target_user.is_locked if target_user else False,
            "status": r.status,
            "reviewed_by": r.reviewed_by,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None
        })
    return results

@router.post("/password-requests/{request_id}/approve")
async def approve_password_request(
    request_id: str,
    current_user: User = Depends(require_soc_analyst),
    db: Session = Depends(get_db)
):
    """
    Approves a pending employee password reset request.
    Applies new password, stores previous password in history,
    lifts account quarantine (is_locked=False, must_reset_password=False),
    and logs the approval event.
    """
    req = db.query(PasswordResetRequestModel).filter(
        PasswordResetRequestModel.id == request_id
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="Password reset request not found.")
    if req.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request cannot be approved because its current status is {req.status}.")

    user = db.query(User).filter(User.id == req.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Target user account not found.")

    # Archive current password in history
    history_entry = PasswordHistory(
        user_id=user.id,
        password_hash=user.password_hash,
        created_at=datetime.utcnow()
    )
    db.add(history_entry)

    # Apply new password
    user.password_hash = req.new_password_hash
    user.is_locked = False
    user.failed_login_count = 0
    user.must_reset_password = False
    user.updated_at = datetime.utcnow()

    # Update request record
    req.status = "APPROVED"
    req.reviewed_by = current_user.username
    req.reviewed_at = datetime.utcnow()

    # Log Security & Audit Event
    record_security_event(
        db=db,
        event_type="PASSWORD_RESET_APPROVED",
        username=user.username,
        source_ip="SOC-CONSOLE",
        user_agent=f"Analyst:{current_user.username}",
        severity="INFO",
        details={
            "approved_by": current_user.username,
            "request_id": req.id,
            "action": "Password updated, quarantine released"
        }
    )

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="APPROVE_PASSWORD_RESET",
        resource=f"User:{user.username}",
        source_ip="SOC-CONSOLE",
        outcome="SUCCESS"
    ))
    db.commit()

    # Broadcast via WebSocket
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({
                "type": "PASSWORD_RESET_RESOLVED",
                "request_id": req.id,
                "username": user.username,
                "status": "APPROVED",
                "reviewer": current_user.username
            }))
    except Exception:
        pass

    return {
        "success": True,
        "message": f"Password reset for '{user.username}' successfully approved by {current_user.username}. Account unlocked and active.",
        "username": user.username
    }

@router.post("/password-requests/{request_id}/reject")
async def reject_password_request(
    request_id: str,
    current_user: User = Depends(require_soc_analyst),
    db: Session = Depends(get_db)
):
    """
    Rejects a pending employee password reset request.
    """
    req = db.query(PasswordResetRequestModel).filter(
        PasswordResetRequestModel.id == request_id
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="Password reset request not found.")
    if req.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request cannot be rejected because its current status is {req.status}.")

    req.status = "REJECTED"
    req.reviewed_by = current_user.username
    req.reviewed_at = datetime.utcnow()

    record_security_event(
        db=db,
        event_type="PASSWORD_RESET_REJECTED",
        username=req.username,
        source_ip="SOC-CONSOLE",
        user_agent=f"Analyst:{current_user.username}",
        severity="MEDIUM",
        details={
            "rejected_by": current_user.username,
            "request_id": req.id
        }
    )

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="REJECT_PASSWORD_RESET",
        resource=f"User:{req.username}",
        source_ip="SOC-CONSOLE",
        outcome="REJECTED"
    ))
    db.commit()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({
                "type": "PASSWORD_RESET_RESOLVED",
                "request_id": req.id,
                "username": req.username,
                "status": "REJECTED",
                "reviewer": current_user.username
            }))
    except Exception:
        pass

    return {
        "success": True,
        "message": f"Password reset request for '{req.username}' rejected.",
        "username": req.username
    }

