import json
import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, BlockedIP, AuditLog, PasswordResetRequestModel
from ..schemas import LoginRequest, LoginResponse, PasswordResetRequest, UserResponse
from ..auth import verify_password, hash_password, validate_password_policy, create_access_token, get_current_user
from ..detection_engine import process_login_attempt, inspect_request_for_web_attacks, record_security_event
from .websocket_routes import ws_manager

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    uname = payload.username.strip()

    # 1. Check Firewall Blocklist
    blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == client_ip, BlockedIP.is_active == True).first()
    if blocked:
        record_security_event(
            db=db,
            event_type="FIREWALL_DROP_BLOCKED_IP",
            username=uname,
            source_ip=client_ip,
            user_agent=user_agent,
            severity="HIGH",
            details={"reason": blocked.reason}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Your IP address ({client_ip}) has been blocked at the perimeter firewall."
        )

    # 2. Check User
    user = db.query(User).filter(
        (User.username.ilike(uname)) | (User.email.ilike(uname))
    ).first()

    if not user:
        result = process_login_attempt(
            db=db,
            username=uname,
            source_ip=client_ip,
            user_agent=user_agent,
            success=False
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    # 3. Check if account is quarantined/locked
    if user.is_locked:
        record_security_event(
            db=db,
            event_type="LOGIN_ATTEMPT_LOCKED_ACCOUNT",
            username=user.username,
            source_ip=client_ip,
            user_agent=user_agent,
            severity="MEDIUM",
            details={"lock_reason": "Account Quarantined"}
        )
        return LoginResponse(
            access_token=None,
            is_locked=True,
            must_reset_password=user.must_reset_password,
            message="ACCOUNT QUARANTINED: High-velocity credential attack detected. Your account has been locked. Please submit a password remediation request.",
            user={
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "is_locked": True,
                "must_reset_password": user.must_reset_password
            }
        )

    # 4. Check Password
    is_valid = verify_password(payload.password, user.password_hash)

    if not is_valid:
        detection_result = process_login_attempt(
            db=db,
            username=user.username,
            source_ip=client_ip,
            user_agent=user_agent,
            success=False
        )

        if detection_result.get("status") == "MALWARE_BURST_DETECTED":
            return LoginResponse(
                access_token=None,
                is_locked=True,
                must_reset_password=True,
                message=detection_result["message"],
                user={
                    "username": user.username,
                    "email": user.email,
                    "full_name": user.full_name,
                    "is_locked": True,
                    "must_reset_password": True
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=detection_result.get("message", "Invalid username or password.")
            )

    # 5. Success
    process_login_attempt(
        db=db,
        username=user.username,
        source_ip=client_ip,
        user_agent=user_agent,
        success=True
    )

    token = create_access_token(data={"sub": user.username, "role": user.role})

    audit = AuditLog(
        user_id=user.id,
        username=user.username,
        action="AUTH_LOGIN",
        resource="Portal Dashboard",
        source_ip=client_ip,
        outcome="SUCCESS"
    )
    db.add(audit)
    db.commit()

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        is_locked=user.is_locked,
        must_reset_password=user.must_reset_password,
        message="Authentication successful.",
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "department": user.department,
            "role": user.role,
            "clearance_level": user.clearance_level,
            "is_locked": user.is_locked,
            "must_reset_password": user.must_reset_password
        }
    )

@router.post("/reset-password")
async def reset_password(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    """
    Submits a password reset request.
    Validates complexity + 3-password history rule.
    Requires Admin or SOC Co-Worker authorization to approve!
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    uname = payload.username.strip()

    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and password confirmation do not match."
        )

    user = db.query(User).filter(
        (User.username.ilike(uname)) | (User.email.ilike(uname))
    ).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    # Validate against complexity AND the strict 3-password history exclusion rule
    validate_password_policy(
        new_password=payload.new_password,
        user=user,
        db=db
    )

    # Hash the proposed new password
    new_hashed = hash_password(payload.new_password)

    # Cancel any existing pending requests for this user
    pending_existing = db.query(PasswordResetRequestModel).filter(
        PasswordResetRequestModel.user_id == user.id,
        PasswordResetRequestModel.status == "PENDING"
    ).all()
    for p in pending_existing:
        p.status = "SUPERSEDED"

    # Create new PENDING password reset request
    reset_req = PasswordResetRequestModel(
        user_id=user.id,
        username=user.username,
        new_password_hash=new_hashed,
        status="PENDING",
        created_at=datetime.utcnow()
    )
    db.add(reset_req)
    db.commit()
    db.refresh(reset_req)

    record_security_event(
        db=db,
        event_type="PASSWORD_RESET_REQUESTED",
        username=user.username,
        source_ip=client_ip,
        user_agent=user_agent,
        severity="INFO",
        details={
            "request_id": reset_req.id,
            "policy_applied": "3-Password History Rule Verified",
            "approval_required": True
        }
    )

    # Broadcast to SOC Console via WebSocket
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_PASSWORD_RESET_REQUEST",
                "request": {
                    "id": reset_req.id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "department": user.department,
                    "created_at": reset_req.created_at.isoformat()
                }
            }))
    except Exception:
        pass

    return {
        "success": True,
        "pending_approval": True,
        "request_id": reset_req.id,
        "message": "Password reset request submitted successfully! In accordance with enterprise security policy, all password changes must be authorized by an Administrator or SOC Analyst. Your request is currently PENDING review.",
        "username": user.username
    }

@router.get("/reset-status")
async def check_reset_status(username: str, db: Session = Depends(get_db)):
    uname = username.strip()
    user = db.query(User).filter((User.username.ilike(uname)) | (User.email.ilike(uname))).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    latest_req = (
        db.query(PasswordResetRequestModel)
        .filter(PasswordResetRequestModel.user_id == user.id)
        .order_by(PasswordResetRequestModel.created_at.desc())
        .first()
    )
    if not latest_req:
        return {"has_request": False, "is_locked": user.is_locked}

    return {
        "has_request": True,
        "request_id": latest_req.id,
        "status": latest_req.status,
        "reviewed_by": latest_req.reviewed_by,
        "is_locked": user.is_locked,
        "must_reset_password": user.must_reset_password
    }

@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication token invalid or expired.")
    return current_user
