import re
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import settings
from .database import get_db
from .models import User, PasswordHistory

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def validate_password_policy(new_password: str, user: User, db: Session):
    if len(new_password) < settings.MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters long."
        )
    if not re.search(r"[A-Z]", new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"\d", new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one number (0-9).")
    
    special_chars = set('!@#$%^&*(),.?:{}|<>_+-="')
    if not any(c in special_chars for c in new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain at least one special symbol (!@#$%^&*...).")

    if verify_password(new_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Policy Error: New password cannot match your current active password."
        )

    history_records = (
        db.query(PasswordHistory)
        .filter(PasswordHistory.user_id == user.id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(settings.PASSWORD_HISTORY_LIMIT)
        .all()
    )

    for idx, history_entry in enumerate(history_records, 1):
        if verify_password(new_password, history_entry.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security Policy Violation: This password matches previous password #{idx} in your history. You cannot reuse any of your last {settings.PASSWORD_HISTORY_LIMIT} passwords. Please choose a different password."
            )

def commit_new_password(db: Session, user: User, new_password: str):
    old_entry = PasswordHistory(
        user_id=user.id,
        password_hash=user.password_hash
    )
    db.add(old_entry)

    user.password_hash = hash_password(new_password)
    user.must_reset_password = False
    user.is_locked = False
    user.failed_login_count = 0
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Optional[User]:
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    username: str = payload.get("sub")
    if not username:
        return None
    return db.query(User).filter(User.username == username).first()

def require_soc_analyst(current_user: Optional[User] = Depends(get_current_user)) -> User:
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SOC Authentication Required: Please log in with SOC credentials."
        )
    if not current_user.is_soc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: SOC clearance required. Only Security Administrators and Analysts are permitted."
        )
    return current_user

def require_soc_admin(current_user: Optional[User] = Depends(require_soc_analyst)) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Administrative authority required for this operation."
        )
    return current_user