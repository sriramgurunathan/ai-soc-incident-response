from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, Document, AuditLog
from ..auth import get_current_user
from ..detection_engine import record_security_event

router = APIRouter(prefix="/api/v1/portal", tags=["Employee Portal"])

@router.get("/documents")
async def list_documents(db: Session = Depends(get_db), current_user: Optional[User] = Depends(get_current_user)):
    docs = db.query(Document).all()
    results = []
    for d in docs:
        results.append({
            "id": d.id,
            "title": d.title,
            "classification": d.classification,
            "department": d.department,
            "description": d.description,
            "file_name": d.file_name,
            "restricted": d.restricted
        })
    return results

@router.get("/documents/{doc_id}/download")
async def download_document(
    doc_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    user_agent = request.headers.get("user-agent", "Unknown")

    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    username = current_user.username if current_user else "anonymous"

    # Access control verification
    if doc.restricted:
        # Check clearance level
        if not current_user or current_user.clearance_level != "Top Secret":
            record_security_event(
                db=db,
                event_type="UNAUTHORIZED_FILE_ACCESS_ATTEMPT",
                username=username,
                source_ip=client_ip,
                user_agent=user_agent,
                severity="HIGH",
                details={
                    "document_id": doc.id,
                    "document_title": doc.title,
                    "classification": doc.classification,
                    "user_clearance": current_user.clearance_level if current_user else "None",
                    "violation": "Attempted download of restricted Top Secret corporate file"
                }
            )
            audit = AuditLog(
                user_id=current_user.id if current_user else None,
                username=username,
                action="FILE_ACCESS_DENIED",
                resource=doc.title,
                source_ip=client_ip,
                outcome="DENIED"
            )
            db.add(audit)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Security Clearance Violation: This document ({doc.title}) is classified as {doc.classification}. Your clearance level is insufficient."
            )

    # Authorized download
    audit = AuditLog(
        user_id=current_user.id if current_user else None,
        username=username,
        action="FILE_DOWNLOAD",
        resource=doc.title,
        source_ip=client_ip,
        outcome="SUCCESS"
    )
    db.add(audit)
    db.commit()

    return {
        "success": True,
        "document": doc.title,
        "file_name": doc.file_name,
        "content_preview": doc.content_snippet or "Confidential company data contents..."
    }

@router.get("/announcements")
async def get_announcements():
    return [
        {
            "id": 1,
            "title": "Corporate Security Bulletin: Brute Force Wave Detected",
            "date": "2026-09-10",
            "priority": "HIGH",
            "summary": "SOC has placed automated burst detection online. Remember: failing 3-4 times normally over a few minutes is tolerated, but rapid automated bursts trigger instant quarantine."
        },
        {
            "id": 2,
            "title": "Password Hygiene Policy Update (3-History Exclusion)",
            "date": "2026-09-08",
            "priority": "MEDIUM",
            "summary": "All employees are reminded that passwords cannot match your active password or any of your last 3 previous passwords."
        },
        {
            "id": 3,
            "title": "Q3 Infrastructure Maintenance Schedule",
            "date": "2026-09-05",
            "priority": "LOW",
            "summary": "Scheduled cloud gateway patch window this Saturday 02:00-04:00 UTC."
        }
    ]
