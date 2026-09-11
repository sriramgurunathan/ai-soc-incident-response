import json
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from sqlalchemy.orm import Session
from .config import settings
from .models import User, SecurityEvent, SecurityIncident, BlockedIP
from .ai_analyst import AISecurityAnalyst
from .routes.websocket_routes import ws_manager

# In-memory sliding window history: user -> list of failure timestamps
# format: [(timestamp, ip, user_agent), ...]
_login_failures: Dict[str, List[Dict]] = defaultdict(list)
_port_scans: Dict[str, List[int]] = defaultdict(list)

def record_security_event(
    db: Session,
    event_type: str,
    username: Optional[str],
    source_ip: str,
    user_agent: str,
    severity: str = "INFO",
    details: Optional[Dict] = None
) -> SecurityEvent:
    """
    Persists a normalized security event to the audit trail and broadcasts it in real-time.
    """
    event = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        user_agent=user_agent,
        severity=severity,
        details=json.dumps(details or {})
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Broadcast event asynchronously to SOC WebSocket subscribers
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_SECURITY_EVENT",
                "event": {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "username": event.username,
                    "source_ip": event.source_ip,
                    "severity": event.severity,
                    "details": details or {}
                }
            }))
    except Exception:
        pass

    return event

def process_login_attempt(
    db: Session,
    username: str,
    source_ip: str,
    user_agent: str,
    success: bool
) -> Dict:
    """
    Core detection heuristic differentiating:
    1. Human Authentication Friction: 3-4 failed logins over 2-3 minutes, followed by success.
       -> Classified as benign/low-risk. Account is NOT locked.
    2. Malware / Automated Brute Force: 5-7 failed attempts in seconds (<15s).
       -> Classified as CRITICAL security incident (MITRE T1110.001).
       -> Automatically locks user account, sets must_reset_password=True, enforces 3-history rule.
       -> Generates AI SOC analysis report.
    """
    user = db.query(User).filter(User.username == username).first()
    now = datetime.utcnow()

    # Clean old records outside the human window (180 seconds)
    cutoff = now - timedelta(seconds=settings.HUMAN_WINDOW_SECONDS)
    _login_failures[username] = [
        item for item in _login_failures[username]
        if item["time"] >= cutoff
    ]

    if success:
        # Successful Login
        failures_count = len(_login_failures[username])
        if failures_count > 0:
            # Benign employee recovery: employee made mistakes previously but now got it right
            record_security_event(
                db=db,
                event_type="LOGIN_SUCCESS_AFTER_FRICTION",
                username=username,
                source_ip=source_ip,
                user_agent=user_agent,
                severity="INFO",
                details={
                    "friction_count": failures_count,
                    "behavior": "Normal Human User Friction (resolved successfully)"
                }
            )
        else:
            record_security_event(
                db=db,
                event_type="LOGIN_SUCCESS",
                username=username,
                source_ip=source_ip,
                user_agent=user_agent,
                severity="INFO",
                details={"behavior": "Standard successful employee authentication"}
            )

        # Clear failure streak
        _login_failures[username] = []
        if user:
            user.failed_login_count = 0
            user.last_login_at = now
            db.commit()

        return {"status": "SUCCESS", "incident_triggered": False}

    # FAILED LOGIN HANDLING
    # Append current failure
    _login_failures[username].append({
        "time": now,
        "ip": source_ip,
        "user_agent": user_agent
    })

    if user:
        user.failed_login_count += 1
        user.last_failed_at = now
        db.commit()

    # Check high-velocity burst window (last 15 seconds)
    burst_cutoff = now - timedelta(seconds=settings.BURST_WINDOW_SECONDS)
    recent_burst = [
        item for item in _login_failures[username]
        if item["time"] >= burst_cutoff
    ]
    burst_count = len(recent_burst)

    # Check overall attempts within 3-minute human window
    total_human_window_count = len(_login_failures[username])

    # Condition 1: Automated Malware Brute Force Burst (>= 5 in < 15 seconds)
    if burst_count >= settings.BURST_FAILURE_THRESHOLD:
        time_span = (recent_burst[-1]["time"] - recent_burst[0]["time"]).total_seconds()
        if time_span < 0.1:
            time_span = 0.5

        # Automated Quarantine Containment
        if user:
            user.is_locked = True
            user.must_reset_password = True
            db.commit()

        # Log high severity event
        record_security_event(
            db=db,
            event_type="BRUTE_FORCE_BURST_DETECTED",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            severity="CRITICAL",
            details={
                "burst_count": burst_count,
                "time_span_seconds": time_span,
                "attack_pattern": "Automated High-Velocity Credential Stuffing / Malware"
            }
        )

        # Build forensic evidence package
        evidence_data = {
            "attempt_count": burst_count,
            "duration_seconds": time_span,
            "target_user": username,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "timestamps": [item["time"].isoformat() for item in recent_burst]
        }

        # Run AI SOC Analyst
        ai_report = AISecurityAnalyst.analyze_incident(
            incident_type="BRUTE_FORCE_BURST",
            target_user=username,
            source_ip=source_ip,
            evidence=evidence_data
        )

        # Create Security Incident record
        incident_number = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        incident = SecurityIncident(
            id=str(uuid.uuid4()),
            incident_number=incident_number,
            title=f"High-Velocity Brute Force: {username}",
            attack_type="Brute Force (High-Velocity)",
            severity="CRITICAL",
            status="OPEN",
            risk_score=94,
            mitre_technique="T1110.001",
            username=username,
            source_ip=source_ip,
            evidence_data=json.dumps(evidence_data),
            ai_summary=json.dumps(ai_report),
            created_at=now,
            updated_at=now
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Broadcast Incident Alert to SOC Dashboard
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(ws_manager.broadcast({
                    "type": "NEW_SECURITY_INCIDENT",
                    "incident": {
                        "id": incident.id,
                        "incident_number": incident.incident_number,
                        "title": incident.title,
                        "severity": incident.severity,
                        "risk_score": incident.risk_score,
                        "mitre_technique": incident.mitre_technique,
                        "username": incident.username,
                        "source_ip": incident.source_ip,
                        "ai_summary": ai_report
                    }
                }))
        except Exception:
            pass

        return {
            "status": "MALWARE_BURST_DETECTED",
            "incident_triggered": True,
            "incident_number": incident.incident_number,
            "locked": True,
            "must_reset_password": True,
            "message": f"CRITICAL THREAT: High-velocity brute force detected ({burst_count} attempts in {time_span:.1f}s). Account quarantined."
        }

    # Condition 2: Normal Human Friction (3-4 attempts over 2-3 minutes)
    elif total_human_window_count <= settings.HUMAN_FAILURE_LIMIT:
        record_security_event(
            db=db,
            event_type="LOGIN_FAILED_HUMAN_FRICTION",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            severity="LOW",
            details={
                "attempt_number": total_human_window_count,
                "window_seconds": settings.HUMAN_WINDOW_SECONDS,
                "classification": "Benign Human Typing Friction / Password Typo"
            }
        )
        return {
            "status": "HUMAN_FRICTION",
            "incident_triggered": False,
            "attempt_number": total_human_window_count,
            "locked": False,
            "message": f"Invalid password. Attempt {total_human_window_count} of 4. (Normal user friction tolerance)."
        }

    # Condition 3: Elevated slow attempts
    else:
        record_security_event(
            db=db,
            event_type="LOGIN_FAILED_ELEVATED",
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            severity="MEDIUM",
            details={
                "attempt_number": total_human_window_count,
                "classification": "Elevated failed attempts (Exceeds normal human friction)"
            }
        )
        return {
            "status": "ELEVATED_FAILURES",
            "incident_triggered": False,
            "attempt_number": total_human_window_count,
            "locked": False,
            "message": f"Repeated authentication failures detected ({total_human_window_count} attempts)."
        }

def inspect_request_for_web_attacks(
    db: Session,
    source_ip: str,
    user_agent: str,
    query_params: str = "",
    body_content: str = "",
    username: Optional[str] = None
) -> Optional[Dict]:
    """
    Inspects incoming payload for SQL Injection and Cross-Site Scripting (XSS).
    """
    combined = f"{query_params} {body_content}".lower()

    # SQL Injection Patterns
    sqli_signatures = ["' or '1'='1", "union select", "1=1--", "information_schema", "drop table", "exec(", ";--"]
    for sig in sqli_signatures:
        if sig in combined:
            evidence = {"payload": sig, "raw_content": combined[:200], "source_ip": source_ip}
            ai_report = AISecurityAnalyst.analyze_incident("SQL_INJECTION", username or "anonymous", source_ip, evidence)

            incident_num = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
            incident = SecurityIncident(
                id=str(uuid.uuid4()),
                incident_number=incident_num,
                title="SQL Injection Exploit Attempt",
                attack_type="SQL Injection",
                severity="HIGH",
                status="OPEN",
                risk_score=88,
                mitre_technique="T1190",
                username=username,
                source_ip=source_ip,
                evidence_data=json.dumps(evidence),
                ai_summary=json.dumps(ai_report)
            )
            db.add(incident)
            record_security_event(
                db=db,
                event_type="SQLI_ATTEMPT_DETECTED",
                username=username,
                source_ip=source_ip,
                user_agent=user_agent,
                severity="HIGH",
                details=evidence
            )
            db.commit()
            return {"type": "SQLI", "incident_number": incident_num}

    # XSS Patterns
    xss_signatures = ["<script", "javascript:", "onerror=", "onload=", "<svg/onload"]
    for sig in xss_signatures:
        if sig in combined:
            evidence = {"payload": sig, "raw_content": combined[:200], "source_ip": source_ip}
            ai_report = AISecurityAnalyst.analyze_incident("XSS_ATTEMPT", username or "anonymous", source_ip, evidence)

            incident_num = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
            incident = SecurityIncident(
                id=str(uuid.uuid4()),
                incident_number=incident_num,
                title="Cross-Site Scripting (XSS) Attempt",
                attack_type="XSS",
                severity="MEDIUM",
                status="OPEN",
                risk_score=72,
                mitre_technique="T1059.007",
                username=username,
                source_ip=source_ip,
                evidence_data=json.dumps(evidence),
                ai_summary=json.dumps(ai_report)
            )
            db.add(incident)
            record_security_event(
                db=db,
                event_type="XSS_ATTEMPT_DETECTED",
                username=username,
                source_ip=source_ip,
                user_agent=user_agent,
                severity="MEDIUM",
                details=evidence
            )
            db.commit()
            return {"type": "XSS", "incident_number": incident_num}

    return None
