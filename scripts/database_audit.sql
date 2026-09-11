-- ====================================================================
-- APEXSHIELD ENTERPRISE SOC: SQL THREAT HUNTING & FORENSICS RUNBOOK
-- ====================================================================

-- 1. Threat Hunting: High-Velocity Authentication Failures (< 15 seconds)
SELECT 
    username, 
    source_ip, 
    COUNT(*) AS total_failed_attempts,
    MIN(timestamp) AS burst_start,
    MAX(timestamp) AS burst_end,
    (strftime('%s', MAX(timestamp)) - strftime('%s', MIN(timestamp))) AS duration_seconds
FROM security_events
WHERE event_type IN ('LOGIN_FAILED_HUMAN_FRICTION', 'BRUTE_FORCE_BURST_DETECTED', 'LOGIN_FAILED_ELEVATED')
GROUP BY username, source_ip
HAVING total_failed_attempts >= 4
ORDER BY total_failed_attempts DESC;

-- 2. Audit Trail: All Quarantined / Locked Accounts Requiring Password Reset
SELECT 
    username, 
    full_name, 
    department, 
    role, 
    clearance_level, 
    is_locked, 
    must_reset_password, 
    failed_login_count, 
    last_failed_at
FROM users
WHERE is_locked = 1 OR must_reset_password = 1;

-- 3. Password History Forensics: Verify Historical Password Hashes per User
SELECT 
    u.username,
    u.full_name,
    ph.id AS history_record_id,
    ph.created_at AS recorded_timestamp
FROM password_history ph
JOIN users u ON ph.user_id = u.id
ORDER BY u.username, ph.created_at DESC;

-- 4. Active High-Risk Security Incidents Correlated with MITRE ATT&CK
SELECT 
    incident_number,
    title,
    attack_type,
    severity,
    status,
    risk_score,
    mitre_technique,
    username,
    source_ip,
    created_at
FROM security_incidents
WHERE severity IN ('HIGH', 'CRITICAL') AND status != 'RESOLVED'
ORDER BY risk_score DESC;

-- 5. Perimeter Firewall Active IP Drop Rules
SELECT 
    ip_address,
    reason,
    blocked_at,
    is_active
FROM blocked_ips
WHERE is_active = 1;
