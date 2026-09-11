# ApexShield Multi-Portal AI-SOC & Enterprise Incident Response Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20(Brute%20Force)-red.svg)](https://attack.mitre.org/techniques/T1110/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Enterprise-Grade Incident Detection & Containment Platform**  
> Features two physically separated interfaces: a **Company Employee Intranet Portal** and a **Restricted SOC Operations Console**, backed by sliding-window brute-force velocity analysis, real-time WebSocket telemetry, perimeter firewall containment, and an Admin/Co-Worker password authorization workflow.

---

## 📑 Table of Contents
- [Architecture & Portal Separation](#-architecture--portal-separation)
- [Key Features & Threat Defense Pipeline](#-key-features--threat-defense-pipeline)
- [Credentials & Role-Based Access Control (RBAC)](#-credentials--role-based-access-control-rbac)
- [Key Concepts & Algorithms](#-key-concepts--algorithms)
- [Important Libraries & Dependencies](#-important-libraries--dependencies)
- [Quick Start & Manual Run](#-quick-start--manual-run)
- [API Reference](#-api-reference)
- [Interview Walkthrough & Talking Points](#-interview-walkthrough--talking-points)

---

## 🏛 Architecture & Portal Separation

```
                            ┌────────────────────────────────────────┐
                            │      FastAPI Gateway (Port 8000)       │
                            └───────────────────┬────────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
     [ Company Employee Portal ]                                   [ SOC Operations Console ]
     URL: http://127.0.0.1:8000/                                  URL: http://127.0.0.1:8000/soc
     Target: Regular Employees                                    Target: Admin & SOC Analysts Only
     Clearance: Confidential / General                             Clearance: Top Secret / Secret
  ┌─────────────────────────────────┐                           ┌─────────────────────────────────┐
  │ • Corporate SSO Login           │                           │ • Real-time Threat Stream (WS)  │
  │ • Benign Friction Tolerance     │                           │ • Sliding-Window Brute Force Det│
  │ • Automated Quarantine Alert    │                           │ • 1-Click IP Firewall Block     │
  │ • Password Remediation Modal    │                           │ • Emergency Portal Lockdown     │
  │ • Corporate Document Vault      │                           │ • Co-Worker Team Management     │
  │ • Security Bulletins            │                           │ • Password Reset Approvals      │
  └─────────────────────────────────┘                           └─────────────────────────────────┘
```

---

## 🛡 Key Features & Threat Defense Pipeline

### 1. Dual-Tier Brute Force Velocity Analyzer (Sliding-Window)
* **Tier 1 — Benign Human Friction:** 1–3 mistyped passwords over 2–3 minutes are recognized as benign human friction. No lockout occurs; attempt count resets upon valid authentication.
* **Tier 2 — High-Velocity Malware Burst:** 5+ failed attempts within a 15-second window trigger:
  1. Instant account quarantine (`is_locked = True`, `must_reset_password = True`).
  2. Automatic security incident creation (`INC-YYYYMMDD-XXXX`) with calculated risk score.
  3. Real-time telemetry broadcast via WebSocket to active SOC analyst screens.

### 2. Admin & Co-Worker Password Reset Approval Workflow
* When a quarantined or active employee requests a password change:
  1. Policy checks enforce minimum 8 characters, uppercase, lowercase, numbers, and symbols.
  2. The proposed password is cryptographically validated against the user's active password and last 3 previous passwords (`password_history` table with salted bcrypt hashes).
  3. Instead of immediate direct activation, a `PENDING` request is logged in `password_reset_requests`.
  4. Both Administrators and SOC Co-Workers review the pending queue under the **Approvals** tab in the SOC console.
  5. Approving the request applies the new hash, releases the quarantine, and logs an immutable audit trail.

### 3. Emergency Lockdown & Perimeter Defense
* **1-Click Emergency Lockdown:** In the event of a coordinated credential-stuffing wave, the Lead Administrator can trigger immediate lockdown, locking all non-SOC accounts simultaneously.
* **Firewall Perimeter Drops:** SOC analysts can block offending IP addresses with one click, persisting active drop rules in `blocked_ips`.
* **Co-Worker Management:** The Lead Administrator can add new analysts, adjust clearance levels, and delete co-workers.

---

## 🔑 Credentials & Role-Based Access Control (RBAC)

| Account Role | Username | Password | Permitted Portal | Clearance Level |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Administrator** | `admin` | `Admin@Apex2026!` | Both (`/` and `/soc`) | Top Secret / Full Authority |
| **Lead SOC Analyst** | `sarah.connor` | `Password123!` | `/soc` Operations Console | Top Secret / Analyst |
| **Senior SOC Specialist**| `alex.mercer` | `Password123!` | `/soc` Operations Console | Secret / Analyst |
| **Staff Employee** | `john.doe` | `Password123!` | `/` Company Portal Only | Confidential / Staff |

> **Note:** Attempting to access the SOC Console (`/soc`) with a regular employee account yields an immediate **HTTP 403 Forbidden ("Access Denied: SOC Security Clearance Required")** and logs an unauthorized access attempt.

---

## 🧠 Key Concepts & Algorithms

1. **Sliding-Window Velocity Detection:**
   Tracks failed attempts within bounded time windows ($\Delta t \le 15\text{s}$) rather than an unbounded static counter, preventing denial-of-service lockout against legitimate users while stopping automated Hydra/Burp Suite attacks in seconds.
2. **Cryptographic Password History Exclusion (Salted Bcrypt):**
   Stores historical passwords as cryptographic hashes. During remediation, `bcrypt.checkpw()` checks the candidate password against the current hash and the previous 3 entries. Old passwords are never stored in plaintext.
3. **Event-Driven Asynchronous Telemetry (WebSockets):**
   Employs an in-memory `ConnectionManager` that broadcasts JSON incident events to all authenticated SOC console clients without client-side polling overhead.
4. **Least-Privilege RBAC:**
   Enforced via FastAPI dependency injection (`Depends(require_soc_analyst)` and `Depends(require_soc_admin)`), verifying JWT claims and database state on every privileged request.

---

## 📦 Important Libraries & Dependencies

| Library | Version | Purpose in Project |
| :--- | :--- | :--- |
| **`fastapi`** | `>=0.110.0` | High-performance asynchronous REST API framework and routing. |
| **`uvicorn`** | `>=0.28.0` | Lightning-fast ASGI production web server. |
| **`sqlalchemy`** | `>=2.0.0` | Object Relational Mapper (ORM) for schema modeling, relationships, and queries. |
| **`pydantic`** | `>=2.0.0` | Strict data validation, schema serialization, and request body parsing. |
| **`bcrypt`** | `>=4.0.0` | Adaptive one-way salted password hashing for security and history checks. |
| **`pyjwt`** | `>=2.8.0` | Creation and verification of signed JSON Web Tokens (JWT) for stateless session auth. |
| **`websockets`** | `>=12.0` | Full-duplex real-time communication channel for streaming SOC telemetry. |
| **`python-multipart`** | `>=0.0.9` | Handles form-data authentication payloads. |

---

## 🚀 Quick Start & Manual Run

### Prerequisites
* Python 3.10 or higher
* PowerShell / Bash terminal

### Installation & Run

```powershell
# 1. Clone repository
git clone https://github.com/MohammedAneezz/ai-soc-incident-response.git
cd ai-soc-incident-response

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch application
python run.py
```

* **Company Intranet Website:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **SOC Security Operations Console:** [http://127.0.0.1:8000/soc](http://127.0.0.1:8000/soc)
* **Interactive OpenAPI (Swagger) Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 📡 API Reference

### Authentication & Portal (`/api/v1/auth`)
* `POST /api/v1/auth/login` - Employee Single Sign-On (analyzes velocity & friction).
* `POST /api/v1/auth/reset-password` - Submits password reset request for Admin/SOC approval.
* `GET /api/v1/auth/reset-status` - Checks approval state of submitted request.
* `GET /api/v1/auth/me` - Returns active session profile.

### SOC Analyst Operations (`/api/v1/soc`)
* `POST /api/v1/soc/auth/login` - Restricted login gate (RBAC clearance enforcement).
* `GET /api/v1/soc/incidents` - Lists active security incidents.
* `POST /api/v1/soc/containment` - Executes containment actions (Block IP, Force Reset, Unlock).
* `GET /api/v1/soc/password-requests` - Lists pending employee password reset requests.
* `POST /api/v1/soc/password-requests/{id}/approve` - Approves reset, lifts quarantine, activates password.
* `POST /api/v1/soc/password-requests/{id}/reject` - Rejects reset request.
* `POST /api/v1/soc/actions/emergency-lockdown` - Admin 1-click quarantine of all employees.
* `POST /api/v1/soc/actions/emergency-unlock` - Admin 1-click release of lockdown.
* `POST /api/v1/soc/coworkers` - Admin adds new SOC analyst.
* `DELETE /api/v1/soc/coworkers/{id}` - Admin removes SOC analyst.

### Threat Simulator (`/api/v1/simulate`)
* `POST /api/v1/simulate/human-login-friction` - Simulates 3 mistyped attempts followed by success.
* `POST /api/v1/simulate/malware-brute-force` - Simulates 7 rapid attempts in seconds.

---

## 🎯 Interview Walkthrough & Talking Points

### Q1: "How does your system distinguish an employee making a typo from an attacker running a brute force attack?"
> *"Instead of using a naive static failed attempt counter, our system uses a **sliding-window velocity algorithm**. If a user enters 2 or 3 wrong passwords spaced over 2 minutes, the system recognizes human friction and avoids disruptive account lockouts. However, if 5 or more failed attempts hit the authentication endpoint within a 15-second burst window, the velocity threshold triggers an immediate quarantine (`is_locked=True`), creates an incident tagged with MITRE ATT&CK T1110, and streams an alert to the SOC console over WebSockets."*

### Q2: "How is the 3-password history rule enforced securely without storing plaintext passwords?"
> *"We never store plaintext passwords. The system maintains a `password_history` table containing salted Bcrypt hashes. When a user requests a reset, the candidate password is first checked against policy (length, uppercase, lowercase, numbers, special characters). Then, `bcrypt.checkpw()` is computed against the active password hash and the user's last 3 history hashes. If any hash matches, an HTTP 400 rejection is returned."*

### Q3: "Explain the separation of portals and how access control is maintained."
> *"The backend serves two independent frontend applications: the Company Intranet Portal at `/` and the SOC Console at `/soc`. Access to `/soc` is protected by a dedicated endpoint `/api/v1/soc/auth/login` and enforced via FastAPI dependencies (`require_soc_analyst` and `require_soc_admin`). Regular employee credentials attempting to authenticate against the SOC gateway receive an immediate HTTP 403 Forbidden with security event telemetry recorded for threat hunting."*

### Q4: "Why did you implement an approval workflow for password resets instead of self-service?"
> *"In a compromised enterprise environment, an attacker with brief access to an employee's session could attempt to reset credentials to maintain persistence. Requiring SOC or Administrator authorization ensures dual-custody verification: the analyst can review the employee's quarantine state and incident logs before approving the credential change."*

---

## 📄 License
This project is licensed under the MIT License.

