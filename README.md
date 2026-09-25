<div align="center">

<img src="https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.13"/>
<img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
<img src="https://img.shields.io/badge/Open_Policy_Agent-8181-7D9199?style=for-the-badge&logo=openpolicyagent&logoColor=white" alt="OPA"/>
<img src="https://img.shields.io/badge/TLS-1.2-4B8BBE?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="TLS 1.2"/>

<br/>

<img src="https://img.shields.io/badge/RSA--2048-Encryption-6E4AFF?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="RSA-2048"/>
<img src="https://img.shields.io/badge/AES--256--GCM-Hybrid-00A86B?style=for-the-badge&logo=openssl&logoColor=white" alt="AES-GCM"/>
<img src="https://img.shields.io/badge/JWT-Auth-D63AFF?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT"/>
<img src="https://img.shields.io/badge/mTLS-Enforced-FF6B35?style=for-the-badge&logo=cloudflare&logoColor=white" alt="mTLS"/>

<br/>

<img src="https://img.shields.io/badge/Redis-Pub%2FSub-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis"/>
<img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/>
<img src="https://img.shields.io/badge/Zero_Trust-Architecture-1F4E79?style=for-the-badge&logo=shield&logoColor=white" alt="ZTA"/>

<br/><br/>

<h1> Zero Trust Architecture</h1>
<h3>Bangladesh Government Document Classification System</h3>

<p><b>Framework: Gateway-Centric Implementation</b></p>

<img src="https://img.shields.io/badge/Bachelor's_Thesis-BRAC_University-8B0000?style=for-the-badge" alt="Thesis"/>
<img src="https://img.shields.io/badge/Status-Research_Prototype-yellow?style=for-the-badge" alt="Status"/>

</div>

---

## Overview

A research prototype implementing **Zero Trust Architecture (ZTA)** principles for a secure government document classification system. This framework adopts a **Gateway-Centric model** where all traffic flows through a single hardened entry point with end-to-end encryption, mutual TLS, and policy-as-code enforcement.

This is the **first of three comparative frameworks** developed for a Bachelor's thesis at BRAC University, demonstrating identity-centric security as a proof-of-concept for modern government security frameworks.

> **Research Prototype Only** (This system is designed for academic demonstration. Not intended for production without comprehensive security review)

---

## Core Security Features

### Authentication & Identity

| Feature                    | Implementation                                                      |
| -------------------------- | ------------------------------------------------------------------- |
| **JWT Authentication**     | RS256-signed tokens with 8-hour expiry, department/clearance claims |
| **Multi-Factor Auth**      | JWT + mTLS certificate + Service Token (3 factors)                  |
| **Clearance Hierarchy**    | `BASIC → CONFIDENTIAL → SECRET → TOP_SECRET`                        |
| **Department Isolation**   | MOD, MOF, NSA with strict cross-department denial                   |
| **Certificate Management** | Automated RSA-2048 key generation per user at first login           |

### Policy-Based Authorization

- **Open Policy Agent (OPA)** as externalized Policy Decision Point
- **Time-based restrictions** TOP_SECRET accessible only 08:00–16:00 (Bangladesh Time)
- **Department matching** enforced for all non-PUBLIC resources
- **Context-aware decisions** user context, resource classification, environment
- **Fail-secure by default** OPA Agent denies access if OPA Server unreachable
- **Complete audit trail** with policy decision rationale

### Encryption & Data Protection

- **End-to-end RSA-2048 encryption** via dedicated OPA Agent
- **Hybrid encryption** (RSA-OAEP-SHA256 + AES-256-GCM) for large payloads
- **Browser-side cryptography** using Web Crypto API
- **Client-side private key storage** in IndexedDB (never transmitted)
- **Encrypted response delivery** plaintext never leaves the OPA Agent

### Monitoring & Audit

- **Real-time event streaming** via Redis Pub/Sub
- **WebSocket-based dashboard** for live security monitoring
- **Complete request tracing** across all 5 services via `X-Request-ID`
- **Security event classification** (INFO/MEDIUM/HIGH/CRITICAL)
- **Policy decision visibility** ALLOW/DENY with reasons in real-time

---

## System Architecture

The prototype implements a **five-layer microservices architecture**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          BROWSER (Client)                           │
│              Web Crypto API · IndexedDB · RSA Private Key           │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTPS + Encrypted Payload
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [1] GATEWAY SERVER  :5000     mTLS + JWT + Service Token           │
│      Entry point · Authentication · Request routing                 │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTPS + Service Token
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [2] OPA AGENT  :8282     PEP + Encryption/Decryption               │
│      Decrypts request · Encrypts response · Holds master keys       │
└──────┬────────────────────────────────────────────┬─────────────────┘
       │ HTTPS + Service Token                      │ HTTPS + Service Token
       ▼                                            ▼
┌──────────────────────────┐              ┌──────────────────────────┐
│  [3] OPA SERVER  :8181   │              │  [4] API SERVER  :5001   │
│      PDP · Rego policies │              │      Business logic      │
│      Clearance · Dept    │              │      SQLite database     │
│      Time-based rules    │              │      Documents · Users   │
└──────────────────────────┘              └──────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  [5] DASHBOARD  :5002       Redis Pub/Sub + WebSocket               │
│      Real-time security event monitoring                            │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer                 | Component                              | Function                                                  |
| --------------------- | -------------------------------------- | --------------------------------------------------------- |
| **1. Transport**      | All services                           | HTTPS/TLS 1.2, mTLS for service-to-service                |
| **2. Authentication** | Gateway (:5000)                        | JWT validation, mTLS termination, service token injection |
| **3. Authorization**  | OPA Server (:8181) + OPA Agent (:8282) | Policy decisions + encryption enforcement                 |
| **4. Data**           | API Server (:5001)                     | Business logic, database operations                       |
| **5. Monitoring**     | Dashboard (:5002)                      | Real-time event streaming, audit visibility               |

---

## Research Objectives Demonstrated

| #   | Objective                       | How It's Demonstrated                                           |
| --- | ------------------------------- | --------------------------------------------------------------- |
| 1   | **Identity-Centric Security**   | Access decisions based on identity claims, not network location |
| 2   | **Automated Policy Management** | Rego policies evaluated for every request; no hardcoded rules   |
| 3   | **Minimal User Friction**       | Automated cert generation; users only enter password            |
| 4   | **Comprehensive Monitoring**    | Every ALLOW/DENY visible in real-time dashboard                 |
| 5   | **Encryption Everywhere**       | Data encrypted in transit AND end-to-end to user                |
| 6   | **Fail-Secure Design**          | No fallbacks if OPA Agent fails, access is denied               |
| 7   | **Scalable Microservices**      | Each service independently deployable and testable              |

---

## Attack Simulation Results

Framework 1 was stress-tested against four attack simulations:

| Attack Simulation         | Result                   | Score            |
| ------------------------- | ------------------------ | ---------------- |
| **JWT Manipulation**      | All 6 attacks blocked    | 0% vulnerability |
| **Zero Trust Compliance** | Multi-factor + isolation | 92%+ compliance  |
| **Policy Engine**         | Full PDP/PEP separation  | 84.5/100         |
| **Transport Security**    | TLS 1.2 enforced         | 91.2/100         |
| **Weighted Final Score**  | **Exceptional Security** | **93.5/100**     |

### Key Attack Results

- **JWT forging** — blocked (all alg confusion attacks failed)
- **Clearance escalation** — blocked (signed claims verified)
- **Department bypass** — blocked (OPA policy enforcement)
- **Expired token replay** — blocked (exp validation)
- **Algorithm confusion** — blocked (`alg: none` rejected)
- **Self-signed cert injection** — blocked (mTLS validation)

---

## Technology Stack

<table>
<tr>
<td valign="top" width="50%">

**Backend**

- Python 3.13
- Flask 3.x
- SQLAlchemy ORM
- SQLite database

**Security**

- `cryptography` (RSA-2048, AES-256-GCM)
- `PyJWT` (RS256 signing)
- Open Policy Agent (OPA + Rego)
- mTLS with custom CA

</td>
<td valign="top" width="50%">

**Real-time**

- Redis Pub/Sub
- WebSocket (Flask-SocketIO)

**Frontend**

- HTML5 + Bootstrap 5
- JavaScript (Web Crypto API)
- IndexedDB for key storage

**Infrastructure**

- Custom Root CA (Bangladesh Government)
- TLS 1.2 (Python 3.13 SSL patch)

</td>
</tr>
</table>

---

## Project Structure

```
ZTA-Thesis/
├── app/
│   ├── api/              # API endpoints (documents, users, logs)
│   ├── auth/             # JWT authentication
│   ├── audit/            # Real-time dashboard routes
│   ├── logs/             # Event logging + Redis streaming
│   ├── middleware/       # Request context collection
│   ├── models/           # SQLAlchemy models (User, Document, Keys)
│   ├── mTLS/             # Certificate manager + middleware
│   ├── opa_agent/        # OPA Agent client + crypto handler
│   ├── policy/           # Rego policies + OPA client
│   ├── services/         # Service communicator + risk scorer
│   ├── static/           # JS/CSS assets
│   └── templates/        # Jinja2 HTML templates
├── certs/                # CA, server, client certificates
│   ├── opa_agent/        # OPA Agent RSA keys
│   ├── user_keys/        # Per-user RSA keypairs
│   ├── clients/          # Client certificates
│   └── services/         # Service certificates
├── instance/
│   └── government_zta.db # SQLite database
├── gateway_server.py     # Port 5000 — Entry point
├── api_server.py         # Port 5001 — Business logic
├── opa_agent_server.py   # Port 8282 — Encryption + PEP
├── run_opa_server.py     # Port 8181 — Policy decisions
└── dashboard_server.py   # Port 5002 — Monitoring
```

---

## Getting Started

### Prerequisites

```bash
Python 3.13+
Redis Server (for event streaming)
```

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/zta-thesis-framework1-gateway-centric.git
cd zta-thesis-framework1-gateway-centric

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt

# Generate certificates (first time only)
python create_certificates.py

# Initialize database
python setup_database.py
```

### Running the Services

```bash
# Terminal 1 — OPA Policy Server
python run_opa_server.py

# Terminal 2 — API Server
python api_server.py

# Terminal 3 — OPA Agent
python opa_agent_server.py

# Terminal 4 — Gateway
python gateway_server.py

# Terminal 5 — Dashboard (optional)
python dashboard_server.py
```

Access the system at: `https://localhost:5000`
Dashboard at: `https://localhost:5002`

### Test Credentials

```
Username: testuser
Password: Test@123
Department: MOD
Clearance: SECRET
```

---

## Security Disclaimer

**Academic Research Prototype**

This system was developed as part of Bachelor's thesis research. While it implements many production-grade security patterns, please note:

- Cryptographic implementations are for **research demonstration**
- **Self-signed certificates** are used (production requires CA-signed certs)
- **Certificate revocation (CRL)** is not fully implemented
- Some services run with **debug mode** enabled for development
- Security implementations should be **reviewed by professionals** before adaptation
- Not all production edge cases are covered

**Do not deploy this system in a production environment** without comprehensive security audit and hardening.

---

## Academic Context

This prototype was developed as part of a Bachelor's thesis at **BRAC University** Department of Computer Science and Engineering.

### Thesis Research Areas

- **Practical implementation challenges** of Zero Trust Architecture
- **Balance between security strength and user experience**
- **Automated policy management** in dynamic environments
- **Real-time monitoring** requirements for continuous verification
- **Comparative analysis** across three architectural frameworks

---

## References & Standards

- **NIST SP 800-207** — Zero Trust Architecture
- **NIST SP 800-53** — Security and Privacy Controls
- **OWASP Top 10** — Web Application Security
- **Open Policy Agent** — Policy-as-Code Documentation
- **RFC 7519** — JSON Web Token (JWT)
- **RFC 5280** — X.509 Public Key Infrastructure

---

## License

This research prototype is shared for **academic discussion and research purposes only**. All implementations are for demonstration and should not be used in production systems without comprehensive security review.

---

<div align="center">

**Developed as part of Bachelor's Thesis Research**

**BRAC University · Department of Computer Science and Engineering**

<br/>

<img src="https://img.shields.io/badge/Made_with-Python_3.13-blue?style=for-the-badge&logo=python" alt="Python"/>
<img src="https://img.shields.io/badge/Secured_by-Zero_Trust-1F4E79?style=for-the-badge&logo=shield" alt="ZTA"/>

<br/><br/>

_"Never trust, always verify."_

</div>
