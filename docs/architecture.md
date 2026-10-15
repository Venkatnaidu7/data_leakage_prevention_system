# DLP System Architecture

## 1. System Overview

The Data Leakage Prevention (DLP) system is designed as a modular, defensive cybersecurity platform. It provides automated detection of sensitive data, policy evaluation, security incident triage, and auditable event tracking.

```
                      +-----------------------------------+
                      |      Web UI / REST API Clients    |
                      +-----------------+-----------------+
                                        | (HTTPS / CSRF)
                                        v
                      +-----------------+-----------------+
                      |     Security & Ingestion Layer    |
                      |  - Session / Auth & RBAC          |
                      |  - Rate Limiter (Flask-Limiter)   |
                      |  - Safe File Upload & Validation  |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |       Scanning Pipeline           |
                      |  - Mime / Ext / Size Allowlist    |
                      |  - Safe Memory Extraction         |
                      |  - Non-executable Sandbox Parse   |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |       Detection Registry          |
                      |  - Email Detector                 |
                      |  - Phone Number Detector          |
                      |  - Credit Card (Luhn) Detector    |
                      |  - Secrets & Tokens Detector      |
                      |  - National ID (SSN, etc.)        |
                      |  - Custom Organization Regex      |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |       Redaction Layer             |
                      |  - Safe Masking (e.g. ****-1234)  |
                      |  - Evidence Minimization Engine   |
                      +-----------------+-----------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |       Policy Engine               |
                      |  - Versioned Priority Rules       |
                      |  - Actions: LOG/WARN/BLOCK/       |
                      |            QUARANTINE/ESCALATE    |
                      |  - Dry-Run / Simulation Mode      |
                      +-----------------+-----------------+
                                        |
                         +--------------+--------------+
                         |                             |
                         v                             v
       +-----------------+----------------+   +--------+----------------+
       |       Incident Management        |   |    Audit Log Service    |
       |  - Lifecycle (New -> Resolved)   |   |  - Append-Only Records  |
       |  - Redacted Evidence Vault       |   |  - Administrative Trail |
       +-----------------+----------------+   +--------+----------------+
                         |                             |
                         +--------------+--------------+
                                        |
                                        v
                      +-----------------+-----------------+
                      |     Database (PostgreSQL / SQLite)|
                      +-----------------------------------+
```

## 2. Core Modules and Responsibilities

- **`app/`**: Application factory (`create_app`), configuration loading, extension management, security headers, global error handlers.
- **`app/auth/`**: Authentication routes and services: Argon2id password hashing, secure session management, role-based access control (RBAC: Admin, Analyst, Auditor).
- **`app/detection/`**: Pluggable detector registry. Every detector implements `BaseDetector` with confidence scoring, match validation (e.g., Luhn checksum for credit cards), and safe redaction.
- **`app/scanning/`**: Safe content and file scanner. Enforces size limits (`MAX_CONTENT_LENGTH`), extension allowlists, UTF-8/safe text decode without running or executing macros or shell binaries.
- **`app/policies/`**: Deterministic policy evaluation engine. Evaluates findings against priority-ordered rules, handles simulation mode, and outputs actionable decisions (`LOG`, `WARN`, `BLOCK`, `QUARANTINE`, `ESCALATE`).
- **`app/incidents/`**: Incident triage lifecycle (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`). Captures severity, detector findings, redacted snippets, and analyst notes.
- **`agent/`**: Endpoint monitoring agent package. Contains observer implementations (`FileObserver`, `RemovableMediaObserver`, `ClipboardObserver`), on-disk queue (`EventQueue`), authenticated HTTP/HTTPS client (`AgentClient`), and service supervisor (`AgentService`).
- **`app/detection/classification.py`**: Four-tier data classification engine (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`) resolving findings to the highest sensitivity level.
- **`app/policies/risk.py`**: Deterministic risk scoring engine (0-100 scale, LOW/MEDIUM/HIGH/CRITICAL bands) providing transparent explanations of risk factors.
- **`app/api/v1/endpoints_api.py`**: Authenticated REST API for endpoint enrollment, heartbeats, event ingestion, and device inventory.
- **`app/endpoints/`**: Web UI routes and views for endpoint device inventory, device detail, and security event explorer.
- **`app/models/endpoint.py`**: Database entities for enrolled endpoints (`EndpointDevice`) and immutable security events (`EndpointEvent`).
- **`scripts/run_agent.py`**: Cross-platform command-line launcher for endpoint agent lifecycle (`enroll`, `status`, `run`, `test-event`).

## 3. Three-Tier Architectural Model

The system organizes into three distinct, cooperating layers:

```
+-------------------------------------------------------------------------+
|                           1. ENDPOINT LAYER                             |
|  - Visible, non-invasive user-space agent (Linux / Windows)             |
|  - Observers: Filesystem, Removable Storage (USB), Opt-in Clipboard     |
|  - Local durable queue (agent_queue.json) with FIFO bounded storage     |
|  - Authenticated API client (X-Device-ID / X-Device-Token)              |
+------------------------------------+------------------------------------+
                                     | (HTTPS / REST v1)
                                     v
+-------------------------------------------------------------------------+
|                      2. SECURITY PLATFORM LAYER                         |
|  - Agent Authentication & Device Revocation Enforcement                 |
|  - Idempotent Event Ingestion & Deduplication                           |
|  - Pluggable Detectors (PCI Cards, SSN, Secrets, PII, Custom Regex)    |
|  - Four-tier Data Classification Engine                                 |
|  - Deterministic Policy Engine (ALLOW, ALERT, BLOCK, NOT_ENFORCED)       |
|  - Quantitative 0-100 Risk Engine (LOW, MEDIUM, HIGH, CRITICAL)         |
|  - Redacted Evidence Vault & Triage Incidents Subsystem                 |
|  - Immutable, Append-Only Audit Trail                                   |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                         3. MANAGEMENT LAYER                             |
|  - Web Management Dashboard (Jinja2, CSP, CSRF, Session Fixation Defense)|
|  - Endpoint Device Inventory & Health Monitoring                        |
|  - Event Explorer with Multi-Dimensional Filtering                      |
|  - Incident Investigation, Triage & Resolution Workflow                 |
|  - Policy Rule Editor & Dry-Run Simulation Sandbox                      |
|  - Compliance Audit Log Viewer & Metadata Export                        |
+-------------------------------------------------------------------------+
```

## 4. End-to-End Event Ingestion Flow

1. **Observation:** Agent observers detect a filesystem modification, USB mount/copy, or clipboard copy.
2. **Buffering:** The event is queued locally on disk (`agent_queue.json`).
3. **Transmission:** The agent submits the event to `POST /api/v1/endpoints/events` using device credentials.
4. **Authentication & Idempotency:** The server validates `X-Device-ID` and token, checks device revocation status, and returns existing decisions for duplicated `event_id` submissions.
5. **Detection & Classification:** Content is inspected by enabled detectors; findings are classified into `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED`.
6. **Policy Evaluation & Risk Scoring:** Priority rules determine action (`ALLOW`, `ALERT`, `BLOCK`), and the risk engine computes a 0-100 score with explanatory factors.
7. **Incident Creation & Audit:** High-risk actions automatically generate triage incidents with masked snippets; the immutable audit log captures the event.

