# DLP Defender: Defensive Data Leakage Prevention Platform

> **Project Status:** Active, fully tested, and operational defensive DLP application. All stated core features (detectors, policy engine, simulation mode, incident triage, security audit logging, RBAC, and versioned REST API) are implemented and verified with automated test suites.

A defensive cybersecurity and privacy engineering platform designed to identify, classify, investigate, and prevent unauthorized disclosure of sensitive data across authorized ingestion channels.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture & Data Flow](#architecture--data-flow)
- [Technology Stack](#technology-stack)
- [Prerequisites & Quickstart](#prerequisites--quickstart)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Database Migrations & Seeding](#database-migrations--seeding)
- [Running the Application](#running-the-application)
- [Docker & Containerized Deployment](#docker--containerized-deployment)
- [Testing, Quality & Security Analysis](#testing-quality--security-analysis)
- [REST API Reference (v1)](#rest-api-reference-v1)
- [Security Controls & Defensive Design](#security-controls--defensive-design)
- [Honest Limitations & Scope Boundaries](#honest-limitations--scope-boundaries)
- [Roadmap](#roadmap)
- [Contributing & License](#contributing--license)

---

## Overview

Modern organizations handle extensive volumes of sensitive information: personal identification records, customer contact details, credentials, financial transaction identifiers, and internal strategic assets. Accidental misdirection, compromised credentials, insider threats, and system misconfigurations pose significant risks of data leakage.

**DLP Defender** provides a centralized defensive platform to:
1. Scan text payloads and authorized document formats without executing arbitrary code.
2. Detect sensitive patterns using validated algorithms (such as Luhn verification for card numbers and Shannon entropy for credentials).
3. Redact and mask sensitive evidence before logging or persistence.
4. Evaluate deterministic, versioned policy rules to recommend or trigger actions (`LOG`, `WARN`, `BLOCK`, `QUARANTINE`, `ESCALATE`).
5. Facilitate incident lifecycle management and produce immutable security audit trails.

> **Important Scope Note:** A web application and file scanner alone do **not** magically intercept all enterprise communications (such as OS-level kernel network packets, encrypted HTTPS tunnels, or USB peripheral transfers). DLP Defender provides the detection engine, policy controller, incident management hub, and API integration endpoints for organizational enforcement points.

---

## Key Features

| Capability | Status | Description |
|---|---|---|
| **Pluggable Detection Registry** | :white_check_mark: Implemented | Dynamic registry supporting email, phone numbers, credit cards, credentials, jurisdiction-specific national IDs, and custom regex. |
| **Luhn Checksum Verification** | :white_check_mark: Implemented | Validates payment card numbers (Visa, Mastercard, Amex, Discover) with delimiter stripping and Luhn checksum to reduce false positives. |
| **Credential & Secret Detection** | :white_check_mark: Implemented | Identifies AWS access keys (`AKIA...`), GitHub personal access tokens (`ghp_...`), Slack tokens, private key headers, and high-entropy secret assignments. |
| **Jurisdiction-Specific IDs** | :white_check_mark: Implemented | Explicitly parameterized national ID detection (e.g., US Social Security Numbers with SSA area, group, and serial validity rules). |
| **Safe Extraction Pipeline** | :white_check_mark: Implemented | Strict MIME/extension allowlists, 10MB file limit, null-byte rejection, and binary executable magic byte rejection (`ELF`, `MZ`, `Mach-O`, `ZIP`). Uploads are never executed. |
| **Endpoint Agent & Device Lifecycle** | :white_check_mark: Implemented | Non-invasive user-space agent (Linux/Windows) with enrollment tokens, heartbeat sync, and administrator revocation controls. |
| **Filesystem & USB Observation** | :white_check_mark: Implemented | Bounded filesystem activity observer (mtime/size debouncing) and removable storage (USB) connection and transfer monitoring. |
| **Privacy-Safe Clipboard Observer** | :white_check_mark: Implemented | Opt-in clipboard copy observation (**disabled by default**), sampling short snippets and immediately discarding raw strings. |
| **Four-Tier Data Classification** | :white_check_mark: Implemented | Deterministic mapping from detector findings to `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED` sensitivity tiers. |
| **Deterministic Risk Scoring** | :white_check_mark: Implemented | Transparent 0–100 quantitative risk score (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with itemized contributing factor explanations. |
| **Offline Buffering & Event Resilience**| :white_check_mark: Implemented | Bounded local on-disk FIFO queue (`agent_queue.json`) with retry backoff, ACK pruning, and idempotency deduplication. |
| **Deterministic Policy Engine** | :white_check_mark: Implemented | Versioned policies with priority-ordered resolution, match thresholds, target detectors, and actions (`LOG`, `WARN`, `BLOCK`, `QUARANTINE`, `ESCALATE`). |
| **Dry-Run Simulation Sandbox** | :white_check_mark: Implemented | Test sensitive payloads and evaluate policy outcomes in dry-run mode without mutating incidents or generating alerts. |
| **Incident Management & Triage** | :white_check_mark: Implemented | Full lifecycle tracking (`NEW` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`), analyst assignment, investigation notes, and strictly redacted evidence viewing. |
| **Privacy-Aware Redaction** | :white_check_mark: Implemented | Mandatory redaction of all sensitive findings before database storage, application logging, or UI rendering. |
| **Role-Based Access Control (RBAC)**| :white_check_mark: Implemented | Dedicated roles: `Admin` (full configuration), `Analyst` (scanning and incident triage), and `Auditor` (read-only audit trail and compliance inspection). |
| **Security Audit Trail** | :white_check_mark: Implemented | Append-only audit log tracking authentication attempts, policy changes, scans, incident updates, and exports. |
| **Hardened REST API (v1)** | :white_check_mark: Implemented | Versioned endpoints for health, scanning, incidents, policies, audit, endpoint enrollment, heartbeats, and event ingestion. |

---

## Architecture & Data Flow

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
                      |  - Email, Phone, Credit Cards     |
                      |  - Tokens, Private Keys, US SSN   |
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

Detailed technical documentation:
- [System Architecture](file:///home/robin/Documents/DTS/docs/architecture.md)
- [STRIDE Threat Model](file:///home/robin/Documents/DTS/docs/threat-model.md)
- [Policy Engine Guide](file:///home/robin/Documents/DTS/docs/policy-guide.md)
- [REST API Reference](file:///home/robin/Documents/DTS/docs/api.md)
- [Operations & Deployment Guide](file:///home/robin/Documents/DTS/docs/operations.md)

---

## Technology Stack

- **Backend Runtime:** Python 3.12+ (Tested on Python 3.13)
- **Framework:** Flask 3.1 (Application Factory pattern with Modular Blueprints)
- **Database & ORM:** SQLAlchemy 2.0, Flask-SQLAlchemy, Alembic / Flask-Migrate
- **Authentication & Cryptography:** Argon2id (`argon2-cffi`), HttpOnly SameSite Session Cookies
- **Input Validation:** Pydantic 2.x and WTForms / Flask-WTF (CSRF Protection)
- **Security & Headers:** Flask-Limiter, strict CSP, frame-ancestors deny, X-Content-Type-Options nosniff
- **Testing & Quality:** Pytest, pytest-cov, Ruff (Linting & Formatting), Bandit (Security AST Analysis)
- **Deployment:** Dockerfile (Non-root user `dlpuser:10001`), Docker Compose, Gunicorn WSGI

---

## Prerequisites & Quickstart

### Prerequisites
- Python 3.12+ installed
- Git

### 1. Local Environment Setup

```bash
cd /home/robin/Documents/DTS

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install application and development tools
pip install -e ".[dev]"

# Configure local development environment
cp .env.example .env
```

### 2. Database Initialization & Seeding

```bash
# Run database migrations
flask --app app db upgrade

# Seed default roles, baseline policies, and initial credentials
python scripts/seed_data.py
```

### 3. Start Development Server

```bash
flask --app app run --debug
```

Access the web dashboard at `http://localhost:5000`.

### Default Seed Credentials

| Role | Username | Password | API Key |
|---|---|---|---|
| **Administrator** | `admin` | `AdminPass123!@#` | `dev_admin_api_key_12345` |
| **Security Analyst** | `analyst` | `AnalystPass123!@#` | `dev_analyst_api_key_67890` |
| **Auditor** | `auditor` | `AuditorPass123!@#` | `dev_auditor_api_key_abcde` |

> **Security Warning:** Change default passwords immediately upon deployment. Never use default development credentials in staging or production.

---

## Configuration & Environment Variables

Settings are read from `.env` or injected container environment variables:

| Variable | Default (Dev) | Production Requirement | Description |
|---|---|---|---|
| `APP_ENV` | `development` | `production` | Environment tier. In `production`, debug mode is forced off and insecure default keys fail startup. |
| `SECRET_KEY` | (dev fallback) | **Required** (>= 32 random characters) | Used for cryptographic signing of session cookies and CSRF tokens. |
| `DATABASE_URL` | `sqlite:///dlp_dev.db` | `postgresql+psycopg://...` | Connection string for application database. |
| `SESSION_COOKIE_SECURE` | `false` | `true` | Enforces HTTPS-only delivery of session cookies. |
| `SESSION_COOKIE_HTTPONLY`| `true` | `true` | Prevents JavaScript DOM access to session cookies. |
| `SESSION_COOKIE_SAMESITE`| `Lax` | `Lax` or `Strict` | Defends against Cross-Site Request Forgery (CSRF). |
| `MAX_CONTENT_LENGTH_BYTES`| `10485760` (10 MB) | Max file upload limit | Enforces payload boundaries to protect against memory exhaustion. |
| `ALLOWED_EXTENSIONS` | `txt,csv,json,xml,md,log,yaml,yml` | Allowlist | Enforced extension allowlist. Executables/scripts are rejected. |
| `RATELIMIT_DEFAULT` | `100/minute` | Rate limit tier | Protects API endpoints against brute force and DoS. |

---

## Testing, Quality & Security Analysis

All quality gates run locally and in GitHub Actions CI:

### 1. Run Unit & Integration Tests (with coverage report)
```bash
pytest --cov=app --cov-report=term-missing tests/
```

### 2. Run Ruff Linting & Formatting Check
```bash
ruff check .
ruff format --check .
```

### 3. Run Bandit AST Security Scan
```bash
bandit -r app
```

---

## Docker & Containerized Deployment

A production-ready `Dockerfile` and `compose.yaml` are provided:
- Unprivileged user execution (`dlpuser:10001`).
- Multi-container PostgreSQL setup with persistent named volume.
- Health checks configured on all services.
- Production Gunicorn WSGI server.

```bash
# Build and start services in background
docker compose up -d --build

# Inspect operational logs
docker compose logs -f dlp-web

# Validate health endpoint
curl -f http://localhost:5000/api/v1/health
```

> [!TIP]
> **Using Podman?** Full cross-platform setup instructions for Linux, Windows, and macOS with Podman & Podman Compose are available in [README_SETUP.md](file:///home/robin/Documents/DTS/README_SETUP.md).

---

## REST API Reference (v1)

Base URL: `/api/v1`

All state-changing API endpoints accept `X-API-Key` headers or active session cookies and enforce RBAC.

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/v1/health` | `GET` | Public | System status and database readiness probe. |
| `/api/v1/scan` | `POST` | Analyst, Admin | Submit text payload or multipart file for DLP inspection. |
| `/api/v1/incidents` | `GET` | All roles | List incidents with status, severity, and pagination filters. |
| `/api/v1/incidents/<id>` | `GET` | All roles | Retrieve incident details with strictly redacted evidence findings. |
| `/api/v1/incidents/<id>` | `PATCH` | Analyst, Admin | Update incident triage status, assignment, or investigation notes. |
| `/api/v1/policies` | `GET` | All roles | List configured DLP policies in priority order. |
| `/api/v1/policies` | `POST` | Admin | Create a new policy rule with threshold and detector targeting. |
| `/api/v1/policies/simulate` | `POST` | Analyst, Admin | Dry-run simulation test against text payload without saving incidents. |
| `/api/v1/audit` | `GET` | Auditor, Admin | Query immutable security audit records. |
| `/api/v1/endpoints/enroll` | `POST` | Public / Endpoint | Enroll endpoint device and issue persistent agent token. |
| `/api/v1/endpoints/heartbeat` | `POST` | Enrolled Agent | Agent heartbeat health ping and policy version synchronization. |
| `/api/v1/endpoints/events` | `POST` | Enrolled Agent | Authenticated event ingestion (file, USB, clipboard) with idempotency. |
| `/api/v1/endpoints` | `GET` | Analyst, Admin, Auditor | List enrolled endpoint inventory and device status. |
| `/api/v1/endpoints/<id>` | `GET` | Analyst, Admin, Auditor | Retrieve device detail and recent security event timeline. |
| `/api/v1/endpoints/<id>/revoke` | `POST` | Admin | Revoke endpoint device credentials and deny event ingestion. |

For detailed JSON request/response schemas, consult [docs/api.md](file:///home/robin/Documents/DTS/docs/api.md).

---

## Endpoint Agent CLI Guide

The endpoint DLP agent operates as a visible user-space background service. It is managed via `scripts/run_agent.py`:

```bash
# 1. Enroll device with central server
python scripts/run_agent.py enroll --server-url http://localhost:5000

# 2. Check device configuration and server connectivity status
python scripts/run_agent.py status

# 3. Start background monitoring daemon
python scripts/run_agent.py run

# 4. (Optional) Run with opt-in clipboard monitoring explicitly enabled
python scripts/run_agent.py run --enable-clipboard

# 5. Submit synthetic diagnostic test event
python scripts/run_agent.py test-event --type usb --sensitive
```

Detailed operator instructions, architecture, and offline buffering details are in [docs/endpoint-agent-guide.md](file:///home/robin/Documents/DTS/docs/endpoint-agent-guide.md).

---

## Security Controls & Defensive Design

1. **Argon2id Password Storage:** Modern memory-hard hashing resistant to GPU cracking.
2. **Session Security & Fixation Defense:** Full session regeneration (`session.clear()`) upon login; cookies configured with `HttpOnly`, `SameSite=Lax`, and `Secure` (production).
3. **Open Redirect Defense:** Login redirect parameter `next` is validated against the request host before redirection.
4. **Data Minimization & Redaction:** Sensitive findings are masked immediately at the detector layer. Raw cards, passwords, and tokens are never stored in the database or written to log files.
5. **Executable Rejection & Path Traversal Prevention:** Upload filenames are normalized with `os.path.basename` and verified against directory traversal patterns (`..`). Binary magic headers (`ELF`, `PE`, `Mach-O`, `ZIP`) are blocked.
6. **Append-Only Audit Trail:** Administrative operations, policy edits, authentication attempts, and incident updates are recorded with user attribution, timestamp, and client IP address.
7. **Offline Queue Resilience:** The agent stores pending events in a local bounded FIFO queue (`agent_queue.json`) with retry backoff and ACK pruning, tolerating temporary network outages without data loss.

---

## Honest Limitations & Enforcement Truthfulness

Defensive security requires transparent self-assessment. The table below explicitly distinguishes what is **detected**, **alerted**, **simulated**, and **actually blocked**:

| Capability | Category | Reality / Enforcement Boundary |
|---|---|---|
| **Payment Cards (Luhn), PII, Secrets, SSN** | **Detected** | High-precision regex and checksum validators run locally on agent and central server. |
| **High-Risk Channel Transfers (USB / Removable)** | **Alerted** | Automatically generates triage incidents with masked evidence in dashboard. |
| **Dry-Run Evaluation Sandbox** | **Simulated** | Full pipeline evaluation returning proposed action without saving incidents. |
| **Invalid/Malicious Server File Uploads** | **Actually Blocked** | Executable binaries (`ELF`, `PE`, `Mach-O`, `ZIP`), path traversal, and >10MB files are rejected with HTTP 400. |
| **Endpoint File / USB Transfers** | **Not Enforced (Audit Only)** | Because the agent runs strictly in user space without kernel filter drivers, policy decisions of `BLOCK` are honestly reported as `NOT_ENFORCED` at the OS level while recording an auditable security finding. |

### Operational Boundaries:
1. **Inspection Scope:** Plain text, CSV, JSON, Markdown, XML, and log files are inspected. Encrypted archives (`.zip`, `.7z`), proprietary binary blobs, and images with embedded steganography are rejected or not parsed.
2. **User-Space Limitations:** The endpoint agent does not install kernel hooks or rootkits. An authorized local administrator can terminate the agent process; missing heartbeats alert central analysts.
3. **Audit Immutability at Enterprise Scale:** While the application audit table is append-only at the ORM layer, raw database administrator access could alter rows. Enterprise deployments should mirror audit records to WORM storage or a dedicated SIEM.


---

## Roadmap

1. **Phase 1 (Complete):** Core architecture, detector registry, Luhn check, policy engine, simulation sandbox, RBAC, incident triage, security audit logging, REST API, test suite, and containerization.
2. **Phase 2 (Planned):** Webhook integrations for Slack / PagerDuty alert escalation when `CRITICAL` policies trigger.
3. **Phase 3 (Planned):** Support for optical character recognition (OCR) sandbox worker for scanned PDFs and image attachments.
4. **Phase 4 (Planned):** SIEM log streaming integration (Syslog RFC 5424 / OpenTelemetry export).

---

## Contributing & License

Contributions are welcome! Please review [CONTRIBUTING.md](file:///home/robin/Documents/DTS/CONTRIBUTING.md) and [SECURITY.md](file:///home/robin/Documents/DTS/SECURITY.md) before opening pull requests or reporting security vulnerabilities.

Licensed under the [Apache License, Version 2.0](file:///home/robin/Documents/DTS/LICENSE).
