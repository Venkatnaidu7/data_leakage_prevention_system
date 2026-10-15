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
- **`app/audit/`**: Security audit log subsystem. Records authentication events, policy alterations, incident state transitions, scans, and export requests.
- **`app/api/v1/`**: RESTful API providing JSON endpoints for health, scanning, policies, incidents, and audit logs.
- **`app/dashboard/`**: Server-rendered Jinja analyst interface with CSRF tokens, accessible UI, and metrics summary.
- **`app/models/`**: SQLAlchemy models with foreign keys, indexes, and parameterized queries.

## 3. Data Flow & Security Boundaries

1. **Ingestion:** Content arrives via Web UI form or REST API. Size and MIME type are validated prior to reading file streams into memory.
2. **Analysis:** The scanning pipeline passes extracted plain text across all enabled detectors registered in the `DetectorRegistry`.
3. **Redaction:** Any sensitive match is masked before incident creation or log generation. Raw secrets are never saved in the database or written to disk.
4. **Policy Evaluation:** The policy engine checks if findings exceed rule thresholds, calculates the highest-severity action, and logs a detailed rationale.
5. **Storage & Audit:** Incidents and audit events are recorded transactionally.
