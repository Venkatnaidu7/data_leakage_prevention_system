# DLP Defender: Beginner-Friendly Operating & Administrator Guide

**Defensive Data Leakage Prevention Platform**  
*Operating on Parrot OS Linux with Rootless Podman, PostgreSQL, and Endpoint Monitoring*

---

## Table of Contents

1. [Project Overview](#1-project-overview)
   - [What is DLP Defender and Why Is It Useful?](#what-is-dlp-defender-and-why-is-it-useful)
   - [System Architecture & Components](#system-architecture--components)
   - [How the Components Work Together](#how-the-components-work-together)
   - [Implemented Features vs. Scope Boundaries & Planned Features](#implemented-features-vs-scope-boundaries--planned-features)
2. [First-Time Setup](#2-first-time-setup)
   - [Prerequisites & Required Software](#prerequisites--required-software)
   - [Navigating to the Project Directory](#navigating-to-the-project-directory)
   - [Configuring Environment Variables Safely (`.env`)](#configuring-environment-variables-safely-env)
   - [Building and Launching the Containers](#building-and-launching-the-containers)
   - [Database Migrations & Initial Data Seeding](#database-migrations--initial-data-seeding)
   - [Step-by-Step Setup Verification](#step-by-step-setup-verification)
3. [Daily Server Operations](#3-daily-server-operations)
   - [Starting Existing Stopped Containers](#starting-existing-stopped-containers)
   - [Starting When Containers Do Not Exist](#starting-when-containers-do-not-exist)
   - [Checking Container Health & Status](#checking-container-health--status)
   - [Accessing the Web Dashboard & Accounts](#accessing-the-web-dashboard--accounts)
   - [Viewing Real-Time Application & Database Logs](#viewing-real-time-application--database-logs)
   - [Restarting Services Safely](#restarting-services-safely)
   - [Stopping Services Without Data Loss](#stopping-services-without-data-loss)
   - [Starting Again After System Reboot](#starting-again-after-system-reboot)
   - [Endpoint Agent Lifecycle: Check, Start, Stop](#endpoint-agent-lifecycle-check-start-stop)
   - [Understanding Podman Lifecycle Commands: `start` vs `up -d` vs `stop` vs `down`](#understanding-podman-lifecycle-commands)
4. [Comprehensive Troubleshooting Guide](#4-comprehensive-troubleshooting-guide)
   - [Diagnostic Command Toolkit](#diagnostic-command-toolkit)
   - [Master Troubleshooting Reference Table](#master-troubleshooting-reference-table)
   - [Deep Dive: Resolving Port 5432 Conflicts on Parrot OS (Host PostgreSQL / Metasploit)](#deep-dive-resolving-port-5432-conflicts-on-parrot-os)
   - [Deep Dive: Resolving Container Startup & Rootless Networking Failures](#deep-dive-resolving-container-startup--rootless-networking-failures)
5. [Database and Data Safety Manual](#5-database-and-data-safety-manual)
   - [Commands That Preserve Data vs. Commands That Destroy Data](#commands-that-preserve-data-vs-commands-that-destroy-data)
   - [Critical Warning: The Danger of `podman compose down -v`](#critical-warning-the-danger-of-podman-compose-down--v)
   - [Non-Destructive Troubleshooting Golden Rule](#non-destructive-troubleshooting-golden-rule)
   - [How to Back Up the Database](#how-to-back-up-the-database)
   - [Verifying Backup Integrity Before Maintenance](#verifying-backup-integrity-before-maintenance)
   - [Restoring the Database from a Backup File](#restoring-the-database-from-a-backup-file)
6. [Endpoint Agent Administrator & Operator Guide](#6-endpoint-agent-administrator--operator-guide)
   - [Agent Purpose & Architecture](#agent-purpose--architecture)
   - [How the Agent Communicates with the Server](#how-the-agent-communicates-with-the-server)
   - [Device Enrollment](#device-enrollment)
   - [Checking Agent Status & Health](#checking-agent-status--health)
   - [Running the Monitoring Daemon](#running-the-monitoring-daemon)
   - [Simulating Synthetic Test Events](#simulating-synthetic-test-events)
   - [Privacy-Safe Clipboard Observer: Design & Guarantees](#privacy-safe-clipboard-observer-design--guarantees)
   - [Local Offline Event Queue & Resilience](#local-offline-event-queue--resilience)
   - [Agent Troubleshooting & Common Errors](#agent-troubleshooting--common-errors)
7. [Security Best Practices & Hardening](#7-security-best-practices--hardening)
   - [Protecting Environment Files & File Permissions](#protecting-environment-files--file-permissions)
   - [Generating Cryptographically Secure Production Keys](#generating-cryptographically-secure-production-keys)
   - [API Key Security & Separation of Roles (RBAC)](#api-key-security--separation-of-roles-rbac)
   - [Audit Trail Integrity & Log Sanitization](#audit-trail-integrity--log-sanitization)
   - [Network Exposure & Local Interface Binding](#network-exposure--local-interface-binding)
8. [Testing and Verification Checklist](#8-testing-and-verification-checklist)
   - [7-Point Verification Matrix](#7-point-verification-matrix)
   - [Verification Commands & Expected Responses](#verification-commands--expected-responses)
9. [Quick-Reference Command Sheet](#9-quick-reference-command-sheet)
   - [Compact Day-to-Day Operations Table](#compact-day-to-day-operations-table)
10. [Beginner Glossary & Concept Guide](#10-beginner-glossary--concept-guide)

---

## 1. Project Overview

### What is DLP Defender and Why Is It Useful?

**Data Leakage Prevention (DLP)** is a cybersecurity discipline focused on detecting and stopping sensitive corporate, customer, or regulatory information from leaving an organization's safe boundaries.

Modern organizations handle huge volumes of sensitive information:
- **Payment Card Data (PCI-DSS):** Visa, MasterCard, American Express, and Discover account numbers.
- **Personally Identifiable Information (PII):** Employee/customer email addresses, phone numbers, and Social Security Numbers (SSN).
- **Security Credentials & Secrets:** Cloud provider access keys (e.g., AWS `AKIA...`), GitHub developer personal tokens (`ghp_...`), Slack webhooks, and cryptographic private keys (`BEGIN RSA PRIVATE KEY`).

If an employee accidentally emails a file containing credit card numbers, copies customer records to an unencrypted personal USB thumb drive, or pastes cloud secrets into public channels, severe regulatory fines, financial loss, and breach of customer trust occur.

**DLP Defender** is an enterprise-grade, defensive cybersecurity platform designed to:
1. **Inspect data streams** across authorized ingestion channels (manual file uploads, text scans, endpoint file modifications, USB transfers, and clipboard operations).
2. **Identify sensitive patterns** with high algorithmic precision using verified algorithms (such as the Luhn algorithm for payment cards and Shannon entropy analysis for cryptographic secrets) to prevent false alerts.
3. **Classify information** into four standardized data sensitivity tiers (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
4. **Calculate a deterministic quantitative risk score** (0 to 100) based on data classification, channel risk (e.g., USB removable drive vs. internal system), and sensitive match volume.
5. **Evaluate deterministic security policies** to recommend or trigger actions: `LOG`, `WARN`, `BLOCK`, `QUARANTINE`, or `ESCALATE`.
6. **Redact and mask sensitive evidence** before storing records so that analysts can investigate incidents without exposing raw credit card numbers or private credentials.
7. **Provide tamper-evident audit trails and Role-Based Access Control (RBAC)** to ensure full compliance with standards like GDPR, PCI-DSS, and HIPAA.

---

### System Architecture & Components

DLP Defender is built with a modular, defensive architecture consisting of three core tiers:

```
+-------------------------------------------------------------------------+
|                         ENDPOINT LAYER (Client Machine)                 |
|                                                                         |
|  [Filesystem Observer]    [USB / Removable Media]    [Clipboard Observer] |
|            \                        |                        /          |
|             +-----------------------+-----------------------+           |
|                                     |                                   |
|                          [Local FIFO Queue: agent_queue.json]           |
|                                     | (Store-and-forward)               |
|                           [Agent Client HTTP REST]                      |
+-------------------------------------|-----------------------------------+
                                      | HTTP POST (X-Device-ID / Token)
                                      v
+-------------------------------------------------------------------------+
|                  CENTRAL SERVER LAYER (Podman Container)                |
|                                                                         |
|  Container: dlp-web-app  (Port 5000)                                    |
|  Engine: Flask 3.1 / Gunicorn WSGI Server                                |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Web Dashboards & UI (/dashboard, /incidents, /policies, /audit)   |  |
|  | REST API v1 (/api/v1/health, /scans, /incidents, /endpoints)      |  |
|  +-------------------------------------------------------------------+  |
|  | Security Pipeline:                                                |  |
|  |   1. Safe Extraction & MIME/Magic Byte Validator                  |  |
|  |   2. Detection Registry (Luhn, Shannon Entropy, Regex, SSN)       |  |
|  |   3. 4-Tier Classification Engine (PUBLIC -> RESTRICTED)          |  |
|  |   4. Deterministic Risk Engine (0-100 Score & Contributing Factors) |
|  |   5. Policy Engine (Priority Ordered: BLOCK, QUARANTINE, etc.)    |  |
|  |   6. Redaction Utility (Masks values before persisting)           |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------|-----------------------------------+
                                      | PostgreSQL Protocol (Port 5432)
                                      v
+-------------------------------------------------------------------------+
|                    PERSISTENCE LAYER (Podman Container)                 |
|                                                                         |
|  Container: dlp-postgres-db  (Port 5432)                                |
|  Database Engine: PostgreSQL 16 Alpine                                  |
|  Persistent Volume: postgres_data -> /var/lib/postgresql/data           |
|                                                                         |
|  Tables: users, policies, incidents, incident_findings,                 |
|          endpoint_devices, endpoint_events, audit_logs                  |
+-------------------------------------------------------------------------+
```

#### 1. Central Web Application (`dlp-web-app` / Service `dlp-web`)
* **Technology**: Python 3.13, Flask 3.1, Gunicorn WSGI server, SQLAlchemy 2.0.
* **Port**: Bound to host port `5000` (`http://localhost:5000`).
* **Purpose**:
  - Hosts the responsive Security Operations Center (SOC) web portal.
  - Exposes the versioned REST API (`/api/v1/...`).
  - Executes data extraction, pattern detection, risk scoring, and policy evaluation.
  - Enforces Role-Based Access Control (`Admin`, `Analyst`, `Auditor`).
  - Records append-only, sanitized audit logs for every system action.

#### 2. Relational Database (`dlp-postgres-db` / Service `dlp-db`)
* **Technology**: PostgreSQL 16 Alpine.
* **Port**: Internal container port `5432` (mapped to host port `5432`).
* **Storage**: Persistent named volume named `postgres_data` mapped to `/var/lib/postgresql/data`.
* **Purpose**:
  - Provides ACID-compliant, persistent storage for user accounts, DLP policies, security incidents, redacted findings, enrolled endpoint devices, raw endpoint event telemetry, and immutable audit logs.
  - Data remains safe inside `postgres_data` even when containers are stopped or recreated.

#### 3. Endpoint Monitoring Agent (`agent/` and `scripts/run_agent.py`)
* **Technology**: Lightweight Python process running directly on client machines (Parrot OS Linux or Windows).
* **Purpose**:
  - Observes user-space activity locally on client machines.
  - **File Observer**: Monitors assigned directories (such as `~/Documents/DTS/monitored_data`) for newly written or modified files, debouncing rapid file writes.
  - **Removable Media Observer**: Watches mount points (`/media`, `/run/media`, `/mnt`) to detect external USB flash drives and files copied to them.
  - **Clipboard Observer**: Privacy-preserving observer that is **strictly disabled by default**. When explicitly enabled, it samples short snippets, hashes contents, and immediately discards raw clipboard text.
  - **Offline Resilience Queue (`agent_queue.json`)**: If network connectivity to the central server is interrupted, the agent stores events in a bounded local FIFO queue and flushes them automatically with exponential backoff once the server is back online.

---

### How the Components Work Together

1. **Device Enrollment**:
   The endpoint agent runs `python scripts/run_agent.py enroll --server-url http://localhost:5000`. The server creates an `EndpointDevice` entry, returns a unique Device ID and authentication token, and saves them locally in `agent_config.json`.
2. **Heartbeat Synchronization**:
   Every 30 seconds, the agent issues an HTTP POST to `/api/v1/endpoints/heartbeat` with headers `X-Device-ID` and `X-Device-Token`. The server updates the device's `last_seen_utc` timestamp and verifies that the device is in `ACTIVE` status.
3. **Telemetry Ingestion**:
   When an observer detects an event (e.g., a file written to a USB mount), it packages a metadata payload and sends an HTTP POST to `/api/v1/endpoints/events`.
4. **Server Analysis & Policy Enforcement**:
   - The server authenticates the agent request.
   - The **Detection Registry** scans the content for sensitive patterns (credit cards, secrets, SSNs, emails, phones).
   - The **Classification Engine** tags the data (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED`).
   - The **Risk Engine** computes a 0–100 risk score based on sensitivity tier, match count, and channel risk factor.
   - The **Policy Engine** evaluates active policies in priority order. If a policy matches, the assigned action (`BLOCK`, `WARN`, `QUARANTINE`, `LOG`, `ESCALATE`) is selected.
   - The finding values are **redacted** (e.g. `4532-****-****-5671`).
   - If policy matches dictate an alert, an **Incident** record is created with redacted findings.
   - An HTTP 201 response containing the decision and risk breakdown is returned to the agent.
5. **Analyst Investigation**:
   Security analysts open `http://localhost:5000/incidents` in their browser, review the incident, inspect the redacted evidence, assign the incident, and update the status (`INVESTIGATING`, `CONFIRMED_LEAK`, `FALSE_POSITIVE`, `RESOLVED`).

---

### Implemented Features vs. Scope Boundaries & Planned Features

To maintain strict cybersecurity honesty, the table below documents what is completely implemented versus what is out of scope or planned for future iterations:

| Feature / Capability | Implementation Status | Technical Details in Codebase |
| :--- | :---: | :--- |
| **Luhn Credit Card Verification** | **Implemented** | Full checksum validation for Visa, Mastercard, Amex, and Discover (`app/detection/credit_card.py`). |
| **API Secret & Key Detection** | **Implemented** | Detects AWS access keys, GitHub PATs, Slack tokens, RSA private keys, and high-entropy secrets (`app/detection/secrets.py`). |
| **US SSN & National IDs** | **Implemented** | Validates Area/Group/Serial number formatting and invalid area rules (`app/detection/national_id.py`). |
| **Safe File Extraction Pipeline** | **Implemented** | 10MB limit, extension allowlist, null-byte rejection, and binary executable magic byte rejection (`ELF`, `MZ`, `Mach-O`, `ZIP`) (`app/scanning/services.py`). |
| **4-Tier Data Classification** | **Implemented** | Deterministic mapping to `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, and `RESTRICTED` (`app/detection/classification.py`). |
| **Deterministic Risk Scoring** | **Implemented** | Transparent 0–100 scoring based on data tier, channel, and volume with itemized factor explanation (`app/policies/risk.py`). |
| **Priority Policy Engine** | **Implemented** | Priority-ordered resolution with configurable actions: `LOG`, `WARN`, `BLOCK`, `QUARANTINE`, `ESCALATE` (`app/policies/engine.py`). |
| **Dry-Run Simulation Sandbox** | **Implemented** | Web and API simulation endpoints allowing rule testing without creating incidents or audit noise (`/policies/simulate`). |
| **Role-Based Access Control (RBAC)** | **Implemented** | Three distinct roles (`admin`, `analyst`, `auditor`) enforced across UI routes and REST API endpoints (`app/auth/services.py`). |
| **Immutable Security Audit Log** | **Implemented** | Append-only database audit trail with automatic sanitization of passwords and sensitive tokens (`app/audit/services.py`). |
| **Endpoint Agent & Offline Queue** | **Implemented** | Filesystem and USB observers, store-and-forward disk queue (`agent_queue.json`) with retry backoff (`agent/service.py`). |
| **Privacy-Safe Clipboard Observer** | **Implemented** | **Disabled by default**. Samples short snippets, hashes content, and discards raw text (`agent/observers/clipboard_observer.py`). |
| **Kernel-Level Packet Interception** | *Out of Scope / Planned* | DLP Defender is an application- and endpoint-observer platform, not an eBPF or NDIS kernel-mode driver. It does not inspect raw TCP network interfaces. |
| **Hardware Kernel USB Bus Locking** | *Out of Scope / Planned* | The agent detects mount events and file transfers; it does not disable host USB controller drivers in the Linux kernel. |
| **Full HTTPS MITM SSL Decryption** | *Out of Scope / Planned* | Does not perform dynamic TLS certificate injection or proxy interception of encrypted browser sessions. |
| **Optical Character Recognition (OCR)**| *Planned Future Feature* | Currently rejects binary image files (`PNG`, `JPG`, `TIFF`); only safe text and structured documents are parsed. |
| **Active Directory / LDAP / SAML SSO** | *Planned Future Feature* | Currently authenticates against local PostgreSQL users hashed with Argon2id. |

---

## 2. First-Time Setup

Follow these step-by-step instructions to configure and initialize DLP Defender from scratch on Parrot OS Linux.

### Prerequisites & Required Software

Your system requires the following packages installed on Parrot OS:
1. **Operating System**: Parrot Security OS (Debian 13 base) or Debian/Ubuntu-compatible Linux.
2. **Podman**: Version 5.0+ (`podman --version`).
3. **Podman Docker-Compose Provider**: Docker Compose plugin version 2.26+ (`podman compose version`).
4. **Python**: Version 3.12 or 3.13 (`python3 --version`).
5. **System Utilities**: `curl`, `jq`, `net-tools` or `iproute2` (`ss`).

To verify that these tools are installed, run:

```bash
# [SAFE] Check tool versions
podman --version
podman compose version
python3 --version
curl --version | head -n 1
```

If Podman or Compose are missing, install them on Parrot OS using:

```bash
# [SAFE] Install required packages if not already present
sudo apt update && sudo apt install -y podman podman-docker docker-compose-plugin curl jq
```

---

### Navigating to the Project Directory

Open your Parrot OS terminal (MATE Terminal) and navigate to the project root:

```bash
# [SAFE] Move into project root directory
cd ~/Documents/DTS

# [SAFE] Confirm current working directory
pwd
```

*Expected Output:*
```text
/home/robin/Documents/DTS
```

---

### Configuring Environment Variables Safely (`.env`)

The application uses an environment file named `.env` to configure database credentials, security keys, and operational limits. 

1. Create your local `.env` file from the provided `.env.example` template:

```bash
# [SAFE] Copy environment template to .env
cp .env.example .env
```

2. Restrict file permissions immediately so other local non-root users cannot read your passwords or keys:

```bash
# [SAFE] Restrict .env permissions to owner only
chmod 600 .env
```

3. Generate a cryptographically secure 32-character secret key:

```bash
# [SAFE] Generate high-entropy secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

*Example Output:*
```text
4f8a1c9e2b3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab
```

4. Edit `.env` using your preferred terminal editor (`nano` or `mousepad`):

```bash
nano .env
```

Ensure the file contains the following essential settings:

```dotenv
# DLP Platform Environment Settings
APP_ENV=production
FLASK_APP=app:create_app
FLASK_DEBUG=false

# Security: Generated 32-character minimum secret key
SECRET_KEY=4f8a1c9e2b3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789ab

# Database Credentials
POSTGRES_DB=dlp_system
POSTGRES_USER=dlp_user
POSTGRES_PASSWORD=ChangeMeSecurePass2026!

# Database connection URL for containers
DATABASE_URL=postgresql+psycopg://dlp_user:ChangeMeSecurePass2026!@dlp-db:5432/dlp_system

# Cookie and Session Security (Use false for local HTTP testing; true for production HTTPS)
SESSION_COOKIE_SECURE=false
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME_MINUTES=60

# Scanning Limits (10 MB = 10485760 bytes)
MAX_CONTENT_LENGTH_BYTES=10485760
ALLOWED_EXTENSIONS=txt,csv,json,xml,md,log,yaml,yml

# Rate Limiting
RATELIMIT_DEFAULT=100/minute
RATELIMIT_AUTH=10/minute
LOG_LEVEL=INFO
```

Save and exit (`Ctrl+O`, `Enter`, then `Ctrl+X` in nano).

---

### Building and Launching the Containers

Before launching, build the web application image and start the containers in detached (background) mode:

```bash
# [SAFE] Build the container images defined in compose.yaml
podman compose build
```

*What this command does:* Reads `compose.yaml` and `Dockerfile`, installs Python system dependencies, copies the source code, sets up an unprivileged user `dlpuser` (UID 10001), and tags the local image `dts-dlp-web:latest`.

Now, launch the containers:

```bash
# [SAFE] Start all containers in detached mode
podman compose up -d
```

*What this command does:*
1. Creates the rootless container network bridge.
2. Creates the named persistent volume `postgres_data` (if it does not exist).
3. Starts container `dlp-postgres-db` on port 5432.
4. Waits for the PostgreSQL health check (`pg_isready`) to report healthy.
5. Starts container `dlp-web-app` on port 5000.

---

### Database Migrations & Initial Data Seeding

Once the database container is healthy, initialize the database tables and default user accounts.

1. **Apply Database Migrations (Schema Tables)**:

```bash
# [SAFE] Apply database schema migrations
podman compose exec dlp-web flask db upgrade
```

*What this command does:* Executes the Alembic migration scripts inside the running web container, creating tables: `users`, `policies`, `incidents`, `incident_findings`, `endpoint_devices`, `endpoint_events`, and `audit_logs`.

2. **Seed Default Roles, Users, and Baseline Policies**:

```bash
# [SAFE] Seed initial users and DLP detection rules
podman compose exec dlp-web python scripts/seed_data.py
```

*Expected Output:*
```text
Created user: admin (admin)
Created user: analyst (analyst)
Created user: auditor (auditor)
Created policy: PCI-DSS Cardholder Data Protection (BLOCK)
Created policy: High-Entropy Secrets & Tokens Blocker (BLOCK)
Created policy: US Social Security Number Protection (WARN)
Created policy: Bulk PII Exfiltration Guard (QUARANTINE)
Created policy: Removable Media Mass Transfer Blocker (BLOCK)
Created policy: Corporate Internal Confidentiality Marker (LOG)
Database seeding completed successfully.
```

---

### Step-by-Step Setup Verification

Run these verification commands to ensure everything is operational before moving forward:

1. **Verify Running Containers**:
```bash
# [SAFE] Check container status and ports
podman ps
```
*Expected Output:* Two containers (`dlp-postgres-db` and `dlp-web-app`) with status `Up` and `(healthy)`.

2. **Query the API Health Probe**:
```bash
# [SAFE] Test the application health check
curl -s http://localhost:5000/api/v1/health | jq .
```
*Expected Output:*
```json
{
  "database": "connected",
  "status": "healthy",
  "timestamp": "2026-10-18T07:30:00.000000+00:00",
  "version": "0.1.0"
}
```

If `"status": "healthy"` and `"database": "connected"` appear, your initial setup is complete!

---

## 3. Daily Server Operations

Use these copy-and-paste commands for routine daily operations.

### Starting Existing Stopped Containers

When containers already exist on your system but are in `Exited` or `Stopped` status:

```bash
# [SAFE] Start existing stopped containers
podman compose start
```

*Alternative using direct Podman commands:*
```bash
# [SAFE] Start containers by name
podman start dlp-postgres-db dlp-web-app
```

---

### Starting When Containers Do Not Exist

If containers were previously removed (e.g., via `podman compose down`), or if you are starting on a fresh environment:

```bash
# [SAFE] Create, configure, and start containers in background
cd ~/Documents/DTS
podman compose up -d
```

---

### Checking Container Health & Status

Check whether containers are running, their uptime, port mappings, and health probe states:

```bash
# [SAFE] List active running containers
podman compose ps
```

*Alternative detailed view:*
```bash
# [SAFE] Check all containers including exited ones
podman ps -a --filter "name=dlp"
```

*Expected Status Column:* Should show `Up ... (healthy)` for both services.

---

### Accessing the Web Dashboard & Accounts

1. Open your browser (such as Firefox on Parrot OS) and navigate to:
   **`http://localhost:5000`** (or **`http://localhost:5000/auth/login`**)

2. The system provides three pre-seeded accounts configured for strict separation of duties:

| Role | Username | Password | API Key (`X-API-Key`) | What This Account Can Do |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPass123!@#` | `dev_admin_api_key_12345` | Full platform control: create/edit/delete policies, revoke compromised endpoints, view all incidents, inspect security audit logs. |
| **Security Analyst** | `analyst` | `AnalystPass123!@#` | `dev_analyst_api_key_67890` | Incident triage: investigate alerts, inspect redacted findings, update status, upload test files for scanning, run policy simulations. *(Blocked from modifying policies or viewing audit logs).* |
| **Compliance Auditor**| `auditor` | `AuditorPass123!@#` | `dev_auditor_api_key_abcde` | Compliance verification: full read-only inspection of immutable audit logs, read-only policy review, read-only incident review. *(Blocked from scanning or modifying incidents).* |

---

### Viewing Real-Time Application & Database Logs

View logs to monitor incoming HTTP requests, policy matches, and background queries:

1. **Follow Web Application Logs (Live Stream)**:
```bash
# [SAFE] Follow web server access and error logs
podman compose logs -f dlp-web
```
*(Press `Ctrl+C` to exit the log follower).*

2. **Follow Database Logs (Live Stream)**:
```bash
# [SAFE] Follow PostgreSQL queries and connections
podman compose logs -f dlp-db
```

3. **View Last 50 Lines Without Following**:
```bash
# [SAFE] Print last 50 log lines
podman compose logs --tail=50 dlp-web
```

---

### Restarting Services Safely

If you change an environment variable or wish to refresh the WSGI server:

1. **Restart Only the Web Application (Database remains running)**:
```bash
# [SAFE] Restart web server container
podman compose restart dlp-web
```

2. **Restart Entire Platform**:
```bash
# [SAFE] Restart both database and web application
podman compose restart
```

---

### Stopping Services Without Data Loss

To stop DLP Defender cleanly without losing any incidents, audit logs, or configuration:

```bash
# [SAFE] Stop containers without removing them
podman compose stop
```

*Alternatively, to stop and remove containers while keeping data volume safe:*
```bash
# [SAFE] Stop and remove containers; DATA VOLUME IS PRESERVED
podman compose down
```

> [!NOTE]
> `podman compose down` stops and unregisters container instances, but **does not delete** the named volume `postgres_data`. When you run `podman compose up -d` next time, all your data will be completely intact!

---

### Starting Again After System Reboot

When you reboot Parrot OS, start DLP Defender with two simple commands:

```bash
# [SAFE] Navigate to project directory and start containers
cd ~/Documents/DTS
podman compose up -d
```

Verify startup:
```bash
# [SAFE] Verify system health
curl -s http://localhost:5000/api/v1/health | jq .
```

---

### Endpoint Agent Lifecycle: Check, Start, Stop

The endpoint agent is an independent Python daemon that communicates with the central server.

1. **Check Local Agent Status & Server Connectivity**:
```bash
# [SAFE] Query agent enrollment and connection health
python scripts/run_agent.py status
```
*Expected Output:* Displays device ID, monitored paths, and confirms `Server Connection: ONLINE (Status: ACKNOWLEDGED)`.

2. **Start the Continuous Monitoring Daemon**:
```bash
# [SAFE] Run agent observer in foreground
python scripts/run_agent.py run --poll-interval 2.0
```
*What this command does:* Starts filesystem and removable media observers, scanning monitored folders every 2.0 seconds.

3. **Stop the Agent Daemon**:
   In the terminal running the agent, press:
   **`Ctrl + C`**
   The agent intercepts `SIGINT`, cleanly stops observers, flushes queued events, and exits.

---

### Understanding Podman Lifecycle Commands

Understanding the exact behavior of container commands prevents accidental downtime or data loss:

| Command | What It Does | Are Containers Preserved? | Is Database Data Preserved? | When to Use |
| :--- | :--- | :---: | :---: | :--- |
| **`podman compose up -d`** | Creates networks, mounts volumes, creates containers, and starts them in the background. | **Yes** (created) | **Yes** (preserved in volume) | First launch, after reboot, or after running `down`. |
| **`podman compose start`** | Wakes up already-existing stopped containers. | **Yes** (reused) | **Yes** (preserved) | Fast daily morning startup when containers already exist. |
| **`podman compose stop`** | Sends `SIGTERM` to running processes and pauses containers. | **Yes** (preserved) | **Yes** (preserved) | End of day pause; leaves containers ready for immediate `start`. |
| **`podman compose down`** | Stops containers and removes container instances and network bridge. | **No** (removed) | **Yes** (preserved in volume) | Clean system shutdown or before rebuilding Dockerfile. |
| **`podman compose down -v`** | Stops containers, removes containers, **AND DELETES THE DATABASE VOLUME**. | **No** (removed) | **NO! DESTROYED!** | **NEVER use in normal operations!** Only for total developer wipe. |

---

## 4. Comprehensive Troubleshooting Guide

### Diagnostic Command Toolkit

Whenever an error occurs, run these diagnostic commands before changing any settings:

```bash
# 1. Check container states and health probes
podman ps -a --filter "name=dlp"

# 2. Check which processes are listening on ports 5432 and 5000
sudo ss -ltnp | grep -E ':5432|:5000'

# 3. Check systemd host PostgreSQL service on Parrot OS
systemctl status postgresql --no-pager

# 4. View the last 50 lines of logs for the failing container
podman compose logs --tail=50 dlp-web
podman compose logs --tail=50 dlp-db
```

---

### Master Troubleshooting Reference Table

| Error / Symptom | Likely Cause | Diagnostic Command | Safe Fix | Verification |
| :--- | :--- | :--- | :--- | :--- |
| **`rootlessport listen tcp 0.0.0.0:5432: bind: address already in use`** | A service on the host (e.g. host PostgreSQL or Metasploit) or another container is holding port 5432. | `sudo ss -ltnp \| grep ':5432'` and `podman ps -a` | **Option A**: If host PostgreSQL is not needed, stop it: `sudo systemctl stop postgresql`.<br>**Option B**: Change host port mapping in `compose.yaml` to `"5433:5432"`. | `podman start dlp-postgres-db` succeeds; `podman ps` shows port active. |
| **PostgreSQL container fails to start** | Corrupted data permissions in volume or invalid PostgreSQL environment credentials. | `podman logs dlp-postgres-db` | Check `.env` for valid `POSTGRES_USER` and `POSTGRES_PASSWORD`. Ensure volume path is accessible. | `podman compose logs dlp-db` shows `database system is ready to accept connections`. |
| **Web container fails to start** | Database container is not yet healthy, or missing/insecure `SECRET_KEY` in production mode. | `podman logs dlp-web-app` | Ensure `dlp-postgres-db` is healthy. Verify `SECRET_KEY` in `.env` is at least 32 characters long. | `podman ps` reports `dlp-web-app` status `Up (healthy)`. |
| **Dashboard does not open at `http://localhost:5000`** | `dlp-web-app` container is stopped, crashed on boot, or bound only to internal interface. | `curl -I http://localhost:5000/api/v1/health` | Run `podman compose up -d`. Inspect web logs for Python traceback errors with `podman compose logs dlp-web`. | `curl -s http://localhost:5000/api/v1/health` returns HTTP 200 `healthy`. |
| **Database connection errors (`psycopg.OperationalError`)** | Database container name resolution failed, or password mismatch between `.env` and `DATABASE_URL`. | `podman compose exec dlp-web env \| grep DATABASE_URL` | Ensure `DATABASE_URL` in `.env` matches the `POSTGRES_USER`, `POSTGRES_PASSWORD`, and host `dlp-db:5432`. | `curl http://localhost:5000/api/v1/health` shows `"database": "connected"`. |
| **Containers exit immediately with code 137 or 1** | Memory exhaustion (OOM), entrypoint permission error, or missing dependency. | `podman inspect dlp-web-app --format '{{.State.ExitCode}}'` | Review `podman logs dlp-web-app`. Rebuild image with `podman compose build --no-cache`. | Container stays in `Up` state for more than 30 seconds. |
| **Podman permission / rootless networking errors** | Rootless subuid/subgid mapping missing or user systemd socket inactive. | `systemctl --user status podman.socket` | Enable socket: `systemctl --user enable --now podman.socket`. Verify `/etc/subuid` contains current user. | `podman info` displays valid rootless user namespace mappings. |
| **Missing environment variables** | `.env` file does not exist, was renamed, or has unreadable file permissions. | `ls -la .env` | Run `cp .env.example .env && chmod 600 .env`. Populate required variables. | `podman compose config` displays parsed environment variables without errors. |
| **Port 5000 is already in use** | A local Flask development server, Gunicorn instance, or another container is running. | `sudo ss -ltnp \| grep ':5000'` | Identify PID from `ss` output and terminate the conflicting process: `kill <PID>`, or map to `"5001:5000"` in `compose.yaml`. | `ss -ltnp \| grep ':5000'` shows only `rootlessport` or `podman`. |
| **Database migrations fail (`alembic.util.exc.CommandError`)** | Schema version mismatch or database container unreachable during migration. | `podman compose exec dlp-web flask db current` | Verify database connection. Stamp or upgrade: `podman compose exec dlp-web flask db upgrade`. | `podman compose exec dlp-web flask db heads` matches current revision. |
| **Endpoint agent cannot connect to server** | Incorrect `server_url`, server container stopped, or firewall blocking port 5000. | `python scripts/run_agent.py status` | Check `server_url` in `agent_config.json`. Ensure `curl http://localhost:5000/api/v1/health` works. | `python scripts/run_agent.py status` reports `Server Connection: ONLINE`. |

---

### Deep Dive: Resolving Port 5432 Conflicts on Parrot OS

A very common issue on Parrot Security OS is encountering this error when starting containers:

```text
Error: unable to start container "...": rootlessport listen tcp 0.0.0.0:5432: bind: address already in use
```

#### Step 1: Identify What Is Using Port 5432
Before terminating any service, determine exactly what process is listening on the port:

```bash
# [SAFE] Identify process using port 5432
sudo ss -ltnp | grep ':5432'
```

*Example Output on Parrot OS:*
```text
LISTEN 0   200   127.0.0.1:5432   0.0.0.0:*   users:(("postgres",pid=4367,fd=7))
```

Now check if Parrot OS is running a local PostgreSQL cluster:
```bash
# [SAFE] Check status of host PostgreSQL service
sudo systemctl status postgresql --no-pager
```

On Parrot OS, the local PostgreSQL service is frequently started automatically to support security tools such as **Metasploit Framework (`msfdb`)**.

#### Step 2: Choose the Safe Resolution

You have two safe choices:

##### Option A: If you are NOT actively using Metasploit or host PostgreSQL
Safely stop the host PostgreSQL service:

```bash
# [SAFE] Stop host PostgreSQL service
sudo systemctl stop postgresql
```

Verify that port 5432 is now free:
```bash
# [SAFE] Confirm port is free
ss -ltnp | grep ':5432'
```
*(No output indicates the port is clear).*

Now start your DLP container:
```bash
# [SAFE] Start DLP database container
podman start dlp-postgres-db
```

*(Note: When you need Metasploit later, you can restart host PostgreSQL with `sudo systemctl start postgresql` after stopping your DLP container).*

##### Option B: If you ARE using Metasploit or need host PostgreSQL running simultaneously
Do **NOT** stop host PostgreSQL. Instead, change the host port mapping for the DLP database container in `compose.yaml`:

1. Open `compose.yaml`:
```bash
nano compose.yaml
```

2. Locate lines 11–12:
```yaml
    ports:
      - "5432:5432"
```

3. Change the host port to `5433`:
```yaml
    ports:
      - "5433:5432"
```

Save and exit.

> [!TIP]
> Inside the container network, `dlp-web` connects directly to `dlp-db:5432` using container DNS. Changing the host-facing port to `5433` eliminates the conflict with host PostgreSQL completely, allowing both Metasploit and DLP Defender to run simultaneously!

---

### Deep Dive: Resolving Container Startup & Rootless Networking Failures

Podman runs rootless on Parrot OS by default. If you encounter permission errors or networking issues:

1. **Verify Rootless SubUID / SubGID Mappings**:
```bash
# [SAFE] Verify your user has subordinate UIDs configured
grep "$USER" /etc/subuid /etc/subgid
```
*Expected Output:* Shows your username followed by a starting UID and count (e.g., `robin:100000:65536`).

2. **Verify User Systemd Podman Socket**:
```bash
# [SAFE] Check Podman user service status
systemctl --user status podman.socket
```
If inactive, start and enable it:
```bash
# [SAFE] Enable Podman user socket
systemctl --user enable --now podman.socket
```

3. **Reset Stale Rootless Pause Process (If container creation hangs)**:
```bash
# [CAUTION] Cleans up stale rootless pause processes without deleting images or volumes
podman system migrate
```

---

## 5. Database and Data Safety Manual

### Commands That Preserve Data vs. Commands That Destroy Data

In production environments, preventing accidental data loss is paramount. Memorize the safety category of these commands:

| Command | Safety Category | Impact on Data | Explanation |
| :--- | :---: | :---: | :--- |
| `podman compose stop` | **[SAFE]** | **100% Preserved** | Pauses processes; containers and volumes remain untouched. |
| `podman compose start` | **[SAFE]** | **100% Preserved** | Resumes paused containers. |
| `podman compose restart` | **[SAFE]** | **100% Preserved** | Restarts container processes cleanly. |
| `podman compose down` | **[SAFE]** | **100% Preserved** | Removes container instances; **volume `postgres_data` is untouched**. |
| `podman compose exec dlp-db pg_dump ...` | **[SAFE]** | **100% Preserved** | Creates an external SQL backup file. |
| `podman compose down -v` | **[DESTRUCTIVE]** | **TOTAL DATA LOSS** | The `-v` flag explicitly **DELETES ALL VOLUMES**, destroying all incidents and audit logs! |
| `podman volume rm postgres_data` | **[DESTRUCTIVE]** | **TOTAL DATA LOSS** | Manually deletes the PostgreSQL storage volume. |

---

### Critical Warning: The Danger of `podman compose down -v`

> [!CAUTION]
> **NEVER execute `podman compose down -v` during troubleshooting!**  
> The `-v` (or `--volumes`) flag tells Podman to purge every named and anonymous volume attached to the compose project. This destroys the `postgres_data` volume, permanently erasing:
> - All recorded security incidents and triaged findings.
> - All policy definitions and customized thresholds.
> - All enrolled endpoint devices and telemetry history.
> - All compliance audit records.

---

### Non-Destructive Troubleshooting Golden Rule

> **Golden Rule of Troubleshooting:**  
> Never delete volumes, containers, or source files as a first troubleshooting step.  
> 99% of startup issues are caused by port conflicts, unapplied migrations, or incorrect `.env` syntax. Diagnose the root cause using logs and network inspection tools first.

---

### How to Back Up the Database

Always create a verified database backup before performing system upgrades or migrations:

```bash
# [SAFE] Create a timestamped SQL backup of the DLP database
podman compose exec dlp-db pg_dump -U dlp_user -d dlp_system > backup_dlp_$(date +%Y%m%d_%H%M%S).sql
```

*What this command does:* Invokes PostgreSQL's native `pg_dump` utility inside `dlp-postgres-db` and exports the complete schema, tables, and records into a plain-text SQL script on your host machine.

---

### Verifying Backup Integrity Before Maintenance

Never assume a backup succeeded without verifying the resulting file:

1. **Verify File Existence and Size**:
```bash
# [SAFE] Check backup file size
ls -lh backup_dlp_*.sql
```
*(The file size must be greater than zero, typically 50KB to several megabytes depending on database activity).*

2. **Inspect the SQL Header**:
```bash
# [SAFE] Inspect the first 15 lines of the backup
head -n 15 $(ls -t backup_dlp_*.sql | head -n 1)
```
*Expected Output:*
```text
--
-- PostgreSQL database dump
--
-- Dumped from database version 16.x
-- Dumped by pg_dump version 16.x
SET statement_timeout = 0;
...
```

If the header shows `PostgreSQL database dump`, the backup is valid and safe.

---

### Restoring the Database from a Backup File

If you ever need to restore your database from a backup file:

```bash
# [CAUTION] Restores database from a previous backup file
podman compose exec -T dlp-db psql -U dlp_user -d dlp_system < backup_dlp_20261018_120000.sql
```

*What this command does:* Streams the SQL statements from your backup file into the running PostgreSQL container, recreating tables and restoring all records.

---

## 6. Endpoint Agent Administrator & Operator Guide

### Agent Purpose & Architecture

The **DLP Endpoint Agent** is a lightweight Python service located under `agent/` and controlled via `scripts/run_agent.py`. It is designed to run in user-space on employee workstations to monitor local activity and report security events to the central DLP server.

Key Agent Components:
- **`agent/client.py`**: Handles secure HTTP communication, authentication headers, heartbeat sync, and event submission.
- **`agent/config.py`**: Manages local settings stored in `agent_config.json`.
- **`agent/queue.py`**: Manages a resilient local FIFO queue (`agent_queue.json`) for offline buffering.
- **`agent/observers/file_observer.py`**: Detects created or modified files in monitored directories.
- **`agent/observers/usb_observer.py`**: Monitors removable media mount events.
- **`agent/observers/clipboard_observer.py`**: Privacy-preserving clipboard inspector (**strictly disabled by default**).

---

### How the Agent Communicates with the Server

The agent communicates with the central DLP server over HTTP REST APIs using standardized JSON payloads:

```
[Endpoint Agent]  --- HTTP POST /api/v1/endpoints/heartbeat --->  [DLP Central Server]
                  <--- HTTP 200 { status: ACKNOWLEDGED } ---

[Endpoint Agent]  --- HTTP POST /api/v1/endpoints/events ------>  [DLP Central Server]
                  <--- HTTP 201 { decision: BLOCK, risk: 100 } -
```

**Required Authentication Headers:**
Every request from an enrolled agent must include:
- `X-Device-ID`: The unique device identifier (e.g., `ep-885d5b74265b4805`).
- `X-Device-Token`: A high-entropy authentication secret generated during enrollment.

If the token does not match, the server returns **HTTP 401 Unauthorized**. If the administrator has marked the device as `REVOKED`, the server returns **HTTP 403 Forbidden**.

---

### Device Enrollment

Before an endpoint agent can submit events, it must be enrolled with the central server:

```bash
# [SAFE] Enroll device with DLP central server
python scripts/run_agent.py enroll --server-url http://localhost:5000
```

*Expected Output:*
```text
[*] Enrolling device 'parrot' with DLP server at http://localhost:5000...
[+] Enrollment successful!
    Device ID   : ep-885d5b74265b4805
    Agent Token : a1b2c3d4... (saved securely to agent_config.json)
```

The enrollment process generates a local configuration file named `agent_config.json` containing the device credentials.

---

### Checking Agent Status & Health

To inspect the agent's current configuration, enrollment status, and live server connectivity:

```bash
# [SAFE] Check endpoint agent status and heartbeat
python scripts/run_agent.py status
```

*Expected Output:*
```text
========================================
       DLP Endpoint Agent Status        
========================================
Config File       : agent_config.json
Server URL        : http://localhost:5000
Hostname          : parrot
OS Platform       : Linux
Device ID         : ep-885d5b74265b4805
Enrolled          : YES
Monitored Paths   : /home/robin/Documents/DTS/monitored_data
USB / Removable   : ENABLED
Clipboard (opt-in): DISABLED (Default)
Queued Events     : 0 event(s) pending
[*] Testing server connectivity and heartbeat...
[+] Server Connection : ONLINE (Status: ACKNOWLEDGED)
========================================
```

---

### Running the Monitoring Daemon

To launch the agent in continuous monitoring mode:

```bash
# [SAFE] Start endpoint agent daemon with 2-second poll interval
python scripts/run_agent.py run --poll-interval 2.0
```

To stop the agent, press `Ctrl + C`.

---

### Simulating Synthetic Test Events

You can test how the DLP system reacts to different security scenarios without waiting for real user activity using the `test-event` subcommand.

#### Scenario 1: Benign File Activity (Expected Decision: ALLOW)
Simulate a normal employee modifying a non-sensitive document:

```bash
# [SAFE] Submit benign file event
python scripts/run_agent.py test-event --type file
```

*Expected Terminal Output:*
```text
[*] Submitting synthetic file event (sensitive=False)...
[*] Response Code : 201
[+] Event ingested successfully! Decision: ALLOW | Risk: INFORMATIONAL (0.0/100)
```

#### Scenario 2: Exfiltration of Credit Card & AWS Keys to USB (Expected Decision: BLOCK)
Simulate an unauthorized transfer of sensitive payment card and cloud credentials to an external USB flash drive:

```bash
# [SAFE] Submit sensitive USB exfiltration event
python scripts/run_agent.py test-event --type usb --sensitive
```

*Expected Terminal Output:*
```text
[*] Submitting synthetic usb event (sensitive=True)...
[*] Response Code : 201
[+] Event ingested successfully! Decision: BLOCK | Risk: CRITICAL (100.0/100)
```

Now open your browser to `http://localhost:5000/incidents`. A new **CRITICAL** incident will appear at the top of the queue: `Endpoint USB Policy Match: PCI-DSS Cardholder Data Protection` with redacted finding `4532-****-****-5671`.

---

### Privacy-Safe Clipboard Observer: Design & Guarantees

Clipboard monitoring is a sensitive topic in enterprise privacy. The DLP Defender codebase implements strict, verifiable privacy protections (`agent/observers/clipboard_observer.py`):

1. **Disabled by Default**: The clipboard observer is strictly turned off in the code. It will never monitor clipboard activity unless an administrator explicitly activates it.
2. **Opt-In Execution**: To enable clipboard monitoring, you must supply the explicit command-line flag:
   ```bash
   python scripts/run_agent.py run --enable-clipboard
   ```
   or manually configure `"monitor_clipboard": true` in `agent_config.json`.
3. **No Keystroke Logging**: The agent does not intercept keystrokes or log passwords.
4. **Content Deduplication via Hashing**: The agent calculates a SHA-256 hash of the clipboard text. If the hash matches the last inspected item, no processing occurs.
5. **Immediate In-Memory Discard**: Raw clipboard text is sampled (up to 2,000 characters maximum) for policy evaluation. The raw text is immediately discarded from memory; only redacted finding snippets are ever persisted.

To test a synthetic sensitive clipboard event:
```bash
# [SAFE] Test synthetic clipboard event
python scripts/run_agent.py test-event --type clipboard --sensitive
```

---

### Local Offline Event Queue & Resilience

If the endpoint machine loses network connectivity (e.g., laptop disconnects from Wi-Fi), the agent does not drop security events:
- Events are appended to a bounded local file on disk: `agent_queue.json`.
- The queue is protected by a 500-event capacity limit to prevent unbounded disk usage.
- Once connectivity is restored, the agent flushes buffered events in chronological order with exponential retry backoff.
- The server checks `event_id` uniqueness to ensure duplicate events are never created in the database.

---

### Agent Troubleshooting & Common Errors

| Error Message | Cause | Fix |
| :--- | :--- | :--- |
| `Device is not enrolled` | Missing `agent_config.json` or `device_id` is null. | Run `python scripts/run_agent.py enroll --server-url http://localhost:5000`. |
| `Server Connection : OFFLINE / ERROR (Connection refused)` | Web container is stopped or listening on another port. | Start the server with `podman compose up -d` and check `curl http://localhost:5000/api/v1/health`. |
| `Server Connection : REVOKED` | An administrator marked this device as `REVOKED` in the DLP dashboard. | Log into dashboard as `admin`, go to `/endpoints`, and un-revoke the device, or re-enroll with a new config. |
| `Agent authentication token mismatch (401)` | Local `agent_token` in `agent_config.json` does not match the database record. | Delete `agent_config.json` and re-run enrollment: `python scripts/run_agent.py enroll`. |

---

## 7. Security Best Practices & Hardening

### Protecting Environment Files & File Permissions

The `.env` file contains sensitive secrets, including the database password and Flask session key.

1. **Enforce Strict Permissions**:
```bash
# [SAFE] Ensure only your user account can read or write .env
chmod 600 ~/Documents/DTS/.env
```

2. **Never Commit Secrets to Git**:
The `.gitignore` file is pre-configured to ignore `.env`, `*.db`, `agent_config.json`, and `agent_queue.json`. Always check `git status` before committing code to ensure configuration files are not tracked.

---

### Generating Cryptographically Secure Production Keys

Never use default or easily guessable secret keys in production. If `APP_ENV=production` is set, DLP Defender enforces a security validation check at startup: `SECRET_KEY` must be at least 32 characters long and cannot contain `"dev-insecure"`.

Generate secure production keys using Python's `secrets` module:

```bash
# [SAFE] Generate high-entropy 32-byte secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Paste this string into `SECRET_KEY=` inside `.env`.

---

### API Key Security & Separation of Roles (RBAC)

The platform strictly segregates responsibilities across three roles:
- **`admin`**: Reserved for platform administrators and security engineers. Can alter detection policies and revoke endpoint devices.
- **`analyst`**: Assigned to SOC incident triage analysts. Can inspect redacted incidents, update investigation notes, and test uploads. Cannot modify policies or view audit trails.
- **`auditor`**: Dedicated to internal compliance and external regulators. Can inspect immutable audit logs and review policies. Cannot modify incidents or upload files.

Keep API keys (`X-API-Key`) stored securely. Never embed API keys directly in client-side scripts or public repositories.

---

### Audit Trail Integrity & Log Sanitization

Compliance frameworks (SOC 2, ISO 27001, PCI-DSS) require tamper-evident logging of administrative actions.
- The `audit_logs` table records every sign-in attempt, policy modification, incident status change, and device revocation.
- **Automated Credential Sanitization**: The audit recording service automatically sanitizes payload fields named `password`, `secret`, `token`, and `api_key`, replacing them with `[REDACTED]` before writing to the database.
- Audit records cannot be edited or deleted from the web application interface.

---

### Network Exposure & Local Interface Binding

In `compose.yaml`:
- The web application binds to host port `5000` (`"5000:5000"`).
- In production deployment behind a reverse proxy (such as Nginx or Traefik), bind ports to localhost only (`"127.0.0.1:5000:5000"`) so that the raw application port is not directly reachable from untrusted external networks.
- Always enable HTTPS/TLS termination at the reverse proxy in production and set `SESSION_COOKIE_SECURE=true` in `.env`.

---

## 8. Testing and Verification Checklist

Use this 7-point verification checklist to confirm that all components of DLP Defender are fully operational:

### 7-Point Verification Matrix

| Checkpoint | Target Component | Verification Command | Expected Successful Result | Pass / Fail |
| :---: | :--- | :--- | :--- | :---: |
| **1** | Database Container Health | `podman inspect dlp-postgres-db --format '{{.State.Health.Status}}'` | `healthy` | [ ] |
| **2** | Web Server Container Health | `podman inspect dlp-web-app --format '{{.State.Health.Status}}'` | `healthy` | [ ] |
| **3** | HTTP API Health Probe | `curl -s http://localhost:5000/api/v1/health \| jq -r .status` | `healthy` | [ ] |
| **4** | Database Connectivity Probe | `curl -s http://localhost:5000/api/v1/health \| jq -r .database` | `connected` | [ ] |
| **5** | Web Login Page HTTP Status | `curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/auth/login` | `200` | [ ] |
| **6** | Endpoint Agent Heartbeat | `python scripts/run_agent.py status` | `Server Connection : ONLINE` | [ ] |
| **7** | Real-Time Detection & Policy | `python scripts/run_agent.py test-event --type file` | `Decision: ALLOW \| Risk: INFORMATIONAL` | [ ] |

---

### Verification Commands & Expected Responses

Run this single copy-and-paste diagnostic block in your terminal to execute the entire verification checklist automatically:

```bash
# [SAFE] Automated 7-point platform verification script
echo "=== DLP DEFENDER PLATFORM VERIFICATION ==="
echo -n "[1/7] Database Container Health : "
podman inspect dlp-postgres-db --format '{{.State.Health.Status}}' 2>/dev/null || echo "NOT RUNNING"

echo -n "[2/7] Web Container Health      : "
podman inspect dlp-web-app --format '{{.State.Health.Status}}' 2>/dev/null || echo "NOT RUNNING"

echo -n "[3/7] API Health Endpoint       : "
curl -s http://localhost:5000/api/v1/health | jq -r .status 2>/dev/null || echo "UNREACHABLE"

echo -n "[4/7] Database Connection Probe : "
curl -s http://localhost:5000/api/v1/health | jq -r .database 2>/dev/null || echo "FAILED"

echo -n "[5/7] Web Login Page Response   : "
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/auth/login 2>/dev/null || echo "FAILED"

echo -n "[6/7] Agent Status & Heartbeat  : "
python scripts/run_agent.py status 2>/dev/null | grep "Server Connection" || echo "AGENT UNENROLLED/OFFLINE"

echo -n "[7/7] Detection Pipeline Test   : "
python scripts/run_agent.py test-event --type file 2>/dev/null | grep "Decision:" || echo "EVENT FAILED"
echo "=== VERIFICATION COMPLETE ==="
```

---

## 9. Quick-Reference Command Sheet

Keep this compact cheat sheet handy for daily administration:

| Category | Goal | Exact Terminal Command | Safety |
| :--- | :--- | :--- | :---: |
| **Start** | Start containers in background | `podman compose up -d` | **[SAFE]** |
| **Start** | Wake up existing stopped containers | `podman compose start` | **[SAFE]** |
| **Status** | Check active container status | `podman compose ps` | **[SAFE]** |
| **Status** | Query API health check | `curl -s http://localhost:5000/api/v1/health \| jq .` | **[SAFE]** |
| **Logs** | Stream live web application logs | `podman compose logs -f dlp-web` | **[SAFE]** |
| **Logs** | Stream live database queries | `podman compose logs -f dlp-db` | **[SAFE]** |
| **Restart** | Restart web container only | `podman compose restart dlp-web` | **[SAFE]** |
| **Restart** | Restart entire platform | `podman compose restart` | **[SAFE]** |
| **Stop** | Stop containers safely (preserve data) | `podman compose stop` | **[SAFE]** |
| **Stop** | Remove containers (volume preserved) | `podman compose down` | **[SAFE]** |
| **Backup** | Backup database to SQL file | `podman compose exec dlp-db pg_dump -U dlp_user -d dlp_system > backup_$(date +%Y%m%d).sql` | **[SAFE]** |
| **Agent** | Check agent health and status | `python scripts/run_agent.py status` | **[SAFE]** |
| **Agent** | Start monitoring daemon | `python scripts/run_agent.py run --poll-interval 2.0` | **[SAFE]** |
| **Agent** | Test USB exfiltration scenario | `python scripts/run_agent.py test-event --type usb --sensitive` | **[SAFE]** |
| **Ports** | Diagnose port 5432 conflict | `sudo ss -ltnp \| grep ':5432'` | **[SAFE]** |
| **Host DB**| Stop host PostgreSQL on Parrot OS | `sudo systemctl stop postgresql` | **[SAFE]** |
| **Wipe** | **DESTROY EVERYTHING INCLUDING DATA** | `podman compose down -v` | **[DESTRUCTIVE]** |

---

## 10. Beginner Glossary & Concept Guide

For developers and system administrators new to cybersecurity and containerization:

* **Container**: A lightweight, isolated environment that packages an application and all its dependencies so it runs reliably on any Linux system without conflicting with host software.
* **Podman**: A secure, daemonless container engine for Linux that allows running containers without root privileges (rootless mode).
* **Port**: A virtual communication endpoint (like an apartment number) that network services listen on. DLP Defender uses port `5000` for the web interface and port `5432` for PostgreSQL.
* **Database Volume**: A dedicated storage directory managed by Podman on the host drive that persists database files even when container instances are stopped or recreated.
* **Database Migration**: A structured version-controlled script (managed by Alembic) that creates or modifies database tables without losing existing data.
* **Endpoint Agent**: A background program (daemon) installed on individual computers that watches for potential security violations locally.
* **Luhn Algorithm**: A mathematical formula used to validate payment card numbers (credit cards) to verify their authenticity and eliminate false positives before raising alerts.
* **Shannon Entropy**: A measurement of randomness in text strings used by DLP Defender to detect high-entropy secrets like private keys and API tokens.
* **Role-Based Access Control (RBAC)**: A security model that restricts system features based on user roles (`Admin`, `Analyst`, `Auditor`).
* **Dry-Run Simulation**: A testing mode where sensitive content is evaluated against security policies without generating incident tickets or alerting operators.
* **Redaction / Masking**: The process of obscuring sensitive numbers (e.g., turning `4532-0150-1234-5671` into `4532-****-****-5671`) to protect privacy while preserving forensic utility.
