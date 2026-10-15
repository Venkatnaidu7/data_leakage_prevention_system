# DLP Defender — Complete Setup & Operator Guide Using Podman
### Cross-Platform Guide for Linux, Windows, and macOS

---

## 1. Introduction

**DLP Defender** is an enterprise-grade, defensive Data Leakage Prevention platform with an integrated endpoint monitoring agent. This guide provides complete, step-by-step instructions for deploying, configuring, running, and testing the entire system using **Podman** and **Podman Compose**.

### Why Podman?
- **Rootless by Default:** Containers run without root privileges, significantly reducing attack surface.
- **Daemonless Architecture:** No monolithic background daemon; processes run directly as standard user processes.
- **OCI Standard Compliant:** Drop-in, compatible replacement for Docker commands and Compose syntax.
- **Cross-Platform:** Native support on Linux, lightweight virtual machines via Podman Machine on macOS and Windows.

---

## 2. System Architecture Under Podman

When deployed via Podman Compose, the system architecture consists of:

```
+---------------------------------------------------------------------------------------+
|                                    HOST MACHINE                                       |
|  (Linux, Windows via WSL2/Podman Machine, or macOS via Podman Machine)                |
|                                                                                       |
|   +-------------------------------------------------------------------------------+   |
|   |                       Endpoint Agent (Host or Container)                      |   |
|   |  - Observes: Filesystem paths, USB mount transfers, Opt-in clipboard          |   |
|   |  - Buffers: Local on-disk queue (agent_queue.json) with offline tolerance     |   |
|   |  - Communicates with Server at http://localhost:5000                          |   |
|   +---------------------------------------+---------------------------------------+   |
|                                           |                                           |
|                                           v                                           |
|   +---------------------------------------+---------------------------------------+   |
|   |                       PODMAN ROOTLESS POD / NETWORK                           |   |
|   |                                                                               |   |
|   |   +-----------------------------------+   +-------------------------------+   |   |
|   |   |    dlp-web (Flask Web & API)      |   |  dlp-db (PostgreSQL 16)       |   |   |
|   |   |  - Detection Registry & Luhn      |<--|  - Relational Data Store      |   |   |
|   |   |  - Data Classification Engine     |   |  - Volume: postgres_data      |   |   |
|   |   |  - Risk Scoring & Policies        |   |  - Port: 5432:5432 (Internal) |   |   |
|   |   |  - Incidents & Audit Trails       |   +-------------------------------+   |   |
|   |   |  - Web UI & REST API v1           |                                       |   |
|   |   |  - Port: 5000:5000                |                                       |   |
|   |   +-----------------------------------+                                       |   |
|   +-------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------+
```

---

## 3. Prerequisites & Podman Installation by Operating System

Select your operating system below to install Podman and the Compose provider:

### 3.1. Linux Installation

#### Ubuntu (22.04 / 24.04 LTS) & Debian (12+)
```bash
sudo apt-get update
sudo apt-get install -y podman podman-compose docker-compose-v2
```

#### Fedora (39+) & RHEL / CentOS Stream (9+)
```bash
sudo dnf install -y podman podman-compose
```

#### Arch Linux
```bash
sudo pacman -Syu podman podman-compose
```

#### Linux Rootless Configuration Check
Ensure non-root user subuids/subgids and user sockets are active:
```bash
# Verify subuid and subgid mappings exist for your user:
grep $USER /etc/subuid
grep $USER /etc/subgid

# Enable the rootless user socket (allows compose tools to connect):
systemctl --user enable --now podman.socket

# (Optional) Verify rootless Podman is operational:
podman info
```

---

### 3.2. Windows 10 / 11 Installation

Podman runs on Windows using WSL2 (Windows Subsystem for Linux).

#### Option A: Podman Desktop GUI (Recommended for Windows)
1. Download the official installer from [https://podman-desktop.io](https://podman-desktop.io) or install via `winget`:
   ```powershell
   winget install RedHat.Podman-Desktop
   winget install RedHat.Podman
   ```
2. Restart your terminal or system when prompted.
3. Open PowerShell as Administrator and initialize the Podman virtual machine:
   ```powershell
   podman machine init --cpus 2 --memory 4096 --disk-size 50
   podman machine start
   ```

#### Option B: Native WSL2 Terminal
If you use Ubuntu inside WSL2, follow the **Linux (Ubuntu)** instructions directly inside your WSL2 terminal.
Ensure port forwarding is permitted for `5000` (web app) and `5432` (database).

---

### 3.3. macOS Installation (Apple Silicon M1/M2/M3 & Intel)

Podman runs on macOS using a native hypervisor-backed Linux virtual machine.

#### Step 1: Install Podman via Homebrew
```bash
brew install podman podman-compose
# Or install Podman Desktop GUI:
brew install --cask podman-desktop
```

#### Step 2: Initialize and Start the Podman Machine
```bash
# Allocate adequate CPU and RAM for compilation and Postgres:
podman machine init --cpus 2 --memory 4096 --disk-size 50

# Start the machine:
podman machine start
```

#### Step 3: Verify Installation
```bash
podman --version
podman machine list
```

---

## 4. Project Setup & Environment Configuration

### Step 1: Clone or Navigate to the Project Directory
```bash
cd /path/to/DTS
```

### Step 2: Configure Environment Variables
Copy `.env.example` to create your active `.env` file:

```bash
cp .env.example .env
```

Open `.env` in your text editor and review the parameters:

```ini
# Environment Tier (production enforces secure cookies and disables debug modes)
APP_ENV=production

# Cryptographic Secret Key (must be at least 32 characters in production)
SECRET_KEY=ChangeMeSecureProductionSecretKey32CharsLong!

# Database Configuration for Podman PostgreSQL container
POSTGRES_DB=dlp_system
POSTGRES_USER=dlp_user
POSTGRES_PASSWORD=ChangeMeSecureDbPass2026!

# Database URL used by Flask application
DATABASE_URL=postgresql+psycopg://dlp_user:ChangeMeSecureDbPass2026!@dlp-db:5432/dlp_system

# Application Security & Scope Parameters
SESSION_COOKIE_SECURE=false  # Set to true when serving behind HTTPS/TLS reverse proxy
MAX_CONTENT_LENGTH_BYTES=10485760  # 10 MB maximum upload limit
ALLOWED_EXTENSIONS=txt,csv,json,xml,md,log,yaml,yml
LOG_LEVEL=INFO
```

> [!TIP]
> When testing locally over plain `http://localhost:5000` (without an SSL certificate), set `SESSION_COOKIE_SECURE=false` in your `.env` so browser session cookies function correctly over HTTP.

---

## 5. Building and Launching the Platform with Podman

### Step 1: Build the Container Image
Build the container using Podman Compose:

```bash
podman compose build
```
*(Alternatively, you can build directly with `podman build -t dlp-defender:latest .`)*

### Step 2: Start the Multi-Container Services
Launch the PostgreSQL database and the DLP Web application in the background:

```bash
podman compose up -d
```

### Step 3: Verify Container Health & Status
Check that both containers are running and healthy:

```bash
podman compose ps
```

Expected output:
```
NAME               IMAGE                     COMMAND                  SERVICE   STATUS              PORTS
dlp-postgres-db    postgres:16-alpine        postgres                 dlp-db    running (healthy)   0.0.0.0:5432->5432/tcp
dlp-web-app        localhost/dts_dlp-web     gunicorn --bind 0.0...   dlp-web   running (healthy)   0.0.0.0:5000->5000/tcp
```

### Step 4: Inspect Live Logs
```bash
# Follow logs for the web application:
podman compose logs -f dlp-web

# Or inspect database logs:
podman compose logs -f dlp-db
```

---

## 6. Database Initialization & Seeding Inside Podman

Before logging in, apply database migrations and seed baseline accounts:

### Step 1: Apply Database Migrations
Run the Alembic database migration inside the running `dlp-web` container:

```bash
podman compose exec dlp-web flask db upgrade
```

### Step 2: Seed Default Roles, Users, and Baseline Policies
Execute the database seeder to generate baseline DLP policies and role accounts:

```bash
podman compose exec dlp-web python scripts/seed_data.py
```

### Baseline Accounts & API Keys

| Username | Password | Role | Default API Key | Primary Responsibilities |
|---|---|---|---|---|
| **`admin`** | `AdminPass123!@#` | `Admin` | `admin_api_key_default_change_me` | Full platform administration, policy editing, user management, device revocation. |
| **`analyst`** | `AnalystPass123!@#` | `Analyst` | `analyst_api_key_default_change_me` | File scanning, incident investigation, policy simulation, endpoint inventory inspection. |
| **`auditor`** | `AuditorPass123!@#` | `Auditor` | `auditor_api_key_default_change_me` | Read-only compliance inspection, incident review, and immutable security audit logs. |

---

## 7. How to Use the Central DLP Platform

Once launched, access the web platform at:
👉 **`http://localhost:5000`**

### 7.1. Login
Navigate to `http://localhost:5000/auth/login` and log in as `analyst` or `admin`.

### 7.2. Inspecting Files via Web File Scanner
1. Go to **File Scanner** (`/scanning/upload`).
2. Upload a test document (e.g., text, CSV, JSON).
3. The server validates MIME/extension allowlists, extracts text safely in memory, runs all registered detectors, applies redaction, and evaluates policies.
4. If sensitive data (credit cards, secrets, SSNs) is found, an **Incident** is automatically created.

### 7.3. Testing Policies via Simulation Sandbox
1. Go to **Simulation** (`/policies/simulate`).
2. Paste sample text containing potential sensitive patterns.
3. Click **Simulate Scan**.
4. The engine evaluates policies and reports the winning action and rationale without saving incidents.

### 7.4. Incident Investigation & Triage
1. Go to **Incidents** (`/incidents`).
2. View detected incidents with severity tags (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
3. Click an incident to view strictly redacted findings (raw card numbers and secrets are masked with asterisks).
4. Update incident status (`NEW` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`) and add investigation notes.

### 7.5. Reviewing Endpoint Inventory & Security Events
1. Go to **Endpoints** (`/endpoints`) to view enrolled devices, operating systems, agent versions, and last seen timestamps.
2. Go to **Events** (`/events`) to view the centralized endpoint event explorer with filters for Channel (File, USB, Clipboard), Risk Level, and Policy Decision.

---

## 8. Setting Up and Running the Endpoint Agent

The **DLP Endpoint Agent** runs on endpoint machines (Linux, Windows, macOS) and communicates with the central DLP platform running in Podman.

### 8.1. Running the Agent on the Host Machine

#### Step 1: Install Host Python Dependencies
The agent requires Python 3.10+ on the host. In your terminal:
```bash
# If using the project virtual environment:
source .venv/bin/activate
# Or install dependencies:
pip install -e .
```

#### Step 2: Enroll the Endpoint Device
Register the endpoint with the DLP platform running in Podman:
```bash
python scripts/run_agent.py enroll --server-url http://localhost:5000
```
Output:
```
[*] Enrolling device 'workstation' with DLP server at http://localhost:5000...
[+] Enrollment successful!
    Device ID   : ep-45e645478abf4afb
    Agent Token : tok_sec_... (saved to agent_config.json)
```

#### Step 3: Check Agent Status & Connectivity
Verify that the agent can communicate with the Podman container:
```bash
python scripts/run_agent.py status
```
Output shows local scopes, queue depth, and live server connection: `[+] Server Connection : ONLINE (Status: OK)`.

#### Step 4: Run the Endpoint Agent Daemon
Start monitoring configured filesystem directories and removable storage (USB):
```bash
python scripts/run_agent.py run
```
To enable opt-in clipboard monitoring:
```bash
python scripts/run_agent.py run --enable-clipboard
```
*(Press `Ctrl+C` to terminate the agent gracefully).*

#### Step 5: Submit a Synthetic Test Event
Verify the entire ingestion, classification, and risk evaluation pipeline without altering real files:
```bash
# Submit a test removable USB transfer with synthetic credit card data:
python scripts/run_agent.py test-event --type usb --sensitive
```
Expected output:
```
[*] Submitting synthetic usb event (sensitive=True)...
[*] Response Code : 201
[+] Event ingested successfully! Decision: BLOCK | Risk: CRITICAL (97.2/100)
```
Check `http://localhost:5000/events` in your browser to see the live event and incident!

---

### 8.2. Running a Test Agent Inside a Dedicated Podman Container

If you want to simulate multiple isolated endpoints without running code on your host, you can launch a containerized agent:

```bash
podman run --rm -it \
  --network dts_default \
  -e DLP_SERVER_URL=http://dlp-web:5000 \
  localhost/dts_dlp-web \
  python scripts/run_agent.py test-event --type file --sensitive
```

---

## 9. Running Tests, Linters & Security Scans Inside Podman

You can execute the entire automated test suite inside the running container without needing Python installed on your host machine:

### 1. Run Complete Automated Test Suite (67 Tests)
```bash
podman compose exec dlp-web pytest -v
```

### 2. Run End-to-End Clean-Start Smoke Test (14 Workflows)
```bash
podman compose exec dlp-web python scripts/smoke_test.py
```

### 3. Run Static Code Quality & Linter Checks
```bash
podman compose exec dlp-web ruff check .
```

### 4. Run AST Security Vulnerability Audit
```bash
podman compose exec dlp-web bandit -r app agent
```

---

## 10. Stopping, Restarting, and Managing the Podman Stack

### Stop Services (Preserving Database Data)
```bash
podman compose stop
```

### Restart Stopped Services
```bash
podman compose start
```

### Tear Down Containers (Preserving Persistent Database Volume)
```bash
podman compose down
```

### Complete Reset (Removes Containers and Database Volume)
```bash
podman compose down -v
```

---

## 11. Troubleshooting & Platform-Specific Tips

### 11.1. Linux: Rootless File Permissions & SELinux
If you encounter permission issues on Linux with SELinux (Fedora/RHEL):
- Volumes in `compose.yaml` use standard named volumes (`postgres_data`).
- If mounting a local host folder into a container, add the `:z` flag to relabel SELinux contexts (e.g. `- ./data:/data:z`).

### 11.2. Windows: Host-to-Container Network Connection
- From PowerShell or CMD, `http://localhost:5000` maps directly into Podman Machine.
- If running the endpoint agent from within a separate WSL2 distribution, ensure you use `http://localhost:5000` or the Windows host IP (`Get-NetIPAddress`).

### 11.3. macOS: Podman Machine Port Forwarding & Performance
- If `localhost:5000` is unreachable on macOS, verify your Podman machine is running: `podman machine status`.
- To increase memory allocation for intensive test runs:
  ```bash
  podman machine stop
  podman machine set --memory 4096 --cpus 2
  podman machine start
  ```

### 11.4. Database Connection Retries
The `dlp-web` service uses Docker Compose `depends_on` with `condition: service_healthy` on `dlp-db`. The web application will automatically wait until PostgreSQL reports ready via `pg_isready` before starting Gunicorn.

---

## 12. Quick Command Cheat Sheet

| Task | Command |
|---|---|
| **Build images** | `podman compose build` |
| **Start stack in background** | `podman compose up -d` |
| **View running containers** | `podman compose ps` |
| **View web logs** | `podman compose logs -f dlp-web` |
| **Apply DB migrations** | `podman compose exec dlp-web flask db upgrade` |
| **Seed initial database accounts** | `podman compose exec dlp-web python scripts/seed_data.py` |
| **Run all 67 tests** | `podman compose exec dlp-web pytest -v` |
| **Run 14-step smoke test** | `podman compose exec dlp-web python scripts/smoke_test.py` |
| **Enroll host agent** | `python scripts/run_agent.py enroll --server-url http://localhost:5000` |
| **Check agent status** | `python scripts/run_agent.py status` |
| **Run agent daemon** | `python scripts/run_agent.py run` |
| **Test synthetic event** | `python scripts/run_agent.py test-event --type usb --sensitive` |
| **Stop stack** | `podman compose down` |
| **Clean wipe (with volume removal)** | `podman compose down -v` |
