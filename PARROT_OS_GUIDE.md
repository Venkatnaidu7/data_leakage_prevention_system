# Parrot OS DLP Operator & Access Guide

This guide provides end-to-end instructions for running, operating, and verifying the **DTS Data Leakage Prevention (DLP)** platform on **Parrot Security OS** (version 7.4 "echo", Debian 13 base) using rootless **Podman**.

---

## 1. Quick Status & Verification

The platform is already built and running on your Parrot OS system with rootless Podman:

| Service | Container Name | Image | Port | Health Status |
| :--- | :--- | :--- | :--- | :--- |
| **DLP Central Web App** | `dlp-web-app` | `docker.io/library/dts-dlp-web:latest` | `http://localhost:5000` | **Healthy** (HTTP 200) |
| **PostgreSQL Database** | `dlp-postgres-db` | `docker.io/library/postgres:16-alpine` | `localhost:5432` | **Healthy** (Port open) |

### Check System Health in Terminal

Open a terminal in `/home/robin/Documents/DTS` and run:

```bash
# 1. Verify running containers
podman ps

# 2. Query the HTTP Health Check endpoint
curl -s http://localhost:5000/api/v1/health | jq .
```

Expected output:
```json
{
  "database": "connected",
  "status": "healthy",
  "timestamp": "2026-10-15T09:29:37.921965+00:00",
  "version": "0.1.0"
}
```

---

## 2. The Three User Accounts: Credentials & Access

The platform comes pre-seeded with three distinct role-based accounts designed for clear separation of duties:

| Role | Username | Password | API Key (`X-API-Key`) | Primary Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `AdminPass123!@#` | `dev_admin_api_key_12345` | Full platform control, rule authoring, device revocation |
| **Security Analyst** | `analyst` | `AnalystPass123!@#` | `dev_analyst_api_key_67890` | Incident triage, investigation, evidence analysis, on-demand scanning |
| **Compliance Auditor** | `auditor` | `AuditorPass123!@#` | `dev_auditor_api_key_abcde` | Read-only compliance review, tamper-evident audit log inspection |

### Web Sign-In URL
Open your web browser (Firefox on Parrot OS) and navigate to:
**`http://localhost:5000/auth/login`**

---

## 3. Account-by-Account Workflows & Permissions

### Account 1: Administrator (`admin`)
* **Login**: `admin` / `AdminPass123!@#`
* **Intended For**: Security Directors, Lead SecOps Engineers, Platform Admins.

#### Permitted Actions:
1. **Policy Management (`/policies`)**:
   - Create new detection policies (`/policies/new`).
   - Edit match thresholds, severity levels, and automated actions (`BLOCK`, `QUARANTINE`, `ESCALATE`, `LOG`).
   - Enable or disable active policies using the toggle switch.
   - Delete obsolete policies.
2. **Endpoint Device Management (`/endpoints`)**:
   - View enrolled devices.
   - **Revoke / Un-revoke devices** (`/endpoints/<id>/revoke`): If an endpoint is compromised, Admin can immediately revoke its authorization token.
3. **Incident Investigation (`/incidents`)**:
   - View all incidents with redacted sensitive findings.
   - Assign incidents, change status to `CONFIRMED_LEAK`, `FALSE_POSITIVE`, or `RESOLVED`, and add resolution notes.
   - Export incidents to CSV or JSON.
4. **On-Demand Scanning (`/scanning/upload`)**:
   - Upload suspicious files or paste raw text for immediate DLP scanning.
5. **Audit Logs (`/audit`)**:
   - Full visibility into the append-only audit trail recording every user login, policy update, and administrative action.

#### How to Test Admin Capabilities:
1. Log in as `admin`.
2. Click **Policies** in the top navigation bar.
3. Click **+ Create Policy** (`http://localhost:5000/policies/new`).
4. Enter Name: `Test Admin Policy`, Action: `BLOCK`, Severity: `HIGH`, select `credit_card`, and save.
5. Notice the success message and notice that a new audit record was created under **Audit Logs**.

---

### Account 2: Security Analyst (`analyst`)
* **Login**: `analyst` / `AnalystPass123!@#`
* **Intended For**: Tier 1/2 SOC Analysts, Incident Responders.

#### Permitted Actions:
1. **Incident Triage & Resolution (`/incidents`)**:
   - View the incident queue, filter by severity (`CRITICAL`, `HIGH`, etc.) and status (`NEW`, `INVESTIGATING`).
   - Open incident details (`/incidents/<id>`) to inspect privacy-redacted snippets (e.g., card numbers masked as `****-****-****-5671`).
   - Assign incidents to themselves or peers.
   - Update incident status (`INVESTIGATING`, `CONFIRMED_LEAK`, `FALSE_POSITIVE`, `RESOLVED`) and enter detailed investigation notes.
   - Export incidents to CSV for external ticketing systems.
2. **On-Demand Scanner (`/scanning/upload`)**:
   - Upload files or paste text to verify if customer or internal documents contain unredacted secrets or PII.
3. **Policy Simulation (`/policies/simulate`)**:
   - Test text against policies in dry-run mode without modifying policies or triggering real incident alerts.
4. **Endpoint & Event Visibility (`/endpoints`, `/events`)**:
   - Monitor live incoming telemetry from enrolled endpoint devices.

#### Forbidden Actions (RBAC Enforced):
* **Cannot modify policies**: Visiting `/policies/new` returns **HTTP 403 Forbidden**.
* **Cannot revoke devices**: The "Revoke" button is not functional for analysts; direct requests return **HTTP 403 Forbidden**.
* **Cannot view Audit Logs**: The "Audit Logs" link is hidden from the navigation bar; navigating directly to `http://localhost:5000/audit` returns **HTTP 403 Forbidden**.

#### How to Test Analyst Permissions:
1. Sign out and log in as `analyst`.
2. Click **File Scanner** in the navigation bar. Paste a mock credit card number (`4532-0150-1234-5671`) and click **Scan Content**. Observe that the scan completes and detects `credit_card`.
3. Open **Incidents** (`/incidents`). Select the newest incident, update its status to `INVESTIGATING`, and add the note: `Triaging leaked credit card event`. Click **Update Incident**.
4. Now test the restriction: Type `http://localhost:5000/audit` into your browser address bar.
   - **Result**: You will see an **HTTP 403 Forbidden** page stating access is restricted.

---

### Account 3: Compliance Auditor (`auditor`)
* **Login**: `auditor` / `AuditorPass123!@#`
* **Intended For**: Internal Compliance Officers, Privacy Officers (GDPR/PCI-DSS), External Regulators.

#### Permitted Actions:
1. **Audit Logs (`/audit`)**:
   - Full access to the immutable compliance audit log.
   - Search by user or action (e.g., `POLICY_CREATED`, `INCIDENT_UPDATED`, `DEVICE_REVOKED`, `LOGIN_SUCCESS`).
2. **Read-Only Incident Inspection (`/incidents`)**:
   - Review all logged incidents and verify that sensitive data was properly redacted in accordance with privacy requirements.
3. **Read-Only Policy Review (`/policies`)**:
   - Inspect active DLP protection rules and thresholds to verify regulatory alignment (PCI-DSS, PII, Secret leakage).
4. **Policy Simulation (`/policies/simulate`)**:
   - Run safe, non-destructive test simulations to verify policy logic.
5. **Read-Only Device & Event Inventory (`/endpoints`, `/events`)**:
   - Review connected devices and raw event telemetry.

#### Forbidden Actions (RBAC Enforced):
* **Cannot perform on-demand scanning**: Navigating to `http://localhost:5000/scanning/upload` returns **HTTP 403 Forbidden**.
* **Cannot modify incident status**: The incident update form is disabled/hidden; posting an update returns **HTTP 403 Forbidden**.
* **Cannot create/edit/delete policies**: Returns **HTTP 403 Forbidden**.
* **Cannot revoke devices**: Returns **HTTP 403 Forbidden**.

#### How to Test Auditor Permissions:
1. Sign out and log in as `auditor`.
2. Click **Audit Logs** in the navigation bar (`http://localhost:5000/audit`).
3. Filter by Action: `INCIDENT_UPDATED` or User: `analyst` to observe analyst actions.
4. Now test the restriction: In your browser URL bar, navigate to `http://localhost:5000/scanning/upload`.
   - **Result**: You will immediately receive an **HTTP 403 Forbidden** response because auditors are strictly restricted to compliance review.

---

## 4. Role-Based Access Control (RBAC) Matrix

| Feature / URL Route | Admin (`admin`) | Analyst (`analyst`) | Auditor (`auditor`) |
| :--- | :---: | :---: | :---: |
| **Security Dashboard** (`/`) | Allowed | Allowed | Allowed |
| **Endpoint Inventory** (`/endpoints`) | Full Access | Read-Only | Read-Only |
| **Revoke Device** (`POST /endpoints/<id>/revoke`) | **Allowed** | Denied (403) | Denied (403) |
| **Endpoint Event Stream** (`/events`) | Full Access | Full Access | Read-Only |
| **File & Text Scanner** (`/scanning/upload`) | **Allowed** | **Allowed** | Denied (403) |
| **View Incidents** (`/incidents`) | Full Access | Full Access | Read-Only |
| **Update Incident Status** (`POST /incidents/<id>/update`) | **Allowed** | **Allowed** | Denied (403) |
| **Export Incidents (CSV)** (`/incidents/export/csv`) | Allowed | Allowed | Allowed |
| **View DLP Policies** (`/policies`) | Full Access | Read-Only | Read-Only |
| **Create/Edit/Toggle Policy** (`/policies/new`, etc.) | **Allowed** | Denied (403) | Denied (403) |
| **Policy Simulation Sandbox** (`/policies/simulate`) | Allowed | Allowed | Allowed |
| **Audit Logs Explorer** (`/audit`) | **Allowed** | Denied (403) | **Allowed** |

---

## 5. Testing the Endpoint Agent on Parrot OS

The endpoint agent is located under `scripts/run_agent.py`. It can monitor directories, inspect USB mounts, process clipboard activity, and report findings to the central server.

### Step 1: Check Local Agent Status & Heartbeat

In your Parrot OS terminal:

```bash
cd /home/robin/Documents/DTS
python scripts/run_agent.py status
```

Output will show the enrolled device status:
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

*(Note: If the device is not enrolled yet, run `python scripts/run_agent.py enroll --server-url http://localhost:5000`)*

---

### Step 2: Simulate Exfiltration Scenarios

#### Scenario A: Sensitive Data Transfer to USB (Expected: BLOCK)
Simulate an employee copying cardholder data and API keys to an external USB flash drive:

```bash
python scripts/run_agent.py test-event --type usb --sensitive
```

Expected response in terminal:
```text
[*] Submitting synthetic usb event (sensitive=True)...
[*] Response Code : 201
[*] Response Body : {
  "decision": "BLOCK",
  "device_id": "ep-885d5b74265b4805",
  "event_id": "evt-...",
  "incident_id": ...,
  "policy_action": "BLOCK",
  "risk_level": "CRITICAL",
  "risk_score": 100.0,
  "status": "PROCESSED"
}
[!] DLP ACTION ENFORCED: BLOCK
[!] Risk Level: CRITICAL (Score: 100.0/100)
```

Now open your browser to **`http://localhost:5000/incidents`**:
- A **CRITICAL** incident will appear at the top of the queue: `Endpoint USB Policy Match: PCI-DSS Cardholder Data Protection`.
- Click on it to inspect the redacted findings: `4532-****-****-5671`.

---

#### Scenario B: Benign File Operation (Expected: ALLOW)
Simulate normal day-to-day employee file editing:

```bash
python scripts/run_agent.py test-event --type file
```

Expected response:
```text
[*] Response Code : 201
[+] DLP Action: ALLOW (Risk: INFORMATIONAL, Score: 0.0/100)
```

---

#### Scenario C: Sensitive Clipboard Copy (Expected: BLOCK / HIGH RISK)
Simulate copying sensitive text to system clipboard:

```bash
python scripts/run_agent.py test-event --type clipboard --sensitive
```

Expected response:
```text
[*] Response Code : 201
[!] DLP ACTION ENFORCED: BLOCK
[!] Risk Level: CRITICAL (Score: 100.0/100)
```

---

### Step 3: Run the Continuous Monitoring Daemon

To run the endpoint agent in live monitoring mode (watching `./monitored_data` and `./mock_usb`):

```bash
python scripts/run_agent.py run --poll-interval 2.0
```

To test live exfiltration detection:
1. Open a second terminal window.
2. Write a mock sensitive file into `./monitored_data`:
   ```bash
   echo "Client Secret: AKIAIOSFODNN7EXAMPLE Card: 4532-0150-1234-5671" > /home/robin/Documents/DTS/monitored_data/leak.txt
   ```
3. Look at the agent terminal: it will immediately detect the file, analyze it, stream the telemetry to the central server, and flag the event.
4. Press `Ctrl+C` in the agent terminal to stop the monitor when done.

---

## 6. Testing the REST API Directly via cURL

You can interact with the DLP backend directly via terminal using the pre-configured API keys:

### 1. Perform a Text Scan via API (Analyst or Admin Key)
```bash
curl -s -X POST http://localhost:5000/api/v1/scans/text \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev_analyst_api_key_67890" \
  -d '{
    "content": "Emergency transfer to card 4532-0150-1234-5671 on file.",
    "source_name": "api_test.txt"
  }' | jq .
```

### 2. Query Incident List via API
```bash
curl -s -X GET http://localhost:5000/api/v1/incidents \
  -H "X-API-Key: dev_analyst_api_key_67890" | jq .
```

### 3. Query Audit Logs via API (Auditor or Admin Key)
```bash
curl -s -X GET http://localhost:5000/api/v1/audit \
  -H "X-API-Key: dev_auditor_api_key_abcde" | jq .
```

*(Note: If you run this query with `dev_analyst_api_key_67890`, the API will return HTTP 403 Forbidden).*

---

## 7. Podman Operations & Maintenance on Parrot OS

### Common Commands

| Action | Command | Notes |
| :--- | :--- | :--- |
| **Check container status** | `podman ps` | Verifies container ports and health probes |
| **View Web App logs** | `podman logs -f dlp-web-app` | Live stream of Gunicorn & Flask logs |
| **View Database logs** | `podman logs -f dlp-postgres-db` | Live stream of PostgreSQL queries |
| **Stop platform** | `podman compose down` | Stops and removes containers, keeps data safe in volume |
| **Start platform** | `podman compose up -d` | Starts containers in background |
| **Restart Web App** | `podman restart dlp-web-app` | Fast restart without touching the database |
| **Reset Database to Default** | `podman compose exec dlp-web python scripts/seed_data.py` | Restores default users and policies |

### Important Parrot OS Tips:
1. **Never prefix with `bash`**: Run `podman compose up -d` or `podman build -t dlp-defender:latest .`. Do not run `bash podman`.
2. **Context directory dot**: Always include the trailing `.` when building images (`podman build -t dlp-defender:latest .`).
3. **Rootless Socket**: The socket is managed by user systemd:
   ```bash
   systemctl --user status podman.socket
   ```
   If ever stopped, re-enable with: `systemctl --user enable --now podman.socket`.
