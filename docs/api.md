# DLP REST API Reference (v1)

## Base URL
`/api/v1`

## Authentication

API requests support:
1. **Session Cookie:** Active login session (for web client requests).
2. **API Token Header:** `X-API-Key: <token>` for programmatic integrations.

Protected endpoints enforce Role-Based Access Control (RBAC):
- **Auditor:** Read-only access to health, incidents, audit logs, and policies.
- **Analyst:** Auditor permissions + scan submission, incident status updates, and policy simulation.
- **Admin:** Full access, including policy creation, modification, and user management.

---

## 1. Health & Readiness

### `GET /api/v1/health`
Checks application readiness and database connectivity.
- **Access:** Public
- **Response `200 OK`:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "database": "connected",
  "timestamp": "2026-10-15T12:00:00Z"
}
```

---

## 2. Scanning Pipeline

### `POST /api/v1/scan`
Submits text or authorized content to the detection and policy evaluation engine.
- **Access:** Analyst, Admin
- **Request Body:**
```json
{
  "source_name": "outgoing_email_draft.txt",
  "content": "Customer invoice with card 4532-0150-1234-5678 and email user@example.com",
  "simulate": false
}
```
- **Response `200 OK`:**
```json
{
  "scan_id": 1,
  "source_name": "outgoing_email_draft.txt",
  "findings_count": 2,
  "findings": [
    {
      "detector": "credit_card",
      "classification": "PCI_CARD_NUMBER",
      "confidence": 0.95,
      "redacted_value": "************5678",
      "line_number": 1
    },
    {
      "detector": "email",
      "classification": "EMAIL_ADDRESS",
      "confidence": 0.99,
      "redacted_value": "u***@example.com",
      "line_number": 1
    }
  ],
  "policy_evaluation": {
    "action": "BLOCK",
    "severity": "CRITICAL",
    "matched_policy": "PCI-DSS Cardholder Data Protection",
    "rationale": "Matched credit_card threshold >= 1"
  },
  "incident_created": true,
  "incident_id": 12
}
```

---

## 3. Incidents

### `GET /api/v1/incidents`
Lists incidents with optional filtering and pagination.
- **Query Parameters:**
  - `status`: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`
  - `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
  - `page`: default `1`
  - `per_page`: default `20`
- **Response `200 OK`:**
```json
{
  "total": 1,
  "page": 1,
  "per_page": 20,
  "items": [
    {
      "id": 12,
      "title": "Data Leakage Alert: PCI_CARD_NUMBER detected",
      "severity": "CRITICAL",
      "status": "NEW",
      "source_name": "outgoing_email_draft.txt",
      "action_taken": "BLOCK",
      "assigned_to": null,
      "created_at": "2026-10-15T12:00:00Z"
    }
  ]
}
```

### `GET /api/v1/incidents/<id>`
Retrieves full details of a specific incident, including redacted evidence findings.
- **Access:** Auditor, Analyst, Admin

### `PATCH /api/v1/incidents/<id>`
Updates status or analyst assignment for an incident.
- **Access:** Analyst, Admin
- **Request Body:**
```json
{
  "status": "INVESTIGATING",
  "assigned_to_id": 2,
  "notes": "Contacted employee to verify whether test data was used."
}
```

---

## 4. Policies

### `GET /api/v1/policies`
Lists all configured detection policies.
- **Access:** Auditor, Analyst, Admin

### `POST /api/v1/policies`
Creates a new policy rule.
- **Access:** Admin only
- **Request Body:**
```json
{
  "name": "Block AWS Credentials",
  "description": "Block AWS Access Key patterns",
  "enabled": true,
  "priority": 1,
  "target_detectors": ["secret_key"],
  "match_threshold": 1,
  "action": "BLOCK",
  "severity": "CRITICAL"
}
```

### `POST /api/v1/policies/simulate`
Dry-run test against provided text without saving incidents.
- **Access:** Analyst, Admin

---

## 5. Audit Trail

### `GET /api/v1/audit`
Queries security audit event history.
- **Access:** Auditor, Admin
- **Query Parameters:** `action`, `user_id`, `limit`, `offset`

---

## 6. Endpoint Agent & Ingestion API

These endpoints handle agent device lifecycle, health pings, and security event ingestion.

### `POST /api/v1/endpoints/enroll`
Registers an endpoint device with the central DLP platform and issues persistent authentication credentials.
- **Access:** Public / Network accessible to endpoints
- **Rate Limit:** 20 per minute
- **Request Body:**
```json
{
  "hostname": "workstation-alpha",
  "os_name": "Linux",
  "os_version": "Ubuntu 24.04 LTS",
  "agent_version": "0.1.0"
}
```
- **Response `201 Created`:**
```json
{
  "status": "ENROLLED",
  "device_id": "ep-45e645478abf4afb",
  "agent_token": "tok_sec_b97c0da9f921d2be11adfa70f80bc...",
  "server_time": "2026-10-15T12:00:00Z",
  "message": "Endpoint successfully enrolled into DLP Defender platform."
}
```

### `POST /api/v1/endpoints/heartbeat`
Agent heartbeat report updating `last_seen_at`, connectivity status, and queue depth.
- **Access:** Enrolled Agent (`X-Device-ID`, `X-Device-Token`)
- **Request Body:**
```json
{
  "device_id": "ep-45e645478abf4afb",
  "agent_version": "0.1.0",
  "queue_depth": 0,
  "status": "OK"
}
```
- **Response `200 OK`:**
```json
{
  "status": "ACKNOWLEDGED",
  "device_status": "ENROLLED",
  "policy_version": 1,
  "server_time": "2026-10-15T12:00:30Z"
}
```

### `POST /api/v1/endpoints/events`
Authenticated ingestion endpoint for endpoint security events (file activity, removable USB media, opt-in clipboard).
- **Access:** Enrolled Agent (`X-Device-ID`, `X-Device-Token`)
- **Headers:**
  - `X-Device-ID: ep-45e645478abf4afb`
  - `X-Device-Token: tok_sec_...`
- **Request Body:**
```json
{
  "event_id": "evt-72d8a01bc24",
  "schema_version": "1.0.0",
  "device_id": "ep-45e645478abf4afb",
  "channel": "removable_media",
  "operation": "file_transferred",
  "file_name": "client_cards.csv",
  "file_type": "csv",
  "file_size_bytes": 1024,
  "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "destination_type": "external_usb",
  "destination_path": "/media/usb_drive",
  "content_sample": "Card Number: 4532-0150-1234-5671"
}
```
- **Response `201 Created` (or `200 OK` if duplicate `event_id` replayed):**
```json
{
  "status": "PROCESSED",
  "event_id": "evt-72d8a01bc24",
  "decision": "BLOCK",
  "enforcement_status": "NOT_ENFORCED",
  "classification": "RESTRICTED",
  "risk_score": 97.2,
  "risk_level": "CRITICAL",
  "incident_id": 15,
  "decision_reason": "Matched policy: Block Credit Cards",
  "risk_factors": [
    "Restricted data classification (+50)",
    "Removable storage / USB egress channel (+25)",
    "1 sensitive finding(s) with 95% avg confidence (+3.8)",
    "Critical policy severity triggered (+15)"
  ]
}
```

### `GET /api/v1/endpoints`
Lists enrolled endpoint inventory.
- **Access:** Analyst, Admin, Auditor (`X-API-Key` or session)
- **Response `200 OK`:** List of device objects.

### `GET /api/v1/endpoints/<device_id>`
Retrieves single device information and its last 20 security events.
- **Access:** Analyst, Admin, Auditor

### `POST /api/v1/endpoints/<device_id>/revoke`
Revokes an endpoint device credential. Revoked devices are prevented from submitting events (HTTP 403).
- **Access:** Admin only

