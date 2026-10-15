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
