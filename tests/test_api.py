"""Tests for versioned REST API v1 endpoints."""

import json


def test_api_health(client):
    """GET /api/v1/health is public and returns healthy status."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_api_scan_with_api_key(client):
    """POST /api/v1/scan using X-API-Key header."""
    headers = {
        "X-API-Key": "analyst_test_key",
        "Content-Type": "application/json",
    }
    payload = {
        "source_name": "outgoing_ticket.txt",
        "content": "Secret leak: AKIAIOSFODNN7EXAMPLE and email test@dlp.test",
        "simulate": False,
    }
    resp = client.post("/api/v1/scan", data=json.dumps(payload), headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["findings_count"] >= 2
    assert data["policy_evaluation"]["action"] == "BLOCK"
    assert data["incident_created"] is True
    assert data["incident_id"] is not None


def test_api_unauthorized(client):
    """Endpoints require authentication."""
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_api_incidents_crud(client, analyst_client):
    """Test incident listing, detail, and PATCH updates via API."""
    # First create a scan
    headers = {"X-API-Key": "analyst_test_key", "Content-Type": "application/json"}
    scan_resp = client.post(
        "/api/v1/scan",
        data=json.dumps({"content": "Credit card: 4532-0150-1234-5671"}),
        headers=headers,
    )
    inc_id = scan_resp.get_json()["incident_id"]

    # 1. List
    list_resp = analyst_client.get("/api/v1/incidents")
    assert list_resp.status_code == 200
    assert list_resp.get_json()["total"] >= 1

    # 2. Detail
    detail_resp = analyst_client.get(f"/api/v1/incidents/{inc_id}")
    assert detail_resp.status_code == 200
    assert len(detail_resp.get_json()["findings"]) >= 1

    # 3. Patch
    patch_resp = analyst_client.patch(
        f"/api/v1/incidents/{inc_id}",
        data=json.dumps({"status": "FALSE_POSITIVE", "notes": "Approved synthetic test token"}),
        content_type="application/json",
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["status"] == "FALSE_POSITIVE"


def test_api_policy_creation_rbac(client, analyst_client, admin_client):
    """Only Admin role can create new policies via API."""
    new_policy = {
        "name": "API Quarantine Rule",
        "priority": 4,
        "action": "QUARANTINE",
        "severity": "HIGH",
        "match_threshold": 1,
        "target_detectors": ["national_id"],
    }

    # Analyst attempt -> 403 Forbidden
    analyst_resp = analyst_client.post(
        "/api/v1/policies",
        data=json.dumps(new_policy),
        content_type="application/json",
    )
    assert analyst_resp.status_code == 403

    # Admin attempt -> 201 Created
    admin_resp = admin_client.post(
        "/api/v1/policies",
        data=json.dumps(new_policy),
        content_type="application/json",
    )
    assert admin_resp.status_code == 201
    assert admin_resp.get_json()["name"] == "API Quarantine Rule"


def test_api_simulate(analyst_client):
    """POST /api/v1/policies/simulate dry-run test."""
    resp = analyst_client.post(
        "/api/v1/policies/simulate",
        data=json.dumps({"content": "Contact admin at security@dlp.test"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["findings_count"] >= 1
    assert data["evaluation"]["is_simulation"] is True
