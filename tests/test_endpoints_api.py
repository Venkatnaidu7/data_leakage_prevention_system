"""Tests for Endpoint DLP Agent API, Event Ingestion, Lifecycle, and UI."""

import json

from app.extensions import db
from app.models.endpoint import DeviceStatus, EndpointDevice, EndpointEvent
from app.models.incident import Incident


def test_endpoint_enrollment_success(client):
    """Device enrollment creates an EndpointDevice record and returns credentials."""
    payload = {
        "hostname": "workstation-alpha",
        "os_name": "Linux",
        "os_version": "Ubuntu 24.04",
        "agent_version": "0.1.0",
    }
    resp = client.post("/api/v1/endpoints/enroll", json=payload)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["status"] == "ENROLLED"
    assert "device_id" in data
    assert "agent_token" in data
    assert data["device_id"].startswith("ep-")

    # Verify device persisted in database
    device = EndpointDevice.query.filter_by(device_id=data["device_id"]).first()
    assert device is not None
    assert device.hostname == "workstation-alpha"
    assert device.status == DeviceStatus.ENROLLED.value
    assert device.agent_auth_token == data["agent_token"]


def test_endpoint_enrollment_validation_failure(client):
    """Invalid enrollment schema returns 400 Bad Request."""
    resp = client.post("/api/v1/endpoints/enroll", json={"hostname": ""})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data


def test_endpoint_heartbeat_lifecycle(client):
    """Enrolled device can send heartbeats and receive policy sync."""
    # 1. Enroll
    enroll_resp = client.post(
        "/api/v1/endpoints/enroll",
        json={"hostname": "dev-box", "os_name": "Linux", "agent_version": "0.1.0"},
    )
    assert enroll_resp.status_code == 201
    creds = enroll_resp.get_json()

    # 2. Heartbeat with credentials
    headers = {
        "X-Device-ID": creds["device_id"],
        "X-Device-Token": creds["agent_token"],
    }
    hb_payload = {
        "device_id": creds["device_id"],
        "agent_version": "0.1.0",
        "queue_depth": 3,
        "status": "OK",
    }
    resp = client.post("/api/v1/endpoints/heartbeat", json=hb_payload, headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ACKNOWLEDGED"
    assert "policy_version" in data

    # 3. Heartbeat with wrong token returns 401
    bad_headers = {
        "X-Device-ID": creds["device_id"],
        "X-Device-Token": "invalid_wrong_token",
    }
    resp_bad = client.post("/api/v1/endpoints/heartbeat", json=hb_payload, headers=bad_headers)
    assert resp_bad.status_code == 401

    # 4. Unknown device returns 404
    unknown_headers = {
        "X-Device-ID": "ep-nonexistent",
        "X-Device-Token": "some-token",
    }
    hb_payload["device_id"] = "ep-nonexistent"
    resp_unknown = client.post("/api/v1/endpoints/heartbeat", json=hb_payload, headers=unknown_headers)
    assert resp_unknown.status_code == 404


def test_endpoint_event_ingestion_benign(client):
    """Benign event with no sensitive findings is marked ALLOW with low risk and no incident."""
    # Enroll
    enroll_resp = client.post(
        "/api/v1/endpoints/enroll",
        json={"hostname": "laptop-01", "os_name": "Linux", "agent_version": "0.1.0"},
    )
    creds = enroll_resp.get_json()
    headers = {
        "X-Device-ID": creds["device_id"],
        "X-Device-Token": creds["agent_token"],
    }

    event_payload = {
        "event_id": "evt-benign-001",
        "schema_version": "1.0.0",
        "device_id": creds["device_id"],
        "channel": "file",
        "operation": "created",
        "file_name": "readme.txt",
        "file_path": "/home/user/docs/readme.txt",
        "file_size_bytes": 120,
        "content_sample": "This is a benign project document with no confidential data.",
    }

    resp = client.post("/api/v1/endpoints/events", json=event_payload, headers=headers)
    assert resp.status_code == 201
    data = resp.get_json()

    assert data["status"] == "PROCESSED"
    assert data["classification"] == "PUBLIC"
    assert data["decision"] == "ALLOW"
    assert data["risk_level"] == "LOW"
    assert data["incident_id"] is None

    # Verify event record in DB
    db_event = EndpointEvent.query.filter_by(event_id="evt-benign-001").first()
    assert db_event is not None
    assert db_event.channel == "file"
    assert db_event.classification == "PUBLIC"


def test_endpoint_event_ingestion_sensitive_pci_card(client):
    """Event containing credit card number triggers RESTRICTED classification, policy match, and incident."""
    enroll_resp = client.post(
        "/api/v1/endpoints/enroll",
        json={"hostname": "finance-pc", "os_name": "Windows", "agent_version": "0.1.0"},
    )
    creds = enroll_resp.get_json()
    headers = {
        "X-Device-ID": creds["device_id"],
        "X-Device-Token": creds["agent_token"],
    }

    # Synthetic Luhn-valid credit card
    card_number = "4532-0150-1234-5671"
    event_payload = {
        "event_id": "evt-pci-alert-002",
        "schema_version": "1.0.0",
        "device_id": creds["device_id"],
        "channel": "removable_media",
        "operation": "file_transferred",
        "file_name": "customer_export.csv",
        "destination_type": "external_usb",
        "destination_path": "/media/usb_stick",
        "content_sample": f"Customer Card: {card_number}\nAmount: $500",
    }

    resp = client.post("/api/v1/endpoints/events", json=event_payload, headers=headers)
    assert resp.status_code == 201
    data = resp.get_json()

    assert data["status"] == "PROCESSED"
    assert data["classification"] == "RESTRICTED"
    assert data["decision"] == "BLOCK"
    assert data["enforcement_status"] == "NOT_ENFORCED"
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert data["incident_id"] is not None

    # Verify incident was created
    incident = db.session.get(Incident, data["incident_id"])
    assert incident is not None
    assert incident.action_taken == "BLOCK"
    assert incident.matched_policy_name == "Block Credit Cards"

    # Verify Privacy Guarantee: Raw credit card number MUST NOT be in incident or event records
    assert card_number not in incident.description
    for f in incident.findings:
        assert card_number != f.redacted_value
        assert "*" in f.redacted_value

    db_event = EndpointEvent.query.filter_by(event_id="evt-pci-alert-002").first()
    assert db_event is not None
    findings_json_str = json.dumps(db_event.detector_findings)
    assert card_number not in findings_json_str


def test_endpoint_event_idempotency(client):
    """Replaying an identical event_id returns existing decision without duplicating incidents."""
    enroll_resp = client.post(
        "/api/v1/endpoints/enroll",
        json={"hostname": "test-box", "os_name": "Linux", "agent_version": "0.1.0"},
    )
    creds = enroll_resp.get_json()
    headers = {
        "X-Device-ID": creds["device_id"],
        "X-Device-Token": creds["agent_token"],
    }

    event_payload = {
        "event_id": "evt-idempotent-003",
        "schema_version": "1.0.0",
        "device_id": creds["device_id"],
        "channel": "file",
        "operation": "created",
        "file_name": "secret.txt",
        "content_sample": "AWS Key: AKIAIOSFODNN7EXAMPLE",
    }

    # First submission
    resp1 = client.post("/api/v1/endpoints/events", json=event_payload, headers=headers)
    assert resp1.status_code == 201
    data1 = resp1.get_json()
    assert data1["incident_id"] is not None

    incidents_count_before = Incident.query.count()

    # Second submission (replay)
    resp2 = client.post("/api/v1/endpoints/events", json=event_payload, headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["status"] == "DUPLICATE_ACKNOWLEDGED"
    assert data2["event_id"] == "evt-idempotent-003"
    assert data2["decision"] == data1["decision"]

    # Verify no new incident created
    incidents_count_after = Incident.query.count()
    assert incidents_count_after == incidents_count_before


def test_endpoint_revocation_enforcement(client, admin_client):
    """Revoked device is prohibited from submitting events and heartbeats."""
    enroll_resp = client.post(
        "/api/v1/endpoints/enroll",
        json={"hostname": "compromised-pc", "os_name": "Linux", "agent_version": "0.1.0"},
    )
    creds = enroll_resp.get_json()
    device_id = creds["device_id"]
    headers = {
        "X-Device-ID": device_id,
        "X-Device-Token": creds["agent_token"],
    }

    # Admin revokes the device
    revoke_resp = admin_client.post(f"/api/v1/endpoints/{device_id}/revoke")
    assert revoke_resp.status_code == 200
    assert revoke_resp.get_json()["status"] == "REVOKED"

    # Heartbeat attempt by revoked device returns 403
    hb_resp = client.post(
        "/api/v1/endpoints/heartbeat",
        json={"device_id": device_id, "agent_version": "0.1.0"},
        headers=headers,
    )
    assert hb_resp.status_code == 403

    # Event submission attempt by revoked device returns 403
    evt_resp = client.post(
        "/api/v1/endpoints/events",
        json={
            "event_id": "evt-revoked-004",
            "device_id": device_id,
            "channel": "file",
            "operation": "created",
            "file_name": "test.txt",
        },
        headers=headers,
    )
    assert evt_resp.status_code == 403


def test_endpoint_inventory_and_detail_api(admin_client):
    """Admin/Analyst can list inventory and view device details via API."""
    # List devices
    resp = admin_client.get("/api/v1/endpoints")
    assert resp.status_code == 200
    devices = resp.get_json()
    assert isinstance(devices, list)

    # Get device detail
    if devices:
        dev_id = devices[0]["device_id"]
        detail_resp = admin_client.get(f"/api/v1/endpoints/{dev_id}")
        assert detail_resp.status_code == 200
        data = detail_resp.get_json()
        assert data["device_id"] == dev_id
        assert "recent_events" in data


def test_endpoint_web_views(client, analyst_client):
    """Web views for endpoints inventory and event explorer require authentication."""
    # Unauthenticated user redirected to login
    resp_unauth = client.get("/endpoints")
    assert resp_unauth.status_code == 302
    assert "/auth/login" in resp_unauth.headers["Location"]

    # Authenticated user can view inventory
    resp_inv = analyst_client.get("/endpoints")
    assert resp_inv.status_code == 200
    assert b"Endpoint Device Inventory" in resp_inv.data

    # Authenticated user can view event explorer
    resp_events = analyst_client.get("/events")
    assert resp_events.status_code == 200
    assert b"Endpoint Event Explorer" in resp_events.data
