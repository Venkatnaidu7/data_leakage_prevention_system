"""End-to-end clean-start smoke test script following README instructions."""

import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models.audit import AuditLog
from app.models.incident import Incident, IncidentStatus
from app.models.policy import Policy
from app.models.user import User


def run_smoke_test():
    print("==================================================")
    print("STARTING DLP DEFENDER END-TO-END SMOKE TEST")
    print("==================================================")

    # 1. Setup clean testing environment
    test_db = Path("dlp_smoke.db")
    if test_db.exists():
        test_db.unlink()

    app = create_app(
        test_config={
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{test_db.resolve()}",
            "SECRET_KEY": "smoke-test-secret-key-32-chars-long!",
            "WTF_CSRF_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
            "RATELIMIT_ENABLED": False,
        }
    )

    with app.app_context():
        # Step 1: Database Migration / Table Creation
        print("\n[Step 1] Initializing database tables...")
        db.create_all()
        print("✓ Database tables created successfully.")

        # Step 2: Seed default roles, policies, and users
        print("\n[Step 2] Seeding initial data...")
        from scripts.seed_data import seed

        # Seed data in this app context
        users_config = [
            ("admin", "admin@dlp.local", "AdminPass123!@#", "admin", "admin_key_smoke"),
            ("analyst", "analyst@dlp.local", "AnalystPass123!@#", "analyst", "analyst_key_smoke"),
            ("auditor", "auditor@dlp.local", "AuditorPass123!@#", "auditor", "auditor_key_smoke"),
        ]
        for uname, email, pwd, role, key in users_config:
            u = User(username=uname, email=email, role=role, api_key=key)
            u.set_password(pwd)
            db.session.add(u)

        # Baseline policies
        p_card = Policy(
            name="Smoke PCI Card Blocker",
            priority=1,
            action="BLOCK",
            severity="CRITICAL",
            match_threshold=1,
            enabled=True,
        )
        p_card.target_detectors = ["credit_card"]
        db.session.add(p_card)
        db.session.commit()
        print("✓ Seeded users and baseline policies.")

    client = app.test_client()

    # Step 3: Health Endpoint Check
    print("\n[Step 3] Checking Health Endpoint (GET /api/v1/health)...")
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200, f"Expected 200, got {health_resp.status_code}"
    health_data = health_resp.get_json()
    assert health_data["status"] == "healthy"
    assert health_data["database"] == "connected"
    print(f"✓ Health Check Passed: {health_data}")

    # Step 4: Authentication & Session Management
    print("\n[Step 4] Testing User Authentication (POST /auth/login)...")
    login_resp = client.post(
        "/auth/login",
        data={"username_or_email": "analyst", "password": "AnalystPass123!@#"},
        follow_redirects=True,
    )
    assert login_resp.status_code == 200
    assert b"Welcome back, analyst" in login_resp.data
    print("✓ Analyst successfully authenticated and session established.")

    # Step 5: Content Scan Submission
    print("\n[Step 5] Submitting Content Scan with PCI Card & Email...")
    scan_payload = {
        "source_name": "smoke_test_payload.txt",
        "content": "Invoice customer payment: Card 4532-0150-1234-5671 and contact analyst@dlp.local",
        "simulate": False,
    }
    scan_resp = client.post(
        "/api/v1/scan",
        data=json.dumps(scan_payload),
        headers={"Content-Type": "application/json", "X-API-Key": "analyst_key_smoke"},
    )
    assert scan_resp.status_code == 200, f"Expected 200, got {scan_resp.status_code}: {scan_resp.data}"
    scan_data = scan_resp.get_json()
    assert scan_data["findings_count"] >= 2
    assert scan_data["policy_evaluation"]["action"] == "BLOCK"
    assert scan_data["incident_created"] is True
    incident_id = scan_data["incident_id"]
    print(f"✓ Scan completed: {scan_data['findings_count']} findings, Action: {scan_data['policy_evaluation']['action']}")
    print(f"✓ Incident #{incident_id} created.")

    # Step 6: Verify Redaction and Incident Detail
    print("\n[Step 6] Inspecting Incident Detail & Redaction (GET /api/v1/incidents/<id>)...")
    inc_resp = client.get(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-API-Key": "analyst_key_smoke"},
    )
    assert inc_resp.status_code == 200
    inc_data = inc_resp.get_json()
    assert inc_data["status"] == "NEW"
    assert len(inc_data["findings"]) >= 2
    # Check that all findings are masked
    for finding in inc_data["findings"]:
        assert "*" in finding["redacted_value"]
        print(f"  - Verified redacted finding: [{finding['detector_name']}] -> {finding['redacted_value']}")
    print("✓ All sensitive findings confirmed strictly redacted.")

    # Step 7: Incident Triage & Resolution Workflow
    print("\n[Step 7] Triaging Incident (PATCH /api/v1/incidents/<id>)...")
    patch_resp = client.patch(
        f"/api/v1/incidents/{incident_id}",
        data=json.dumps({"status": "RESOLVED", "notes": "Smoke test verified and resolved."}),
        headers={"Content-Type": "application/json", "X-API-Key": "analyst_key_smoke"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["status"] == "RESOLVED"
    print("✓ Incident successfully updated to RESOLVED with investigation notes.")

    # Step 8: Policy Simulation Mode
    print("\n[Step 8] Testing Dry-Run Policy Simulation (POST /api/v1/policies/simulate)...")
    sim_resp = client.post(
        "/api/v1/policies/simulate",
        data=json.dumps({"content": "Test card 4532-0150-1234-5671"}),
        headers={"Content-Type": "application/json", "X-API-Key": "analyst_key_smoke"},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.get_json()
    assert sim_data["evaluation"]["is_simulation"] is True
    print(f"✓ Simulation Dry-Run verified: Proposed Action: {sim_data['evaluation']['action']}, Sim Flag: True")

    # Step 9: Audit Trail Verification
    print("\n[Step 9] Querying Immutable Audit Trail (GET /api/v1/audit)...")
    audit_resp = client.get(
        "/api/v1/audit",
        headers={"X-API-Key": "auditor_key_smoke"},
    )
    assert audit_resp.status_code == 200
    audit_data = audit_resp.get_json()
    assert audit_data["total"] >= 1
    actions_recorded = [a["action"] for a in audit_data["items"]]
    print(f"✓ Audit events verified ({audit_data['total']} total recorded): {set(actions_recorded)}")

    # Clean up test database
    if test_db.exists():
        test_db.unlink()

    print("\n==================================================")
    print("ALL SMOKE TEST WORKFLOWS COMPLETED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_smoke_test()
