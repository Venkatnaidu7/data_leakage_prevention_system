"""Incident workflow and triage tests."""

from app.extensions import db
from app.models.audit import AuditLog
from app.models.incident import Incident, IncidentFinding, IncidentStatus
from app.models.user import User


def test_incident_lifecycle_and_triage(app, analyst_client):
    """Test incident triage update and status transitions."""
    with app.app_context():
        incident = Incident(
            title="DLP Alert: Cardholder Data",
            severity="CRITICAL",
            status=IncidentStatus.NEW.value,
            source_name="checkout.log",
            action_taken="BLOCK",
        )
        db.session.add(incident)
        db.session.flush()

        finding = IncidentFinding(
            incident_id=incident.id,
            detector_name="credit_card",
            classification="PCI_CARD_NUMBER",
            confidence=0.95,
            redacted_value="************5678",
            line_number=4,
        )
        db.session.add(finding)
        db.session.commit()
        inc_id = incident.id

    # 1. View incident detail
    resp = analyst_client.get(f"/incidents/{inc_id}")
    assert resp.status_code == 200
    assert b"checkout.log" in resp.data
    assert b"************5678" in resp.data

    # 2. Update status to INVESTIGATING with notes
    analyst_user = User.query.filter_by(username="analyst").first()
    post_resp = analyst_client.post(
        f"/incidents/{inc_id}/update",
        data={
            "status": IncidentStatus.INVESTIGATING.value,
            "assigned_to_id": analyst_user.id,
            "resolution_notes": "Confirmed synthetic test transaction.",
        },
        follow_redirects=True,
    )
    assert post_resp.status_code == 200

    # 3. Verify updated in DB
    updated_inc = db.session.get(Incident, inc_id)
    assert updated_inc.status == IncidentStatus.INVESTIGATING.value
    assert updated_inc.assigned_to_id == analyst_user.id
    assert "Confirmed synthetic test transaction" in updated_inc.resolution_notes


def test_auditor_cannot_update_incident(app, auditor_client):
    """Auditor role must receive 403 Forbidden on update attempt."""
    with app.app_context():
        incident = Incident(
            title="Auditor Test Alert",
            severity="LOW",
            status=IncidentStatus.NEW.value,
            source_name="audit.txt",
            action_taken="LOG",
        )
        db.session.add(incident)
        db.session.commit()
        inc_id = incident.id

    resp = auditor_client.post(
        f"/incidents/{inc_id}/update",
        data={"status": IncidentStatus.RESOLVED.value},
    )
    assert resp.status_code == 403


def test_incident_export(app, analyst_client):
    """Test incident export to CSV and JSON with audit event."""
    with app.app_context():
        incident = Incident(
            title="Exportable Alert",
            severity="HIGH",
            status=IncidentStatus.NEW.value,
            source_name="export_test.txt",
            action_taken="ESCALATE",
        )
        db.session.add(incident)
        db.session.commit()

    # CSV Export
    csv_resp = analyst_client.get("/incidents/export?format=csv")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["Content-Type"]
    assert b"Exportable Alert" in csv_resp.data

    # JSON Export
    json_resp = analyst_client.get("/incidents/export?format=json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["Content-Type"]
    assert b"export_test.txt" in json_resp.data

    # Verify audit event
    audit = AuditLog.query.filter_by(action="INCIDENT_EXPORTED").first()
    assert audit is not None
