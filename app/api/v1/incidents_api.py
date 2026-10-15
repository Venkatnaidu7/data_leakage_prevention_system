"""Incidents REST API endpoints."""

from flask import Blueprint, jsonify, request
from pydantic import ValidationError

from app.api.schemas import IncidentUpdateSchema
from app.audit.services import record_audit
from app.auth.services import get_current_user, login_required, role_required
from app.extensions import csrf, db
from app.models.incident import Incident, IncidentStatus
from app.models.user import Role

incidents_api_bp = Blueprint("incidents_api", __name__)


@incidents_api_bp.route("/incidents", methods=["GET"])
@login_required
def list_incidents():
    """List incidents with filtering and pagination."""
    status = request.args.get("status")
    severity = request.args.get("severity")
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)

    query = Incident.query
    if status and status in [s.value for s in IncidentStatus]:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity.upper())

    pagination = query.order_by(Incident.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify(
        {
            "total": pagination.total,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "pages": pagination.pages,
            "items": [inc.to_dict(include_findings=False) for inc in pagination.items],
        }
    ), 200


@incidents_api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@login_required
def get_incident(incident_id: int):
    """Retrieve detailed incident with redacted findings."""
    incident = db.get_or_404(Incident, incident_id)
    return jsonify(incident.to_dict(include_findings=True)), 200


@incidents_api_bp.route("/incidents/<int:incident_id>", methods=["PATCH"])
@csrf.exempt
@role_required(Role.ADMIN, Role.ANALYST)
def update_incident(incident_id: int):
    """Update incident status, assignment, or notes."""
    incident = db.get_or_404(Incident, incident_id)
    user = get_current_user()

    try:
        update_data = IncidentUpdateSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    old_status = incident.status
    if update_data.status:
        incident.status = update_data.status
    if update_data.assigned_to_id is not None:
        incident.assigned_to_id = update_data.assigned_to_id
    if update_data.notes:
        incident.resolution_notes = update_data.notes

    db.session.commit()

    record_audit(
        action="API_INCIDENT_UPDATED",
        target_type="incident",
        target_id=incident.id,
        details={
            "old_status": old_status,
            "new_status": incident.status,
            "assigned_to_id": incident.assigned_to_id,
        },
        user=user,
    )

    return jsonify(incident.to_dict(include_findings=True)), 200
