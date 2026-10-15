"""Incident management routes."""

import csv
import io
import json

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

from app.audit.services import record_audit
from app.auth.services import get_current_user, login_required, role_required
from app.extensions import db
from app.models.incident import Incident, IncidentStatus
from app.models.user import Role, User

incidents_bp = Blueprint("incidents", __name__, url_prefix="/incidents")


@incidents_bp.route("")
@login_required
def index():
    """List incidents with filtering and pagination."""
    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")
    search_query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 15

    query = Incident.query

    if status_filter and status_filter in [s.value for s in IncidentStatus]:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter.upper())
    if search_query:
        query = query.filter(
            (Incident.title.ilike(f"%{search_query}%"))
            | (Incident.source_name.ilike(f"%{search_query}%"))
            | (Incident.matched_policy_name.ilike(f"%{search_query}%"))
        )

    pagination = query.order_by(Incident.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "incidents/list.html",
        pagination=pagination,
        incidents=pagination.items,
        status_filter=status_filter,
        severity_filter=severity_filter,
        search_query=search_query,
        statuses=[s.value for s in IncidentStatus],
    )


@incidents_bp.route("/<int:incident_id>")
@login_required
def detail(incident_id: int):
    """View incident details with redacted findings."""
    incident = db.get_or_404(Incident, incident_id)
    analysts = User.query.filter(User.role.in_([Role.ADMIN.value, Role.ANALYST.value])).all()
    return render_template(
        "incidents/detail.html",
        incident=incident,
        analysts=analysts,
        statuses=[s.value for s in IncidentStatus],
    )


@incidents_bp.route("/<int:incident_id>/update", methods=["POST"])
@role_required(Role.ADMIN, Role.ANALYST)
def update(incident_id: int):
    """Update incident status, assignment, and resolution notes."""
    incident = db.get_or_404(Incident, incident_id)
    user = get_current_user()

    new_status = request.form.get("status")
    assigned_to_id = request.form.get("assigned_to_id")
    resolution_notes = request.form.get("resolution_notes", "").strip()

    old_status = incident.status
    if new_status and new_status in [s.value for s in IncidentStatus]:
        incident.status = new_status

    if assigned_to_id:
        try:
            incident.assigned_to_id = int(assigned_to_id) if assigned_to_id != "unassigned" else None
        except ValueError:
            pass

    if resolution_notes:
        incident.resolution_notes = resolution_notes

    db.session.commit()

    record_audit(
        action="INCIDENT_UPDATED",
        target_type="incident",
        target_id=incident.id,
        details={
            "old_status": old_status,
            "new_status": incident.status,
            "assigned_to_id": incident.assigned_to_id,
        },
        user=user,
    )

    flash("Incident updated successfully.", "success")
    return redirect(url_for("incidents.detail", incident_id=incident.id))


@incidents_bp.route("/export")
@login_required
def export():
    """Safely export incident summaries with masked findings to CSV or JSON."""
    user = get_current_user()
    fmt = request.args.get("format", "csv").lower()
    incidents = Incident.query.order_by(Incident.created_at.desc()).limit(1000).all()

    record_audit(
        action="INCIDENT_EXPORTED",
        target_type="incident_export",
        details={"format": fmt, "count": len(incidents)},
        user=user,
    )

    if fmt == "json":
        data = [inc.to_dict(include_findings=True) for inc in incidents]
        return Response(
            json.dumps(data, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=dlp_incidents_redacted.json"},
        )

    # Default CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Incident ID",
            "Title",
            "Severity",
            "Status",
            "Source Name",
            "Action Taken",
            "Matched Policy",
            "Assigned Analyst",
            "Findings Count",
            "Created At",
        ]
    )
    for inc in incidents:
        writer.writerow(
            [
                inc.id,
                inc.title,
                inc.severity,
                inc.status,
                inc.source_name,
                inc.action_taken,
                inc.matched_policy_name or "N/A",
                inc.assigned_to.username if inc.assigned_to else "Unassigned",
                len(inc.findings),
                inc.created_at.isoformat() if inc.created_at else "",
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=dlp_incidents_redacted.csv"},
    )
