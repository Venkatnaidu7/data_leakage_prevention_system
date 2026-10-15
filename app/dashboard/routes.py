"""Main security dashboard view."""

from flask import Blueprint, render_template

from app.auth.services import login_required
from app.models.incident import Incident, IncidentStatus
from app.models.policy import Policy, PolicySeverity
from app.models.scan import ScanRecord

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    """Analyst security dashboard overview."""
    # Counts by status
    status_counts = {status.value: Incident.query.filter_by(status=status.value).count() for status in IncidentStatus}

    # Counts by severity
    severity_counts = {sev.value: Incident.query.filter_by(severity=sev.value).count() for sev in PolicySeverity}

    total_incidents = Incident.query.count()
    total_scans = ScanRecord.query.count()
    active_policies_count = Policy.query.filter_by(enabled=True).count()

    recent_incidents = Incident.query.order_by(Incident.created_at.desc()).limit(5).all()
    recent_scans = ScanRecord.query.order_by(ScanRecord.created_at.desc()).limit(5).all()

    return render_template(
        "dashboard/index.html",
        total_incidents=total_incidents,
        total_scans=total_scans,
        active_policies_count=active_policies_count,
        status_counts=status_counts,
        severity_counts=severity_counts,
        recent_incidents=recent_incidents,
        recent_scans=recent_scans,
    )
