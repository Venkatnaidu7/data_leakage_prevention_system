"""Web dashboard views for endpoint device inventory and event explorer."""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.services import record_audit
from app.auth.services import get_current_user, login_required, role_required
from app.extensions import db
from app.models.endpoint import DeviceStatus, EndpointDevice, EndpointEvent
from app.models.user import Role

endpoints_bp = Blueprint("endpoints", __name__)


@endpoints_bp.route("/endpoints")
@login_required
def device_inventory():
    """Device inventory overview."""
    status_filter = request.args.get("status")
    query = EndpointDevice.query
    if status_filter and status_filter in [s.value for s in DeviceStatus]:
        query = query.filter_by(status=status_filter)

    devices = query.order_by(EndpointDevice.last_seen_at.desc()).all()
    return render_template(
        "endpoints/inventory.html",
        devices=devices,
        status_filter=status_filter,
        statuses=[s.value for s in DeviceStatus],
    )


@endpoints_bp.route("/endpoints/<string:device_id>")
@login_required
def device_detail(device_id: str):
    """Device detail and recent activity history."""
    device = EndpointDevice.query.filter_by(device_id=device_id).first_or_404()
    events = (
        EndpointEvent.query.filter_by(device_id=device.id).order_by(EndpointEvent.timestamp_utc.desc()).limit(50).all()
    )
    return render_template("endpoints/detail.html", device=device, events=events)


@endpoints_bp.route("/endpoints/<string:device_id>/revoke", methods=["POST"])
@role_required(Role.ADMIN)
def revoke_device(device_id: str):
    """Revoke or restore endpoint device authorization."""
    device = EndpointDevice.query.filter_by(device_id=device_id).first_or_404()
    user = get_current_user()

    if device.status == DeviceStatus.ENROLLED.value:
        device.status = DeviceStatus.REVOKED.value
        flash(f"Device '{device.hostname}' ({device.device_id}) has been REVOKED.", "warning")
        action = "DEVICE_REVOKED"
    else:
        device.status = DeviceStatus.ENROLLED.value
        flash(f"Device '{device.hostname}' has been restored to ENROLLED status.", "success")
        action = "DEVICE_ENROLLED"

    db.session.commit()
    record_audit(action=action, target_type="device", target_id=device.device_id, user=user)

    return redirect(url_for("endpoints.device_inventory"))


@endpoints_bp.route("/events")
@login_required
def event_explorer():
    """Search and filter endpoint security event stream."""
    channel_filter = request.args.get("channel")
    classification_filter = request.args.get("classification")
    risk_filter = request.args.get("risk")
    decision_filter = request.args.get("decision")
    page = request.args.get("page", 1, type=int)
    per_page = 20

    query = EndpointEvent.query
    if channel_filter:
        query = query.filter_by(channel=channel_filter)
    if classification_filter:
        query = query.filter_by(classification=classification_filter)
    if risk_filter:
        query = query.filter_by(risk_level=risk_filter.upper())
    if decision_filter:
        query = query.filter_by(decision=decision_filter.upper())

    pagination = query.order_by(EndpointEvent.timestamp_utc.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        "endpoints/events.html",
        pagination=pagination,
        events=pagination.items,
        channel_filter=channel_filter,
        classification_filter=classification_filter,
        risk_filter=risk_filter,
        decision_filter=decision_filter,
    )


@endpoints_bp.route("/events/<string:event_id>")
@login_required
def event_detail(event_id: str):
    """Detailed inspection of an individual endpoint event."""
    event = EndpointEvent.query.filter_by(event_id=event_id).first_or_404()
    return render_template("endpoints/event_detail.html", event=event)
