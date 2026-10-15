"""Audit events REST API endpoints."""

from flask import Blueprint, jsonify, request

from app.auth.services import role_required
from app.models.audit import AuditLog
from app.models.user import Role

audit_api_bp = Blueprint("audit_api", __name__)


@audit_api_bp.route("/audit", methods=["GET"])
@role_required(Role.ADMIN, Role.AUDITOR)
def list_audit_logs():
    """Query immutable audit events with pagination and filters."""
    action = request.args.get("action")
    username = request.args.get("username")
    limit = min(request.args.get("limit", 50, type=int), 200)
    offset = request.args.get("offset", 0, type=int)

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username}%"))

    total = query.count()
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()

    return jsonify(
        {
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": [log.to_dict() for log in logs],
        }
    ), 200
