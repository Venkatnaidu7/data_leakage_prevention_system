"""Audit logs inspection routes."""

from flask import Blueprint, render_template, request

from app.auth.services import role_required
from app.models.audit import AuditLog
from app.models.user import Role

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("")
@role_required(Role.ADMIN, Role.AUDITOR)
def index():
    """Display immutable audit logs with search and pagination."""
    action_filter = request.args.get("action", "").strip()
    username_filter = request.args.get("username", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
    if username_filter:
        query = query.filter(AuditLog.username.ilike(f"%{username_filter}%"))

    pagination = query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "audit/list.html",
        pagination=pagination,
        logs=pagination.items,
        action_filter=action_filter,
        username_filter=username_filter,
    )
