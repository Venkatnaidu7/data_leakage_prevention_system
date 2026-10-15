"""Security Audit logging service."""

import json
from typing import Any

from flask import has_request_context, request, session

from app.extensions import db
from app.models.audit import AuditLog
from app.models.user import User


def record_audit(
    action: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | str | None = None,
    user: User | None = None,
) -> AuditLog:
    """Record an immutable security audit event.

    Never logs unredacted raw payload or passwords.
    """
    user_id = None
    username = None
    ip_address = None

    if user:
        user_id = user.id
        username = user.username
    elif has_request_context() and "user_id" in session:
        user_id = session.get("user_id")
        username = session.get("username")

    if has_request_context():
        # Handle X-Forwarded-For safely if behind reverse proxy
        if request.headers.get("X-Forwarded-For"):
            ip_address = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        else:
            ip_address = request.remote_addr

    details_str = None
    if details:
        if isinstance(details, dict):
            # Sanitize details to avoid logging raw passwords or keys
            sanitized = {}
            for k, v in details.items():
                if any(secret_term in k.lower() for secret_term in ["password", "token", "secret", "raw_content"]):
                    sanitized[k] = "[REDACTED]"
                else:
                    sanitized[k] = v
            details_str = json.dumps(sanitized)
        else:
            details_str = str(details)

    log_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=details_str,
        ip_address=ip_address,
    )

    db.session.add(log_entry)
    db.session.commit()
    return log_entry
