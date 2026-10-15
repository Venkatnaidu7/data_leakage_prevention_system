"""Security Audit Log model for append-only tracking of administrative actions."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text

from app.extensions import db


class AuditLog(db.Model):
    """Immutable audit record for security events and configuration changes."""

    __tablename__ = "audit_logs"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, nullable=True, index=True)
    username = db.Column(String(64), nullable=True, index=True)
    action = db.Column(String(100), nullable=False, index=True)
    target_type = db.Column(String(50), nullable=True)  # e.g., 'policy', 'user', 'incident', 'scan'
    target_id = db.Column(String(50), nullable=True)
    details = db.Column(Text, nullable=True)  # JSON or redacted message
    ip_address = db.Column(String(45), nullable=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    def to_dict(self) -> dict:
        """Serialize audit record."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
