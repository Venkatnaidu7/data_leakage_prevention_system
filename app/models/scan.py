"""ScanRecord model for tracking authorized scan jobs."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.extensions import db


class ScanRecord(db.Model):
    """Metadata record of an executed scan job (no raw payload content stored)."""

    __tablename__ = "scan_records"

    id = db.Column(Integer, primary_key=True)
    source_name = db.Column(String(255), nullable=False)
    file_size_bytes = db.Column(Integer, default=0, nullable=False)
    findings_count = db.Column(Integer, default=0, nullable=False)
    action_taken = db.Column(String(20), default="LOG", nullable=False)
    is_simulation = db.Column(Boolean, default=False, nullable=False)
    user_id = db.Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    user = relationship("User", back_populates="scans")

    def to_dict(self) -> dict:
        """Serialize scan record."""
        return {
            "id": self.id,
            "source_name": self.source_name,
            "file_size_bytes": self.file_size_bytes,
            "findings_count": self.findings_count,
            "action_taken": self.action_taken,
            "is_simulation": self.is_simulation,
            "user": self.user.username if self.user else "Anonymous / API",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
