"""Policy models and rule schemas."""

import json
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Boolean, DateTime, Integer, String, Text

from app.extensions import db


class PolicyAction(str, Enum):
    """Enforcement and reporting actions."""

    LOG = "LOG"
    WARN = "WARN"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    ESCALATE = "ESCALATE"


class PolicySeverity(str, Enum):
    """Policy violation severity classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Policy(db.Model):
    """DLP Policy rule definition."""

    __tablename__ = "policies"

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(100), unique=True, nullable=False, index=True)
    description = db.Column(Text, nullable=True)
    enabled = db.Column(Boolean, default=True, nullable=False, index=True)
    priority = db.Column(Integer, default=10, nullable=False, index=True)  # Lower is evaluated first
    _target_detectors = db.Column("target_detectors", Text, nullable=False, default="*")  # JSON list or "*"
    match_threshold = db.Column(Integer, default=1, nullable=False)  # Min findings to trigger
    action = db.Column(String(20), default=PolicyAction.LOG.value, nullable=False)
    severity = db.Column(String(20), default=PolicySeverity.MEDIUM.value, nullable=False)
    is_simulation = db.Column(Boolean, default=False, nullable=False)
    version = db.Column(Integer, default=1, nullable=False)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    @property
    def target_detectors(self) -> list[str]:
        """Return target detectors as a Python list."""
        if not self._target_detectors or self._target_detectors == "*":
            return ["*"]
        try:
            return json.loads(self._target_detectors)
        except Exception:
            return [d.strip() for d in self._target_detectors.split(",") if d.strip()]

    @target_detectors.setter
    def target_detectors(self, value: list[str] | str) -> None:
        """Store target detectors as JSON string."""
        if isinstance(value, list):
            self._target_detectors = json.dumps(value)
        else:
            self._target_detectors = str(value)

    def to_dict(self) -> dict:
        """Serialize policy rule."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "priority": self.priority,
            "target_detectors": self.target_detectors,
            "match_threshold": self.match_threshold,
            "action": self.action,
            "severity": self.severity,
            "is_simulation": self.is_simulation,
            "version": self.version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
