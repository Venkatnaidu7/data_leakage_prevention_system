"""Incident and IncidentFinding models."""

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.extensions import db


class IncidentStatus(str, Enum):
    """Incident lifecycle triage statuses."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Incident(db.Model):
    """Security Incident record."""

    __tablename__ = "incidents"

    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(200), nullable=False)
    description = db.Column(Text, nullable=True)
    severity = db.Column(String(20), nullable=False, default="MEDIUM", index=True)
    status = db.Column(String(20), nullable=False, default=IncidentStatus.NEW.value, index=True)
    source_name = db.Column(String(255), nullable=False)
    action_taken = db.Column(String(20), nullable=False, default="LOG")
    matched_policy_name = db.Column(String(100), nullable=True)

    # Assignment
    assigned_to_id = db.Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    assigned_to = relationship("User", back_populates="assigned_incidents")

    # Resolution & Investigation
    resolution_notes = db.Column(Text, nullable=True)

    # Timestamps
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at = db.Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Redacted findings
    findings = relationship(
        "IncidentFinding",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentFinding.line_number",
    )

    def to_dict(self, include_findings: bool = False) -> dict:
        """Serialize incident safely with redacted findings."""
        data = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source_name": self.source_name,
            "action_taken": self.action_taken,
            "matched_policy_name": self.matched_policy_name,
            "assigned_to": self.assigned_to.username if self.assigned_to else None,
            "assigned_to_id": self.assigned_to_id,
            "resolution_notes": self.resolution_notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "findings_count": len(self.findings) if self.findings else 0,
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


class IncidentFinding(db.Model):
    """Specific sensitive match belonging to an incident (strictly redacted)."""

    __tablename__ = "incident_findings"

    id = db.Column(Integer, primary_key=True)
    incident_id = db.Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    detector_name = db.Column(String(50), nullable=False)
    classification = db.Column(String(50), nullable=False)
    confidence = db.Column(Float, nullable=False, default=1.0)
    redacted_value = db.Column(String(255), nullable=False)  # MUST ALWAYS BE MASKED
    line_number = db.Column(Integer, default=1, nullable=False)
    context_snippet = db.Column(String(500), nullable=True)  # Masked surrounding text

    incident = relationship("Incident", back_populates="findings")

    def to_dict(self) -> dict:
        """Serialize individual finding."""
        return {
            "id": self.id,
            "detector_name": self.detector_name,
            "classification": self.classification,
            "confidence": self.confidence,
            "redacted_value": self.redacted_value,
            "line_number": self.line_number,
            "context_snippet": self.context_snippet,
        }
