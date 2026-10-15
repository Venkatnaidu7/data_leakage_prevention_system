"""Endpoint devices and events models."""

import json
import secrets
import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.extensions import db


class DeviceStatus(str, Enum):
    """Enrollment and lifecycle state of endpoint agents."""

    ENROLLED = "ENROLLED"
    REVOKED = "REVOKED"
    INACTIVE = "INACTIVE"


class EndpointDevice(db.Model):
    """Enrolled workstation or server running the DLP agent."""

    __tablename__ = "endpoint_devices"

    id = db.Column(Integer, primary_key=True)
    device_id = db.Column(String(64), unique=True, nullable=False, index=True)
    hostname = db.Column(String(128), nullable=False)
    ip_address = db.Column(String(45), nullable=True)
    os_name = db.Column(String(50), nullable=False, default="Windows")
    os_version = db.Column(String(100), nullable=True)
    agent_version = db.Column(String(30), nullable=False, default="0.1.0")
    status = db.Column(String(20), nullable=False, default=DeviceStatus.ENROLLED.value, index=True)
    agent_auth_token = db.Column(String(64), unique=True, nullable=False, index=True)
    last_seen_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    enrolled_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    events = relationship("EndpointEvent", back_populates="device", cascade="all, delete-orphan")

    @classmethod
    def generate_token(cls) -> str:
        """Generate a cryptographically secure token for agent authentication."""
        return secrets.token_hex(32)

    def is_active(self) -> bool:
        """Return whether device is authorized to communicate with server."""
        return self.status == DeviceStatus.ENROLLED.value

    def to_dict(self) -> dict:
        """Serialize device inventory summary."""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "agent_version": self.agent_version,
            "status": self.status,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "enrolled_at": self.enrolled_at.isoformat() if self.enrolled_at else None,
        }


class EndpointEvent(db.Model):
    """Structured security event emitted by an authorized endpoint agent."""

    __tablename__ = "endpoint_events"

    id = db.Column(Integer, primary_key=True)
    event_id = db.Column(String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    schema_version = db.Column(String(10), nullable=False, default="1.0.0")
    device_id = db.Column(Integer, ForeignKey("endpoint_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    device_uuid = db.Column(String(64), nullable=False, index=True)
    timestamp_utc = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Activity channel & operation
    channel = db.Column(String(30), nullable=False, index=True)  # file, removable_media, clipboard
    operation = db.Column(String(40), nullable=False, index=True)  # created, modified, copied, etc.

    # File / Content metadata
    file_path = db.Column(String(512), nullable=True)
    file_name = db.Column(String(255), nullable=True)
    file_type = db.Column(String(30), nullable=True)
    file_size_bytes = db.Column(Integer, default=0, nullable=False)
    content_hash = db.Column(String(64), nullable=True)  # SHA-256

    # Destination
    destination_type = db.Column(String(50), nullable=True)  # external_usb, internal_drive, clipboard
    destination_path = db.Column(String(512), nullable=True)
    _device_metadata = db.Column("device_metadata", Text, nullable=True)

    # Findings (STRICTLY REDACTED JSON)
    _detector_findings = db.Column("detector_findings", Text, nullable=True)

    # Classification & Risk
    classification = db.Column(String(30), nullable=False, default="PUBLIC", index=True)
    risk_score = db.Column(Float, nullable=False, default=0.0, index=True)
    risk_level = db.Column(String(20), nullable=False, default="LOW", index=True)

    # Policy Decision & Enforcement
    policy_id = db.Column(Integer, ForeignKey("policies.id"), nullable=True)
    policy_name = db.Column(String(100), nullable=True)
    decision = db.Column(String(20), nullable=False, default="ALLOW", index=True)  # ALLOW, ALERT, BLOCK, NOT_ENFORCED
    enforcement_status = db.Column(
        String(20), nullable=False, default="NOT_ENFORCED"
    )  # ENFORCED, NOT_ENFORCED, SIMULATED
    decision_reason = db.Column(Text, nullable=True)

    # Incident link
    incident_id = db.Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)

    # Replay protection & deduplication
    idempotency_key = db.Column(String(64), unique=True, nullable=True, index=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    device = relationship("EndpointDevice", back_populates="events")
    incident = relationship("Incident")

    @property
    def device_metadata(self) -> dict:
        """Parse device metadata JSON safely."""
        if not self._device_metadata:
            return {}
        try:
            return json.loads(self._device_metadata)
        except Exception:
            return {}

    @device_metadata.setter
    def device_metadata(self, val: dict | str | None) -> None:
        if isinstance(val, dict):
            self._device_metadata = json.dumps(val)
        else:
            self._device_metadata = str(val) if val else None

    @property
    def detector_findings(self) -> list[dict]:
        """Parse detector findings JSON safely."""
        if not self._detector_findings:
            return []
        try:
            return json.loads(self._detector_findings)
        except Exception:
            return []

    @detector_findings.setter
    def detector_findings(self, val: list[dict] | str | None) -> None:
        if isinstance(val, list):
            self._detector_findings = json.dumps(val)
        else:
            self._detector_findings = str(val) if val else None

    def to_dict(self) -> dict:
        """Serialize event summary with redacted findings."""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "device_id": self.device_uuid,
            "timestamp_utc": self.timestamp_utc.isoformat() if self.timestamp_utc else None,
            "channel": self.channel,
            "operation": self.operation,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "file_size_bytes": self.file_size_bytes,
            "content_hash": self.content_hash,
            "destination_type": self.destination_type,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "policy_name": self.policy_name,
            "decision": self.decision,
            "enforcement_status": self.enforcement_status,
            "decision_reason": self.decision_reason,
            "incident_id": self.incident_id,
            "detector_findings": self.detector_findings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
