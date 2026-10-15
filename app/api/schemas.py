"""Validation schemas for REST API endpoints using Pydantic."""

from typing import Any, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequestSchema(BaseModel):
    """Schema for direct content scan submissions."""

    content: str = Field(..., min_length=1, max_length=10_000_000, description="Raw text payload to inspect")
    source_name: Optional[str] = Field("api_payload.txt", max_length=255)
    simulate: Optional[bool] = Field(False, description="If true, perform dry-run evaluation without saving incidents")


class IncidentUpdateSchema(BaseModel):
    """Schema for updating incident state and assignment."""

    status: Optional[str] = Field(None, pattern="^(NEW|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")
    assigned_to_id: Optional[int] = Field(None)
    notes: Optional[str] = Field(None, max_length=5000)


class PolicyCreateSchema(BaseModel):
    """Schema for creating a new DLP policy."""

    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    priority: int = Field(10, ge=1, le=1000)
    target_detectors: List[str] = Field(default_factory=lambda: ["*"])
    match_threshold: int = Field(1, ge=1, le=1000)
    action: str = Field("LOG", pattern="^(LOG|WARN|BLOCK|QUARANTINE|ESCALATE)$")
    severity: str = Field("MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    is_simulation: bool = Field(False)
    enabled: bool = Field(True)

    @field_validator("target_detectors")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        if not v:
            return ["*"]
        return v


class SimulateRequestSchema(BaseModel):
    """Schema for dry-run policy simulation."""

    content: str = Field(..., min_length=1, max_length=10_000_000)


class DeviceEnrollmentSchema(BaseModel):
    """Schema for endpoint agent enrollment request."""

    hostname: str = Field(..., min_length=1, max_length=128)
    os_name: str = Field("Windows", max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    agent_version: str = Field("0.1.0", max_length=30)
    enrollment_token: Optional[str] = Field(None, max_length=64)


class DeviceHeartbeatSchema(BaseModel):
    """Schema for agent heartbeat status report."""

    device_id: str = Field(..., min_length=1, max_length=64)
    agent_version: str = Field(..., max_length=30)
    queue_depth: int = Field(0, ge=0)
    status: str = Field("OK", max_length=20)


class EndpointEventIngestSchema(BaseModel):
    """Schema for structured endpoint security event ingestion."""

    event_id: str = Field(..., min_length=1, max_length=64)
    schema_version: Optional[str] = Field("1.0.0", max_length=10)
    device_id: str = Field(..., min_length=1, max_length=64)
    timestamp_utc: Optional[str] = Field(None)
    channel: str = Field(..., pattern="^(file|removable_media|clipboard|network)$")
    operation: str = Field(
        ...,
        pattern="^(created|modified|copied|deleted|device_connected|device_disconnected|clipboard_copy|file_transferred)$",
    )
    file_path: Optional[str] = Field(None, max_length=512)
    file_name: Optional[str] = Field(None, max_length=255)
    file_type: Optional[str] = Field(None, max_length=30)
    file_size_bytes: Optional[int] = Field(0, ge=0)
    content_hash: Optional[str] = Field(None, max_length=64)
    destination_type: Optional[str] = Field(None, max_length=50)
    destination_path: Optional[str] = Field(None, max_length=512)
    device_metadata: Optional[dict[str, Any]] = Field(default_factory=dict)
    content_sample: Optional[str] = Field(None, max_length=1_000_000)
    local_findings: Optional[list[dict[str, Any]]] = Field(None)
    idempotency_key: Optional[str] = Field(None, max_length=64)
