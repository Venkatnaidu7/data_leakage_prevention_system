"""Validation schemas for REST API endpoints using Pydantic."""

from typing import List, Optional

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
