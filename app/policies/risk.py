"""Deterministic risk scoring engine for DLP events."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from app.detection.base import Finding
from app.detection.classification import DataClassification


class RiskLevel(str, Enum):
    """Four-tier risk severity classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskAssessment:
    """Output of risk evaluation containing numeric score, tier, and rationale."""

    score: float
    level: str
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert assessment to dictionary."""
        return asdict(self)


class RiskEngine:
    """Calculates deterministic, transparent risk scores for endpoint events."""

    @classmethod
    def calculate_risk(
        cls,
        classification: str,
        findings: list[Finding] | None = None,
        channel: str = "file",
        destination_type: str | None = None,
        policy_severity: str | None = None,
    ) -> RiskAssessment:
        """Compute 0-100 score and explain top contributing risk factors."""
        findings = findings or []
        score = 0.0
        factors = []

        # 1. Classification baseline
        if classification == DataClassification.RESTRICTED.value:
            score += 50.0
            factors.append("Restricted data classification (+50)")
        elif classification == DataClassification.CONFIDENTIAL.value:
            score += 35.0
            factors.append("Confidential data classification (+35)")
        elif classification == DataClassification.INTERNAL.value:
            score += 15.0
            factors.append("Internal data classification (+15)")
        else:
            factors.append("Public / Non-sensitive data (0)")

        # 2. Exfiltration Channel & Destination Modifier
        channel_norm = channel.lower() if channel else "file"
        dest_norm = destination_type.lower() if destination_type else ""

        if channel_norm == "removable_media" or "usb" in dest_norm or "removable" in dest_norm:
            score += 25.0
            factors.append("Removable storage / USB egress channel (+25)")
        elif channel_norm == "clipboard":
            score += 15.0
            factors.append("Application clipboard copy channel (+15)")
        elif channel_norm == "file":
            score += 5.0
            factors.append("Local filesystem activity (+5)")

        # 3. Findings volume & confidence modifier
        if findings:
            avg_confidence = sum(f.confidence for f in findings) / len(findings)
            volume_bonus = min(len(findings) * 4.0, 20.0) * avg_confidence
            score += volume_bonus
            factors.append(
                f"{len(findings)} sensitive finding(s) with {avg_confidence:.0%} avg confidence (+{volume_bonus:.1f})"
            )

        # 4. Policy severity amplifier
        if policy_severity:
            sev = policy_severity.upper()
            if sev == "CRITICAL":
                score += 15.0
                factors.append("Critical policy severity triggered (+15)")
            elif sev == "HIGH":
                score += 10.0
                factors.append("High policy severity triggered (+10)")
            elif sev == "MEDIUM":
                score += 5.0
                factors.append("Medium policy severity (+5)")

        # Clamp between 0.0 and 100.0
        final_score = round(min(max(score, 0.0), 100.0), 1)

        # Determine Risk Band
        if final_score >= 75.0:
            level = RiskLevel.CRITICAL.value
        elif final_score >= 50.0:
            level = RiskLevel.HIGH.value
        elif final_score >= 25.0:
            level = RiskLevel.MEDIUM.value
        else:
            level = RiskLevel.LOW.value

        return RiskAssessment(score=final_score, level=level, factors=factors)
