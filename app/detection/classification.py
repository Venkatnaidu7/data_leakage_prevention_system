"""Data Classification Engine mapping detector findings to organizational sensitivity levels."""

from enum import Enum

from app.detection.base import Finding


class DataClassification(str, Enum):
    """Standard four-tier data classification hierarchy."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


# Sensitivity rank weights for deterministic resolution
CLASSIFICATION_WEIGHTS = {
    DataClassification.PUBLIC.value: 1,
    DataClassification.INTERNAL.value: 2,
    DataClassification.CONFIDENTIAL.value: 3,
    DataClassification.RESTRICTED.value: 4,
}


class ClassificationEngine:
    """Classifies content based on detected sensitive patterns and compliance categories."""

    @classmethod
    def classify(cls, findings: list[Finding]) -> str:
        """Resolve a list of findings to the highest applicable classification tier."""
        if not findings:
            return DataClassification.PUBLIC.value

        highest_classification = DataClassification.INTERNAL.value
        highest_weight = CLASSIFICATION_WEIGHTS[DataClassification.INTERNAL.value]

        for finding in findings:
            det = finding.detector_name.lower()
            cls_name = finding.classification.upper()

            # Restricted: Payment card numbers, credentials, private keys
            if det in ("credit_card", "secret_key") or "CREDENTIAL" in cls_name or "PCI" in cls_name:
                return DataClassification.RESTRICTED.value

            # Confidential: National IDs (SSN), bulk PII, personal phone numbers
            elif det in ("national_id", "phone") or "NATIONAL_ID" in cls_name:
                weight = CLASSIFICATION_WEIGHTS[DataClassification.CONFIDENTIAL.value]
                if weight > highest_weight:
                    highest_classification = DataClassification.CONFIDENTIAL.value
                    highest_weight = weight

            # Multiple emails escalate to Confidential
            elif det == "email" and len([f for f in findings if f.detector_name == "email"]) >= 3:
                weight = CLASSIFICATION_WEIGHTS[DataClassification.CONFIDENTIAL.value]
                if weight > highest_weight:
                    highest_classification = DataClassification.CONFIDENTIAL.value
                    highest_weight = weight

            # Single email or custom organization identifiers default to Internal
            else:
                weight = CLASSIFICATION_WEIGHTS[DataClassification.INTERNAL.value]
                if weight > highest_weight:
                    highest_classification = DataClassification.INTERNAL.value
                    highest_weight = weight

        return highest_classification
