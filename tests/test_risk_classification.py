"""Tests for Data Classification Engine and Deterministic Risk Scoring Engine."""

from app.detection.base import Finding
from app.detection.classification import ClassificationEngine, DataClassification
from app.policies.risk import RiskEngine, RiskLevel


def test_classification_public_when_no_findings():
    """No detector findings must classify as PUBLIC."""
    assert ClassificationEngine.classify([]) == DataClassification.PUBLIC.value


def test_classification_internal_for_low_sensitivity():
    """Single email or benign match classifies as INTERNAL."""
    f1 = Finding(
        detector_name="email",
        classification="EMAIL",
        confidence=0.9,
        redacted_value="u***@company.com",
        raw_length=16,
    )
    assert ClassificationEngine.classify([f1]) == DataClassification.INTERNAL.value


def test_classification_confidential_for_pii_and_bulk():
    """National ID, phone numbers, or bulk emails classify as CONFIDENTIAL."""
    # Phone number
    phone_finding = Finding(
        detector_name="phone",
        classification="PHONE",
        confidence=0.85,
        redacted_value="***-***-0199",
        raw_length=11,
    )
    assert ClassificationEngine.classify([phone_finding]) == DataClassification.CONFIDENTIAL.value

    # SSN / National ID
    ssn_finding = Finding(
        detector_name="national_id",
        classification="NATIONAL_ID_US",
        confidence=0.95,
        redacted_value="***-**-3456",
        raw_length=11,
    )
    assert ClassificationEngine.classify([ssn_finding]) == DataClassification.CONFIDENTIAL.value

    # 3+ emails escalate to CONFIDENTIAL
    emails = [
        Finding(
            detector_name="email",
            classification="EMAIL",
            confidence=0.9,
            redacted_value=f"t***{i}@example.com",
            raw_length=15,
        )
        for i in range(3)
    ]
    assert ClassificationEngine.classify(emails) == DataClassification.CONFIDENTIAL.value


def test_classification_restricted_for_secrets_and_cards():
    """Credit card numbers and API secrets classify as RESTRICTED."""
    cc_finding = Finding(
        detector_name="credit_card",
        classification="PCI_CARD",
        confidence=1.0,
        redacted_value="4532-****-****-5678",
        raw_length=16,
    )
    assert ClassificationEngine.classify([cc_finding]) == DataClassification.RESTRICTED.value

    secret_finding = Finding(
        detector_name="secret_key",
        classification="CREDENTIAL",
        confidence=0.95,
        redacted_value="AKIA************",
        raw_length=20,
    )
    assert ClassificationEngine.classify([secret_finding]) == DataClassification.RESTRICTED.value


def test_classification_resolves_to_highest_severity():
    """Mixed findings must deterministically resolve to the highest severity tier."""
    email = Finding(
        detector_name="email", classification="EMAIL", confidence=0.8, redacted_value="t***@example.com", raw_length=15
    )
    phone = Finding(
        detector_name="phone", classification="PHONE", confidence=0.8, redacted_value="***-***-0199", raw_length=11
    )
    cc = Finding(
        detector_name="credit_card",
        classification="PCI_CARD",
        confidence=1.0,
        redacted_value="4532-****-****-5678",
        raw_length=16,
    )

    # Email (Internal) + Phone (Confidential) -> Confidential
    assert ClassificationEngine.classify([email, phone]) == DataClassification.CONFIDENTIAL.value

    # Email (Internal) + Phone (Confidential) + CC (Restricted) -> Restricted
    assert ClassificationEngine.classify([email, phone, cc]) == DataClassification.RESTRICTED.value


def test_risk_scoring_baseline_and_factors():
    """Verify deterministic risk scoring and explanation factors."""
    # Public local file -> score = 5.0 (LOW)
    assessment = RiskEngine.calculate_risk(
        classification=DataClassification.PUBLIC.value,
        findings=[],
        channel="file",
    )
    assert assessment.score == 5.0
    assert assessment.level == RiskLevel.LOW.value
    assert any("Public" in f for f in assessment.factors)
    assert any("filesystem" in f for f in assessment.factors)


def test_risk_scoring_removable_media_modifier():
    """Removable media adds 25 points to baseline risk."""
    assessment = RiskEngine.calculate_risk(
        classification=DataClassification.CONFIDENTIAL.value,
        channel="removable_media",
        destination_type="external_usb",
    )
    # 35 (Confidential) + 25 (USB) = 60.0 -> HIGH
    assert assessment.score == 60.0
    assert assessment.level == RiskLevel.HIGH.value
    assert any("Removable storage" in f for f in assessment.factors)


def test_risk_scoring_restricted_critical_exfiltration():
    """Restricted data copied to USB with policy severity CRITICAL reaches CRITICAL band."""
    findings = [
        Finding(
            detector_name="credit_card",
            classification="PCI",
            confidence=1.0,
            redacted_value="4532-****-****-5678",
            raw_length=16,
        ),
        Finding(
            detector_name="secret_key",
            classification="SECRET",
            confidence=1.0,
            redacted_value="AKIA************",
            raw_length=20,
        ),
    ]
    assessment = RiskEngine.calculate_risk(
        classification=DataClassification.RESTRICTED.value,
        findings=findings,
        channel="removable_media",
        destination_type="external_usb",
        policy_severity="CRITICAL",
    )
    # 50 (Restricted) + 25 (USB) + 8 (findings) + 15 (Critical severity) = 98.0 -> CRITICAL
    assert assessment.score >= 80.0
    assert assessment.level == RiskLevel.CRITICAL.value
    assert len(assessment.factors) >= 4


def test_risk_scoring_clamps_to_100():
    """Score must never exceed 100.0 even under extreme additive criteria."""
    findings = [
        Finding(detector_name="credit_card", classification="PCI", confidence=1.0, redacted_value="card", raw_length=16)
        for _ in range(10)
    ]
    assessment = RiskEngine.calculate_risk(
        classification=DataClassification.RESTRICTED.value,
        findings=findings,
        channel="removable_media",
        destination_type="external_usb",
        policy_severity="CRITICAL",
    )
    assert assessment.score <= 100.0


def test_risk_scoring_handles_missing_and_none_fields():
    """Robustness against None or empty arguments."""
    assessment = RiskEngine.calculate_risk(
        classification="UNKNOWN",
        findings=None,
        channel="",
        destination_type=None,
        policy_severity=None,
    )
    assert 0.0 <= assessment.score <= 100.0
    assert assessment.level in [lvl.value for lvl in RiskLevel]
    assert isinstance(assessment.to_dict(), dict)
