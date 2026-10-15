"""Unit and integration tests for DLP Policy Engine."""

from app.detection.base import Finding
from app.models.policy import Policy, PolicyAction, PolicySeverity
from app.policies.engine import PolicyEngine


def test_policy_no_findings():
    """Empty findings should return default LOG/LOW evaluation."""
    result = PolicyEngine.evaluate([])
    assert result.action == PolicyAction.LOG.value
    assert result.severity == PolicySeverity.LOW.value
    assert result.findings_count == 0
    assert "No sensitive data patterns identified" in result.rationale


def test_single_policy_match():
    """Test policy triggering when findings meet threshold."""
    policy = Policy(
        id=1,
        name="Credit Card Blocker",
        priority=1,
        action=PolicyAction.BLOCK.value,
        severity=PolicySeverity.CRITICAL.value,
        match_threshold=1,
        enabled=True,
    )
    policy.target_detectors = ["credit_card"]

    findings = [
        Finding(
            detector_name="credit_card",
            classification="PCI_CARD_NUMBER",
            confidence=0.95,
            redacted_value="************5678",
            raw_length=16,
        )
    ]

    result = PolicyEngine.evaluate(findings, policies=[policy])
    assert result.action == PolicyAction.BLOCK.value
    assert result.severity == PolicySeverity.CRITICAL.value
    assert result.matched_policy_name == "Credit Card Blocker"
    assert not result.is_simulation


def test_priority_conflict_resolution():
    """Lower priority number takes deterministic precedence."""
    p1 = Policy(
        id=1,
        name="High Priority Escalation",
        priority=1,
        action=PolicyAction.ESCALATE.value,
        severity=PolicySeverity.HIGH.value,
        match_threshold=1,
        enabled=True,
    )
    p1.target_detectors = ["*"]

    p2 = Policy(
        id=2,
        name="Low Priority Warning",
        priority=10,
        action=PolicyAction.WARN.value,
        severity=PolicySeverity.MEDIUM.value,
        match_threshold=1,
        enabled=True,
    )
    p2.target_detectors = ["*"]

    findings = [
        Finding(
            detector_name="email",
            classification="EMAIL_ADDRESS",
            confidence=0.9,
            redacted_value="u***@example.com",
            raw_length=15,
        )
    ]

    result = PolicyEngine.evaluate(findings, policies=[p2, p1])
    assert result.matched_policy_name == "High Priority Escalation"
    assert result.action == PolicyAction.ESCALATE.value


def test_threshold_requirement():
    """Policy must not trigger if finding count is below match_threshold."""
    policy = Policy(
        id=1,
        name="Bulk Email Blocker",
        priority=1,
        action=PolicyAction.BLOCK.value,
        severity=PolicySeverity.HIGH.value,
        match_threshold=3,
        enabled=True,
    )
    policy.target_detectors = ["email"]

    # Only 2 findings provided
    findings = [
        Finding(
            detector_name="email",
            classification="EMAIL_ADDRESS",
            confidence=0.9,
            redacted_value="a***@test.com",
            raw_length=10,
        ),
        Finding(
            detector_name="email",
            classification="EMAIL_ADDRESS",
            confidence=0.9,
            redacted_value="b***@test.com",
            raw_length=10,
        ),
    ]

    result = PolicyEngine.evaluate(findings, policies=[policy])
    assert result.action == PolicyAction.LOG.value
    assert "did not reach the threshold" in result.rationale


def test_disabled_policy_ignored():
    """Disabled policy must be ignored during evaluation."""
    disabled_policy = Policy(
        id=1,
        name="Disabled Blocker",
        priority=1,
        action=PolicyAction.BLOCK.value,
        severity=PolicySeverity.CRITICAL.value,
        match_threshold=1,
        enabled=False,
    )
    disabled_policy.target_detectors = ["*"]

    fallback_policy = Policy(
        id=2,
        name="Active Log Policy",
        priority=10,
        action=PolicyAction.LOG.value,
        severity=PolicySeverity.LOW.value,
        match_threshold=1,
        enabled=True,
    )
    fallback_policy.target_detectors = ["*"]

    findings = [
        Finding(
            detector_name="email",
            classification="EMAIL_ADDRESS",
            confidence=0.9,
            redacted_value="a***@test.com",
            raw_length=10,
        )
    ]

    result = PolicyEngine.evaluate(findings, policies=[disabled_policy, fallback_policy])
    assert result.matched_policy_name == "Active Log Policy"
    assert result.action == PolicyAction.LOG.value


def test_simulation_mode():
    """Simulation dry-run returns proposed action with simulation flag set."""
    policy = Policy(
        id=1,
        name="Quarantine Policy",
        priority=1,
        action=PolicyAction.QUARANTINE.value,
        severity=PolicySeverity.HIGH.value,
        match_threshold=1,
        enabled=True,
    )
    policy.target_detectors = ["*"]

    findings = [
        Finding(
            detector_name="phone",
            classification="PHONE_NUMBER",
            confidence=0.85,
            redacted_value="***-***-1234",
            raw_length=12,
        )
    ]

    result = PolicyEngine.evaluate(findings, policies=[policy], simulate=True)
    assert result.action == PolicyAction.QUARANTINE.value
    assert result.is_simulation is True
