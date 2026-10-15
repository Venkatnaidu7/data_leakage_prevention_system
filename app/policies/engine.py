"""DLP Policy Evaluation Engine."""

from dataclasses import asdict, dataclass, field
from typing import Any

from app.detection.base import Finding
from app.models.policy import Policy, PolicyAction, PolicySeverity

SEVERITY_WEIGHTS = {
    PolicySeverity.CRITICAL.value: 4,
    PolicySeverity.HIGH.value: 3,
    PolicySeverity.MEDIUM.value: 2,
    PolicySeverity.LOW.value: 1,
}

ACTION_WEIGHTS = {
    PolicyAction.BLOCK.value: 5,
    PolicyAction.QUARANTINE.value: 4,
    PolicyAction.ESCALATE.value: 3,
    PolicyAction.WARN.value: 2,
    PolicyAction.LOG.value: 1,
}


@dataclass
class PolicyEvaluationResult:
    """Output summary of policy evaluation."""

    action: str
    severity: str
    matched_policy_name: str | None
    matched_policy_id: int | None
    findings_count: int
    rationale: str
    is_simulation: bool
    triggered_policies: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return asdict(self)


class PolicyEngine:
    """Evaluates detection findings against configured security policies."""

    @classmethod
    def evaluate(
        cls,
        findings: list[Finding],
        policies: list[Policy] | None = None,
        simulate: bool = False,
    ) -> PolicyEvaluationResult:
        """Evaluate findings deterministically against active policies."""
        if not findings:
            return PolicyEvaluationResult(
                action=PolicyAction.LOG.value,
                severity=PolicySeverity.LOW.value,
                matched_policy_name=None,
                matched_policy_id=None,
                findings_count=0,
                rationale="No sensitive data patterns identified.",
                is_simulation=simulate,
                triggered_policies=[],
            )

        if policies is None:
            # Load active policies from DB ordered by priority
            policies = Policy.query.filter_by(enabled=True).order_by(Policy.priority.asc(), Policy.id.asc()).all()

        # Filter enabled policies
        active_policies = [p for p in policies if p.enabled]

        if not active_policies:
            return PolicyEvaluationResult(
                action=PolicyAction.LOG.value,
                severity=PolicySeverity.LOW.value,
                matched_policy_name=None,
                matched_policy_id=None,
                findings_count=len(findings),
                rationale="Sensitive data detected, but no active policies are configured.",
                is_simulation=simulate,
                triggered_policies=[],
            )

        triggered: list[tuple[Policy, int, list[Finding]]] = []

        for policy in active_policies:
            # Check target detectors
            targets = policy.target_detectors
            matching_findings = [f for f in findings if "*" in targets or f.detector_name in targets]

            if len(matching_findings) >= policy.match_threshold:
                triggered.append((policy, len(matching_findings), matching_findings))

        if not triggered:
            return PolicyEvaluationResult(
                action=PolicyAction.LOG.value,
                severity=PolicySeverity.LOW.value,
                matched_policy_name=None,
                matched_policy_id=None,
                findings_count=len(findings),
                rationale="Findings did not reach the threshold for any active policy.",
                is_simulation=simulate,
                triggered_policies=[],
            )

        # Deterministic conflict resolution:
        # 1. Lower priority integer first
        # 2. Higher severity weight
        # 3. Higher action weight
        def sort_key(item: tuple[Policy, int, list[Finding]]):
            pol = item[0]
            prio = pol.priority
            sev_wt = SEVERITY_WEIGHTS.get(pol.severity, 0)
            act_wt = ACTION_WEIGHTS.get(pol.action, 0)
            return (prio, -sev_wt, -act_wt)

        triggered.sort(key=sort_key)
        winner_policy, match_count, matched_findings = triggered[0]

        triggered_summary = [
            {
                "id": p.id,
                "name": p.name,
                "priority": p.priority,
                "action": p.action,
                "severity": p.severity,
                "matched_count": cnt,
            }
            for p, cnt, _ in triggered
        ]

        rationale = (
            f"Policy '{winner_policy.name}' triggered (Priority: {winner_policy.priority}, "
            f"Action: {winner_policy.action}, Severity: {winner_policy.severity}) "
            f"with {match_count} matching finding(s) (threshold >= {winner_policy.match_threshold})."
        )
        if len(triggered) > 1:
            rationale += f" Evaluated against {len(triggered)} matching policies using deterministic priority rules."

        # If individual policy is marked for simulation or caller requested simulate
        effective_simulation = simulate or winner_policy.is_simulation

        return PolicyEvaluationResult(
            action=winner_policy.action,
            severity=winner_policy.severity,
            matched_policy_name=winner_policy.name,
            matched_policy_id=winner_policy.id,
            findings_count=len(findings),
            rationale=rationale,
            is_simulation=effective_simulation,
            triggered_policies=triggered_summary,
        )
