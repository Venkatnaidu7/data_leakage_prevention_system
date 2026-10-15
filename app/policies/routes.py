"""Policy management and simulation routes."""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.services import record_audit
from app.auth.services import get_current_user, login_required, role_required
from app.detection.registry import default_registry
from app.extensions import db
from app.models.policy import Policy, PolicyAction, PolicySeverity
from app.models.user import Role
from app.policies.engine import PolicyEngine

policies_bp = Blueprint("policies", __name__, url_prefix="/policies")


@policies_bp.route("")
@login_required
def index():
    """List all configured DLP policies."""
    policies = Policy.query.order_by(Policy.priority.asc(), Policy.id.asc()).all()
    return render_template("policies/list.html", policies=policies)


@policies_bp.route("/new", methods=["GET", "POST"])
@role_required(Role.ADMIN)
def create():
    """Create a new DLP policy."""
    user = get_current_user()
    detectors = default_registry.list_detectors()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        priority = int(request.form.get("priority", 10))
        action = request.form.get("action", PolicyAction.LOG.value)
        severity = request.form.get("severity", PolicySeverity.MEDIUM.value)
        match_threshold = int(request.form.get("match_threshold", 1))
        is_simulation = request.form.get("is_simulation") == "on"
        selected_detectors = request.form.getlist("target_detectors")

        if not name:
            flash("Policy name is required.", "danger")
            return render_template(
                "policies/form.html",
                detectors=detectors,
                actions=[a.value for a in PolicyAction],
                severities=[s.value for s in PolicySeverity],
                policy=None,
            )

        if not selected_detectors:
            selected_detectors = ["*"]

        policy = Policy(
            name=name,
            description=description,
            priority=priority,
            action=action,
            severity=severity,
            match_threshold=match_threshold,
            is_simulation=is_simulation,
            enabled=True,
            version=1,
        )
        policy.target_detectors = selected_detectors

        db.session.add(policy)
        db.session.commit()

        record_audit(
            action="POLICY_CREATED",
            target_type="policy",
            target_id=policy.id,
            details={"name": policy.name, "action": policy.action, "priority": policy.priority},
            user=user,
        )

        flash(f"Policy '{policy.name}' created successfully.", "success")
        return redirect(url_for("policies.index"))

    return render_template(
        "policies/form.html",
        detectors=detectors,
        actions=[a.value for a in PolicyAction],
        severities=[s.value for s in PolicySeverity],
        policy=None,
    )


@policies_bp.route("/<int:policy_id>/edit", methods=["GET", "POST"])
@role_required(Role.ADMIN)
def edit(policy_id: int):
    """Edit an existing policy and bump version."""
    policy = db.get_or_404(Policy, policy_id)
    user = get_current_user()
    detectors = default_registry.list_detectors()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        priority = int(request.form.get("priority", 10))
        action = request.form.get("action", PolicyAction.LOG.value)
        severity = request.form.get("severity", PolicySeverity.MEDIUM.value)
        match_threshold = int(request.form.get("match_threshold", 1))
        is_simulation = request.form.get("is_simulation") == "on"
        selected_detectors = request.form.getlist("target_detectors")

        if not name:
            flash("Policy name cannot be empty.", "danger")
            return render_template(
                "policies/form.html",
                detectors=detectors,
                actions=[a.value for a in PolicyAction],
                severities=[s.value for s in PolicySeverity],
                policy=policy,
            )

        policy.name = name
        policy.description = description
        policy.priority = priority
        policy.action = action
        policy.severity = severity
        policy.match_threshold = match_threshold
        policy.is_simulation = is_simulation
        policy.target_detectors = selected_detectors if selected_detectors else ["*"]
        policy.version += 1

        db.session.commit()

        record_audit(
            action="POLICY_UPDATED",
            target_type="policy",
            target_id=policy.id,
            details={"name": policy.name, "version": policy.version},
            user=user,
        )

        flash(f"Policy '{policy.name}' updated (v{policy.version}).", "success")
        return redirect(url_for("policies.index"))

    return render_template(
        "policies/form.html",
        detectors=detectors,
        actions=[a.value for a in PolicyAction],
        severities=[s.value for s in PolicySeverity],
        policy=policy,
    )


@policies_bp.route("/<int:policy_id>/toggle", methods=["POST"])
@role_required(Role.ADMIN)
def toggle(policy_id: int):
    """Toggle enabled/disabled state of a policy."""
    policy = db.get_or_404(Policy, policy_id)
    user = get_current_user()

    policy.enabled = not policy.enabled
    db.session.commit()

    record_audit(
        action="POLICY_TOGGLED",
        target_type="policy",
        target_id=policy.id,
        details={"name": policy.name, "enabled": policy.enabled},
        user=user,
    )

    state_str = "enabled" if policy.enabled else "disabled"
    flash(f"Policy '{policy.name}' is now {state_str}.", "info")
    return redirect(url_for("policies.index"))


@policies_bp.route("/simulate", methods=["GET", "POST"])
@login_required
def simulate():
    """Policy dry-run simulation sandbox."""
    result = None
    sample_text = ""

    if request.method == "POST":
        sample_text = request.form.get("sample_text", "")
        findings = default_registry.scan_text(sample_text)
        evaluation = PolicyEngine.evaluate(findings, simulate=True)
        result = {
            "findings": [f.to_dict() for f in findings],
            "evaluation": evaluation.to_dict(),
        }

    return render_template(
        "policies/simulate.html",
        result=result,
        sample_text=sample_text,
    )
