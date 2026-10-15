"""Policies REST API endpoints."""

from flask import Blueprint, jsonify, request
from pydantic import ValidationError

from app.api.schemas import PolicyCreateSchema, SimulateRequestSchema
from app.audit.services import record_audit
from app.auth.services import get_current_user, login_required, role_required
from app.detection.registry import default_registry
from app.extensions import csrf, db
from app.models.policy import Policy
from app.models.user import Role
from app.policies.engine import PolicyEngine

policies_api_bp = Blueprint("policies_api", __name__)


@policies_api_bp.route("/policies", methods=["GET"])
@login_required
def list_policies():
    """List all configured detection policies."""
    policies = Policy.query.order_by(Policy.priority.asc(), Policy.id.asc()).all()
    return jsonify([p.to_dict() for p in policies]), 200


@policies_api_bp.route("/policies", methods=["POST"])
@csrf.exempt
@role_required(Role.ADMIN)
def create_policy():
    """Create a new policy rule."""
    user = get_current_user()

    try:
        policy_data = PolicyCreateSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    existing = Policy.query.filter_by(name=policy_data.name).first()
    if existing:
        return jsonify({"error": {"code": "CONFLICT", "message": f"Policy '{policy_data.name}' already exists."}}), 409

    policy = Policy(
        name=policy_data.name,
        description=policy_data.description,
        priority=policy_data.priority,
        action=policy_data.action,
        severity=policy_data.severity,
        match_threshold=policy_data.match_threshold,
        is_simulation=policy_data.is_simulation,
        enabled=policy_data.enabled,
        version=1,
    )
    policy.target_detectors = policy_data.target_detectors

    db.session.add(policy)
    db.session.commit()

    record_audit(
        action="API_POLICY_CREATED",
        target_type="policy",
        target_id=policy.id,
        details={"name": policy.name, "action": policy.action, "priority": policy.priority},
        user=user,
    )

    return jsonify(policy.to_dict()), 201


@policies_api_bp.route("/policies/simulate", methods=["POST"])
@csrf.exempt
@role_required(Role.ADMIN, Role.ANALYST)
def simulate_policy():
    """Dry-run test content against configured policies without creating incidents."""
    try:
        req_data = SimulateRequestSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    findings = default_registry.scan_text(req_data.content)
    evaluation = PolicyEngine.evaluate(findings, simulate=True)

    return jsonify(
        {
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "evaluation": evaluation.to_dict(),
        }
    ), 200
