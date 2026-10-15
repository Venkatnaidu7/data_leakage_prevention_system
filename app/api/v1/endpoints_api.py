"""REST API endpoints for Endpoint DLP Agent enrollment, heartbeats, and event ingestion."""

import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from pydantic import ValidationError

from app.api.schemas import (
    DeviceEnrollmentSchema,
    DeviceHeartbeatSchema,
    EndpointEventIngestSchema,
)
from app.audit.services import record_audit
from app.auth.services import login_required, role_required
from app.detection.base import Finding
from app.detection.classification import ClassificationEngine
from app.detection.registry import default_registry
from app.extensions import csrf, db, limiter
from app.models.endpoint import DeviceStatus, EndpointDevice, EndpointEvent
from app.models.incident import Incident, IncidentFinding, IncidentStatus
from app.models.policy import Policy
from app.models.user import Role
from app.policies.engine import PolicyEngine
from app.policies.risk import RiskEngine

endpoints_api_bp = Blueprint("endpoints_api", __name__)


def authenticate_agent_request(req_device_id: str | None = None) -> EndpointDevice | tuple[dict, int]:
    """Verify that agent request contains valid device credentials."""
    device_id = request.headers.get("X-Device-ID") or req_device_id
    token = request.headers.get("X-Device-Token")

    if not device_id or not token:
        return {
            "error": {"code": "UNAUTHORIZED_AGENT", "message": "Missing X-Device-ID or X-Device-Token headers."}
        }, 401

    device = EndpointDevice.query.filter_by(device_id=device_id).first()
    if not device:
        return {"error": {"code": "DEVICE_NOT_FOUND", "message": "Device is not registered."}}, 404

    if device.agent_auth_token != token:
        return {"error": {"code": "INVALID_AGENT_CREDENTIALS", "message": "Agent authentication token mismatch."}}, 401

    if device.status == DeviceStatus.REVOKED.value:
        return {
            "error": {
                "code": "DEVICE_REVOKED",
                "message": "Endpoint device access has been revoked by an administrator.",
            }
        }, 403

    return device


@endpoints_api_bp.route("/endpoints/enroll", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute")
def enroll_device():
    """Enroll a new endpoint device and issue persistent credentials."""
    try:
        data = DeviceEnrollmentSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    device_uuid = f"ep-{uuid.uuid4().hex[:16]}"
    auth_token = EndpointDevice.generate_token()

    device = EndpointDevice(
        device_id=device_uuid,
        hostname=data.hostname,
        ip_address=client_ip,
        os_name=data.os_name,
        os_version=data.os_version,
        agent_version=data.agent_version,
        status=DeviceStatus.ENROLLED.value,
        agent_auth_token=auth_token,
    )
    db.session.add(device)
    db.session.commit()

    record_audit(
        action="DEVICE_ENROLLED",
        target_type="device",
        target_id=device.device_id,
        details={
            "hostname": device.hostname,
            "os_name": device.os_name,
            "agent_version": device.agent_version,
            "ip_address": client_ip,
        },
    )

    return jsonify(
        {
            "status": "ENROLLED",
            "device_id": device.device_id,
            "agent_token": auth_token,
            "server_time": datetime.now(timezone.utc).isoformat(),
            "message": "Endpoint successfully enrolled into DLP Defender platform.",
        }
    ), 201


@endpoints_api_bp.route("/endpoints/heartbeat", methods=["POST"])
@csrf.exempt
def device_heartbeat():
    """Agent health ping and policy version sync."""
    try:
        data = DeviceHeartbeatSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    auth_result = authenticate_agent_request(data.device_id)
    if isinstance(auth_result, tuple):
        return jsonify(auth_result[0]), auth_result[1]
    device: EndpointDevice = auth_result

    device.last_seen_at = datetime.now(timezone.utc)
    device.agent_version = data.agent_version
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or device.ip_address).split(",")[0].strip()
    device.ip_address = client_ip
    db.session.commit()

    # Calculate latest policy version
    latest_policy = Policy.query.order_by(Policy.updated_at.desc()).first()
    policy_version = latest_policy.version if latest_policy else 1

    return jsonify(
        {
            "status": "ACKNOWLEDGED",
            "device_status": device.status,
            "policy_version": policy_version,
            "server_time": datetime.now(timezone.utc).isoformat(),
        }
    ), 200


@endpoints_api_bp.route("/endpoints/events", methods=["POST"])
@csrf.exempt
def ingest_event():
    """Ingest, analyze, classify, evaluate policies, and record endpoint security events."""
    try:
        event_data = EndpointEventIngestSchema(**request.get_json(force=True))
    except ValidationError as e:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

    auth_result = authenticate_agent_request(event_data.device_id)
    if isinstance(auth_result, tuple):
        return jsonify(auth_result[0]), auth_result[1]
    device: EndpointDevice = auth_result

    # 1. Idempotency & Replay Protection
    idempotency_key = event_data.idempotency_key or event_data.event_id
    existing_event = EndpointEvent.query.filter(
        (EndpointEvent.event_id == event_data.event_id) | (EndpointEvent.idempotency_key == idempotency_key)
    ).first()

    if existing_event:
        # Return existing decision without duplicate incident creation
        return jsonify(
            {
                "status": "DUPLICATE_ACKNOWLEDGED",
                "event_id": existing_event.event_id,
                "decision": existing_event.decision,
                "enforcement_status": existing_event.enforcement_status,
                "risk_score": existing_event.risk_score,
                "risk_level": existing_event.risk_level,
                "classification": existing_event.classification,
            }
        ), 200

    # 2. Sensitive Content Detection
    findings: list[Finding] = []
    if event_data.content_sample:
        findings = default_registry.scan_text(event_data.content_sample)
    elif event_data.local_findings:
        # Reconstruct structured findings from agent
        for lf in event_data.local_findings:
            findings.append(
                Finding(
                    detector_name=lf.get("detector_name", "local_detector"),
                    classification=lf.get("classification", "SENSITIVE_DATA"),
                    confidence=float(lf.get("confidence", 1.0)),
                    redacted_value=lf.get("redacted_value", "****"),
                    raw_length=int(lf.get("raw_length", 4)),
                    line_number=int(lf.get("line_number", 1)),
                    context_snippet=lf.get("context_snippet", ""),
                )
            )

    # 3. Data Classification
    classification = ClassificationEngine.classify(findings)

    # 4. Policy Evaluation
    policy_eval = PolicyEngine.evaluate(findings, simulate=False)

    # 5. Deterministic Risk Assessment
    risk = RiskEngine.calculate_risk(
        classification=classification,
        findings=findings,
        channel=event_data.channel,
        destination_type=event_data.destination_type,
        policy_severity=policy_eval.severity,
    )

    # 6. Enforcement & Decision Mapping
    # ALLOW, ALERT, BLOCK, NOT_ENFORCED
    if policy_eval.action == "BLOCK":
        decision = "BLOCK"
        # User-space agents can enforce file locks or safe quarantine if technically supported,
        # otherwise accurately report NOT_ENFORCED
        enforcement_status = "NOT_ENFORCED"
    elif policy_eval.action in ("WARN", "ESCALATE", "QUARANTINE"):
        decision = "ALERT"
        enforcement_status = "NOT_ENFORCED"
    else:
        decision = "ALLOW"
        enforcement_status = "NOT_ENFORCED"

    # 7. Create Incident if decision requires triage
    incident_id = None
    if findings and decision in ("ALERT", "BLOCK"):
        incident = Incident(
            title=f"Endpoint Alert: {event_data.channel.upper()} {event_data.operation} on {device.hostname}",
            description=(
                f"Observed {event_data.channel} {event_data.operation} of {event_data.file_name or 'content'}. "
                f"Classification: {classification}, Risk: {risk.level} ({risk.score}/100). "
                f"Engine Decision: {decision}. Matched Policy: {policy_eval.matched_policy_name or 'Baseline'}. "
                f"Rationale: {policy_eval.rationale}"
            ),
            severity=risk.level,
            status=IncidentStatus.NEW.value,
            source_name=f"[{device.hostname}] {event_data.file_name or event_data.file_path or event_data.channel}",
            action_taken=decision,
            matched_policy_name=policy_eval.matched_policy_name,
        )
        db.session.add(incident)
        db.session.flush()
        incident_id = incident.id

        # Attach redacted findings
        for f in findings:
            finding_model = IncidentFinding(
                incident_id=incident.id,
                detector_name=f.detector_name,
                classification=f.classification,
                confidence=f.confidence,
                redacted_value=f.redacted_value,
                line_number=f.line_number,
                context_snippet=f.context_snippet,
            )
            db.session.add(finding_model)

    # 8. Record Immutable Endpoint Event
    redacted_findings_list = [f.to_dict() for f in findings]
    endpoint_event = EndpointEvent(
        event_id=event_data.event_id,
        schema_version=event_data.schema_version or "1.0.0",
        device_id=device.id,
        device_uuid=device.device_id,
        channel=event_data.channel,
        operation=event_data.operation,
        file_path=event_data.file_path,
        file_name=event_data.file_name,
        file_type=event_data.file_type,
        file_size_bytes=event_data.file_size_bytes or 0,
        content_hash=event_data.content_hash,
        destination_type=event_data.destination_type,
        destination_path=event_data.destination_path,
        device_metadata=event_data.device_metadata or {},
        detector_findings=redacted_findings_list,
        classification=classification,
        risk_score=risk.score,
        risk_level=risk.level,
        policy_id=policy_eval.matched_policy_id,
        policy_name=policy_eval.matched_policy_name,
        decision=decision,
        enforcement_status=enforcement_status,
        decision_reason=policy_eval.rationale,
        incident_id=incident_id,
        idempotency_key=idempotency_key,
    )
    db.session.add(endpoint_event)
    db.session.commit()

    record_audit(
        action="ENDPOINT_EVENT_INGESTED",
        target_type="endpoint_event",
        target_id=endpoint_event.event_id,
        details={
            "device_id": device.device_id,
            "channel": endpoint_event.channel,
            "operation": endpoint_event.operation,
            "classification": classification,
            "risk_score": risk.score,
            "decision": decision,
            "incident_id": incident_id,
        },
    )

    return jsonify(
        {
            "status": "PROCESSED",
            "event_id": endpoint_event.event_id,
            "decision": decision,
            "enforcement_status": enforcement_status,
            "classification": classification,
            "risk_score": risk.score,
            "risk_level": risk.level,
            "incident_id": incident_id,
            "decision_reason": policy_eval.rationale,
            "risk_factors": risk.factors,
        }
    ), 201


@endpoints_api_bp.route("/endpoints", methods=["GET"])
@login_required
def list_devices():
    """List enrolled endpoint inventory."""
    status_filter = request.args.get("status")
    query = EndpointDevice.query
    if status_filter:
        query = query.filter_by(status=status_filter.upper())

    devices = query.order_by(EndpointDevice.last_seen_at.desc()).all()
    return jsonify([d.to_dict() for d in devices]), 200


@endpoints_api_bp.route("/endpoints/<string:device_id>", methods=["GET"])
@login_required
def get_device(device_id: str):
    """Get single device details and recent event history."""
    device = EndpointDevice.query.filter_by(device_id=device_id).first_or_404()
    events = (
        EndpointEvent.query.filter_by(device_id=device.id).order_by(EndpointEvent.timestamp_utc.desc()).limit(20).all()
    )
    data = device.to_dict()
    data["recent_events"] = [e.to_dict() for e in events]
    return jsonify(data), 200


@endpoints_api_bp.route("/endpoints/<string:device_id>/revoke", methods=["POST"])
@csrf.exempt
@role_required(Role.ADMIN)
def revoke_device(device_id: str):
    """Revoke an endpoint agent's authorization."""
    device = EndpointDevice.query.filter_by(device_id=device_id).first_or_404()
    device.status = DeviceStatus.REVOKED.value
    db.session.commit()

    record_audit(
        action="DEVICE_REVOKED",
        target_type="device",
        target_id=device.device_id,
        details={"hostname": device.hostname},
    )

    return jsonify(
        {"status": "REVOKED", "device_id": device.device_id, "message": "Device credentials have been revoked."}
    ), 200
