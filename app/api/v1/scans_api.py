"""Scanning REST API endpoints."""

from flask import Blueprint, jsonify, request
from pydantic import ValidationError

from app.api.schemas import ScanRequestSchema
from app.auth.services import get_current_user, role_required
from app.extensions import csrf, limiter
from app.models.user import Role
from app.scanning.extractors import ExtractionError
from app.scanning.scanner import ScanService

scans_api_bp = Blueprint("scans_api", __name__)


@scans_api_bp.route("/scan", methods=["POST"])
@csrf.exempt
@limiter.limit("60 per minute")
@role_required(Role.ADMIN, Role.ANALYST)
def submit_scan():
    """Submit content for DLP inspection."""
    user = get_current_user()

    # Handle multipart file upload or JSON payload
    if request.is_json:
        try:
            req_data = ScanRequestSchema(**request.get_json(force=True))
        except ValidationError as e:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "details": e.errors()}}), 400

        result = ScanService.scan_text(
            text=req_data.content,
            source_name=req_data.source_name or "api_payload.txt",
            is_simulation=req_data.simulate or False,
            user=user,
        )
        return jsonify(result), 200

    elif "file" in request.files:
        uploaded_file = request.files["file"]
        simulate = request.form.get("simulate", "false").lower() in ("true", "1")
        try:
            result = ScanService.scan_file(
                file=uploaded_file,
                is_simulation=simulate,
                user=user,
            )
            return jsonify(result), 200
        except ExtractionError as e:
            return jsonify({"error": {"code": "INVALID_FILE", "message": str(e)}}), 400
        except Exception as e:
            return jsonify({"error": {"code": "SCAN_FAILED", "message": str(e)}}), 500

    return jsonify(
        {
            "error": {
                "code": "BAD_REQUEST",
                "message": "Expected JSON body with 'content' or multipart/form-data with 'file'.",
            }
        }
    ), 400
