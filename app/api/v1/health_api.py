"""Health check and readiness API endpoints."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify
from sqlalchemy import text

from app.extensions import db

health_api_bp = Blueprint("health_api", __name__)


@health_api_bp.route("/health", methods=["GET"])
def health_check():
    """Health status and database connectivity probe."""
    db_status = "connected"
    status_code = 200

    try:
        db.session.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {e}"
        status_code = 503

    return jsonify(
        {
            "status": "healthy" if status_code == 200 else "degraded",
            "version": "0.1.0",
            "database": db_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    ), status_code
