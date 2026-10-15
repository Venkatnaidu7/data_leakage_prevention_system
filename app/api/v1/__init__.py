"""API v1 blueprint bundle."""

from flask import Blueprint

from app.api.v1.audit_api import audit_api_bp
from app.api.v1.health_api import health_api_bp
from app.api.v1.incidents_api import incidents_api_bp
from app.api.v1.policies_api import policies_api_bp
from app.api.v1.scans_api import scans_api_bp

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

api_v1_bp.register_blueprint(health_api_bp)
api_v1_bp.register_blueprint(scans_api_bp)
api_v1_bp.register_blueprint(incidents_api_bp)
api_v1_bp.register_blueprint(policies_api_bp)
api_v1_bp.register_blueprint(audit_api_bp)
