"""Application factory and initialization."""

import os

from flask import Flask, jsonify, render_template, request

from app.api.v1 import api_v1_bp
from app.audit.routes import audit_bp
from app.auth.routes import auth_bp
from app.auth.services import get_current_user
from app.config import config_by_name
from app.dashboard.routes import dashboard_bp
from app.endpoints.routes import endpoints_bp
from app.extensions import csrf, db, limiter, migrate
from app.incidents.routes import incidents_bp
from app.policies.routes import policies_bp
from app.scanning.routes import scanning_bp


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
    """Construct and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    if test_config:
        app.config.from_mapping(test_config)
    else:
        if config_name is None:
            config_name = os.getenv("APP_ENV", "development").lower()
        config_class = config_by_name.get(config_name, config_by_name["development"])
        app.config.from_object(config_class)
        if config_name == "production" and hasattr(config_class, "validate"):
            config_class.validate()

    # Initialize Flask extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(scanning_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(policies_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(endpoints_bp)
    app.register_blueprint(api_v1_bp)

    # Security headers middleware
    @app.after_request
    def apply_security_headers(response):
        # Strict Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    # Template context processor
    @app.context_processor
    def inject_user_context():
        return {
            "current_user": get_current_user(),
            "app_version": "0.1.0",
        }

    # Error Handlers
    def handle_error(code: int, message: str, template: str):
        if request.path.startswith("/api/"):
            return jsonify({"error": {"code": message.upper().replace(" ", "_"), "message": message}}), code
        return render_template(template), code

    @app.errorhandler(400)
    def bad_request(e):
        return handle_error(400, "Bad Request", "errors/400.html")

    @app.errorhandler(403)
    def forbidden(e):
        return handle_error(403, "Forbidden - Insufficient Permissions", "errors/403.html")

    @app.errorhandler(404)
    def not_found(e):
        return handle_error(404, "Page Not Found", "errors/404.html")

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return handle_error(413, "Uploaded Payload Exceeds Maximum Limit (10MB)", "errors/413.html")

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return handle_error(429, "Rate Limit Exceeded. Please try again later.", "errors/429.html")

    @app.errorhandler(500)
    def internal_server_error(e):
        return handle_error(500, "Internal Server Error", "errors/500.html")

    return app
