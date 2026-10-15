"""Security, authorization matrix, headers, and audit hardening tests."""

import pytest

from app.audit.services import record_audit
from app.config import ProductionConfig


def test_security_headers(client):
    """Verify presence and strictness of defensive security headers."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

    headers = resp.headers
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("Permissions-Policy", "")


def test_rbac_matrix_analyst_restrictions(analyst_client):
    """Security Analyst cannot access Admin-only policy creation or audit trail."""
    # Policy creation -> 403 Forbidden
    resp = analyst_client.get("/policies/new")
    assert resp.status_code == 403

    # Audit log -> 403 Forbidden
    resp_audit = analyst_client.get("/audit")
    assert resp_audit.status_code == 403


def test_rbac_matrix_auditor_restrictions(auditor_client):
    """Auditor has read-only access and cannot submit file scans or create policies."""
    # Scanning -> 403 Forbidden
    resp_scan = auditor_client.get("/scanning/upload")
    assert resp_scan.status_code == 403

    # Policy creation -> 403 Forbidden
    resp_pol = auditor_client.get("/policies/new")
    assert resp_pol.status_code == 403

    # Can view audit trail
    resp_audit = auditor_client.get("/audit")
    assert resp_audit.status_code == 200


def test_audit_log_password_sanitization(app):
    """Audit service must automatically redact passwords and tokens from detail payloads."""
    with app.app_context():
        record = record_audit(
            action="TEST_ACTION",
            details={
                "username": "attacker",
                "password": "SuperSecretPassword123!",
                "api_token": "live_secret_token_abcde",
                "safe_field": "safe_metadata",
            },
        )
        assert record.details is not None
        assert "SuperSecretPassword123!" not in record.details
        assert "live_secret_token_abcde" not in record.details
        assert "[REDACTED]" in record.details
        assert "safe_metadata" in record.details


def test_production_config_validation(monkeypatch):
    """Production configuration must reject missing or default development secrets."""
    monkeypatch.setenv("SECRET_KEY", "dev-insecure-secret-key-change-in-production-min32chars")
    with pytest.raises(ValueError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        ProductionConfig.validate()

    monkeypatch.setenv("SECRET_KEY", "short-key")
    with pytest.raises(ValueError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        ProductionConfig.validate()
