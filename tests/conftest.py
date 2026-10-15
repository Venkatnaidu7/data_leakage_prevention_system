"""Pytest test configuration and fixtures."""

import os
import sys
from pathlib import Path

import pytest

# Add DTS project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure testing configuration is active
os.environ["APP_ENV"] = "testing"

from app import create_app
from app.extensions import db as _db
from app.models.policy import Policy, PolicyAction, PolicySeverity
from app.models.user import Role, User


@pytest.fixture
def app():
    """Create and configure a fresh Flask application for each test."""
    test_config = {
        "TESTING": True,
        "DEBUG": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-super-secret-key-32-chars-long!",
        "SESSION_COOKIE_SECURE": False,
        "RATELIMIT_ENABLED": False,
        "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
        "ALLOWED_EXTENSIONS": {"txt", "csv", "json", "log", "md", "xml", "yaml", "yml"},
    }

    application = create_app(test_config=test_config)

    with application.app_context():
        _db.create_all()

        # Seed baseline roles/users
        admin = User(username="admin", email="admin@dlp.test", role=Role.ADMIN.value, api_key="admin_test_key")
        admin.set_password("AdminPass123!@#")

        analyst = User(
            username="analyst", email="analyst@dlp.test", role=Role.ANALYST.value, api_key="analyst_test_key"
        )
        analyst.set_password("AnalystPass123!@#")

        auditor = User(
            username="auditor", email="auditor@dlp.test", role=Role.AUDITOR.value, api_key="auditor_test_key"
        )
        auditor.set_password("AuditorPass123!@#")

        _db.session.add_all([admin, analyst, auditor])

        # Seed baseline policies
        p1 = Policy(
            name="Block Credit Cards",
            priority=1,
            action=PolicyAction.BLOCK.value,
            severity=PolicySeverity.CRITICAL.value,
            match_threshold=1,
            enabled=True,
        )
        p1.target_detectors = ["credit_card"]

        p2 = Policy(
            name="Block Secrets",
            priority=2,
            action=PolicyAction.BLOCK.value,
            severity=PolicySeverity.CRITICAL.value,
            match_threshold=1,
            enabled=True,
        )
        p2.target_detectors = ["secret_key"]

        p3 = Policy(
            name="Alert Bulk PII",
            priority=5,
            action=PolicyAction.ESCALATE.value,
            severity=PolicySeverity.HIGH.value,
            match_threshold=2,
            enabled=True,
        )
        p3.target_detectors = ["email", "phone"]

        _db.session.add_all([p1, p2, p3])
        _db.session.commit()

        yield application

        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def admin_client(app):
    """Authenticated client for an Administrator."""
    test_client = app.test_client()
    with test_client.session_transaction() as sess:
        user = User.query.filter_by(username="admin").first()
        sess["user_id"] = user.id
        sess["username"] = user.username
        sess["role"] = user.role
    return test_client


@pytest.fixture
def analyst_client(app):
    """Authenticated client for a Security Analyst."""
    test_client = app.test_client()
    with test_client.session_transaction() as sess:
        user = User.query.filter_by(username="analyst").first()
        sess["user_id"] = user.id
        sess["username"] = user.username
        sess["role"] = user.role
    return test_client


@pytest.fixture
def auditor_client(app):
    """Authenticated client for a Read-Only Auditor."""
    test_client = app.test_client()
    with test_client.session_transaction() as sess:
        user = User.query.filter_by(username="auditor").first()
        sess["user_id"] = user.id
        sess["username"] = user.username
        sess["role"] = user.role
    return test_client
