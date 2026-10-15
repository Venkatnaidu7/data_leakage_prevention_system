"""Authentication and session security tests."""

from app.models.user import User


def test_password_hashing(app):
    """Test Argon2id password hashing and validation."""
    with app.app_context():
        user = User(username="testuser", email="test@dlp.test")
        user.set_password("SecurePassword!2026")

        assert user.password_hash.startswith("$argon2id$")
        assert user.check_password("SecurePassword!2026") is True
        assert user.check_password("WrongPassword") is False


def test_login_success(client):
    """Test successful login redirects and populates session."""
    response = client.post(
        "/auth/login",
        data={"username_or_email": "analyst", "password": "AnalystPass123!@#"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome back, analyst" in response.data
    with client.session_transaction() as sess:
        assert sess.get("username") == "analyst"
        assert sess.get("role") == "analyst"


def test_login_invalid_credentials(client):
    """Test failed login with incorrect password."""
    response = client.post(
        "/auth/login",
        data={"username_or_email": "analyst", "password": "WrongPassword!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data
    with client.session_transaction() as sess:
        assert "username" not in sess


def test_open_redirect_protection(client):
    """Ensure evil open redirect via 'next' query param is blocked."""
    response = client.post(
        "/auth/login?next=https://attacker-controlled-site.com/steal",
        data={"username_or_email": "admin", "password": "AdminPass123!@#"},
        follow_redirects=False,
    )
    # Redirects to internal dashboard '/' instead of attacker URL
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_logout(analyst_client):
    """Test logout clears session."""
    response = analyst_client.get("/auth/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"You have been signed out" in response.data
    with analyst_client.session_transaction() as sess:
        assert "username" not in sess
