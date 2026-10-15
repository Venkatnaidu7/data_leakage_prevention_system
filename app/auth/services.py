"""Authentication, authorization, and session services."""

from datetime import datetime, timezone
from functools import wraps
from typing import Callable

from flask import flash, g, redirect, render_template, request, session, url_for

from app.audit.services import record_audit
from app.extensions import db
from app.models.user import Role, User


def get_current_user() -> User | None:
    """Retrieve currently authenticated user from API token or session."""
    # 1. Check X-API-Key header first for programmatic API calls
    api_key = request.headers.get("X-API-Key")
    if api_key:
        if hasattr(g, "current_user") and g.current_user and g.current_user.api_key == api_key:
            return g.current_user
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        if user:
            g.current_user = user
            return user

    # 2. Check active session for browser requests
    user_id = session.get("user_id")
    if user_id:
        if hasattr(g, "current_user") and g.current_user and g.current_user.id == user_id:
            return g.current_user
        user = db.session.get(User, user_id)
        if user and user.is_active:
            g.current_user = user
            return user

    g.current_user = None
    return None


def authenticate_user(username_or_email: str, password: str) -> User | None:
    """Validate credentials and return User if valid, recording audit event."""
    user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

    if not user or not user.is_active or not user.check_password(password):
        record_audit(
            action="AUTH_LOGIN_FAILED",
            target_type="user",
            target_id=user.id if user else None,
            details={"attempted_identifier": username_or_email},
        )
        return None

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    record_audit(
        action="AUTH_LOGIN_SUCCESS",
        target_type="user",
        target_id=user.id,
        user=user,
    )
    return user


def login_user_session(user: User) -> None:
    """Set up user session with protection against session fixation."""
    session.clear()  # Regenerate session state
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role
    session.permanent = True
    g.current_user = user


def logout_user_session() -> None:
    """Terminate user session safely."""
    user = get_current_user()
    if user:
        record_audit(
            action="AUTH_LOGOUT",
            target_type="user",
            target_id=user.id,
            user=user,
        )
    session.clear()
    g.current_user = None


def login_required(f: Callable) -> Callable:
    """Decorator requiring active authenticated user."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            if request.path.startswith("/api/"):
                return {"error": {"code": "UNAUTHORIZED", "message": "Authentication required."}}, 401
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles: Role | str) -> Callable:
    """Decorator requiring one of the specified roles."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if user is None:
                if request.path.startswith("/api/"):
                    return {"error": {"code": "UNAUTHORIZED", "message": "Authentication required."}}, 401
                flash("Please sign in to access this page.", "warning")
                return redirect(url_for("auth.login", next=request.url))

            if not user.has_role(*roles):
                record_audit(
                    action="AUTH_ACCESS_DENIED",
                    target_type="route",
                    target_id=request.path,
                    details={"required_roles": [r.value if isinstance(r, Role) else r for r in roles]},
                    user=user,
                )
                if request.path.startswith("/api/"):
                    return {
                        "error": {
                            "code": "FORBIDDEN",
                            "message": "Insufficient permissions for this action.",
                        }
                    }, 403
                return render_template("errors/403.html"), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator
