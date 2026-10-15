"""Authentication routes blueprint."""

from urllib.parse import urlsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.auth.forms import LoginForm
from app.auth.services import authenticate_user, login_user_session, logout_user_session
from app.extensions import limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def is_safe_redirect_url(target: str) -> bool:
    """Ensure redirect URL stays on the same host to prevent open redirect vulnerabilities."""
    if not target:
        return False
    ref_url = urlsplit(request.host_url)
    test_url = urlsplit(target)
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    """Sign-in route with rate-limiting and open redirect protection."""
    form = LoginForm()
    if form.validate_on_submit():
        user = authenticate_user(
            form.username_or_email.data.strip(),
            form.password.data,
        )
        if user:
            login_user_session(user)
            flash(f"Welcome back, {user.username}.", "success")
            next_page = request.args.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))
        else:
            flash("Invalid credentials or account deactivated.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """Sign-out route."""
    logout_user_session()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
