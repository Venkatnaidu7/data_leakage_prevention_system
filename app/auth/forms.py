"""Authentication WTForms with validation and CSRF protection."""

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """Secure user sign-in form."""

    username_or_email = StringField(
        "Username or Email",
        validators=[DataRequired(), Length(min=3, max=120)],
        render_kw={"placeholder": "analyst@dlp.local", "autocomplete": "username"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
        render_kw={"placeholder": "••••••••", "autocomplete": "current-password"},
    )
    submit = SubmitField("Sign In")
