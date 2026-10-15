"""User and Role models with Argon2id password hashing."""

import secrets
from datetime import datetime, timezone
from enum import Enum

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import relationship

from app.extensions import db

ph = PasswordHasher()


class Role(str, Enum):
    """User authorization roles."""

    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class User(db.Model):
    """User account with authentication credentials and assigned role."""

    __tablename__ = "users"

    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), unique=True, nullable=False, index=True)
    email = db.Column(String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(String(255), nullable=False)
    role = db.Column(String(20), nullable=False, default=Role.ANALYST.value)
    is_active = db.Column(Boolean, default=True, nullable=False)
    api_key = db.Column(String(64), unique=True, nullable=True, index=True)
    created_at = db.Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(DateTime, nullable=True)

    # Relationships
    assigned_incidents = relationship("Incident", back_populates="assigned_to")
    scans = relationship("ScanRecord", back_populates="user")

    def set_password(self, password: str) -> None:
        """Hash password using Argon2id."""
        self.password_hash = ph.hash(password)

    def check_password(self, password: str) -> bool:
        """Verify password against stored Argon2id hash."""
        try:
            return ph.verify(self.password_hash, password)
        except (VerifyMismatchError, Exception):
            return False

    def generate_api_key(self) -> str:
        """Generate a cryptographically secure API key."""
        self.api_key = secrets.token_hex(32)
        return self.api_key

    def has_role(self, *roles: Role | str) -> bool:
        """Check if user holds one of the specified roles."""
        role_values = [r.value if isinstance(r, Role) else r for r in roles]
        return self.role in role_values

    def to_dict(self) -> dict:
        """Serialize user summary safely (never exposes password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
