"""Application configuration settings."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Base configuration."""

    APP_ENV = os.getenv("APP_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-in-production-min32chars")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'dlp_dev.db'}")

    # Fix legacy postgres:// URI if present
    if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)

    # Security & Sessions
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = int(os.getenv("PERMANENT_SESSION_LIFETIME_MINUTES", "60")) * 60

    # Uploads & Scanning Limits
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_BYTES", str(10 * 1024 * 1024)))  # 10 MB default
    ALLOWED_EXTENSIONS = {
        ext.strip().lower() for ext in os.getenv("ALLOWED_EXTENSIONS", "txt,csv,json,xml,md,log,yaml,yml").split(",")
    }

    # Rate Limiting
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "100/minute")
    RATELIMIT_AUTH = os.getenv("RATELIMIT_AUTH", "10/minute")

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False  # Disable CSRF in tests unless explicitly testing CSRF
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Hardened production configuration."""

    DEBUG = False
    SESSION_COOKIE_SECURE = True

    @classmethod
    def validate(cls):
        """Ensure required secrets are provided in production."""
        secret = os.getenv("SECRET_KEY")
        if not secret or len(secret) < 32 or "dev-insecure" in secret:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "Production environment requires a strong SECRET_KEY (min 32 characters)."
            )
        db_url = os.getenv("DATABASE_URL")
        if not db_url or "sqlite" in db_url.lower():
            # In production, recommend PostgreSQL
            pass


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
