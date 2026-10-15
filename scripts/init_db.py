"""Database initialization script."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db


def init_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("Database schema successfully initialized.")


if __name__ == "__main__":
    init_database()
