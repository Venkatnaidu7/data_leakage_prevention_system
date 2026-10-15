# Operations and Deployment Guide

## 1. Environment Configuration

The DLP system requires configuration via environment variables or an `.env` file in the project root.

| Variable | Default (Dev) | Production Requirement | Description |
|---|---|---|---|
| `APP_ENV` | `development` | `production` | Environment tier. In `production`, debug mode is forced off and insecure defaults fail startup. |
| `SECRET_KEY` | (dev fallback) | **Required** (>= 32 random characters) | Used for signing session cookies and CSRF tokens. |
| `DATABASE_URL` | `sqlite:///dlp_dev.db` | `postgresql+psycopg://...` | Connection URI for the application database. |
| `SESSION_COOKIE_SECURE` | `false` | `true` | Enforces HTTPS-only delivery of session cookies. |
| `SESSION_COOKIE_HTTPONLY`| `true` | `true` | Prevents JavaScript access to session cookies. |
| `SESSION_COOKIE_SAMESITE`| `Lax` | `Lax` or `Strict` | Mitigates CSRF. |
| `MAX_CONTENT_LENGTH_BYTES`| `10485760` (10 MB) | Max upload limit | Prevents memory exhaustion during file uploads. |
| `RATELIMIT_DEFAULT` | `100/minute` | Rate limit tier | Protects API endpoints against brute force and DoS. |
| `RATELIMIT_AUTH` | `10/minute` | Rate limit tier | Protects login and token endpoints. |

## 2. Local Setup and Startup

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -e ".[dev]"

# 3. Configure environment
cp .env.example .env

# 4. Initialize database and seed initial demo users and policies
python scripts/init_db.py
python scripts/seed_data.py

# 5. Start development server
flask --app app run --debug
```

Default credentials seeded:
- **Administrator:** `admin@dlp.local` / `AdminPass123!@#` (Role: `Admin`)
- **Security Analyst:** `analyst@dlp.local` / `AnalystPass123!@#` (Role: `Analyst`)
- **Auditor:** `auditor@dlp.local` / `AuditorPass123!@#` (Role: `Auditor`)

> **Warning:** Change all default passwords immediately upon deployment. Never use default passwords in staging or production.

## 3. Production Deployment with Docker Compose

A hardened multi-container Docker Compose configuration is provided:
- Unprivileged user execution (UID/GID `10001`).
- Non-root Postgres database container with persistent volume.
- Gunicorn WSGI server.
- Health checks enabled for all containers.

```bash
# Build and run containers
docker compose up -d --build

# View operational logs
docker compose logs -f dlp-web
```

## 4. Database Migrations

Database schema changes are managed with Flask-Migrate (Alembic):

```bash
# Apply pending migrations
flask --app app db upgrade

# Generate a new migration script
flask --app app db migrate -m "Add new policy attribute"
```

## 5. Backup and Data Retention Policy

- **Database Backups:** Daily encrypted snapshots of the PostgreSQL database using `pg_dump`.
- **Evidence Retention:** Sensitive snippets stored in incidents are masked by default. Incidents older than the corporate data retention policy (e.g., 90 or 180 days) should be purged or archived using the data maintenance script.
- **Audit Log Immutability:** Audit records should be periodically streamed or exported to an external centralized SIEM or immutable cloud log bucket (e.g. AWS CloudWatch / S3 with Object Lock).
