# DLP Platform - Multi-Stage Hardened Containerfile
FROM python:3.13-slim AS base

# Install security updates and curl for health check
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group
RUN groupadd -g 10001 dlpgroup && \
    useradd -u 10001 -g dlpgroup -s /bin/false -m dlpuser

WORKDIR /app

# Copy dependency specifications
COPY pyproject.toml .

# Install dependencies into system site-packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application source code
COPY app/ app/
COPY migrations/ migrations/
COPY scripts/ scripts/
COPY docs/ docs/

# Set file ownership to non-root user
RUN chown -R dlpuser:dlpgroup /app

# Switch to non-root execution
USER dlpuser

# Expose web port
EXPOSE 5000

# Container health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/api/v1/health || exit 1

# Launch using production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--access-logfile", "-", "--error-logfile", "-", "app:create_app()"]
