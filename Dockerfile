# Multi-stage build for Keycloak Operator
# Stage 1: Build dependencies and install uv
FROM python:3.13-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv (Python package manager)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./

# Install dependencies with uv (creates .venv)
RUN uv sync --frozen --no-dev

# Stage 2: Runtime image
FROM python:3.13-slim as runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r keycloak --gid=1001 && \
    useradd -r -g keycloak --uid=1001 --shell=/bin/bash --create-home keycloak

# Set working directory
WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /app/.venv /app/.venv

# Copy source code
COPY src/ src/
COPY pyproject.toml ./

# Set ownership
RUN chown -R keycloak:keycloak /app

# Switch to non-root user
USER keycloak

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose metrics port (if using Kopf metrics)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/healthz', timeout=5)" || exit 1

# Run the operator
CMD ["python", "-m", "keycloak_operator.operator"]