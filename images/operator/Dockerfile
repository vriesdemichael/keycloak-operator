# syntax=docker/dockerfile:1.7
#
# Multi-stage Dockerfile for Keycloak Operator
#
# Targets:
#   - production: Production image (default)
#   - test: Extends production with coverage instrumentation for testing
#
# Usage:
#   docker build --target production -t keycloak-operator:latest .
#   docker build --target test -t keycloak-operator:test .

# ============================================================================
# Stage 1: Builder - Resolve and install dependencies
# ============================================================================
FROM python:3.13-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy only files needed to resolve dependencies
COPY pyproject.toml uv.lock README.md LICENSE ./

# Install dependencies (improves layer caching)
RUN uv sync --frozen --no-dev --no-install-project || \
    (echo "If this failed because uv.lock is absent, remove --frozen or generate the lock file." && exit 1)

# Add application source and install the project
COPY src/ src/
RUN uv sync --frozen --no-dev

# ============================================================================
# Stage 2: Production - Lean runtime image
# ============================================================================
FROM python:3.13-slim AS production

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade system python tools to fix potential vulnerabilities (e.g. CVE-2025-8869 in pip)
# Install latest versions for maximum security (sacrificing determinism)
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Non-root user
RUN groupadd -r keycloak --gid=1001 && \
    useradd -r -g keycloak --uid=1001 --shell=/usr/sbin/nologin --create-home keycloak

WORKDIR /app

# Copy virtual environment and source from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/pyproject.toml /app/pyproject.toml
COPY --from=builder /app/README.md /app/README.md
COPY --from=builder /app/LICENSE /app/LICENSE

RUN chown -R keycloak:keycloak /app
USER keycloak

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/healthz', timeout=5)" || exit 1

CMD ["python", "-m", "keycloak_operator.operator"]

# ============================================================================
# Stage 3: Test - Extends production with coverage instrumentation
# ============================================================================
# This stage adds test dependencies and coverage collection to the production
# image, ensuring we test exactly what we ship.
FROM production AS test

# Switch to root to install test dependencies
USER root

# Copy uv for installing test dependencies
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy lock file for reproducible test dep installation
COPY pyproject.toml uv.lock /app/

# Install test group dependencies into existing venv
RUN uv sync --frozen --group test --no-install-project

# Copy coverage configurations
COPY .coveragerc /app/.coveragerc
COPY images/operator/coveragerc.container /app/.coveragerc.container

# Copy test injection module for auto-starting coverage
COPY images/operator/test-inject /app/test-inject

# Install the .pth file to auto-import sitecustomize.py at startup
RUN python - <<'PY'
import sysconfig, pathlib
sp = sysconfig.get_paths()['purelib']
pth = pathlib.Path(sp) / "test_inject.pth"
pth.write_text("/app/test-inject\n")
print(f"Created {pth}")
PY

# Set coverage environment variables
ENV COVERAGE_PROCESS_START=/app/.coveragerc.container
ENV COVERAGE_FILE=/tmp/coverage/.coverage

# Create coverage data directory with proper permissions
RUN mkdir -p /tmp/coverage && \
    chown -R keycloak:keycloak /app /tmp/coverage

USER keycloak

# Override CMD to run with coverage instrumentation
CMD ["coverage", "run", "--parallel-mode", "--source=/app/src/keycloak_operator", "-m", "keycloak_operator.operator"]
