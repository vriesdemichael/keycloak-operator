# syntax=docker/dockerfile:1.7
#
# Multi-stage Dockerfile for Keycloak Operator (Alpine Version)
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
FROM python:3.14-alpine AS builder

ENV UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

# Install build dependencies
# 'build-base' is needed to compile python extensions if musl wheels aren't available
# 'git' is often needed if dependencies are referenced via git URLs
# RUN apk add --no-cache build-base git

# Install uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy only files needed to resolve dependencies
COPY pyproject.toml uv.lock README.md LICENSE ./

# Install dependencies with caching mounts
# We use --frozen to ensure the lockfile is respected strictly
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project || \
    (echo "If this failed because uv.lock is absent, remove --frozen or generate the lock file." && exit 1)

# Add application source and install the project
COPY src/ src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ============================================================================
# Stage 2: Production - Lean runtime image
# ============================================================================
FROM python:3.14-alpine AS production

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install runtime system dependencies
RUN apk add --no-cache \
    ca-certificates
    # libstdc++ is often required by binary python extensions
    # libstdc++

# # Upgrade pip/setuptools in the virtual environment to fix potential vulnerabilities
# RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Create non-root user (Alpine syntax)
# -S creates a system user/group
RUN addgroup -g 1001 -S keycloak && \
    adduser -u 1001 -S -G keycloak -s /sbin/nologin -h /home/keycloak keycloak

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
FROM production AS test

# Switch to root to install test dependencies
USER root

# Install build dependencies for test packages (just in case test deps need compilation)
RUN apk add --no-cache build-base

# Copy uv for installing test dependencies
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy lock file for reproducible test dep installation
COPY pyproject.toml uv.lock /app/

# Install test group dependencies into existing venv using cache
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --group test --no-install-project

# Copy coverage configurations
COPY .coveragerc /app/.coveragerc
COPY images/operator/coveragerc.container /app/.coveragerc.container

# Copy test injection module
COPY images/operator/test-inject/ /app/test-inject/

# Install the .pth file
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

# Create coverage data directory
RUN mkdir -p /tmp/coverage && \
    chown -R keycloak:keycloak /app /tmp/coverage

USER keycloak

CMD ["coverage", "run", "--parallel-mode", "--source=/app/src/keycloak_operator", "-m", "keycloak_operator.operator"]
