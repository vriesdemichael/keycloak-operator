# syntax=docker/dockerfile:1.7

# ---- Stage 1: Build / Resolve deps -----------------------------------------
FROM python:3.13-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app

# Copy only files needed to resolve dependencies
# If uv.lock does not exist yet, omit it (or create it locally with `uv lock`)
COPY pyproject.toml uv.lock README.md LICENSE ./

# First install ONLY dependencies (improves layer caching)
# Use --no-install-project so missing src/ does not break the build
RUN uv sync --frozen --no-dev --no-install-project || \
    (echo "If this failed because uv.lock is absent, remove --frozen or generate the lock file." && exit 1)

# Now add the application source and install the project itself
COPY src/ src/

# Install the project (editable not needed inside image)
# Re-run sync to add project to venv without re-resolving deps
RUN uv sync --frozen --no-dev

# ---- Stage 2: Runtime ------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r keycloak --gid=1001 && \
    useradd -r -g keycloak --uid=1001 --shell=/usr/sbin/nologin --create-home keycloak

WORKDIR /app

# Copy virtual environment and source
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
