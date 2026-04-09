# Optimized Keycloak Image for Testing
# This image pre-builds Keycloak with PostgreSQL database support and common settings
# to significantly reduce startup time in test environments.
#
# Build time optimization trades container build time for runtime startup speed.
# Expected startup time: 20-30s (vs 70s+ for unoptimized)

ARG KEYCLOAK_VERSION=26.4.1
ARG KEYCLOAK_IMAGE_DIGEST=sha256:bbb299c7e58a2c61c683dc3439da3e2698e005ca88ba6fd249629311d70250ab

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}@${KEYCLOAK_IMAGE_DIGEST} AS builder

# Configure for PostgreSQL (used in tests via CNPG)
ENV KC_DB=postgres

# Enable health and metrics endpoints
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Enable HTTP for ingress TLS termination
ENV KC_HTTP_ENABLED=true

# Enable proxy headers forwarding
ENV KC_PROXY_HEADERS=xforwarded

# Optional: enable OpenTelemetry tracing support (Keycloak 26.x+ via Quarkus).
# KC_TRACING_ENABLED is a build-time option; the OTEL provider must be compiled
# in during `kc.sh build`. Pass --build-arg TRACING_ENABLED=true to include it.
# Runtime env vars (KC_TRACING_ENDPOINT, KC_TRACING_SAMPLER_RATIO) still control
# whether traces are actually exported.
ARG TRACING_ENABLED=false
ENV KC_TRACING_ENABLED=${TRACING_ENABLED}

WORKDIR /opt/keycloak

# Build the optimized Keycloak image
# This pre-processes:
# - Database drivers (PostgreSQL)
# - Feature configuration (health, metrics)
# - HTTP/proxy settings
# - Theme compilation
# - Cache configuration
RUN /opt/keycloak/bin/kc.sh build

# Production image - copy optimized build
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}@${KEYCLOAK_IMAGE_DIGEST} AS production

# Copy the optimized Keycloak build from builder stage
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Set working directory
WORKDIR /opt/keycloak

# Use optimized startup mode
# Runtime configuration (connection details, credentials) can still be provided via env vars:
# - KC_DB_URL_HOST, KC_DB_URL_PORT, KC_DB_URL_DATABASE
# - KC_DB_USERNAME, KC_DB_PASSWORD
# - KEYCLOAK_ADMIN, KEYCLOAK_ADMIN_PASSWORD
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]

# OCI image labels - declared last to avoid busting the layer cache for expensive
# COPY steps above. In multi-stage builds each stage must declare its own ARGs.
# KEYCLOAK_VERSION is a global ARG (declared before the first FROM) so it must be
# re-declared here to be usable within this stage.
ARG KEYCLOAK_VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Keycloak (Optimized)" \
      org.opencontainers.image.description="Pre-built optimized Keycloak image with PostgreSQL, health, metrics and proxy support" \
      org.opencontainers.image.source="https://github.com/vriesdemichael/keycloak-operator" \
      org.opencontainers.image.url="https://github.com/vriesdemichael/keycloak-operator" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${KEYCLOAK_VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
