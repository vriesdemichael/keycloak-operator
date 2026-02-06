# Optimized Keycloak Image for Testing
# This image pre-builds Keycloak with PostgreSQL database support and common settings
# to significantly reduce startup time in test environments.
#
# Build time optimization trades container build time for runtime startup speed.
# Expected startup time: 20-30s (vs 70s+ for unoptimized)

ARG KEYCLOAK_VERSION=26.4.1

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder

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
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

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
