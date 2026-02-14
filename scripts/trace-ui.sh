#!/bin/bash
# Start Jaeger UI and load OTLP traces for visual debugging
#
# This script:
# - Checks for trace files in .tmp/traces/
# - Starts a Jaeger all-in-one container with OTLP ingestion
# - Pushes collected traces into Jaeger via OTLP HTTP
# - Opens the Jaeger UI in the browser
#
# Usage:
#   ./scripts/trace-ui.sh                          # Default: .tmp/traces/traces.jsonl
#   ./scripts/trace-ui.sh /path/to/traces.jsonl    # Custom trace file

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source common utilities
source "${SCRIPT_DIR}/common.sh"

CONTAINER_NAME="keycloak-operator-jaeger"
JAEGER_IMAGE="jaegertracing/jaeger:1.54.0"  # Pinned for reproducible trace debugging
JAEGER_UI_PORT=16686
OTLP_HTTP_PORT=4318
TRACE_FILE="${1:-${REPO_ROOT}/.tmp/traces/traces.jsonl}"

# ============================================================================
# Pre-flight checks
# ============================================================================

if ! command -v docker &>/dev/null; then
    error "Docker is required but not installed"
    exit 1
fi

if [[ ! -f "${TRACE_FILE}" ]]; then
    error "Trace file not found: ${TRACE_FILE}"
    log ""
    log "Traces are collected during integration test runs."
    log "Run 'make test' first, then try again."
    log ""
    log "If traces are in a different location, pass the path as an argument:"
    log "  ./scripts/trace-ui.sh /path/to/traces.jsonl"
    exit 1
fi

TRACE_LINES=$(wc -l < "${TRACE_FILE}")
TRACE_SIZE=$(wc -c < "${TRACE_FILE}")
log "Found trace file: ${TRACE_FILE} (${TRACE_LINES} lines, ${TRACE_SIZE} bytes)"

if [[ "${TRACE_LINES}" -eq 0 ]]; then
    error "Trace file is empty"
    exit 1
fi

# ============================================================================
# Start Jaeger
# ============================================================================

# Clean up any existing container
if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    log "Removing existing Jaeger container..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1
fi

log "Starting Jaeger all-in-one (OTLP-enabled)..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    --rm \
    -p "${JAEGER_UI_PORT}:${JAEGER_UI_PORT}" \
    -p "${OTLP_HTTP_PORT}:${OTLP_HTTP_PORT}" \
    -e COLLECTOR_OTLP_ENABLED=true \
    -e COLLECTOR_OTLP_HTTP_HOST_PORT="0.0.0.0:${OTLP_HTTP_PORT}" \
    "${JAEGER_IMAGE}" >/dev/null

# Wait for Jaeger to be ready
log "Waiting for Jaeger to be ready..."
RETRIES=30
for i in $(seq 1 ${RETRIES}); do
    if curl -sf "http://localhost:${JAEGER_UI_PORT}/" >/dev/null 2>&1; then
        break
    fi
    if [[ "${i}" -eq "${RETRIES}" ]]; then
        error "Jaeger failed to start within ${RETRIES} seconds"
        docker logs "${CONTAINER_NAME}" 2>&1 | tail -20
        exit 1
    fi
    sleep 1
done
success "Jaeger is ready"

# ============================================================================
# Push traces
# ============================================================================

log "Pushing ${TRACE_LINES} trace records to Jaeger..."
PUSHED=0
FAILED=0

TMPLINE=$(mktemp)
trap "rm -f '${TMPLINE}'" EXIT

while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue

    printf '%s' "${line}" > "${TMPLINE}"

    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        "http://localhost:${OTLP_HTTP_PORT}/v1/traces" \
        -d @"${TMPLINE}" 2>/dev/null) || HTTP_CODE="000"

    if [[ "${HTTP_CODE}" == "200" ]]; then
        PUSHED=$((PUSHED + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done < "${TRACE_FILE}"

if [[ "${FAILED}" -gt 0 ]]; then
    warn "Pushed ${PUSHED} trace records, ${FAILED} failed"
else
    success "Pushed ${PUSHED} trace records to Jaeger"
fi

# ============================================================================
# Open UI
# ============================================================================

JAEGER_URL="http://localhost:${JAEGER_UI_PORT}"
log ""
success "Jaeger UI available at: ${JAEGER_URL}"
log ""
log "To stop Jaeger:  make trace-ui-stop"
log "                 docker rm -f ${CONTAINER_NAME}"
log ""

# Try to open the browser
if command -v xdg-open &>/dev/null; then
    xdg-open "${JAEGER_URL}" 2>/dev/null || true
elif command -v open &>/dev/null; then
    open "${JAEGER_URL}" 2>/dev/null || true
fi
