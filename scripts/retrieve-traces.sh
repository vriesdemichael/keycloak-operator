#!/bin/bash
# Retrieve traces from OTEL Collector pod
#
# This script:
# - Uses the trace-access sidecar (busybox) to copy trace files
# - The main collector container is distroless and lacks tar/sh/cat,
#   so kubectl cp targets the sidecar instead
# - Copies traces to the local .tmp/traces directory
# - Can be used after test runs for post-mortem analysis

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source common utilities
source "${SCRIPT_DIR}/common.sh"

OUTPUT_DIR="${REPO_ROOT}/.tmp/traces"
NAMESPACE="observability"
CONTAINER="trace-access"

log "Retrieving traces from OTEL Collector..."

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Find the collector pod
POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l app=otel-collector -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${POD_NAME}" ]]; then
    warn "No OTEL Collector pod found in namespace ${NAMESPACE}"
    warn "Traces may not have been collected"
    exit 0
fi

log "Found OTEL Collector pod: ${POD_NAME}"

# Check if traces file exists using the trace-access sidecar
if ! kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- ls /traces/traces.jsonl >/dev/null 2>&1; then
    warn "No traces file found at /traces/traces.jsonl"
    warn "Either tracing is not enabled or no traces have been collected yet"
    exit 0
fi

# Get trace file size for context
TRACE_SIZE=$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- sh -c 'wc -c < /traces/traces.jsonl' 2>/dev/null || echo "unknown")
TRACE_LINES=$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -c "${CONTAINER}" -- sh -c 'wc -l < /traces/traces.jsonl' 2>/dev/null || echo "unknown")
log "Trace file: ${TRACE_SIZE} bytes, ${TRACE_LINES} lines"

# Copy trace file using the sidecar container (which has tar)
log "Copying traces to ${OUTPUT_DIR}..."
kubectl cp "${NAMESPACE}/${POD_NAME}:/traces/traces.jsonl" "${OUTPUT_DIR}/traces.jsonl" -c "${CONTAINER}"

if [[ -f "${OUTPUT_DIR}/traces.jsonl" ]]; then
    LOCAL_SIZE=$(wc -c < "${OUTPUT_DIR}/traces.jsonl")
    success "Retrieved traces: ${LOCAL_SIZE} bytes → ${OUTPUT_DIR}/traces.jsonl"
else
    error "Failed to copy traces"
    exit 1
fi

# Print analysis hints
log ""
log "To analyze traces, run:"
log "  uv run python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --summary"
log "  uv run python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --errors-only"
log "  uv run python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --filter 'test_name'"
