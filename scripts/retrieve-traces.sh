#!/bin/bash
# Retrieve traces from OTEL Collector pod
#
# This script:
# - Finds trace files in the OTEL collector pod
# - Copies them to the local .tmp/traces directory
# - Can be used after test runs for post-mortem analysis

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source common utilities
source "${SCRIPT_DIR}/common.sh"

OUTPUT_DIR="${REPO_ROOT}/.tmp/traces"
NAMESPACE="observability"
POD_LABEL="app=otel-collector"

log "Retrieving traces from OTEL Collector..."

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Find the collector pod
POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "${POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${POD_NAME}" ]]; then
    warn "No OTEL Collector pod found in namespace ${NAMESPACE}"
    warn "Traces may not have been collected"
    exit 0
fi

log "Found OTEL Collector pod: ${POD_NAME}"

# Check if traces directory exists in pod
if ! kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- ls /traces >/dev/null 2>&1; then
    warn "No traces directory found in pod"
    exit 0
fi

# List trace files
log "Looking for trace files..."
TRACE_FILES=$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- find /traces -name "*.jsonl" -type f 2>/dev/null || true)

if [[ -z "${TRACE_FILES}" ]]; then
    warn "No trace files found"
    exit 0
fi

log "Found trace files:"
echo "${TRACE_FILES}" | while read -r file; do
    if [[ -n "${file}" ]]; then
        log "  - ${file}"
    fi
done

# Copy trace files
log "Copying trace files to ${OUTPUT_DIR}..."
echo "${TRACE_FILES}" | while read -r file; do
    if [[ -n "${file}" ]]; then
        filename=$(basename "${file}")
        kubectl cp "${NAMESPACE}/${POD_NAME}:${file}" "${OUTPUT_DIR}/${filename}"
        success "  ✓ Copied ${filename}"
    fi
done

# Show summary
COPIED_COUNT=$(find "${OUTPUT_DIR}" -name "*.jsonl" -type f 2>/dev/null | wc -l)
success "Retrieved ${COPIED_COUNT} trace file(s) to ${OUTPUT_DIR}"

# Print analysis hint
log ""
log "To analyze traces, run:"
log "  python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --summary"
log "  python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --errors-only"
log "  python scripts/analyze-trace.py ${OUTPUT_DIR}/traces.jsonl --filter 'test_name'"
