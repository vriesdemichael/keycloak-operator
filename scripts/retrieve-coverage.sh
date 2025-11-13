#!/usr/bin/env bash
# Retrieve coverage data from operator pod running in Kubernetes cluster
# Usage: ./scripts/retrieve-coverage.sh [namespace] [label-selector]

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/common.sh
source "${SCRIPT_DIR}/common.sh"

# Configuration
NAMESPACE="${1:-keycloak-test-system}"
LABEL_SELECTOR="${2:-app.kubernetes.io/name=keycloak-operator}"
COVERAGE_DIR=".tmp/coverage"
COVERAGE_SRC_PATH="/tmp/coverage"

log "Retrieving coverage data from operator pod..."

# Create local coverage directory
mkdir -p "${COVERAGE_DIR}"
log "Created coverage directory: ${COVERAGE_DIR}"

# Find operator pod
log "Looking for operator pod with selector: ${LABEL_SELECTOR} in namespace: ${NAMESPACE}"
POD_NAME=$(kubectl get pods -n "${NAMESPACE}" \
    -l "${LABEL_SELECTOR}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "${POD_NAME}" ]; then
    error "No operator pod found with label ${LABEL_SELECTOR} in namespace ${NAMESPACE}"
    exit 1
fi

log "Found operator pod: ${POD_NAME}"

# Check if pod is running
POD_STATUS=$(kubectl get pod -n "${NAMESPACE}" "${POD_NAME}" \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "")

if [ "${POD_STATUS}" != "Running" ]; then
    warn "Pod ${POD_NAME} is not running (status: ${POD_STATUS})"
    warn "Coverage data may be incomplete"
fi

# List coverage files in pod
log "Checking for coverage files in pod..."
COVERAGE_FILES=$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- \
    sh -c "ls -1 ${COVERAGE_SRC_PATH}/.coverage* 2>/dev/null || true")

if [ -z "${COVERAGE_FILES}" ]; then
    warn "No coverage files found in pod at ${COVERAGE_SRC_PATH}"
    warn "This is expected if coverage was not enabled or operator hasn't processed any requests"
    exit 0
fi

log "Found coverage files:"
echo "${COVERAGE_FILES}" | while read -r file; do
    log "  - ${file}"
done

# Copy coverage files from pod to local directory
log "Copying coverage files from pod to ${COVERAGE_DIR}..."
FILE_COUNT=0
while IFS= read -r file; do
    if [ -z "${file}" ]; then
        continue
    fi

    BASENAME=$(basename "${file}")
    LOCAL_PATH="${COVERAGE_DIR}/${BASENAME}"

    log "Copying ${file} -> ${LOCAL_PATH}"
    if kubectl cp -n "${NAMESPACE}" "${POD_NAME}:${file}" "${LOCAL_PATH}" 2>/dev/null; then
        FILE_COUNT=$((FILE_COUNT + 1))
        success "  ✓ Copied ${BASENAME}"
    else
        error "  ✗ Failed to copy ${BASENAME}"
    fi
done <<< "${COVERAGE_FILES}"

if [ "${FILE_COUNT}" -eq 0 ]; then
    error "Failed to copy any coverage files"
    exit 1
fi

success "Successfully retrieved ${FILE_COUNT} coverage file(s) from operator pod"
log "Coverage files are in: ${COVERAGE_DIR}"

# List retrieved files
log "Retrieved files:"
ls -lh "${COVERAGE_DIR}"

exit 0
