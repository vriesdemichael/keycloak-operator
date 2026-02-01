#!/bin/bash
# Deploy OpenTelemetry Collector for trace collection during tests
#
# This script deploys an OTEL Collector that:
# - Receives traces via OTLP (gRPC and HTTP)
# - Exports traces to a JSONL file for post-mortem analysis
# - Is accessible within the cluster at otel-collector.observability.svc.cluster.local:4317

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source common utilities
source "${SCRIPT_DIR}/common.sh"

OTEL_MANIFESTS_DIR="${REPO_ROOT}/k8s/testing/otel-collector"

log "Starting OTEL Collector deployment..."

# Check if manifests exist
if [[ ! -d "${OTEL_MANIFESTS_DIR}" ]]; then
    error "OTEL Collector manifests not found at ${OTEL_MANIFESTS_DIR}"
    exit 1
fi

# Deploy in order: namespace, configmap, deployment, service
log "Deploying OpenTelemetry Collector..."

log "Creating namespace..."
kubectl apply -f "${OTEL_MANIFESTS_DIR}/namespace.yaml"

log "Creating ConfigMap..."
kubectl apply -f "${OTEL_MANIFESTS_DIR}/configmap.yaml"

log "Creating Deployment..."
kubectl apply -f "${OTEL_MANIFESTS_DIR}/deployment.yaml"

log "Creating Service..."
kubectl apply -f "${OTEL_MANIFESTS_DIR}/service.yaml"

# Wait for collector to be ready
log "Waiting for OTEL Collector to be ready..."
kubectl wait --for=condition=available deployment/otel-collector \
    -n observability \
    --timeout=120s

success "OTEL Collector deployed successfully"

# Verify deployment
log "Verifying OTEL Collector deployment..."
kubectl get pods -n observability

log "OTEL Collector endpoint: otel-collector.observability.svc.cluster.local:4317"

success "OTEL Collector is ready to receive traces"

# Print usage instructions
log ""
log "Configure operator tracing with:"
log "  OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability.svc.cluster.local:4317"

success "OTEL Collector setup completed!"
