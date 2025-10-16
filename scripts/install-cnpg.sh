#!/bin/bash
# install-cnpg.sh - Install CloudNativePG operator into the Kind test cluster
#
# Purpose: Installs CNPG operator using Helm
# Prerequisites: kubectl, helm
# Produces: Running CNPG operator and CRDs
# Used by: Makefile install-cnpg target
#
# This script is idempotent and safe to re-run.

set -euo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/config.sh"

# CNPG values for Helm
CNPG_VALUES=$(cat <<'EOF'
metrics:
  enablePodMonitor: true
webhook:
  create: true
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
watchNamespace: ""
EOF
)

check_prerequisites() {
    if ! command -v kubectl >/dev/null 2>&1; then
        error "kubectl not found"
        exit 1
    fi

    if ! command -v helm >/dev/null 2>&1; then
        error "Helm not available; please install Helm for CNPG installation"
        exit 1
    fi
}

check_already_installed() {
    local REQUIRED_CRDS=(clusters.postgresql.cnpg.io backups.postgresql.cnpg.io poolers.postgresql.cnpg.io)

    local already_complete=true
    for r in "${REQUIRED_CRDS[@]}"; do
        if ! kubectl get crd "$r" >/dev/null 2>&1; then
            already_complete=false
        fi
    done

    if $already_complete && kubectl get deployment -n "$CNPG_NAMESPACE" cnpg-controller-manager >/dev/null 2>&1; then
        ok "CloudNativePG already installed and CRDs present"
        exit 0
    fi
}

install_cnpg() {
    log "Creating CNPG namespace..."
    kubectl create namespace "$CNPG_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    log "Adding CloudNativePG Helm repository..."
    if ! helm repo list | grep -q cloudnative-pg; then
        helm repo add cloudnative-pg https://cloudnative-pg.github.io/charts >/dev/null 2>&1 || {
            error "Failed adding cloudnative-pg repo"
            exit 1
        }
    fi
    helm repo update >/dev/null 2>&1 || true

    log "Installing CloudNativePG helm chart version ${CNPG_CHART_VERSION_PRIMARY}"
    if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
        --version "$CNPG_CHART_VERSION_PRIMARY" \
        --namespace "$CNPG_NAMESPACE" \
        --create-namespace -f -; then
        warn "Primary version failed; attempting fallback ${CNPG_CHART_VERSION_FALLBACK}"
        if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
            --version "$CNPG_CHART_VERSION_FALLBACK" \
            --namespace "$CNPG_NAMESPACE" \
            --create-namespace -f -; then
            error "Helm installation failed for both primary and fallback versions"
            exit 1
        fi
    fi
}

wait_for_crds() {
    log "Waiting for CNPG CRDs to become available..."
    local CRDS=(clusters.postgresql.cnpg.io backups.postgresql.cnpg.io poolers.postgresql.cnpg.io)
    for crd in "${CRDS[@]}"; do
        if ! kubectl wait --for=condition=Established "crd/${crd}" --timeout=180s 2>/dev/null; then
            warn "CRD ${crd} not established yet (continuing)"
        else
            ok "CRD ${crd} established"
        fi
    done
}

wait_for_operator() {
    log "Waiting for CNPG operator deployment to be ready..."
    # Deployment name differs between helm (cnpg) and manifest (cloudnative-pg); check both
    local target_dep
    if kubectl get deployment cnpg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cnpg
    elif kubectl get deployment cloudnative-pg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cloudnative-pg
    elif kubectl get deployment cnpg-cloudnative-pg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cnpg-cloudnative-pg        
    else
        warn "Could not find CNPG operator deployment yet; listing resources"
        kubectl get all -n "$CNPG_NAMESPACE" || true
        target_dep=cloudnative-pg
    fi

    if ! kubectl rollout status "deployment/${target_dep}" -n "$CNPG_NAMESPACE" --timeout=240s; then
        error "CNPG operator deployment ${target_dep} not ready"
        exit 1
    fi
}

main() {
    log "Installing CloudNativePG operator..."

    check_prerequisites
    check_already_installed
    install_cnpg
    wait_for_crds
    wait_for_operator

    ok "CloudNativePG operator installed successfully"
}

main "$@"
