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

# Configuration
CNPG_NAMESPACE="cnpg-system"
CNPG_HELM_RELEASE="cnpg"
CNPG_HELM_CHART="cloudnative-pg/cloudnative-pg"
CNPG_CHART_VERSION_PRIMARY="0.22.1"
CNPG_CHART_VERSION_FALLBACK="0.21.6"

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
        echo "❌ ERROR: kubectl not found"
        exit 1
    fi

    if ! command -v helm >/dev/null 2>&1; then
        echo "❌ ERROR: Helm not available; please install Helm for CNPG installation"
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
        echo "✅ CloudNativePG already installed and CRDs present"
        exit 0
    fi
}

install_cnpg() {
    echo "📦 Creating CNPG namespace..."
    kubectl create namespace "$CNPG_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    echo "📦 Adding CloudNativePG Helm repository..."
    if ! helm repo list | grep -q cloudnative-pg; then
        helm repo add cloudnative-pg https://cloudnative-pg.github.io/charts >/dev/null 2>&1 || {
            echo "❌ ERROR: Failed adding cloudnative-pg repo"
            exit 1
        }
    fi
    helm repo update >/dev/null 2>&1 || true

    echo "📦 Installing CloudNativePG helm chart version ${CNPG_CHART_VERSION_PRIMARY}"
    if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
        --version "$CNPG_CHART_VERSION_PRIMARY" \
        --namespace "$CNPG_NAMESPACE" \
        --create-namespace -f -; then
        echo "⚠️  Primary version failed; attempting fallback ${CNPG_CHART_VERSION_FALLBACK}"
        if ! printf "%s" "$CNPG_VALUES" | helm upgrade --install "$CNPG_HELM_RELEASE" "$CNPG_HELM_CHART" \
            --version "$CNPG_CHART_VERSION_FALLBACK" \
            --namespace "$CNPG_NAMESPACE" \
            --create-namespace -f -; then
            echo "❌ ERROR: Helm installation failed for both primary and fallback versions"
            exit 1
        fi
    fi
}

wait_for_crds() {
    echo "📦 Waiting for CNPG CRDs to become available..."
    local CRDS=(clusters.postgresql.cnpg.io backups.postgresql.cnpg.io poolers.postgresql.cnpg.io)
    for crd in "${CRDS[@]}"; do
        if ! kubectl wait --for=condition=Established "crd/${crd}" --timeout=180s 2>/dev/null; then
            echo "⚠️  CRD ${crd} not established yet (continuing)"
        else
            echo "✅ CRD ${crd} established"
        fi
    done
}

wait_for_operator() {
    echo "📦 Waiting for CNPG operator deployment to be ready..."
    # Deployment name differs between helm (cnpg) and manifest (cloudnative-pg); check both
    local target_dep
    if kubectl get deployment cnpg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cnpg
    elif kubectl get deployment cloudnative-pg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cloudnative-pg
    elif kubectl get deployment cnpg-cloudnative-pg -n "$CNPG_NAMESPACE" >/dev/null 2>&1; then
        target_dep=cnpg-cloudnative-pg        
    else
        echo "⚠️  Could not find CNPG operator deployment yet; listing resources"
        kubectl get all -n "$CNPG_NAMESPACE" || true
        target_dep=cloudnative-pg
    fi

    if ! kubectl rollout status "deployment/${target_dep}" -n "$CNPG_NAMESPACE" --timeout=240s; then
        echo "❌ ERROR: CNPG operator deployment ${target_dep} not ready"
        exit 1
    fi
}

main() {
    echo "📦 Installing CloudNativePG operator..."

    check_prerequisites
    check_already_installed
    install_cnpg
    wait_for_crds
    wait_for_operator

    echo "✅ CloudNativePG operator installed successfully"
}

main "$@"
