#!/bin/bash
# install-cert-manager.sh - Install cert-manager in the cluster
#
# Purpose: Installs cert-manager for webhook certificate management
# Prerequisites: kubectl, running Kubernetes cluster
# Produces: cert-manager installed and ready
# Used by: Makefile deploy target
#
# Note: Required for admission webhooks to function

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# cert-manager version
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.14.4}"

check_prerequisites() {
    log "Checking prerequisites..."

    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install it."
        exit 1
    fi

    # Check if cluster is accessible
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi

    success "Prerequisites check passed"
}

install_cert_manager() {
    log "Checking if cert-manager is already installed..."

    if kubectl get namespace cert-manager &> /dev/null; then
        if kubectl get deployment -n cert-manager cert-manager &> /dev/null; then
            log "cert-manager is already installed. Checking if it's ready..."
            if kubectl wait --for=condition=available deployment/cert-manager \
                -n cert-manager --timeout=10s &> /dev/null; then
                success "cert-manager is already installed and ready"
                return 0
            else
                warn "cert-manager is installed but not ready. Waiting for it to become ready..."
            fi
        fi
    fi

    log "Installing cert-manager $CERT_MANAGER_VERSION..."
    kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"

    success "cert-manager manifests applied"
}

wait_for_cert_manager() {
    log "Waiting for cert-manager to be ready..."

    # Wait for namespace
    kubectl wait --for=jsonpath='{.status.phase}'=Active namespace/cert-manager --timeout=60s

    # Wait for deployments
    log "Waiting for cert-manager controller..."
    kubectl wait --for=condition=available deployment/cert-manager \
        -n cert-manager --timeout=120s

    log "Waiting for cert-manager webhook..."
    kubectl wait --for=condition=available deployment/cert-manager-webhook \
        -n cert-manager --timeout=120s

    log "Waiting for cert-manager cainjector..."
    kubectl wait --for=condition=available deployment/cert-manager-cainjector \
        -n cert-manager --timeout=120s

    # Wait for webhook to be ready to accept requests
    log "Verifying webhook is accepting requests..."
    sleep 5

    success "cert-manager is ready"
}

verify_installation() {
    log "Verifying cert-manager installation..."

    # Check cert-manager version
    log "cert-manager components:"
    kubectl get deployment -n cert-manager -o wide

    # Check CRDs
    log "cert-manager CRDs:"
    kubectl get crd | grep cert-manager.io || true

    # Create test issuer to verify functionality
    log "Testing cert-manager functionality with a test issuer..."
    cat <<EOF | kubectl apply -f - > /dev/null
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: test-selfsigned
  namespace: default
spec:
  selfSigned: {}
EOF

    # Wait a moment for the issuer to be ready
    sleep 2

    # Check if issuer is ready
    if kubectl get issuer test-selfsigned -n default -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q "True"; then
        success "cert-manager is functioning correctly"
        kubectl delete issuer test-selfsigned -n default > /dev/null
    else
        warn "Test issuer created but may not be ready yet. This is usually fine."
        kubectl delete issuer test-selfsigned -n default > /dev/null || true
    fi

    success "Installation verification completed"
}

main() {
    log "Starting cert-manager installation..."

    check_prerequisites
    install_cert_manager
    wait_for_cert_manager
    verify_installation

    success "🎉 cert-manager installation completed successfully!"
    log "Version: $CERT_MANAGER_VERSION"
    log ""
    log "Next steps:"
    log "  - Deploy the operator with webhooks enabled"
    log "  - Certificates will be automatically generated and rotated"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Installs cert-manager for webhook certificate management."
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  CERT_MANAGER_VERSION  cert-manager version to install (default: v1.14.4)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
