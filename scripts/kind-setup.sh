#!/bin/bash
# kind-setup.sh - Create bare Kind cluster for Keycloak operator testing
#
# Purpose: Creates a minimal Kind cluster with required namespaces
# Prerequisites: kind, kubectl, docker
# Produces: Running cluster with operator and CNPG namespaces created
# Used by: Taskfile cluster:create task
#
# Note: CRDs, RBAC, and operator deployment are handled by the test harness.

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/config.sh"

check_prerequisites() {
    log "Checking prerequisites..."

    # Check if kind is installed
    if ! command -v kind &> /dev/null; then
        error "kind is not installed. Please install it from https://kind.sigs.k8s.io/"
        exit 1
    fi

    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed. Please install it."
        exit 1
    fi

    # Check if docker is running
    if ! docker info &> /dev/null; then
        error "Docker is not running. Please start Docker."
        exit 1
    fi

    success "Prerequisites check passed"
}

create_cluster() {
    log "Creating Kind cluster '$CLUSTER_NAME'..."

    # Check if cluster already exists
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        if [ "${KIND_RETAIN_CLUSTER:-false}" == "true" ]; then
            log "Cluster '$CLUSTER_NAME' exists and KIND_RETAIN_CLUSTER is true. Skipping creation."
            return
        fi
        warn "Cluster '$CLUSTER_NAME' already exists. Deleting and recreating..."
        kind delete cluster --name "$CLUSTER_NAME"
    fi

    # Create the cluster
    kind create cluster \
        --name "$CLUSTER_NAME" \
        --config "$KIND_CONFIG" \
        --image "kindest/node:$KUBERNETES_VERSION" \
        --wait 300s

    success "Kind cluster created successfully"
}

setup_cluster() {
    log "Setting up cluster namespaces..."

    # Set kubectl context
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"

    # Wait for nodes to be ready
    log "Waiting for nodes to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s

    # Check CNI setup
    log "Verifying CNI setup..."
    if ! kubectl get pods -n kube-system | grep -q "kindnet\|flannel\|calico\|weave"; then
        warn "No CNI detected. Installing Kindnet..."
        kubectl apply -f https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml
        kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s
    fi

    # Create required namespaces
    # Note: operator namespace (keycloak-system) is created by Helm chart
    # Only create CNPG namespace here as it's managed by CNPG Helm chart

    log "Creating CNPG namespace ($CNPG_NAMESPACE)..."
    kubectl create namespace "$CNPG_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Deploy OTEL Collector for trace collection during tests
    log "Deploying OTEL Collector for trace collection..."
    bash "${SCRIPT_DIR}/deploy-otel-collector.sh"

    success "Cluster setup completed"
}

verify_setup() {
    log "Verifying cluster setup..."

    # Check cluster info
    kubectl cluster-info

    # Check nodes
    log "Cluster nodes:"
    kubectl get nodes -o wide

    # Check namespaces
    log "Created namespaces:"
    kubectl get namespace | grep -E "$OPERATOR_NAMESPACE|$CNPG_NAMESPACE"

    success "Cluster verification completed"
}

main() {
    log "Starting Kind cluster setup for Keycloak operator testing..."

    check_prerequisites
    create_cluster
    setup_cluster
    verify_setup

    success "🎉 Kind cluster setup completed successfully!"
    log "Cluster name: $CLUSTER_NAME"
    log "Kubernetes version: $KUBERNETES_VERSION"
    log "To use this cluster, run: kubectl config use-context kind-$CLUSTER_NAME"
    log ""
    log "Next steps:"
    log "  1. Run 'task infra:all' to install operator dependencies (CNPG, etc.)"
    log "  2. Run 'task test:all' to run the complete test suite"
    log "  3. Run 'task cluster:destroy' to cleanup when done"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Creates a bare Kind cluster for Keycloak operator development."
        echo "CRDs, RBAC, and operator deployment are handled by the test harness."
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  KUBERNETES_VERSION  Kubernetes version to use (default: v1.28.0)"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
