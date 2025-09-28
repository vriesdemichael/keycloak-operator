#!/bin/bash
# kind-teardown.sh - Clean up Kind cluster and resources

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}

# Configuration
CLUSTER_NAME="keycloak-operator-test"

cleanup_cluster() {
    log "Cleaning up Kind cluster '$CLUSTER_NAME'..."

    # Check if cluster exists
    if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        warn "Cluster '$CLUSTER_NAME' does not exist. Nothing to clean up."
        return 0
    fi

    # Delete the cluster
    kind delete cluster --name "$CLUSTER_NAME"

    success "Kind cluster deleted successfully"
}

cleanup_docker_resources() {
    log "Cleaning up Docker resources..."

    # Remove dangling images from Kind
    if docker images | grep -q "kindest/node"; then
        log "Cleaning up Kind node images..."
        # Only remove unused images to avoid removing images for other clusters
        docker image prune -f --filter "label=io.k8s.sigs.kind.cluster=$CLUSTER_NAME" 2>/dev/null || true
    fi

    # Clean up any leftover containers
    log "Cleaning up leftover containers..."
    docker container prune -f 2>/dev/null || true

    success "Docker cleanup completed"
}

cleanup_kubectl_context() {
    log "Cleaning up kubectl context..."

    local context_name="kind-${CLUSTER_NAME}"

    # Check if context exists
    if kubectl config get-contexts | grep -q "$context_name"; then
        # Delete the context
        kubectl config delete-context "$context_name" 2>/dev/null || true
        log "Kubectl context '$context_name' removed"
    else
        log "Kubectl context '$context_name' not found"
    fi

    # Switch to a different context if the deleted one was current
    local current_context
    current_context=$(kubectl config current-context 2>/dev/null || echo "")
    if [ "$current_context" = "$context_name" ]; then
        log "Switching to default context..."
        # Try to switch to a reasonable default
        if kubectl config get-contexts | grep -q "docker-desktop"; then
            kubectl config use-context docker-desktop
        elif kubectl config get-contexts | grep -q "minikube"; then
            kubectl config use-context minikube
        else
            warn "No suitable default context found. You may need to set a context manually."
        fi
    fi

    success "Kubectl context cleanup completed"
}

cleanup_local_files() {
    log "Cleaning up local test files..."

    # Remove any temporary test files
    if [ -f "test-keycloak.yaml" ]; then
        rm -f test-keycloak.yaml
        log "Removed test-keycloak.yaml"
    fi

    # Remove any test logs
    if [ -d "test-logs" ]; then
        rm -rf test-logs
        log "Removed test-logs directory"
    fi

    # Kill any leftover port-forward processes
    pkill -f "kubectl.*port-forward" 2>/dev/null || true
    pkill -f "port-forward" 2>/dev/null || true

    success "Local file cleanup completed"
}

verify_cleanup() {
    log "Verifying cleanup..."

    # Check if cluster still exists
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        error "Cluster '$CLUSTER_NAME' still exists!"
        return 1
    fi

    # Check kubectl context
    if kubectl config get-contexts 2>/dev/null | grep -q "kind-${CLUSTER_NAME}"; then
        error "Kubectl context still exists!"
        return 1
    fi

    success "Cleanup verification passed"
}

main() {
    log "Starting Kind cluster cleanup..."

    cleanup_cluster
    cleanup_kubectl_context
    cleanup_docker_resources
    cleanup_local_files
    verify_cleanup

    success "🧹 Kind cluster cleanup completed successfully!"
    log "All resources for cluster '$CLUSTER_NAME' have been removed."
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "This script cleans up the Kind cluster and associated resources"
        echo "created for Keycloak operator integration testing."
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help message"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac