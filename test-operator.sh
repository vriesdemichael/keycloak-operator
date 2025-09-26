#!/bin/bash
# test-operator.sh - Quick integration test for Keycloak operator
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

cleanup() {
    log "Cleaning up test resources..."
    kubectl delete -f test-keycloak.yaml 2>/dev/null || true
    kubectl delete namespace keycloak-test 2>/dev/null || true
    pkill -f "port-forward" 2>/dev/null || true
    pkill -f "keycloak_operator" 2>/dev/null || true
    log "Cleanup complete"
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

main() {
    log "Starting Keycloak operator integration test..."

    # Check prerequisites
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed or not in PATH"
        exit 1
    fi

    if ! command -v uv &> /dev/null; then
        error "uv is not installed or not in PATH"
        exit 1
    fi

    # Test kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Install CRDs
    log "Installing CRDs..."
    kubectl apply -f k8s/crds/ > /dev/null
    success "CRDs installed"

    # Start operator in background
    log "Starting operator..."
    uv run python -m keycloak_operator.operator &
    OPERATOR_PID=$!
    sleep 5
    success "Operator started (PID: $OPERATOR_PID)"

    # Create test namespace
    log "Creating test namespace..."
    kubectl create namespace keycloak-test > /dev/null
    success "Test namespace created"

    # Create secrets
    log "Creating test secrets..."
    kubectl create secret generic keycloak-db-secret \
        --from-literal=password=testpass -n keycloak-test > /dev/null
    kubectl create secret generic keycloak-admin-secret \
        --from-literal=password=admin123 -n keycloak-test > /dev/null
    success "Test secrets created"

    # Create test Keycloak YAML
    log "Creating test Keycloak resource..."
    cat > test-keycloak.yaml << EOF
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: test-keycloak
  namespace: keycloak-test
spec:
  image: "quay.io/keycloak/keycloak:23.0.0"
  replicas: 1
  database:
    type: "h2"
    host: "localhost"
    name: "keycloak"
    username: "keycloak"
    password_secret:
      name: "keycloak-db-secret"
      key: "password"
  admin_access:
    username: "admin"
    password_secret:
      name: "keycloak-admin-secret"
      key: "password"
  service:
    type: "ClusterIP"
    port: 8080
EOF

    # Deploy Keycloak instance
    log "Deploying test Keycloak instance..."
    kubectl apply -f test-keycloak.yaml > /dev/null
    success "Keycloak resource created"

    # Wait for deployment
    log "Waiting for Keycloak deployment (timeout: 300s)..."
    if kubectl wait --for=condition=available deployment/test-keycloak-keycloak \
        -n keycloak-test --timeout=300s > /dev/null 2>&1; then
        success "Keycloak deployment is ready"
    else
        warn "Keycloak deployment not ready within timeout, continuing..."
    fi

    # Check resources
    log "Checking created resources..."
    kubectl get keycloaks.keycloak.mdvr.nl,deployments,services,pods -n keycloak-test

    # Test connectivity
    log "Testing Keycloak connectivity..."
    kubectl port-forward -n keycloak-test service/test-keycloak-keycloak 8080:8080 &
    PORT_FORWARD_PID=$!
    sleep 5

    # Test health endpoint
    if curl -s http://localhost:8080/health | grep -q '"status":"UP"'; then
        success "Keycloak health endpoint is responding correctly"
        success "🎉 Integration test PASSED! Operator is working correctly."
    else
        error "Keycloak health endpoint is not responding correctly"
        error "❌ Integration test FAILED!"
        exit 1
    fi
}

# Parse command line arguments
case "${1:-}" in
    --cleanup-only)
        cleanup
        exit 0
        ;;
    --help|-h)
        echo "Usage: $0 [--cleanup-only|--help]"
        echo ""
        echo "Options:"
        echo "  --cleanup-only  Only perform cleanup operations"
        echo "  --help, -h      Show this help message"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac