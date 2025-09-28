#!/bin/bash
# test-integration-local.sh - Run integration tests locally using Kind cluster

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
OPERATOR_IMAGE="keycloak-operator:test"
SETUP_CLUSTER=${SETUP_CLUSTER:-true}
CLEANUP_AFTER=${CLEANUP_AFTER:-false}
TEST_PATTERN=${TEST_PATTERN:-""}

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

cleanup() {
    log "Cleaning up test resources..."

    # Kill any background processes
    pkill -f "kubectl.*port-forward" 2>/dev/null || true
    pkill -f "keycloak_operator" 2>/dev/null || true

    # Clean up test namespaces
    kubectl delete namespace keycloak-test --ignore-not-found=true 2>/dev/null || true
    kubectl delete namespace integration-test --ignore-not-found=true 2>/dev/null || true

    # Clean up operator deployment if it exists
    kubectl delete deployment keycloak-operator -n keycloak-system --ignore-not-found=true 2>/dev/null || true

    log "Test cleanup completed"
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

check_prerequisites() {
    log "Checking prerequisites..."

    # Check if required tools are installed
    local tools=("kind" "kubectl" "docker" "uv")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is not installed or not in PATH"
            exit 1
        fi
    done

    # Check if cluster exists
    if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        if [ "$SETUP_CLUSTER" = "true" ]; then
            log "Cluster not found. Setting up Kind cluster..."
            ./scripts/kind-setup.sh
        else
            error "Kind cluster '$CLUSTER_NAME' not found. Run with SETUP_CLUSTER=true or run ./scripts/kind-setup.sh first"
            exit 1
        fi
    fi

    # Set kubectl context
    kubectl config use-context "kind-${CLUSTER_NAME}"

    # Verify cluster is ready
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kind cluster"
        exit 1
    fi

    success "Prerequisites check passed"
}

build_operator_image() {
    log "Building operator image..."

    # Build the operator image
    docker build -t "$OPERATOR_IMAGE" .

    # Load image into Kind cluster
    kind load docker-image "$OPERATOR_IMAGE" --name "$CLUSTER_NAME"

    success "Operator image built and loaded into cluster"
}

deploy_operator() {
    log "Deploying operator to cluster..."

    # Update deployment manifest to use local image
    local temp_deployment=$(mktemp)
    cat k8s/operator-deployment.yaml | \
        sed "s|image: keycloak-operator:latest|image: $OPERATOR_IMAGE|g" | \
        sed "s|imagePullPolicy: IfNotPresent|imagePullPolicy: Never|g" > "$temp_deployment"

    # Deploy the operator
    kubectl apply -f "$temp_deployment"

    # Wait for operator to be ready
    log "Waiting for operator to be ready..."
    kubectl wait --for=condition=available deployment/keycloak-operator -n keycloak-system --timeout=300s

    # Verify operator is running
    local operator_pods
    operator_pods=$(kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --no-headers | wc -l)
    if [ "$operator_pods" -eq 0 ]; then
        error "No operator pods found"
        kubectl get pods -n keycloak-system
        kubectl describe deployment keycloak-operator -n keycloak-system
        exit 1
    fi

    success "Operator deployed successfully"
    rm -f "$temp_deployment"
}

run_test_suite() {
    local test_name="$1"
    local test_command="$2"

    log "Running test suite: $test_name"

    if eval "$test_command"; then
        success "✅ $test_name PASSED"
        ((TESTS_PASSED++))
    else
        error "❌ $test_name FAILED"
        FAILED_TESTS+=("$test_name")
        ((TESTS_FAILED++))
    fi
}

test_operator_health() {
    log "Testing operator health endpoints..."

    # Port forward to operator
    kubectl port-forward -n keycloak-system service/keycloak-operator-metrics 8080:8080 &
    local pf_pid=$!
    sleep 5

    # Test health endpoint
    local health_response
    health_response=$(curl -s http://localhost:8080/health || echo "FAILED")

    if echo "$health_response" | grep -q '"status":"healthy"'; then
        success "Health endpoint responding correctly"
        return 0
    else
        error "Health endpoint not responding correctly: $health_response"
        return 1
    fi
}

test_basic_keycloak_deployment() {
    log "Testing basic Keycloak deployment..."

    # Create test namespace
    kubectl create namespace integration-test --dry-run=client -o yaml | kubectl apply -f -

    # Create test secrets
    kubectl create secret generic keycloak-db-secret \
        --from-literal=password=testpass -n integration-test \
        --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic keycloak-admin-secret \
        --from-literal=password=admin123 -n integration-test \
        --dry-run=client -o yaml | kubectl apply -f -

    # Create Keycloak resource
    cat <<EOF | kubectl apply -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: test-keycloak
  namespace: integration-test
spec:
  image: "quay.io/keycloak/keycloak:23.0.0"
  replicas: 1
  database:
    type: "postgresql"
    host: "postgres.postgres.svc.cluster.local"
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

    # Wait for deployment to be ready (with timeout)
    log "Waiting for Keycloak deployment to be ready..."
    if kubectl wait --for=condition=available deployment/test-keycloak-keycloak \
        -n integration-test --timeout=300s; then
        success "Keycloak deployment is ready"
        return 0
    else
        error "Keycloak deployment failed to become ready"
        kubectl get pods,deployments,services -n integration-test
        kubectl describe deployment test-keycloak-keycloak -n integration-test
        return 1
    fi
}

test_finalizer_behavior() {
    log "Testing finalizer behavior..."

    # Create a test resource
    cat <<EOF | kubectl apply -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: finalizer-test
  namespace: integration-test
spec:
  image: "quay.io/keycloak/keycloak:23.0.0"
  replicas: 1
  database:
    type: "postgresql"
    host: "postgres.postgres.svc.cluster.local"
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
EOF

    # Wait for finalizer to be added
    sleep 10

    # Check if finalizer was added
    local finalizers
    finalizers=$(kubectl get keycloak finalizer-test -n integration-test -o jsonpath='{.metadata.finalizers}' || echo "[]")

    if echo "$finalizers" | grep -q "keycloak.mdvr.nl/cleanup"; then
        success "Finalizer correctly added"
    else
        error "Finalizer not added. Found: $finalizers"
        return 1
    fi

    # Delete the resource
    kubectl delete keycloak finalizer-test -n integration-test

    # Wait for cleanup to complete
    local timeout=60
    local count=0
    while kubectl get keycloak finalizer-test -n integration-test &>/dev/null; do
        if [ $count -ge $timeout ]; then
            error "Resource not cleaned up within timeout"
            return 1
        fi
        sleep 5
        ((count+=5))
    done

    success "Finalizer cleanup completed correctly"
    return 0
}

test_leader_election() {
    log "Testing leader election behavior..."

    # Scale operator to 2 replicas
    kubectl scale deployment keycloak-operator -n keycloak-system --replicas=2

    # Wait for both replicas to be ready
    kubectl wait --for=condition=available deployment/keycloak-operator -n keycloak-system --timeout=300s

    # Check that lease exists
    sleep 30  # Give time for leader election to stabilize

    if kubectl get lease keycloak-operator -n keycloak-system &>/dev/null; then
        local holder
        holder=$(kubectl get lease keycloak-operator -n keycloak-system -o jsonpath='{.spec.holderIdentity}')
        success "Leader election lease exists. Current leader: $holder"
    else
        error "Leader election lease not found"
        return 1
    fi

    # Scale back to 1 replica
    kubectl scale deployment keycloak-operator -n keycloak-system --replicas=1
    kubectl wait --for=condition=available deployment/keycloak-operator -n keycloak-system --timeout=300s

    return 0
}

run_python_integration_tests() {
    log "Running Python integration tests..."

    # Set environment variables for tests
    export KUBECONFIG="$HOME/.kube/config"
    export KUBERNETES_CONTEXT="kind-${CLUSTER_NAME}"

    # Run Python integration tests
    if [ -n "$TEST_PATTERN" ]; then
        uv run pytest tests/integration/ -v -k "$TEST_PATTERN"
    else
        uv run pytest tests/integration/ -v
    fi
}

collect_logs() {
    log "Collecting logs for analysis..."

    local log_dir="test-logs/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$log_dir"

    # Collect operator logs
    kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --all-containers=true > "$log_dir/operator.log" 2>/dev/null || true

    # Collect cluster state
    kubectl get all,keycloaks,keycloakrealms,keycloakclients --all-namespaces -o yaml > "$log_dir/cluster-state.yaml" 2>/dev/null || true

    # Collect events
    kubectl get events --all-namespaces --sort-by='.lastTimestamp' > "$log_dir/events.log" 2>/dev/null || true

    log "Logs collected in $log_dir"
}

print_test_summary() {
    echo ""
    log "Test Summary"
    log "============"
    success "Tests passed: $TESTS_PASSED"
    if [ $TESTS_FAILED -gt 0 ]; then
        error "Tests failed: $TESTS_FAILED"
        for test in "${FAILED_TESTS[@]}"; do
            error "  - $test"
        done
    fi
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        success "🎉 All integration tests PASSED!"
        return 0
    else
        error "❌ Some integration tests FAILED!"
        return 1
    fi
}

main() {
    log "Starting Keycloak operator integration tests..."

    check_prerequisites
    build_operator_image
    deploy_operator

    # Run test suites
    run_test_suite "Operator Health" "test_operator_health"
    run_test_suite "Basic Keycloak Deployment" "test_basic_keycloak_deployment"
    run_test_suite "Finalizer Behavior" "test_finalizer_behavior"
    run_test_suite "Leader Election" "test_leader_election"

    # Run Python integration tests if they exist
    if [ -d "tests/integration" ] && [ "$(ls -A tests/integration/*.py 2>/dev/null)" ]; then
        run_test_suite "Python Integration Tests" "run_python_integration_tests"
    fi

    collect_logs
    print_test_summary

    # Cleanup if requested
    if [ "$CLEANUP_AFTER" = "true" ]; then
        log "Cleaning up cluster as requested..."
        ./scripts/kind-teardown.sh
    fi
}

# Handle command line arguments
case "${1:-}" in
    --no-setup)
        SETUP_CLUSTER=false
        main
        ;;
    --cleanup-after)
        CLEANUP_AFTER=true
        main
        ;;
    --pattern)
        TEST_PATTERN="$2"
        shift 2
        main "$@"
        ;;
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --no-setup       Don't set up Kind cluster (assume it exists)"
        echo "  --cleanup-after  Delete Kind cluster after tests"
        echo "  --pattern PATTERN Run only tests matching pattern"
        echo "  --help, -h       Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  SETUP_CLUSTER    Set up cluster if not exists (default: true)"
        echo "  CLEANUP_AFTER    Clean up cluster after tests (default: false)"
        echo "  TEST_PATTERN     Pattern for test selection"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac