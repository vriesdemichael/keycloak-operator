#!/bin/bash
# kind-setup.sh - Set up Kind cluster for Keycloak operator integration testing

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
KIND_CONFIG="tests/kind/kind-config.yaml"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.28.0}"

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
    log "Setting up cluster for operator testing..."

    # Set kubectl context
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"

    # Wait for nodes to be ready
    log "Waiting for nodes to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=300s

    # Install a CNI if needed (Kind usually comes with one, but let's ensure)
    log "Checking CNI setup..."
    if ! kubectl get pods -n kube-system | grep -q "kindnet\|flannel\|calico\|weave"; then
        warn "No CNI detected. Installing Kindnet..."
        kubectl apply -f https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml
        kubectl wait --for=condition=Ready pods --all -n kube-system --timeout=300s
    fi

    # Create the operator namespace
    log "Creating operator namespace..."
    kubectl create namespace keycloak-system --dry-run=client -o yaml | kubectl apply -f -

    # Install operator CRDs
    log "Installing Keycloak operator CRDs..."
    kubectl apply -f k8s/crds/

    # Wait for CRDs to be established
    log "Waiting for CRDs to be established..."
    kubectl wait --for condition=established --timeout=60s crd/keycloaks.keycloak.mdvr.nl
    kubectl wait --for condition=established --timeout=60s crd/keycloakrealms.keycloak.mdvr.nl
    kubectl wait --for condition=established --timeout=60s crd/keycloakclients.keycloak.mdvr.nl

    # Install RBAC
    log "Installing operator RBAC..."
    kubectl apply -f k8s/rbac/

    success "Cluster setup completed"
}

install_test_dependencies() {
    log "Installing test dependencies..."

    # Install PostgreSQL for database testing
    log "Installing PostgreSQL for database testing..."
    kubectl create namespace postgres --dry-run=client -o yaml | kubectl apply -f -

    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: postgres
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: keycloak
        - name: POSTGRES_USER
          value: keycloak
        - name: POSTGRES_PASSWORD
          value: keycloak
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
      volumes:
      - name: postgres-storage
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: postgres
spec:
  type: NodePort
  ports:
  - port: 5432
    targetPort: 5432
    nodePort: 30432
  selector:
    app: postgres
EOF

    # Wait for PostgreSQL to be ready
    kubectl wait --for=condition=available deployment/postgres -n postgres --timeout=300s

    success "Test dependencies installed"
}

verify_setup() {
    log "Verifying cluster setup..."

    # Check cluster info
    kubectl cluster-info

    # Check nodes
    log "Cluster nodes:"
    kubectl get nodes -o wide

    # Check CRDs
    log "Installed CRDs:"
    kubectl get crd | grep keycloak

    # Check RBAC
    log "Operator RBAC:"
    kubectl get clusterrole,clusterrolebinding,serviceaccount -A | grep keycloak

    # Check test dependencies
    log "Test dependencies:"
    kubectl get pods,services -n postgres

    success "Cluster verification completed"
}

main() {
    log "Starting Kind cluster setup for Keycloak operator testing..."

    check_prerequisites
    create_cluster
    setup_cluster
    install_test_dependencies
    verify_setup

    success "🎉 Kind cluster setup completed successfully!"
    log "Cluster name: $CLUSTER_NAME"
    log "Kubernetes version: $KUBERNETES_VERSION"
    log "To use this cluster, run: kubectl config use-context kind-$CLUSTER_NAME"
    log "To run integration tests, run: ./scripts/test-integration-local.sh"
    log "To cleanup, run: ./scripts/kind-teardown.sh"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
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