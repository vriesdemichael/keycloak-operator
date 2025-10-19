#!/bin/bash
# Measure Keycloak startup time
# Compares default vs optimized images

set -e

NAMESPACE="keycloak-benchmark"
KEYCLOAK_NAME="keycloak-test"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔬 Keycloak Startup Time Measurement"
echo "===================================="

# Function to measure startup time
measure_startup() {
    local image=$1
    local version=$2
    local test_name=$3
    
    echo ""
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    echo "Image: ${image}:${version}"
    
    # Create namespace
    kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Keycloak CR
    cat <<EOF | kubectl apply -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: ${KEYCLOAK_NAME}
  namespace: ${NAMESPACE}
spec:
  image: ${image}:${version}
  replicas: 1
  database:
    type: postgresql
    host: fake-postgres  # Won't connect, but that's ok for startup measurement
    port: 5432
    database: keycloak
    username: keycloak
    passwordSecret:
      name: fake-secret
      key: password
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
EOF
    
    # Record start time
    START=$(date +%s)
    echo "⏱️  Waiting for deployment to be created..."
    
    # Wait for deployment to exist
    while ! kubectl get deployment ${KEYCLOAK_NAME}-keycloak -n ${NAMESPACE} &>/dev/null; do
        sleep 1
    done
    
    echo "⏱️  Deployment created, waiting for pod to be ready..."
    
    # Wait for pod to be ready (or fail after 5 minutes)
    if timeout 300 kubectl wait --for=condition=Ready pod -l app=keycloak,keycloak.mdvr.nl/instance=${KEYCLOAK_NAME} -n ${NAMESPACE} --timeout=300s; then
        END=$(date +%s)
        DURATION=$((END - START))
        echo -e "${GREEN}✓ Pod ready in ${DURATION} seconds${NC}"
        
        # Get pod details
        POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app=keycloak,keycloak.mdvr.nl/instance=${KEYCLOAK_NAME} -o jsonpath='{.items[0].metadata.name}')
        echo "  Pod: ${POD_NAME}"
        
        # Check if it actually tried to connect to database
        echo "  Checking logs for startup indicators..."
        kubectl logs ${POD_NAME} -n ${NAMESPACE} | tail -20
    else
        echo "❌ Pod failed to become ready within 5 minutes"
        DURATION="TIMEOUT"
        
        # Show pod status
        kubectl get pods -n ${NAMESPACE}
        
        # Show pod events
        POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app=keycloak,keycloak.mdvr.nl/instance=${KEYCLOAK_NAME} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        if [ -n "${POD_NAME}" ]; then
            echo "Pod logs:"
            kubectl logs ${POD_NAME} -n ${NAMESPACE} | tail -50
        fi
    fi
    
    # Cleanup
    echo "🧹 Cleaning up..."
    kubectl delete namespace ${NAMESPACE} --wait=false
    
    # Return the duration
    echo "${DURATION}"
}

# Ensure we have a Kind cluster
if ! kind get clusters | grep -q keycloak-operator-test; then
    echo "❌ Kind cluster 'keycloak-operator-test' not found"
    echo "Please run: make kind-setup"
    exit 1
fi

# Check if optimized image exists
if ! docker images | grep -q keycloak-optimized; then
    echo "❌ Optimized Keycloak image not found"
    echo "Please run: make build-keycloak-optimized"
    exit 1
fi

# Load images into Kind if needed
echo "📦 Loading images into Kind..."
kind load docker-image keycloak-optimized:test --name keycloak-operator-test 2>/dev/null || true

# Measure default Keycloak
DEFAULT_TIME=$(measure_startup "quay.io/keycloak/keycloak" "26.0.0" "Default Keycloak Image")

# Give cluster a moment to settle
sleep 5

# Measure optimized Keycloak  
OPTIMIZED_TIME=$(measure_startup "keycloak-optimized" "test" "Optimized Keycloak Image")

# Summary
echo ""
echo "======================================"
echo "📊 Results Summary"
echo "======================================"
echo "Default Image:   ${DEFAULT_TIME}s"
echo "Optimized Image: ${OPTIMIZED_TIME}s"

if [ "${DEFAULT_TIME}" != "TIMEOUT" ] && [ "${OPTIMIZED_TIME}" != "TIMEOUT" ]; then
    IMPROVEMENT=$((DEFAULT_TIME - OPTIMIZED_TIME))
    PERCENT=$((IMPROVEMENT * 100 / DEFAULT_TIME))
    echo ""
    echo -e "${GREEN}✨ Improvement: ${IMPROVEMENT}s faster (${PERCENT}% reduction)${NC}"
fi
