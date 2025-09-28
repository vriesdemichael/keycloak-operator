#!/bin/bash

# Test script for multi-replica leader election behavior
# This script tests leader election functionality with chaos engineering principles

set -e

NAMESPACE="keycloak-system"
OPERATOR_NAME="keycloak-operator"
TEST_TIMEOUT=300  # 5 minutes

echo "🧪 Starting Leader Election Multi-Replica Test"
echo "=============================================="

# Function to check leader election status
check_leader_election() {
    echo "📊 Checking leader election status..."
    kubectl get lease -n "$NAMESPACE" | grep "$OPERATOR_NAME" || echo "No lease found yet"

    # Get current replicas
    CURRENT_REPLICAS=$(kubectl get deployment "$OPERATOR_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    READY_REPLICAS=$(kubectl get deployment "$OPERATOR_NAME" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')

    echo "Current replicas: $CURRENT_REPLICAS"
    echo "Ready replicas: $READY_REPLICAS"

    # Get pod status
    echo "Pod status:"
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$OPERATOR_NAME" -o wide
}

# Function to simulate pod failure (chaos engineering)
simulate_pod_failure() {
    echo "💥 Simulating pod failure (chaos engineering test)..."

    # Get current leader pod
    LEADER_POD=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name="$OPERATOR_NAME" -o jsonpath='{.items[0].metadata.name}')

    if [ -n "$LEADER_POD" ]; then
        echo "Deleting leader pod: $LEADER_POD"
        kubectl delete pod "$LEADER_POD" -n "$NAMESPACE"

        echo "Waiting for new leader election..."
        sleep 30
        check_leader_election
    else
        echo "No leader pod found to delete"
    fi
}

# Function to test scaling
test_scaling() {
    echo "📈 Testing scaling behavior..."

    # Scale up to 3 replicas
    echo "Scaling up to 3 replicas..."
    kubectl scale deployment "$OPERATOR_NAME" -n "$NAMESPACE" --replicas=3

    # Wait for scale up
    kubectl rollout status deployment/"$OPERATOR_NAME" -n "$NAMESPACE" --timeout=120s

    check_leader_election

    # Scale back to 2 replicas
    echo "Scaling back to 2 replicas..."
    kubectl scale deployment "$OPERATOR_NAME" -n "$NAMESPACE" --replicas=2

    # Wait for scale down
    kubectl rollout status deployment/"$OPERATOR_NAME" -n "$NAMESPACE" --timeout=120s

    check_leader_election
}

# Function to verify leader election lease
verify_lease() {
    echo "🔍 Verifying leader election lease..."

    # Check if lease exists
    if kubectl get lease "$OPERATOR_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
        echo "✅ Lease exists"

        # Get lease details
        HOLDER=$(kubectl get lease "$OPERATOR_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.holderIdentity}')
        ACQUIRE_TIME=$(kubectl get lease "$OPERATOR_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.acquireTime}')
        RENEW_TIME=$(kubectl get lease "$OPERATOR_NAME" -n "$NAMESPACE" -o jsonpath='{.spec.renewTime}')

        echo "Current leader: $HOLDER"
        echo "Acquire time: $ACQUIRE_TIME"
        echo "Last renew time: $RENEW_TIME"
    else
        echo "❌ No lease found - leader election may not be working"
        return 1
    fi
}

# Function to test Keycloak resource handling during leadership changes
test_resource_handling() {
    echo "🎯 Testing resource handling during leadership changes..."

    # Create a test Keycloak resource
    cat <<EOF | kubectl apply -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: test-leader-election
  namespace: keycloak-test
spec:
  image: "quay.io/keycloak/keycloak:23.0.0"
  replicas: 1
  database:
    type: "postgresql"
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

    echo "Waiting for resource to be processed..."
    sleep 10

    # Check resource status
    kubectl get keycloaks.keycloak.mdvr.nl test-leader-election -n keycloak-test -o yaml

    # Trigger leader change and verify resource is still handled
    simulate_pod_failure

    echo "Verifying resource is still being handled after leadership change..."
    sleep 10
    kubectl get keycloaks.keycloak.mdvr.nl test-leader-election -n keycloak-test -o yaml

    # Cleanup test resource
    kubectl delete keycloak test-leader-election -n keycloak-test --ignore-not-found=true
}

# Main test execution
main() {
    echo "Starting comprehensive leader election test..."

    # Ensure test namespace exists
    kubectl create namespace keycloak-test --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic keycloak-db-secret --from-literal=password=testpass -n keycloak-test --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic keycloak-admin-secret --from-literal=password=admin123 -n keycloak-test --dry-run=client -o yaml | kubectl apply -f -

    # Check initial state
    check_leader_election

    # Verify lease functionality
    verify_lease

    # Test scaling behavior
    test_scaling

    # Test chaos engineering (pod failure)
    simulate_pod_failure

    # Test resource handling during leadership changes
    test_resource_handling

    # Final verification
    echo "🏁 Final verification..."
    check_leader_election
    verify_lease

    echo "✅ Leader election test completed successfully!"

    # Cleanup
    kubectl delete namespace keycloak-test --ignore-not-found=true
}

# Check if operator deployment exists
if ! kubectl get deployment "$OPERATOR_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "❌ Operator deployment not found. Please deploy the operator first."
    echo "Use: kubectl apply -f k8s/"
    exit 1
fi

# Run the main test
main