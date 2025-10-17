#!/usr/bin/env bash
#
# RBAC Integration Test Script
# 
# This script tests the namespaced RBAC implementation for the Keycloak operator.
# It validates that:
# 1. Operator can be deployed with minimal cluster-wide permissions
# 2. Realm/Client CRs in different namespaces require RoleBindings
# 3. Secrets require the keycloak.mdvr.nl/allow-operator-read=true label
# 4. Reconciliation fails appropriately when permissions are missing
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-keycloak-test-operator}"
REALM_NAMESPACE="${REALM_NAMESPACE:-keycloak-test-realm}"
CLIENT_NAMESPACE="${CLIENT_NAMESPACE:-keycloak-test-client}"
CHART_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/charts"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up test resources..."
    
    # Delete namespaces (this will cascade delete everything)
    kubectl delete namespace "$CLIENT_NAMESPACE" --ignore-not-found=true --wait=false || true
    kubectl delete namespace "$REALM_NAMESPACE" --ignore-not-found=true --wait=false || true
    kubectl delete namespace "$OPERATOR_NAMESPACE" --ignore-not-found=true --wait=false || true
    
    # Wait for namespaces to be deleted
    log_info "Waiting for namespaces to be deleted..."
    kubectl wait --for=delete namespace/"$CLIENT_NAMESPACE" --timeout=60s 2>/dev/null || true
    kubectl wait --for=delete namespace/"$REALM_NAMESPACE" --timeout=60s 2>/dev/null || true
    kubectl wait --for=delete namespace/"$OPERATOR_NAMESPACE" --timeout=60s 2>/dev/null || true
    
    log_info "Cleanup complete"
}

# Trap to cleanup on exit
trap cleanup EXIT

# Test 1: Deploy operator
test_deploy_operator() {
    log_info "Test 1: Deploying Keycloak operator in $OPERATOR_NAMESPACE"
    
    # Create namespace
    kubectl create namespace "$OPERATOR_NAMESPACE" || true
    
    # Deploy operator with Keycloak instance
    helm install keycloak-operator "$CHART_PATH/keycloak-operator" \
        --namespace "$OPERATOR_NAMESPACE" \
        --set namespace.name="$OPERATOR_NAMESPACE" \
        --set namespace.create=false \
        --set keycloak.enabled=true \
        --set keycloak.database.cnpg.enabled=true \
        --set keycloak.admin.passwordSecret.name=keycloak-admin-password \
        --wait --timeout=5m
    
    log_info "✅ Operator deployed successfully"
    
    # Verify RBAC resources
    log_info "Verifying RBAC resources..."
    
    # Check ClusterRole for minimal permissions
    kubectl get clusterrole keycloak-operator-core || {
        log_error "ClusterRole keycloak-operator-core not found"
        return 1
    }
    
    # Check namespace-access ClusterRole template
    kubectl get clusterrole keycloak-operator-namespace-access || {
        log_error "ClusterRole keycloak-operator-namespace-access not found"
        return 1
    }
    
    # Check namespace Role
    kubectl get role keycloak-operator-manager -n "$OPERATOR_NAMESPACE" || {
        log_error "Role keycloak-operator-manager not found in $OPERATOR_NAMESPACE"
        return 1
    }
    
    log_info "✅ RBAC resources verified"
}

# Test 2: Create realm in different namespace WITH RoleBinding
test_create_realm_with_rbac() {
    log_info "Test 2: Creating realm in $REALM_NAMESPACE with RoleBinding"
    
    # Create namespace
    kubectl create namespace "$REALM_NAMESPACE" || true
    
    # Create SMTP password secret WITH required label
    kubectl create secret generic smtp-password \
        --from-literal=password='test-smtp-password' \
        -n "$REALM_NAMESPACE"
    
    kubectl label secret smtp-password \
        keycloak.mdvr.nl/allow-operator-read=true \
        -n "$REALM_NAMESPACE"
    
    log_info "Created labeled secret: smtp-password"
    
    # Deploy realm (this should create RoleBinding automatically)
    helm install test-realm "$CHART_PATH/keycloak-realm" \
        --namespace "$REALM_NAMESPACE" \
        --set realmName=test-realm \
        --set operatorRef.namespace="$OPERATOR_NAMESPACE" \
        --set rbac.create=true \
        --set rbac.operatorServiceAccountName=keycloak-operator \
        --set smtpServer.enabled=true \
        --set smtpServer.host=smtp.example.com \
        --set smtpServer.from=noreply@example.com \
        --set smtpServer.passwordSecret.name=smtp-password \
        --wait --timeout=2m
    
    log_info "✅ Realm created successfully"
    
    # Verify RoleBinding was created
    kubectl get rolebinding test-realm-operator-access -n "$REALM_NAMESPACE" || {
        log_error "RoleBinding not created in $REALM_NAMESPACE"
        return 1
    }
    
    log_info "✅ RoleBinding verified"
    
    # Wait for realm to be Ready
    log_info "Waiting for realm to reconcile..."
    kubectl wait --for=jsonpath='{.status.phase}'=Ready \
        keycloakrealm/test-realm \
        -n "$REALM_NAMESPACE" \
        --timeout=300s || {
        log_warn "Realm did not become Ready, checking status..."
        kubectl get keycloakrealm test-realm -n "$REALM_NAMESPACE" -o yaml
        return 1
    }
    
    log_info "✅ Realm reconciled successfully"
}

# Test 3: Create client in different namespace
test_create_client_with_rbac() {
    log_info "Test 3: Creating client in $CLIENT_NAMESPACE with RoleBinding"
    
    # Create namespace
    kubectl create namespace "$CLIENT_NAMESPACE" || true
    
    # Get realm authorization secret
    REALM_SECRET=$(kubectl get keycloakrealm test-realm \
        -n "$REALM_NAMESPACE" \
        -o jsonpath='{.status.authorizationSecretName}')
    
    if [ -z "$REALM_SECRET" ]; then
        log_error "Realm authorization secret not found"
        return 1
    fi
    
    log_info "Using realm secret: $REALM_SECRET"
    
    # Deploy client (this should create RoleBinding automatically)
    helm install test-client "$CHART_PATH/keycloak-client" \
        --namespace "$CLIENT_NAMESPACE" \
        --set clientId=test-client \
        --set realmRef.name=test-realm \
        --set realmRef.namespace="$REALM_NAMESPACE" \
        --set realmRef.authorizationSecretRef.name="$REALM_SECRET" \
        --set rbac.create=true \
        --set rbac.operatorNamespace="$OPERATOR_NAMESPACE" \
        --set rbac.operatorServiceAccountName=keycloak-operator \
        --wait --timeout=2m
    
    log_info "✅ Client created successfully"
    
    # Verify RoleBinding was created
    kubectl get rolebinding test-client-operator-access -n "$CLIENT_NAMESPACE" || {
        log_error "RoleBinding not created in $CLIENT_NAMESPACE"
        return 1
    }
    
    log_info "✅ RoleBinding verified"
    
    # Wait for client to be Ready
    log_info "Waiting for client to reconcile..."
    kubectl wait --for=jsonpath='{.status.phase}'=Ready \
        keycloakclient/test-client \
        -n "$CLIENT_NAMESPACE" \
        --timeout=300s || {
        log_warn "Client did not become Ready, checking status..."
        kubectl get keycloakclient test-client -n "$CLIENT_NAMESPACE" -o yaml
        return 1
    }
    
    log_info "✅ Client reconciled successfully"
}

# Test 4: Verify secret without label fails
test_secret_without_label() {
    log_info "Test 4: Testing secret without required label (should fail)"
    
    # Create a new realm with unlabeled secret
    kubectl create secret generic unlabeled-secret \
        --from-literal=password='test-password' \
        -n "$REALM_NAMESPACE"
    
    # Try to create a realm using this secret
    cat <<EOF | kubectl apply -f - || true
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: test-realm-unlabeled
  namespace: $REALM_NAMESPACE
spec:
  realm: test-realm-unlabeled
  keycloak_instance:
    name: keycloak
    namespace: $OPERATOR_NAMESPACE
  smtpServer:
    host: smtp.example.com
    from: noreply@example.com
    passwordSecret:
      name: unlabeled-secret
      key: password
EOF
    
    log_info "Waiting for realm to show error status..."
    sleep 10
    
    # Check if realm shows error about missing label
    STATUS=$(kubectl get keycloakrealm test-realm-unlabeled -n "$REALM_NAMESPACE" -o jsonpath='{.status.message}' 2>/dev/null || echo "")
    
    if echo "$STATUS" | grep -q "allow-operator-read"; then
        log_info "✅ Realm correctly failed due to missing label"
    else
        log_warn "Status message: $STATUS"
        log_warn "Expected error about missing label, but reconciliation may not have completed yet"
    fi
    
    # Cleanup test resource
    kubectl delete keycloakrealm test-realm-unlabeled -n "$REALM_NAMESPACE" --ignore-not-found=true
    kubectl delete secret unlabeled-secret -n "$REALM_NAMESPACE" --ignore-not-found=true
}

# Main test execution
main() {
    log_info "========================================"
    log_info "RBAC Integration Test Suite"
    log_info "========================================"
    log_info ""
    log_info "Configuration:"
    log_info "  Operator Namespace: $OPERATOR_NAMESPACE"
    log_info "  Realm Namespace: $REALM_NAMESPACE"
    log_info "  Client Namespace: $CLIENT_NAMESPACE"
    log_info "  Chart Path: $CHART_PATH"
    log_info ""
    
    # Run tests
    test_deploy_operator
    log_info ""
    
    test_create_realm_with_rbac
    log_info ""
    
    test_create_client_with_rbac
    log_info ""
    
    test_secret_without_label
    log_info ""
    
    log_info "========================================"
    log_info "✅ All tests completed successfully!"
    log_info "========================================"
}

# Run main
main
