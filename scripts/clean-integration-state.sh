#!/usr/bin/env bash
#
# Clean integration test state for cluster reuse
#
# This script resets Keycloak state WITHOUT tearing down the cluster
# or CNPG database cluster. Use this for fast iteration between test runs.
#
# What it cleans:
# - Test namespaces (test-*)
# - Keycloak instance in operator namespace
# - Operator auth token secret
# - Token metadata configmap
#
# What it preserves:
# - Kind cluster
# - CRDs
# - RBAC
# - CNPG operator
# - CNPG database cluster (tests will deploy Keycloak which creates the database)

set -e

OPERATOR_NS="${OPERATOR_NAMESPACE:-keycloak-test-system}"

echo "🔄 Resetting integration test state in $OPERATOR_NS..."
echo ""

# 1. Clean test namespaces
echo "Step 1/4: Cleaning test namespaces..."
./scripts/clean-test-resources.sh --force 2>&1 | grep -v "^$" || true
echo ""

# 2. Delete Keycloak instance (if exists)
# This will trigger deletion of the database in CNPG via Keycloak's finalizer
echo "Step 2/4: Deleting Keycloak instance..."
if kubectl get keycloak keycloak -n "$OPERATOR_NS" &>/dev/null; then
    kubectl delete keycloak keycloak -n "$OPERATOR_NS" --wait=false
    echo "  Keycloak deletion initiated"
else
    echo "  No Keycloak instance found (already clean)"
fi
echo ""

# 3. Delete operator auth tokens
echo "Step 3/4: Deleting operator auth tokens..."
kubectl delete secret keycloak-operator-auth-token -n "$OPERATOR_NS" --ignore-not-found=true
kubectl delete configmap keycloak-operator-token-metadata -n "$OPERATOR_NS" --ignore-not-found=true
echo "  Auth tokens deleted"
echo ""

# 4. Wait for cleanup to complete
echo "Step 4/4: Waiting for resources to terminate..."
echo "  Waiting for Keycloak..."
kubectl wait --for=delete keycloak/keycloak -n "$OPERATOR_NS" --timeout=60s 2>/dev/null || true

echo ""
echo "✅ State reset complete. Cluster ready for next test run."
echo "   Note: CNPG cluster preserved. Tests will create Keycloak which initializes the database."

