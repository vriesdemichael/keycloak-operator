#!/usr/bin/env bash
#
# Clean integration test state for cluster reuse
#
# This script resets Keycloak and database state WITHOUT tearing down the cluster.
# Use this for fast iteration between test runs.
#
# What it cleans:
# - Test namespaces (test-*)
# - Keycloak instance in operator namespace
# - CNPG database cluster (to ensure clean database state)
# - Operator auth token secret
# - Token metadata configmap
#
# What it preserves:
# - Kind cluster
# - CRDs
# - RBAC
# - CNPG operator (tests will recreate database cluster via Helm)

set -e

OPERATOR_NS="${OPERATOR_NAMESPACE:-keycloak-test-system}"

echo "🔄 Resetting integration test state in $OPERATOR_NS..."
echo ""

# 1. Clean test namespaces
echo "Step 1/5: Cleaning test namespaces..."
./scripts/clean-test-resources.sh --force || true
echo ""

# 2. Delete Keycloak instance (if exists)
echo "Step 2/5: Deleting Keycloak instance..."
if kubectl get keycloak keycloak -n "$OPERATOR_NS" &>/dev/null; then
    kubectl delete keycloak keycloak -n "$OPERATOR_NS" --wait=false
    echo "  Keycloak deletion initiated"
else
    echo "  No Keycloak instance found (already clean)"
fi
echo ""

# 3. Delete CNPG cluster to ensure clean database
# Note: Tests recreate this via Helm (idempotent)
echo "Step 3/5: Deleting CNPG database cluster..."
if kubectl get cluster -n "$OPERATOR_NS" &>/dev/null; then
    kubectl delete cluster --all -n "$OPERATOR_NS" --wait=false
    echo "  CNPG cluster deletion initiated"
else
    echo "  No CNPG cluster found (already clean)"
fi
echo ""

# 4. Delete operator auth tokens
echo "Step 4/5: Deleting operator auth tokens..."
kubectl delete secret keycloak-operator-auth-token -n "$OPERATOR_NS" --ignore-not-found=true
kubectl delete configmap keycloak-operator-token-metadata -n "$OPERATOR_NS" --ignore-not-found=true
echo "  Auth tokens deleted"
echo ""

# 5. Wait for cleanup to complete
echo "Step 5/5: Waiting for resources to terminate..."
echo "  Waiting for Keycloak..."
kubectl wait --for=delete keycloak/keycloak -n "$OPERATOR_NS" --timeout=60s 2>/dev/null || true

echo "  Waiting for CNPG cluster..."
kubectl wait --for=delete cluster --all -n "$OPERATOR_NS" --timeout=60s 2>/dev/null || true

echo ""
echo "✅ State reset complete. Cluster ready for next test run."
echo "   Note: Tests will recreate CNPG cluster via Helm (ensures clean database)."

