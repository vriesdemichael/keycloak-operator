#!/usr/bin/env bash
#
# Clean up stuck test resources
#
# This script forcefully removes test namespaces and resources that may be
# stuck due to finalizer issues. Use this when integration tests leave behind
# resources that won't clean up normally.
#
# Usage:
#   ./scripts/clean-test-resources.sh [--force] [--prefix test-]
#

set -e

FORCE=false
PREFIX="test-"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--force] [--prefix test-]"
            echo ""
            echo "Clean up stuck test resources from Kubernetes cluster"
            echo ""
            echo "Options:"
            echo "  --force         Skip confirmation prompt"
            echo "  --prefix STR    Namespace prefix to match (default: test-)"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "🔍 Checking for test resources with prefix: $PREFIX"
echo ""

# Find test namespaces
TEST_NAMESPACES=$(kubectl get namespaces -o name | grep "${PREFIX}" | sed 's|namespace/||' || true)

if [ -z "$TEST_NAMESPACES" ]; then
    echo "✅ No test namespaces found"
    exit 0
fi

# Count resources
NS_COUNT=$(echo "$TEST_NAMESPACES" | wc -l)
echo "Found $NS_COUNT test namespace(s):"
echo "$TEST_NAMESPACES" | sed 's/^/  - /'
echo ""

# Check for resources in those namespaces
echo "Checking for Keycloak resources..."
REALMS_FOUND=false
CLIENTS_FOUND=false

for ns in $TEST_NAMESPACES; do
    REALMS=$(kubectl get keycloakrealms -n "$ns" --no-headers 2>/dev/null | wc -l || echo "0")
    CLIENTS=$(kubectl get keycloakclients -n "$ns" --no-headers 2>/dev/null | wc -l || echo "0")

    if [ "$REALMS" -gt 0 ]; then
        echo "  - $ns: $REALMS realm(s)"
        REALMS_FOUND=true
    fi
    if [ "$CLIENTS" -gt 0 ]; then
        echo "  - $ns: $CLIENTS client(s)"
        CLIENTS_FOUND=true
    fi
done

if [ "$REALMS_FOUND" = false ] && [ "$CLIENTS_FOUND" = false ]; then
    echo "  (no Keycloak resources found)"
fi
echo ""

# Confirmation
if [ "$FORCE" = false ]; then
    echo "⚠️  This will forcefully delete all test namespaces and their resources."
    echo "   Finalizers will be removed if resources are stuck."
    echo ""
    read -p "Continue? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 1
    fi
    echo ""
fi

echo "🧹 Cleaning up test resources..."
echo ""

# Function to remove finalizers from a resource
remove_finalizers() {
    local resource_type=$1
    local namespace=$2
    local name=$3

    echo "  Removing finalizers from $resource_type/$name in $namespace..."
    kubectl patch "$resource_type" "$name" -n "$namespace" \
        --type json -p='[{"op": "remove", "path": "/metadata/finalizers"}]' \
        2>/dev/null || true
}

# Clean up resources in each namespace
for ns in $TEST_NAMESPACES; do
    echo "Cleaning namespace: $ns"

    # Try to remove finalizers from clients
    CLIENTS=$(kubectl get keycloakclients -n "$ns" -o name 2>/dev/null || true)
    if [ -n "$CLIENTS" ]; then
        echo "  Removing finalizers from clients..."
        for client in $CLIENTS; do
            CLIENT_NAME=$(echo "$client" | sed 's|keycloakclient.vriesdemichael.github.io/||')
            remove_finalizers "keycloakclient" "$ns" "$CLIENT_NAME"
        done
    fi

    # Try to remove finalizers from realms
    REALMS=$(kubectl get keycloakrealms -n "$ns" -o name 2>/dev/null || true)
    if [ -n "$REALMS" ]; then
        echo "  Removing finalizers from realms..."
        for realm in $REALMS; do
            REALM_NAME=$(echo "$realm" | sed 's|keycloakrealm.vriesdemichael.github.io/||')
            remove_finalizers "keycloakrealm" "$ns" "$REALM_NAME"
        done
    fi

    # Force delete namespace
    echo "  Deleting namespace..."
    kubectl delete namespace "$ns" --force --grace-period=0 --wait=false 2>/dev/null || true

    echo "  ✓ Namespace $ns cleanup initiated"
done

echo ""
echo "⏳ Waiting for namespace cleanup to complete (max 30 seconds)..."

# Wait for namespaces to be fully deleted
for i in {1..15}; do
    REMAINING=$(kubectl get namespaces -o name | grep "${PREFIX}" | wc -l || echo "0")
    if [ "$REMAINING" -eq 0 ]; then
        echo "✅ All test namespaces cleaned up successfully!"
        exit 0
    fi
    sleep 2
    echo "  Still waiting... ($REMAINING namespace(s) remaining)"
done

# Check final status
REMAINING=$(kubectl get namespaces -o name | grep "${PREFIX}" | wc -l || echo "0")
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ All test namespaces cleaned up successfully!"
    exit 0
else
    echo ""
    echo "⚠️  Some namespaces are still terminating:"
    kubectl get namespaces | grep "${PREFIX}"
    echo ""
    echo "These may take a few more minutes to complete."
    echo "You can check status with: kubectl get namespaces | grep ${PREFIX}"
    exit 0
fi
