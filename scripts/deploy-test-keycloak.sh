#!/bin/bash
# deploy-test-keycloak.sh - Deploy CNPG cluster and Keycloak instance for testing
#
# Purpose: Creates test Keycloak instance with CNPG PostgreSQL database
# Prerequisites: kubectl, CNPG operator installed, operator deployed
# Produces: Running Keycloak instance with CNPG database
# Used by: Makefile deploy-local target
#
# This script is idempotent and safe to re-run.

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/config.sh"

# Test Keycloak configuration
KEYCLOAK_NAME="keycloak"
CNPG_CLUSTER="keycloak-cnpg"
DATABASE_NAME="keycloak"

deploy_cnpg_cluster() {
    log "Checking CNPG cluster status..."

    if kubectl get cluster -n "$OPERATOR_NAMESPACE" "$CNPG_CLUSTER" 2>/dev/null; then
        success "CNPG cluster '$CNPG_CLUSTER' already exists"
        return 0
    fi

    log "Creating CNPG cluster '$CNPG_CLUSTER'..."
    cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: $CNPG_CLUSTER
  namespace: $OPERATOR_NAMESPACE
spec:
  instances: 1
  primaryUpdateStrategy: unsupervised
  storage:
    size: 1Gi
  bootstrap:
    initdb:
      database: $DATABASE_NAME
      owner: app
  enableSuperuserAccess: false
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 200m
      memory: 256Mi
EOF

    log "Waiting for CNPG cluster to be ready..."
    kubectl wait --for=condition=Ready cluster/"$CNPG_CLUSTER" -n "$OPERATOR_NAMESPACE" --timeout=420s || {
        warn "CNPG cluster not ready after 420s, continuing anyway..."
    }
}

deploy_keycloak() {
    log "Checking Keycloak instance status..."

    if kubectl get keycloak -n "$OPERATOR_NAMESPACE" "$KEYCLOAK_NAME" 2>/dev/null; then
        success "Keycloak instance '$KEYCLOAK_NAME' already exists"
        return 0
    fi

    log "Creating Keycloak instance..."
    cat <<EOF | kubectl apply -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: $KEYCLOAK_NAME
  namespace: $OPERATOR_NAMESPACE
spec:
  image: quay.io/keycloak/keycloak:26.4.0
  replicas: 1
  database:
    type: postgresql
    host: ${CNPG_CLUSTER}-rw
    port: 5432
    database: $DATABASE_NAME
    username: app
    password_secret:
      name: ${CNPG_CLUSTER}-app
      key: password
EOF

    log "Waiting for Keycloak to be ready..."
    kubectl wait --for=jsonpath='{.status.phase}'=Ready keycloak/"$KEYCLOAK_NAME" -n "$OPERATOR_NAMESPACE" --timeout=600s || {
        warn "Keycloak not ready after 600s"
        warn "Check status with: kubectl get keycloak -n $OPERATOR_NAMESPACE $KEYCLOAK_NAME -o yaml"
    }
}

main() {
    log "Deploying test Keycloak instance with CNPG PostgreSQL..."

    deploy_cnpg_cluster
    deploy_keycloak

    success "✓ Test Keycloak deployment complete"
    log "Keycloak: $KEYCLOAK_NAME in namespace $OPERATOR_NAMESPACE"
    log "Database: CNPG cluster $CNPG_CLUSTER"
}

main "$@"
