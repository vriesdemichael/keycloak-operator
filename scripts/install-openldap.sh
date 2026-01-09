#!/bin/bash
# install-openldap.sh - Deploy OpenLDAP for user federation testing
#
# Purpose: Deploys OpenLDAP and optionally OpenLDAP-AD to a Kind cluster
# Prerequisites: kubectl, running Kind cluster
# Usage: ./scripts/install-openldap.sh [--with-ad] [--namespace NAMESPACE]

set -e

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/config.sh"

# Configuration
NAMESPACE="${OPERATOR_NAMESPACE:-keycloak-test-system}"
INSTALL_AD=false
FIXTURES_DIR="${SCRIPT_DIR}/../tests/integration/fixtures"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-ad)
            INSTALL_AD=true
            shift
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Deploy OpenLDAP for user federation testing"
            echo ""
            echo "Options:"
            echo "  --with-ad           Also deploy OpenLDAP with AD schema"
            echo "  --namespace NAME    Target namespace (default: $NAMESPACE)"
            echo "  --help, -h          Show this help message"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    success "Prerequisites check passed"
}

deploy_openldap() {
    log "Deploying OpenLDAP to namespace $NAMESPACE..."

    # Update namespace in manifests and apply
    sed "s/keycloak-test-system/$NAMESPACE/g" \
        "$FIXTURES_DIR/openldap-deployment.yaml" | kubectl apply -f -

    log "Waiting for OpenLDAP to be ready..."
    kubectl wait --for=condition=available deployment/openldap \
        -n "$NAMESPACE" --timeout=300s

    success "OpenLDAP is ready!"
    log "Connection URL: ldap://openldap.$NAMESPACE.svc.cluster.local:389"
    log "Bind DN: cn=admin,dc=example,dc=org"
    log "Password: admin"
    log "Users DN: ou=People,dc=example,dc=org"
    log ""
    log "Test users: alice, bob, charlie (password = <username>123)"
}

deploy_openldap_ad() {
    log "Deploying OpenLDAP with AD schema to namespace $NAMESPACE..."

    # Update namespace in manifests and apply
    sed "s/keycloak-test-system/$NAMESPACE/g" \
        "$FIXTURES_DIR/openldap-ad-deployment.yaml" | kubectl apply -f -

    log "Waiting for OpenLDAP-AD to be ready..."
    kubectl wait --for=condition=available deployment/openldap-ad \
        -n "$NAMESPACE" --timeout=300s

    success "OpenLDAP with AD schema is ready!"
    log "Connection URL: ldap://openldap-ad.$NAMESPACE.svc.cluster.local:389"
    log "Bind DN: cn=admin,dc=corp,dc=example,dc=com"
    log "Password: admin"
    log "Users DN: ou=Users,dc=corp,dc=example,dc=com"
    log ""
    log "Test users: alice, bob, charlie (sAMAccountName format)"
}

main() {
    log "Starting OpenLDAP deployment for user federation testing..."

    check_prerequisites

    # Ensure namespace exists
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    deploy_openldap

    if [ "$INSTALL_AD" = true ]; then
        echo ""
        deploy_openldap_ad
    fi

    echo ""
    success "🎉 OpenLDAP deployment completed!"
    log ""
    log "Next steps:"
    log "  1. Create a secret with LDAP bind password"
    log "  2. Configure userFederation in your KeycloakRealm spec"
    log "  3. Create or update your realm to trigger federation setup"
    log ""
    log "Example secret creation:"
    log "  kubectl create secret generic ldap-bind-secret \\"
    log "    --from-literal=password=admin \\"
    log "    -n YOUR_NAMESPACE"
    log "  kubectl label secret ldap-bind-secret \\"
    log "    vriesdemichael.github.io/keycloak-allow-operator-read=true \\"
    log "    -n YOUR_NAMESPACE"
}

main "$@"
