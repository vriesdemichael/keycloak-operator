#!/bin/bash
# config.sh - Shared configuration for Keycloak operator scripts
#
# This file defines common constants used across all operator development
# and testing scripts. Centralizing these ensures consistency.
#
# Usage: source scripts/config.sh

# Kind cluster configuration
CLUSTER_NAME="keycloak-operator-test"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.28.0}"
KIND_CONFIG="tests/kind/kind-config.yaml"

# Kubernetes namespaces
OPERATOR_NAMESPACE="keycloak-system"
CNPG_NAMESPACE="cnpg-system"

# Image configuration
OPERATOR_IMAGE="keycloak-operator:test"

# CNPG configuration
CNPG_HELM_RELEASE="cnpg"
CNPG_HELM_CHART="cloudnative-pg/cloudnative-pg"
CNPG_CHART_VERSION_PRIMARY="0.26.0"
CNPG_CHART_VERSION_FALLBACK="0.25.2"
