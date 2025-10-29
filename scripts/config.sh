#!/bin/bash
# config.sh - Configuration for Kind cluster setup

# Cluster configuration
CLUSTER_NAME="${KIND_CLUSTER_NAME:-keycloak-operator-test}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.30.0}"

# Namespace configuration
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-keycloak-test-system}"
CNPG_NAMESPACE="${CNPG_NAMESPACE:-cnpg-system}"

# Image configuration
OPERATOR_IMAGE="${OPERATOR_IMAGE:-keycloak-operator:test}"
