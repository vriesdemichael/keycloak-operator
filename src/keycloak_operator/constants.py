"""
Constants used throughout the Keycloak operator.

This module defines all constant values used by the operator including:
- Finalizer names for cleanup coordination
- Resource labels and annotations
- Default configuration values
- Error messages and status constants
"""

import logging

from keycloak_operator.settings import settings

# Unified finalizer for all resources - managed by Kopf
# This prevents Kubernetes from deleting resources until cleanup is complete
# Kopf automatically adds this on create and removes it after delete handler completes
OPERATOR_FINALIZER = "vriesdemichael.github.io/keycloak-operator"

# Label constants for resource identification and management
OPERATOR_LABEL_KEY = "vriesdemichael.github.io/keycloak-managed-by"
OPERATOR_LABEL_VALUE = "keycloak-operator"
INSTANCE_LABEL_KEY = "vriesdemichael.github.io/keycloak-instance"
COMPONENT_LABEL_KEY = "vriesdemichael.github.io/keycloak-component"

# RBAC security labels
ALLOW_OPERATOR_READ_LABEL = "vriesdemichael.github.io/keycloak-allow-operator-read"

# Annotation constants for configuration and metadata
PRESERVE_DATA_ANNOTATION = "vriesdemichael.github.io/keycloak-preserve-data"
ISOLATION_ANNOTATION = "vriesdemichael.github.io/keycloak-isolation"
ALLOWED_NAMESPACES_ANNOTATION = "vriesdemichael.github.io/keycloak-allowed-namespaces"

# Component type constants
COMPONENT_KEYCLOAK = "keycloak"
COMPONENT_DATABASE = "database"
COMPONENT_INGRESS = "ingress"
COMPONENT_SERVICE = "service"
COMPONENT_CONFIG = "config"

# Status phase constants
PHASE_PENDING = "Pending"
PHASE_PROVISIONING = "Provisioning"
PHASE_READY = "Ready"
PHASE_FAILED = "Failed"
PHASE_UPDATING = "Updating"
PHASE_RECONCILING = "Reconciling"
PHASE_DEGRADED = "Degraded"

# Condition type constants (following Kubernetes conventions)
CONDITION_READY = "Ready"
CONDITION_AVAILABLE = "Available"
CONDITION_PROGRESSING = "Progressing"
CONDITION_RECONCILING = "Reconciling"

# Condition status constants
CONDITION_TRUE = "True"
CONDITION_FALSE = "False"
CONDITION_UNKNOWN = "Unknown"

# Default configuration values
DEFAULT_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.4.1"
DEFAULT_KEYCLOAK_OPTIMIZED_VERSION = "26.4.1"  # Version for optimized test image
MINIMUM_KEYCLOAK_VERSION = "25.0.0"  # Minimum version for management port support
CANONICAL_MODEL_VERSION = "26.5.2"  # Version our Pydantic models are generated from
DEFAULT_KEYCLOAK_PORT = 8080
DEFAULT_KEYCLOAK_HTTPS_PORT = 8443
DEFAULT_HEALTH_PORT = 9000
DEFAULT_ADMIN_PORT = 9090
DEFAULT_REPLICAS = 1
DEFAULT_NAMESPACE_ISOLATION = "default"

# Resource naming patterns
DEPLOYMENT_SUFFIX = "-keycloak"
SERVICE_SUFFIX = "-keycloak"
INGRESS_SUFFIX = "-keycloak"
ADMIN_SECRET_SUFFIX = "-admin-credentials"
CONFIG_MAP_SUFFIX = "-config"
PVC_SUFFIX = "-data"

# Timeout constants (in seconds)
DEFAULT_RECONCILIATION_TIMEOUT = 300  # 5 minutes
DEFAULT_HEALTH_CHECK_TIMEOUT = 30
DEFAULT_DELETION_TIMEOUT = 600  # 10 minutes

# Timer intervals for health checks and stuck finalizer detection
# Configurable via environment variables for testing
TIMER_INTERVAL_KEYCLOAK = settings.timer_interval_keycloak
TIMER_INTERVAL_REALM = settings.timer_interval_realm
TIMER_INTERVAL_CLIENT = settings.timer_interval_client

# Retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_INITIAL_DELAY = 1.0

# Handler entry logging level - configurable via HANDLER_ENTRY_LOG_LEVEL env var
# Controls log level for "Handler invoked" messages at handler entry
# Default: INFO for debugging visibility; set to DEBUG in production if too noisy
HANDLER_ENTRY_LOG_LEVEL = getattr(
    logging, settings.handler_entry_log_level.upper(), logging.INFO
)

# Rate limiting configuration
RATE_LIMIT_GLOBAL_TPS = settings.api_global_rate_limit_tps
RATE_LIMIT_GLOBAL_BURST = settings.api_global_burst
RATE_LIMIT_NAMESPACE_TPS = settings.api_namespace_rate_limit_tps
RATE_LIMIT_NAMESPACE_BURST = settings.api_namespace_burst
RECONCILE_JITTER_MAX = settings.reconcile_jitter_max_seconds

# Production validation constants
SUPPORTED_DATABASES = ["postgresql", "mysql", "mariadb", "oracle", "mssql"]
DEPRECATED_DATABASES = ["h2"]  # No longer supported in production

# Admission webhook quota configuration
# These can be overridden via environment variables for different deployment scenarios
WEBHOOK_MAX_REALMS_PER_NAMESPACE = settings.webhook_max_realms_per_namespace
WEBHOOK_MAX_CLIENTS_PER_NAMESPACE = settings.webhook_max_clients_per_namespace
# Keycloak instances: enforced as 1 per namespace (ADR-062)
WEBHOOK_MAX_KEYCLOAKS_PER_NAMESPACE = 1

# Error message templates
ERROR_MISSING_SECRET = "Required secret '{}' not found in namespace '{}'"
ERROR_SECRET_NOT_LABELED = (
    "Secret '{}' in namespace '{}' is missing required label '{}=true'. "
    "Add this label to grant operator access to the secret."
)
ERROR_INVALID_DATABASE = "Database type '{}' is not supported. Supported types: {}"
ERROR_RBAC_DENIED = (
    "RBAC permission denied for operation '{}' on resource '{}' in namespace '{}'"
)
ERROR_NAMESPACE_ACCESS_DENIED = (
    "Operator does not have access to namespace '{}'. "
    "Create a RoleBinding to grant access: "
    "kubectl create rolebinding keycloak-operator-access "
    "--clusterrole=keycloak-operator-namespace-access "
    "--serviceaccount={}:keycloak-operator-{} -n {}"
)
ERROR_NAMESPACE_ISOLATION = (
    "Namespace isolation policy prevents access from '{}' to '{}'"
)
ERROR_FINALIZER_TIMEOUT = "Timeout waiting for finalizer cleanup after {} seconds"

# Success message templates
SUCCESS_RECONCILIATION = "Resource reconciliation completed successfully"
SUCCESS_DELETION = "Resource deletion and cleanup completed successfully"
SUCCESS_UPDATE = "Resource update applied successfully"
