"""
Constants used throughout the Keycloak operator.

This module defines all constant values used by the operator including:
- Finalizer names for cleanup coordination
- Resource labels and annotations
- Default configuration values
- Error messages and status constants
"""

# Finalizer constants for cleanup coordination
# These prevent Kubernetes from deleting resources until cleanup is complete
KEYCLOAK_FINALIZER = "keycloak.mdvr.nl/cleanup"
REALM_FINALIZER = "keycloak.mdvr.nl/realm-cleanup"
CLIENT_FINALIZER = "keycloak.mdvr.nl/client-cleanup"

# Label constants for resource identification and management
OPERATOR_LABEL_KEY = "keycloak.mdvr.nl/managed-by"
OPERATOR_LABEL_VALUE = "keycloak-operator"
INSTANCE_LABEL_KEY = "keycloak.mdvr.nl/instance"
COMPONENT_LABEL_KEY = "keycloak.mdvr.nl/component"

# RBAC security labels
ALLOW_OPERATOR_READ_LABEL = "keycloak.mdvr.nl/allow-operator-read"

# Annotation constants for configuration and metadata
PRESERVE_DATA_ANNOTATION = "keycloak.mdvr.nl/preserve-data"
BACKUP_ANNOTATION = "keycloak.mdvr.nl/backup-before-delete"
ISOLATION_ANNOTATION = "keycloak.mdvr.nl/isolation"
ALLOWED_NAMESPACES_ANNOTATION = "keycloak.mdvr.nl/allowed-namespaces"

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
DEFAULT_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.4.0"
DEFAULT_KEYCLOAK_OPTIMIZED_VERSION = "26.4.1"  # Version for optimized test image
MINIMUM_KEYCLOAK_VERSION = "25.0.0"  # Minimum version for management port support
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
BACKUP_SUFFIX = "-backup"

# Timeout constants (in seconds)
DEFAULT_RECONCILIATION_TIMEOUT = 300  # 5 minutes
DEFAULT_HEALTH_CHECK_TIMEOUT = 30
DEFAULT_DELETION_TIMEOUT = 600  # 10 minutes
DEFAULT_BACKUP_TIMEOUT = 900  # 15 minutes

# Retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 2.0
DEFAULT_INITIAL_DELAY = 1.0

# Rate limiting configuration
import os

RATE_LIMIT_GLOBAL_TPS = float(
    os.getenv("KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS", "50")
)
RATE_LIMIT_GLOBAL_BURST = int(os.getenv("KEYCLOAK_API_GLOBAL_BURST", "100"))
RATE_LIMIT_NAMESPACE_TPS = float(
    os.getenv("KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS", "5")
)
RATE_LIMIT_NAMESPACE_BURST = int(os.getenv("KEYCLOAK_API_NAMESPACE_BURST", "10"))
RECONCILE_JITTER_MAX = float(os.getenv("RECONCILE_JITTER_MAX_SECONDS", "5.0"))

# Production validation constants
SUPPORTED_DATABASES = ["postgresql", "mysql", "mariadb", "oracle", "mssql"]
DEPRECATED_DATABASES = ["h2"]  # No longer supported in production

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
SUCCESS_BACKUP = "Data backup completed successfully"
