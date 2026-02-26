"""
Type aliases for structural typing in Keycloak operator models.

This module defines type aliases that provide semantic clarity about the
expected structure of dynamic fields, without being overly restrictive.

Categories:
- Keycloak API types: Flat string-to-string mappings (Keycloak REST API convention)
- Kubernetes types: Nested structures from K8s API
- Operational types: Runtime data with truly dynamic structure
"""

import os
from typing import Any

from pydantic import BaseModel, Field


def get_default_operator_namespace() -> str:
    """Get default operator namespace from environment or fallback."""
    return os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")


class OperatorRef(BaseModel):
    """Reference to the operator instance managing this resource (ADR-062)."""

    model_config = {"populate_by_name": True}

    namespace: str = Field(
        default_factory=get_default_operator_namespace,
        description="Namespace where the operator is running",
    )


# =============================================================================
# Keycloak API Types
# =============================================================================
# Keycloak API Types
# =============================================================================
# Keycloak's REST API uses flat string-to-string mappings for all config blocks.
# Even boolean and numeric values are represented as strings:
#   - "multivalued": "true" (not True)
#   - "priority": "10" (not 10)
#   - "claim.name": "email"

type KeycloakConfigMap = dict[str, str]
"""
Flat string-to-string configuration map used by Keycloak REST API.

Used for:
- Protocol mapper configurations
- Identity provider configurations
- User federation configurations
- Client attribute configurations
"""

# =============================================================================
# Kubernetes API Types
# =============================================================================
# Kubernetes objects have nested structures. We use Any for deep nesting
# but the type alias communicates the expected structure category.

type KubernetesProbeConfig = dict[str, Any]
"""
Kubernetes probe configuration (startup, liveness, readiness).

Expected structure:
- httpGet/tcpSocket/exec: probe type configuration
- initialDelaySeconds: int
- periodSeconds: int
- timeoutSeconds: int
- failureThreshold: int
- successThreshold: int
"""

type KubernetesSecurityContext = dict[str, Any]
"""
Kubernetes SecurityContext or PodSecurityContext.

Expected structure:
- runAsUser: int
- runAsGroup: int
- runAsNonRoot: bool
- fsGroup: int
- capabilities: dict with add/drop lists
- seccompProfile: dict
- seLinuxOptions: dict
"""

type KubernetesMetadata = dict[str, Any]
"""
Kubernetes ObjectMeta structure.

Expected structure:
- name: str
- namespace: str
- labels: dict[str, str]
- annotations: dict[str, str]
- uid: str
- resourceVersion: str
- generation: int
- creationTimestamp: str
"""

# =============================================================================
# Authentication Flow Types
# =============================================================================
# NOTE: Authentication execution types have been moved to proper Pydantic models
# in realm.py (AuthenticatorConfigInfo, AuthenticationExecutionExport) to match
# the Keycloak Admin API representations.

# =============================================================================
# Operational Types
# =============================================================================

type OperationalStats = dict[str, Any]
"""
Runtime operational statistics and metrics.

This is truly dynamic as it contains runtime-collected data
that may vary based on what metrics are available.
"""
