"""
Ownership tracking utilities for Keycloak resources.

This module provides utilities for tracking which operator instance created
resources in Keycloak, enabling drift detection and multi-operator support.
"""

import os
from datetime import UTC, datetime

# Keycloak attribute keys for ownership tracking
# These are stored in the 'attributes' field of Keycloak resources
ATTR_MANAGED_BY = "io.kubernetes.managed-by"
ATTR_OPERATOR_INSTANCE = "io.kubernetes.operator-instance"
ATTR_CR_NAMESPACE = "io.kubernetes.cr-namespace"
ATTR_CR_NAME = "io.kubernetes.cr-name"
ATTR_CREATED_AT = "io.kubernetes.created-at"

# Constant value for managed-by attribute
MANAGED_BY_VALUE = "keycloak-operator"

# Cache for operator instance ID to avoid repeated environment lookups
_operator_instance_id_cache: str | None = None


def get_operator_instance_id() -> str:
    """
    Get the current operator instance ID from environment.

    The instance ID uniquely identifies this operator deployment and is used
    to track ownership of Keycloak resources. The value is cached after first
    retrieval to avoid repeated environment variable lookups.

    Returns:
        Operator instance ID (e.g., "keycloak-operator-production")

    Raises:
        RuntimeError: If OPERATOR_INSTANCE_ID environment variable is not set
    """
    global _operator_instance_id_cache

    if _operator_instance_id_cache is not None:
        return _operator_instance_id_cache

    instance_id = os.getenv("OPERATOR_INSTANCE_ID")
    if not instance_id:
        raise RuntimeError(
            "OPERATOR_INSTANCE_ID environment variable is not set. "
            "This should be configured in the Helm chart deployment."
        )

    _operator_instance_id_cache = instance_id
    return instance_id


def create_ownership_attributes(cr_namespace: str, cr_name: str) -> dict[str, str]:
    """
    Create ownership attributes for a Keycloak resource.

    These attributes are added to Keycloak resources (realms, clients, etc.)
    to track which operator instance created them and which CR they correspond to.

    Args:
        cr_namespace: Kubernetes namespace of the CR
        cr_name: Name of the CR

    Returns:
        Dictionary of ownership attributes to add to Keycloak resource

    Example:
        >>> attrs = create_ownership_attributes("production", "my-realm")
        >>> # Add to realm creation:
        >>> realm_data = {
        ...     "realm": "my-realm",
        ...     "enabled": True,
        ...     "attributes": attrs
        ... }
    """
    return {
        ATTR_MANAGED_BY: MANAGED_BY_VALUE,
        ATTR_OPERATOR_INSTANCE: get_operator_instance_id(),
        ATTR_CR_NAMESPACE: cr_namespace,
        ATTR_CR_NAME: cr_name,
        ATTR_CREATED_AT: datetime.now(UTC).isoformat(),
    }


def is_owned_by_this_operator(attributes: dict[str, str | list[str]] | None) -> bool:
    """
    Check if a Keycloak resource is owned by this operator instance.

    Args:
        attributes: Keycloak resource attributes (may be None or empty)

    Returns:
        True if the resource was created by this operator instance

    Example:
        >>> realm = keycloak_admin.get_realm("my-realm")
        >>> if is_owned_by_this_operator(realm.get("attributes")):
        ...     print("This realm is managed by us")
    """
    if not attributes:
        return False

    # Keycloak attributes can be either strings or lists of strings
    # We need to handle both cases
    operator_instance = attributes.get(ATTR_OPERATOR_INSTANCE)

    # Convert to string if it's a list
    if isinstance(operator_instance, list):
        operator_instance = operator_instance[0] if operator_instance else None

    return operator_instance == get_operator_instance_id()


def is_managed_by_operator(attributes: dict[str, str | list[str]] | None) -> bool:
    """
    Check if a Keycloak resource is managed by any operator instance.

    Args:
        attributes: Keycloak resource attributes (may be None or empty)

    Returns:
        True if the resource has operator ownership attributes

    Example:
        >>> realm = keycloak_admin.get_realm("my-realm")
        >>> if not is_managed_by_operator(realm.get("attributes")):
        ...     print("This is an unmanaged realm")
    """
    if not attributes:
        return False

    managed_by = attributes.get(ATTR_MANAGED_BY)

    # Convert to string if it's a list
    if isinstance(managed_by, list):
        managed_by = managed_by[0] if managed_by else None

    return managed_by == MANAGED_BY_VALUE


def get_cr_reference(
    attributes: dict[str, str | list[str]] | None,
) -> tuple[str, str] | None:
    """
    Extract CR namespace and name from Keycloak resource attributes.

    Args:
        attributes: Keycloak resource attributes

    Returns:
        Tuple of (namespace, name) or None if attributes are missing

    Example:
        >>> realm = keycloak_admin.get_realm("my-realm")
        >>> ref = get_cr_reference(realm.get("attributes"))
        >>> if ref:
        ...     namespace, name = ref
        ...     cr = k8s_api.get_namespaced_custom_object(..., namespace, name)
    """
    if not attributes:
        return None

    # Extract namespace and name, handling both string and list values
    namespace = attributes.get(ATTR_CR_NAMESPACE)
    name = attributes.get(ATTR_CR_NAME)

    if isinstance(namespace, list):
        namespace = namespace[0] if namespace else None
    if isinstance(name, list):
        name = name[0] if name else None

    if not namespace or not name:
        return None

    return (namespace, name)


def get_resource_age_hours(
    attributes: dict[str, str | list[str]] | None,
) -> float | None:
    """
    Calculate how old a Keycloak resource is based on creation timestamp.

    Args:
        attributes: Keycloak resource attributes

    Returns:
        Age in hours, or None if creation timestamp is missing/invalid

    Example:
        >>> realm = keycloak_admin.get_realm("orphaned-realm")
        >>> age = get_resource_age_hours(realm.get("attributes"))
        >>> if age and age > 24:
        ...     print(f"Orphan is {age:.1f} hours old - safe to delete")
    """
    if not attributes:
        return None

    created_at = attributes.get(ATTR_CREATED_AT)

    # Convert to string if it's a list
    if isinstance(created_at, list):
        created_at = created_at[0] if created_at else None

    if not created_at:
        return None

    try:
        # Handle ISO 8601 timestamps with Z suffix (Python 3.11+ handles this natively)
        # For older Python: manually replace Z with +00:00
        if created_at.endswith("Z"):
            created_at = created_at[:-1] + "+00:00"

        created_time = datetime.fromisoformat(created_at)
        age_seconds = (datetime.now(UTC) - created_time).total_seconds()
        return age_seconds / 3600.0  # Convert to hours
    except (ValueError, AttributeError):
        # Invalid timestamp format
        return None
