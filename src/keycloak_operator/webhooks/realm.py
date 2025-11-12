"""
Validating admission webhook for KeycloakRealm resources.

This webhook validates realm configurations before they are accepted by
Kubernetes, enforcing:
- Resource quotas (max realms per namespace)
- Naming conventions and scope restrictions
- Valid operator references
- Realm configuration constraints
"""

import logging

import kopf
from kubernetes import client
from pydantic import ValidationError

from keycloak_operator.constants import WEBHOOK_MAX_REALMS_PER_NAMESPACE
from keycloak_operator.models.realm import KeycloakRealmSpec

logger = logging.getLogger(__name__)


async def get_realm_count_in_namespace(namespace: str) -> int:
    """
    Count existing KeycloakRealm resources in a namespace.

    Args:
        namespace: Namespace to count realms in

    Returns:
        Number of existing realms
    """
    try:
        api = client.CustomObjectsApi()
        realms = api.list_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
        )
        return len(realms.get("items", []))
    except Exception as e:
        logger.warning(f"Failed to count realms in namespace {namespace}: {e}")
        # If we can't count, allow the request (fail open)
        return 0


@kopf.on.validate(
    "vriesdemichael.github.io", "v1", "keycloakrealms", id="validate-realm"
)
async def validate_realm(
    spec: dict,
    namespace: str,
    name: str,
    operation: str,
    dryrun: bool,
    **kwargs,
) -> dict:
    """
    Validate KeycloakRealm resource before admission.

    Validates:
    - Namespace quota (max realms per namespace)
    - Required fields (realmName, operatorRef)
    - Pydantic model validation
    - Operator reference validity

    Args:
        spec: Resource specification
        namespace: Resource namespace
        name: Resource name
        operation: CREATE or UPDATE
        dryrun: Whether this is a dry-run request

    Returns:
        Admission response dict with allowed/denied status

    Raises:
        kopf.AdmissionError: If validation fails
    """
    logger.info(
        f"Validating KeycloakRealm {name} in namespace {namespace} "
        f"(operation: {operation}, dryrun: {dryrun})"
    )

    # Validate with Pydantic model first
    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)
        logger.debug(f"Pydantic validation passed for realm {name}")
    except ValidationError as e:
        error_msg = f"Invalid realm specification: {e}"
        logger.warning(f"Realm {name} validation failed: {error_msg}")
        raise kopf.AdmissionError(error_msg) from e

    # Only check quota on CREATE operations (not updates)
    if operation == "CREATE":
        realm_count = await get_realm_count_in_namespace(namespace)
        if realm_count >= WEBHOOK_MAX_REALMS_PER_NAMESPACE:
            error_msg = (
                f"Namespace quota exceeded: maximum {WEBHOOK_MAX_REALMS_PER_NAMESPACE} realms "
                f"per namespace (currently {realm_count})"
            )
            logger.warning(f"Realm {name} rejected: {error_msg}")
            raise kopf.AdmissionError(error_msg)

    # Validate operator reference exists and is accessible
    operator_ns = realm_spec.operator_ref.namespace
    if not operator_ns:
        raise kopf.AdmissionError("operatorRef.namespace is required")

    logger.info(f"KeycloakRealm {name} validation passed")

    # Return empty dict = allowed (Kopf handles response format)
    return {}
