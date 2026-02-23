"""
Validating admission webhook for KeycloakRealm resources.

This webhook validates realm configurations before they are accepted by
Kubernetes, enforcing:
- Resource quotas (max realms per namespace)
- Naming conventions and scope restrictions
- Valid operator references
- Realm configuration constraints
- No Keycloak environment variable placeholders
"""

import asyncio
import logging

import kopf
from kubernetes import client
from pydantic import ValidationError

from keycloak_operator.constants import WEBHOOK_MAX_REALMS_PER_NAMESPACE
from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.utils.validation import (
    ValidationError as PlaceholderValidationError,
)
from keycloak_operator.utils.validation import validate_spec_no_placeholders

logger = logging.getLogger(__name__)


def _sync_list_realms(namespace: str) -> dict:
    """Synchronous helper to list realms (runs in thread pool)."""
    api = client.CustomObjectsApi()
    return api.list_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=namespace,
        plural="keycloakrealms",
    )


async def get_realm_count_in_namespace(namespace: str) -> int:
    """
    Count existing KeycloakRealm resources in a namespace.

    Args:
        namespace: Namespace to count realms in

    Returns:
        Number of existing realms
    """
    try:
        realms = await asyncio.to_thread(_sync_list_realms, namespace)
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

    # Multi-tenancy check: Only validate if this resource is for US.
    # We check operatorRef.namespace. If it doesn't match our namespace,
    # we return success immediately to avoid interfering with other operators.
    from keycloak_operator.settings import settings as operator_settings

    try:
        # We need a partial parse to get operatorRef
        operator_ns = spec.get("operatorRef", {}).get("namespace")
        if operator_ns and operator_ns != operator_settings.operator_namespace:
            logger.info(
                f"Skipping validation for realm {name}: targeted at operator in namespace {operator_ns} "
                f"(we are {operator_settings.operator_namespace})"
            )
            return {}
    except Exception as e:
        logger.warning(f"Error checking operatorRef for realm {name}: {e}")
        # Continue to full validation if we can't determine ownership

    # Validate with Pydantic model first
    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)
        logger.debug(f"Pydantic validation passed for realm {name}")
    except ValidationError as e:
        error_msg = f"Invalid realm specification: {e}"
        logger.warning(f"Realm {name} validation failed: {error_msg}")
        raise kopf.AdmissionError(error_msg) from e

    # Check for Keycloak environment variable placeholders
    try:
        validate_spec_no_placeholders(spec, "KeycloakRealm")
    except PlaceholderValidationError as e:
        logger.warning(f"Realm {name} contains unsupported placeholders: {e}")
        raise kopf.AdmissionError(str(e)) from e

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
