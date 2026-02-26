"""
Validating admission webhook for Keycloak resources.

This webhook validates Keycloak instance configurations before they are
accepted by Kubernetes, enforcing:
- Resource quotas (one Keycloak per operator)
- Valid configuration
- Database settings
- Resource requirements
"""

import asyncio
import logging

import kopf
from kubernetes import client
from pydantic import ValidationError

from keycloak_operator.models.keycloak import KeycloakSpec
from keycloak_operator.utils.isolation import is_managed_by_this_operator

logger = logging.getLogger(__name__)


def _sync_list_keycloaks(namespace: str) -> dict:
    """Synchronous helper to list keycloaks (runs in thread pool)."""
    api = client.CustomObjectsApi()
    return api.list_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=namespace,
        plural="keycloaks",
    )


async def get_keycloak_count_in_namespace(namespace: str) -> int:
    """
    Count existing Keycloak resources in a namespace.

    Args:
        namespace: Namespace to count Keycloak instances in

    Returns:
        Number of existing Keycloak instances
    """
    try:
        keycloaks = await asyncio.to_thread(_sync_list_keycloaks, namespace)
        return len(keycloaks.get("items", []))
    except Exception as e:
        logger.warning(f"Failed to count Keycloaks in namespace {namespace}: {e}")
        # If we can't count, allow the request (fail open)
        return 0


@kopf.on.validate("vriesdemichael.github.io", "v1", "keycloaks", id="validate-keycloak")
async def validate_keycloak(
    spec: dict,
    namespace: str,
    name: str,
    operation: str,
    dryrun: bool,
    **kwargs,
) -> dict:
    """
    Validate Keycloak resource before admission.

    Validates:
    - One Keycloak per namespace (ADR-062)
    - Required fields
    - Pydantic model validation
    - Database configuration

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
        f"Validating Keycloak {name} in namespace {namespace} "
        f"(operation: {operation}, dryrun: {dryrun})"
    )

    # Multi-tenancy check (ADR-062): Only validate if this resource is for US.

    if not is_managed_by_this_operator(spec, namespace):
        logger.info(
            f"Skipping validation for Keycloak {name} in namespace {namespace}: not owned by this operator"
        )
        return {}

    # Validate with Pydantic model first
    try:
        _keycloak_spec = KeycloakSpec.model_validate(spec)
        logger.debug(f"Pydantic validation passed for Keycloak {name}")
    except ValidationError as e:
        error_msg = f"Invalid Keycloak specification: {e}"
        logger.warning(f"Keycloak {name} validation failed: {error_msg}")
        raise kopf.AdmissionError(error_msg) from e

    # Enforce one Keycloak per namespace (ADR-062)
    if operation == "CREATE":
        keycloak_count = await get_keycloak_count_in_namespace(namespace)
        if keycloak_count > 0:
            error_msg = (
                f"Only one Keycloak instance allowed per namespace (ADR-062). "
                f"Found {keycloak_count} existing instance(s)"
            )
            logger.warning(f"Keycloak {name} rejected: {error_msg}")
            raise kopf.AdmissionError(error_msg)

    logger.info(f"Keycloak {name} validation passed")

    return {}
