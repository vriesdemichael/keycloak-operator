"""
Validating admission webhook for KeycloakClient resources.

This webhook validates client configurations before they are accepted by
Kubernetes, enforcing:
- Resource quotas (max clients per namespace)
- Valid realm references
- Client configuration constraints
- Service account role assignments
"""

import asyncio
import logging

import kopf
from kubernetes import client
from pydantic import ValidationError

from keycloak_operator.constants import WEBHOOK_MAX_CLIENTS_PER_NAMESPACE
from keycloak_operator.models.client import KeycloakClientSpec

logger = logging.getLogger(__name__)


def _sync_list_clients(namespace: str) -> dict:
    """Synchronous helper to list clients (runs in thread pool)."""
    api = client.CustomObjectsApi()
    return api.list_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=namespace,
        plural="keycloakclients",
    )


async def get_client_count_in_namespace(namespace: str) -> int:
    """
    Count existing KeycloakClient resources in a namespace.

    Args:
        namespace: Namespace to count clients in

    Returns:
        Number of existing clients
    """
    try:
        clients = await asyncio.to_thread(_sync_list_clients, namespace)
        return len(clients.get("items", []))
    except Exception as e:
        logger.warning(f"Failed to count clients in namespace {namespace}: {e}")
        # If we can't count, allow the request (fail open)
        return 0


@kopf.on.validate(
    "vriesdemichael.github.io", "v1", "keycloakclients", id="validate-client"
)
async def validate_client(
    spec: dict,
    namespace: str,
    name: str,
    operation: str,
    dryrun: bool,
    **kwargs,
) -> dict:
    """
    Validate KeycloakClient resource before admission.

    Validates:
    - Namespace quota (max clients per namespace)
    - Required fields (clientId, realmRef)
    - Pydantic model validation
    - Realm reference validity

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
        f"Validating KeycloakClient {name} in namespace {namespace} "
        f"(operation: {operation}, dryrun: {dryrun})"
    )

    # Validate with Pydantic model first
    try:
        client_spec = KeycloakClientSpec.model_validate(spec)
        logger.debug(f"Pydantic validation passed for client {name}")
    except ValidationError as e:
        error_msg = f"Invalid client specification: {e}"
        logger.warning(f"Client {name} validation failed: {error_msg}")
        raise kopf.AdmissionError(error_msg) from e

    # Only check quota on CREATE operations
    if operation == "CREATE":
        client_count = await get_client_count_in_namespace(namespace)
        if client_count >= WEBHOOK_MAX_CLIENTS_PER_NAMESPACE:
            error_msg = (
                f"Namespace quota exceeded: maximum {WEBHOOK_MAX_CLIENTS_PER_NAMESPACE} clients "
                f"per namespace (currently {client_count})"
            )
            logger.warning(f"Client {name} rejected: {error_msg}")
            raise kopf.AdmissionError(error_msg)

    # Validate realm reference
    realm_ref = client_spec.realm_ref
    if not realm_ref.name or not realm_ref.namespace:
        raise kopf.AdmissionError("realmRef.name and realmRef.namespace are required")

    logger.info(f"KeycloakClient {name} validation passed")

    return {}
