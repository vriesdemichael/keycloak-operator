"""
Validating admission webhook for KeycloakClient resources.

This webhook validates client configurations before they are accepted by
Kubernetes, enforcing:
- Resource quotas (max clients per namespace)
- Valid realm references
- Client configuration constraints
- Service account role assignments
- No Keycloak environment variable placeholders
"""

import asyncio
import logging

import kopf
from kubernetes import client
from pydantic import ValidationError

from keycloak_operator.constants import WEBHOOK_MAX_CLIENTS_PER_NAMESPACE
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.utils.validation import (
    ValidationError as PlaceholderValidationError,
)
from keycloak_operator.utils.validation import validate_spec_no_placeholders

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

    # Multi-tenancy check: Only validate if the parent Realm is managed by us.
    # This prevents Operator A from blocking Operator B's clients via quotas.
    from keycloak_operator.settings import settings as operator_settings

    try:
        realm_ref = spec.get("realmRef", {})
        realm_name = realm_ref.get("name")
        realm_ns = realm_ref.get("namespace")

        if realm_name and realm_ns:
            # Look up the realm to check its operatorRef
            from kubernetes import client as k8s_client

            api = k8s_client.CustomObjectsApi()
            realm = await asyncio.to_thread(
                api.get_namespaced_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=realm_ns,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Check if realm is targeted at another operator
            target_op_ns = realm.get("spec", {}).get("operatorRef", {}).get("namespace")
            if target_op_ns and target_op_ns != operator_settings.operator_namespace:
                logger.warning(
                    f"DEBUG: Skipping validation for client {name}: parent realm {realm_name} "
                    f"targeted at operator in {target_op_ns} (we are {operator_settings.operator_namespace})"
                )
                return {}
            else:
                logger.warning(
                    f"DEBUG: Proceeding with validation for client {name}: target_op_ns={target_op_ns}, our_ns={operator_settings.operator_namespace}"
                )
    except Exception as e:
        # If realm doesn't exist yet or lookup fails, we continue to full validation.
        # This allows creating a client alongside a realm in a single manifest.
        logger.debug(f"Could not determine realm ownership for client {name}: {e}")

    # Validate with Pydantic model first
    try:
        client_spec = KeycloakClientSpec.model_validate(spec)
        logger.debug(f"Pydantic validation passed for client {name}")
    except ValidationError as e:
        error_msg = f"Invalid client specification: {e}"
        logger.warning(f"Client {name} validation failed: {error_msg}")
        raise kopf.AdmissionError(error_msg) from e

    # Check for Keycloak environment variable placeholders
    try:
        validate_spec_no_placeholders(spec, "KeycloakClient")
    except PlaceholderValidationError as e:
        logger.warning(f"Client {name} contains unsupported placeholders: {e}")
        raise kopf.AdmissionError(str(e)) from e

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

    # Security validation: Restricted Roles
    roles_config = client_spec.service_account_roles
    if client_spec.settings.service_accounts_enabled:
        # Realm roles
        restricted_realm_roles = {"admin"}
        for role in roles_config.realm_roles:
            if role in restricted_realm_roles:
                raise kopf.AdmissionError(
                    f"Assigning restricted realm role '{role}' to service account is not allowed for security reasons."
                )

        # Client roles
        from keycloak_operator.services.client_reconciler import RESTRICTED_CLIENT_ROLES
        from keycloak_operator.settings import settings as operator_settings

        if roles_config.client_roles:
            for target_client, roles in roles_config.client_roles.items():
                if target_client in RESTRICTED_CLIENT_ROLES:
                    restricted_roles = RESTRICTED_CLIENT_ROLES[target_client]
                    for role in roles:
                        # Allow impersonation only if explicitly configured
                        if (
                            role == "impersonation"
                            and operator_settings.allow_impersonation
                        ):
                            continue

                        if role in restricted_roles or role == "impersonation":
                            raise kopf.AdmissionError(
                                f"Assigning restricted client role '{role}' from '{target_client}' "
                                "to service account is not allowed for security reasons."
                            )

    # Security validation: Script Mappers
    from keycloak_operator.services.client_reconciler import (
        DANGEROUS_SCRIPT_MAPPER_TYPES,
    )

    if not operator_settings.allow_script_mappers and client_spec.protocol_mappers:
        for mapper_spec in client_spec.protocol_mappers:
            m_type = (
                mapper_spec.protocol_mapper.lower()
                if mapper_spec.protocol_mapper
                else ""
            )
            if m_type in DANGEROUS_SCRIPT_MAPPER_TYPES:
                raise kopf.AdmissionError(
                    f"Script mapper '{mapper_spec.name}' (type: {mapper_spec.protocol_mapper}) is not allowed. "
                    "Script mappers are disabled by default for security."
                )

    logger.info(f"KeycloakClient {name} validation passed")

    return {}
