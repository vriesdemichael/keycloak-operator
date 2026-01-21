"""
KeycloakClient handlers - Manages dynamic client provisioning across namespaces.

This module implements the core feature of dynamic client provisioning that
enables GitOps-compatible client management. Key features:

- Cross-namespace client creation: Clients can reference Keycloak instances
  in different namespaces (subject to RBAC permissions)
- RBAC-based authorization: Uses Kubernetes RBAC instead of Keycloak's
  built-in security mechanisms
- Secure secret management: Client credentials stored in Kubernetes secrets
  with proper access controls
- GitOps compatibility: All client configuration is declarative

The handlers support various client types including:
- Public clients (SPAs, mobile apps)
- Confidential clients (backend services)
- Service accounts for machine-to-machine communication
"""

import asyncio
import logging
import random
from datetime import UTC, datetime
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    RECONCILE_JITTER_MAX,
    TIMER_INTERVAL_CLIENT,
)
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.services import KeycloakClientReconciler
from keycloak_operator.utils.handler_logging import log_handler_entry
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import (
    get_kubernetes_client,
)

logger = logging.getLogger(__name__)


class StatusWrapper:
    """Wrapper to make kopf patch.status compatible with StatusProtocol.

    This wrapper provides both attribute and dict-like access to patch.status,
    ensuring all updates are written directly to the underlying patch object.

    Automatically converts snake_case Python attribute names to camelCase for K8s API.
    """

    def __init__(self, patch_status: Any):
        object.__setattr__(self, "_patch_status", patch_status)

    @staticmethod
    def _to_camel_case(snake_str: str) -> str:
        """Convert snake_case to camelCase."""
        components = snake_str.split("_")
        return components[0] + "".join(x.title() for x in components[1:])

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        # Convert to camelCase for K8s API
        camel_name = self._to_camel_case(name)
        self._patch_status[camel_name] = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        # Convert to camelCase and read from patch.status
        camel_name = self._to_camel_case(name)
        try:
            return self._patch_status[camel_name]
        except (KeyError, TypeError):
            return None

    def update(self, data: dict[str, Any]) -> None:
        """Update multiple fields. Assumes data keys are already in camelCase."""
        for k, v in data.items():
            self._patch_status[k] = v


async def _perform_client_cleanup(
    name: str,
    namespace: str,
    spec: dict[str, Any],
    status: dict[str, Any],
    rate_limiter: Any,
    trigger: str = "delete_handler",
) -> None:
    """
    Perform client cleanup from Keycloak.

    This is the core cleanup logic for delete handlers.
    Finalizer management is handled by Kopf via settings.persistence.finalizer.

    Args:
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        spec: KeycloakClient resource specification
        status: Current status of the resource
        rate_limiter: Rate limiter for Keycloak API calls
        trigger: What triggered this cleanup (for logging)
    """
    reconciler = KeycloakClientReconciler(rate_limiter=rate_limiter)
    status_wrapper = StatusWrapper(status)

    # Check if resource actually exists in Keycloak before attempting cleanup
    resource_exists = await reconciler.check_resource_exists(
        name=name, namespace=namespace, spec=spec, status=status_wrapper
    )

    if resource_exists:
        # Resource exists in Keycloak, perform cleanup
        logger.info(
            f"Client {name} exists in Keycloak, performing cleanup",
            extra={
                "resource_type": "client",
                "resource_name": name,
                "namespace": namespace,
                "cleanup_phase": "keycloak_cleanup_starting",
                "cleanup_trigger": trigger,
            },
        )
        await reconciler.cleanup_resources(
            name=name, namespace=namespace, spec=spec, status=status_wrapper
        )
    else:
        # Resource never materialized in Keycloak, no cleanup needed
        logger.info(
            f"Client {name} does not exist in Keycloak, "
            f"skipping cleanup (resource never materialized)",
            extra={
                "resource_type": "client",
                "resource_name": name,
                "namespace": namespace,
                "cleanup_phase": "skipped_not_materialized",
                "cleanup_trigger": trigger,
            },
        )

    # Note: Finalizer removal is handled by Kopf automatically after this handler completes

    logger.info(
        f"Successfully cleaned up KeycloakClient {name}",
        extra={
            "resource_type": "client",
            "resource_name": name,
            "namespace": namespace,
            "cleanup_phase": "completed",
            "cleanup_trigger": trigger,
        },
    )


@kopf.on.create(
    "keycloakclients", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
@kopf.on.resume(
    "keycloakclients", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
async def ensure_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    **kwargs: Any,
) -> None:
    """
    Ensure KeycloakClient exists in the target Keycloak instance.

    This handler implements dynamic client provisioning across namespaces.
    It can create clients in Keycloak instances located in any namespace,
    subject to RBAC permissions.

    Note: Deletion is handled by the @kopf.on.delete handler (delete_keycloak_client).
    Do not add deletion logic here to avoid race conditions with the delete handler.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the KeycloakClient resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        Dictionary with status information for the resource

    """
    # Log handler entry immediately for debugging
    log_handler_entry("create/resume", "keycloakclient", name, namespace)

    # Check if resource is being deleted - if so, skip reconciliation
    # The @kopf.on.delete handler (delete_keycloak_client) handles cleanup
    meta = kwargs.get("meta", {})
    deletion_timestamp = meta.get("deletionTimestamp")

    if deletion_timestamp:
        logger.debug(
            f"KeycloakClient {name} has deletionTimestamp, "
            f"skipping reconciliation (delete handler will manage cleanup)"
        )
        return None

    logger.info(f"Ensuring KeycloakClient {name} in namespace {namespace}")

    # Note: Finalizer is managed by Kopf via settings.persistence.finalizer
    # configured in operator.py startup handler

    # Use patch.status for updates instead of wrapping the read-only status dict
    # Add jitter to prevent thundering herd

    jitter = random.uniform(0, RECONCILE_JITTER_MAX)

    await asyncio.sleep(jitter)

    reconciler = KeycloakClientReconciler(rate_limiter=memo.rate_limiter)
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.reconcile(
        spec=spec, name=name, namespace=namespace, status=status_wrapper, **kwargs
    )
    # Return None to avoid Kopf creating status subpaths
    return


@kopf.on.update(
    "keycloakclients", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
async def update_keycloak_client(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Handle updates to KeycloakClient specifications.

    This handler processes changes to client configurations and applies
    them to the target Keycloak instance.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        None to avoid Kopf creating status subpaths

    """
    # Log handler entry immediately for debugging
    log_handler_entry("update", "keycloakclient", name, namespace)

    logger.info(f"Updating KeycloakClient {name} in namespace {namespace}")

    # Use patch.status for updates instead of wrapping the read-only status dict
    # Add jitter to prevent thundering herd

    jitter = random.uniform(0, RECONCILE_JITTER_MAX)

    await asyncio.sleep(jitter)

    reconciler = KeycloakClientReconciler(rate_limiter=memo.rate_limiter)
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.update(
        old_spec=old.get("spec", {}),
        new_spec=new.get("spec", {}),
        diff=diff,
        name=name,
        namespace=namespace,
        status=status_wrapper,
        **kwargs,
    )
    return


@kopf.on.delete(
    "keycloakclients", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
async def delete_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    retry: int,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakClient deletion.

    This handler performs comprehensive cleanup of the client from Keycloak
    and any associated Kubernetes resources. Finalizer management is handled
    automatically by Kopf via settings.persistence.finalizer.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
        retry: Kopf retry count (starts from 0)
    """
    # Log handler entry immediately for debugging - this is the first thing we do
    retry_count = retry if retry else 0
    log_handler_entry(
        "delete",
        "keycloakclient",
        name,
        namespace,
        extra={"retry_count": retry_count},
    )

    logger.info(
        f"Starting deletion of KeycloakClient {name} in namespace {namespace} "
        f"(attempt {retry_count + 1})",
        extra={
            "resource_type": "client",
            "resource_name": name,
            "namespace": namespace,
            "retry_count": retry_count,
            "cleanup_phase": "handler_started",
        },
    )

    try:
        # Add jitter to prevent thundering herd on mass deletion
        jitter = random.uniform(0, RECONCILE_JITTER_MAX)
        await asyncio.sleep(jitter)

        # Perform Keycloak cleanup - finalizer is managed by Kopf
        await _perform_client_cleanup(
            name=name,
            namespace=namespace,
            spec=spec,
            status=status,
            rate_limiter=memo.rate_limiter,
            trigger="delete_handler",
        )

    except Exception as e:
        logger.error(
            f"Error during KeycloakClient deletion (attempt {retry_count + 1}): {e}",
            extra={
                "resource_type": "client",
                "resource_name": name,
                "namespace": namespace,
                "retry_count": retry_count,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "cleanup_phase": "failed",
            },
            exc_info=True,
        )
        # Update status to indicate deletion failure
        try:
            status["phase"] = "Failed"
            status["message"] = f"Deletion failed (attempt {retry_count + 1}): {str(e)}"
        except Exception:
            pass  # Status update might fail if resource is being deleted

        # Re-raise the exception to trigger retry
        # Kopf will retry the deletion with exponential backoff
        raise kopf.TemporaryError(
            f"Failed to delete KeycloakClient {name} (attempt {retry_count + 1}): {e}",
            delay=30,  # Wait 30 seconds before retry
        ) from e


@kopf.timer("keycloakclients", interval=TIMER_INTERVAL_CLIENT)
async def monitor_client_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    meta: dict[str, Any],
    memo: kopf.Memo,
    **kwargs: Any,
) -> None:
    """
    Periodic health check for KeycloakClients.

    This timer verifies that clients still exist in Keycloak and
    that their configuration matches the desired state.

    The interval is configurable via TIMER_INTERVAL_CLIENT environment variable.
    Default: 300 seconds (5 minutes).

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        meta: Resource metadata
        memo: Kopf memo for accessing shared state like rate_limiter

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    # Skip health checks for resources being deleted
    deletion_timestamp = meta.get("deletionTimestamp")
    if deletion_timestamp:
        return

    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed, pending, or unknown clients
    # Unknown = resource just created, reconciliation hasn't started yet
    if current_phase in ["Failed", "Pending", "Unknown"]:
        return

    logger.debug(f"Checking health of KeycloakClient {name} in {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # Get realm reference to find the Keycloak instance
        realm_ref = client_spec.realm_ref
        realm_namespace = realm_ref.namespace or namespace

        # Resolve Keycloak instance from realm's status (same approach as client_reconciler)
        # We need to fetch the realm resource to get the keycloakInstance from its status
        try:
            custom_api = client.CustomObjectsApi(get_kubernetes_client())
            realm_resource = custom_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=realm_namespace,
                plural="keycloakrealms",
                name=realm_ref.name,
            )

            # Get actual Keycloak realm name from spec
            actual_realm_name = realm_resource.get("spec", {}).get("realmName")
            if not actual_realm_name:
                logger.warning(
                    f"Realm {realm_ref.name} does not have realmName in spec"
                )
                return

            # Get Keycloak instance from realm status (format: "namespace/name")
            realm_status = realm_resource.get("status", {})
            keycloak_instance = realm_status.get("keycloakInstance", "")

            if "/" in keycloak_instance and keycloak_instance.count("/") == 1:
                keycloak_namespace, keycloak_name = keycloak_instance.split("/", 1)
            else:
                # Fallback to defaults
                logger.warning(
                    f"Realm {realm_ref.name} has unexpected keycloakInstance format: '{keycloak_instance}'. "
                    f"Using default: {realm_namespace}/keycloak"
                )
                keycloak_namespace, keycloak_name = realm_namespace, "keycloak"

        except ApiException as e:
            if e.status == 404:
                logger.warning(
                    f"Realm {realm_ref.name} not found in namespace {realm_namespace}"
                )
            else:
                logger.warning(f"Failed to get realm {realm_ref.name}: {e}")
            return

        async with await get_keycloak_admin_client(
            keycloak_name, keycloak_namespace
        ) as admin_client:
            # Check if client exists in Keycloak
            # Use actual_realm_name (from realm spec) not realm_ref.name (CR name)
            existing_client = await admin_client.get_client_by_name(
                client_spec.client_id, actual_realm_name, namespace
            )

            if not existing_client:
                logger.warning(f"Client {client_spec.client_id} missing from Keycloak")
                patch.status.update(
                    {
                        "phase": "Degraded",
                        "message": "Client missing from Keycloak, will recreate",
                        "lastHealthCheck": datetime.now(UTC).isoformat(),
                    }
                )
                return

            # Verify client configuration matches spec
            # Compare current Keycloak client config with desired spec
            try:
                desired_config = client_spec.to_keycloak_config()
                config_matches = True

                # Check critical configuration fields
                if existing_client.enabled != desired_config.get("enabled", True):
                    config_matches = False
                    logger.warning(
                        f"Client {client_spec.client_id} enabled state mismatch"
                    )

                if existing_client.public_client != desired_config.get(
                    "publicClient", False
                ):
                    config_matches = False
                    logger.warning(
                        f"Client {client_spec.client_id} public client setting mismatch"
                    )

                # Check redirect URIs if specified
                if desired_config.get("redirectUris"):
                    existing_uris = set(existing_client.redirect_uris or [])
                    desired_uris = set(desired_config.get("redirectUris", []))
                    if existing_uris != desired_uris:
                        config_matches = False
                        logger.warning(
                            f"Client {client_spec.client_id} redirect URIs mismatch"
                        )

                # Check web origins if specified
                if desired_config.get("webOrigins"):
                    existing_origins = set(existing_client.web_origins or [])
                    desired_origins = set(desired_config.get("webOrigins", []))
                    if existing_origins != desired_origins:
                        config_matches = False
                        logger.warning(
                            f"Client {client_spec.client_id} web origins mismatch"
                        )

                if not config_matches:
                    logger.info(
                        f"Client {client_spec.client_id} configuration drift detected"
                    )
                    patch.status.update(
                        {
                            "phase": "Degraded",
                            "message": "Configuration drift detected",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }
                    )
                    return

            except Exception as e:
                logger.warning(f"Failed to verify client configuration: {e}")
                # Don't fail health check for verification errors

        # Check credentials secret exists and is valid
        if not client_spec.public_client:
            try:
                k8s_client = get_kubernetes_client()
                core_api = client.CoreV1Api(k8s_client)
                secret_name = f"{name}-credentials"

                # Check if secret exists
                try:
                    secret = core_api.read_namespaced_secret(
                        name=secret_name, namespace=namespace
                    )

                    # Validate secret has required keys
                    required_keys = ["client-id", "client-secret"]
                    missing_keys = []

                    if not secret.data:
                        patch.status.update(
                            {
                                "phase": "Degraded",
                                "message": "Client credentials secret exists but has no data",
                                "lastHealthCheck": datetime.now(UTC).isoformat(),
                            }
                        )
                        return

                    for key in required_keys:
                        if key not in secret.data:
                            missing_keys.append(key)

                    if missing_keys:
                        patch.status.update(
                            {
                                "phase": "Degraded",
                                "message": f"Client credentials secret missing keys: {', '.join(missing_keys)}",
                                "lastHealthCheck": datetime.now(UTC).isoformat(),
                            }
                        )
                        return

                    logger.debug(f"Client credentials secret {secret_name} is valid")

                except ApiException as e:
                    if e.status == 404:
                        patch.status.update(
                            {
                                "phase": "Degraded",
                                "message": "Client credentials secret missing",
                                "lastHealthCheck": datetime.now(UTC).isoformat(),
                            }
                        )
                        return
                    else:
                        logger.warning(f"Failed to check credentials secret: {e}")

            except Exception as e:
                logger.warning(f"Failed to validate credentials secret: {e}")
                # Don't fail health check for secret validation errors

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakClient {name} health check passed")
            patch.status.update(
                {
                    "phase": "Ready",
                    "message": "Client is healthy and properly configured",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }
            )

    except Exception as e:
        logger.error(f"Health check failed for KeycloakClient {name}: {e}")
        patch.status.update(
            {
                "phase": "Degraded",
                "message": f"Health check failed: {str(e)}",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }
        )


@kopf.on.event(
    "secrets", labels={"vriesdemichael.github.io/keycloak-client": kopf.PRESENT}
)
async def monitor_client_secrets(
    event: dict[str, Any],
    logger: logging.Logger,
    **kwargs: Any,
) -> None:
    """
    Monitor client secrets and trigger reconciliation if deleted.

    If a managed secret is deleted, we must trigger reconciliation on the
    parent KeycloakClient to recreate it.
    """
    # Only react to deletion events
    if event["type"] != "DELETED":
        return

    meta = event["object"]["metadata"]
    name = meta["name"]
    namespace = meta["namespace"]
    labels = meta.get("labels", {})
    client_name = labels.get("vriesdemichael.github.io/keycloak-client")

    if not client_name:
        return

    logger.info(
        f"Managed secret {name} deleted, triggering reconciliation for KeycloakClient {client_name}"
    )

    # Touch the KeycloakClient to trigger reconciliation
    try:
        api = client.CustomObjectsApi(get_kubernetes_client())

        # We need to use a distinct annotation value to ensure a change event
        patch_body = {
            "metadata": {
                "annotations": {
                    "keycloak-operator/force-reconcile": f"secret-deleted-{datetime.now(UTC).timestamp()}"
                }
            }
        }

        # Use run_in_executor to avoid blocking the event loop with synchronous K8s calls
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: api.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                body=patch_body,
            ),
        )
        logger.info(f"Triggered reconciliation for KeycloakClient {client_name}")

    except ApiException as e:
        if e.status == 404:
            logger.warning(
                f"Parent KeycloakClient {client_name} not found, ignoring secret deletion"
            )
        else:
            logger.error(
                f"Failed to trigger reconciliation for KeycloakClient {client_name}: {e}"
            )
    except Exception as e:
        logger.error(f"Unexpected error triggering reconciliation: {e}")
