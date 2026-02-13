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
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    RECONCILE_JITTER_MAX,
    TIMER_INTERVAL_CLIENT,
)
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.observability.metrics import (
    SECRET_NEXT_ROTATION_TIMESTAMP,
    SECRET_ROTATION_DURATION,
    SECRET_ROTATION_ERRORS_TOTAL,
    SECRET_ROTATION_RETRIES_TOTAL,
    SECRET_ROTATION_TOTAL,
)
from keycloak_operator.observability.tracing import traced_handler
from keycloak_operator.services import KeycloakClientReconciler
from keycloak_operator.utils.handler_logging import log_handler_entry
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import (
    create_client_secret,
    get_kubernetes_client,
    validate_keycloak_reference,
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
@traced_handler("reconcile_client")
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
@traced_handler("update_client")
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
@traced_handler("delete_client")
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


@kopf.daemon(
    "keycloakclients",
    cancellation_timeout=10.0,
)
async def monitor_client_health(
    stopped: kopf.DaemonStopped,
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
    Periodic health check daemon for KeycloakClients.

    This daemon verifies that clients still exist in Keycloak and
    that their configuration matches the desired state.

    Uses a daemon instead of a timer to work around Kopf 1.40.x not
    supporting callable ``initial_delay`` (lambda). The daemon sleeps
    a random jitter on startup to spread reconciliation load, then
    loops at TIMER_INTERVAL_CLIENT between iterations.

    The interval is configurable via TIMER_INTERVAL_CLIENT environment variable.
    Default: 300 seconds (5 minutes).

    Args:
        stopped: Kopf daemon stopped flag for graceful shutdown
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        meta: Resource metadata
        memo: Kopf memo for accessing shared state like rate_limiter

    """
    # Random jitter on startup to prevent thundering herd
    initial_jitter = random.uniform(0, TIMER_INTERVAL_CLIENT)
    await stopped.wait(initial_jitter)

    while not stopped:
        # Skip health checks for resources being deleted
        deletion_timestamp = meta.get("deletionTimestamp")
        if deletion_timestamp:
            return

        current_phase = status.get("phase", "Unknown")

        # Skip health checks for non-stable phases
        # Unknown/Pending = not yet reconciled
        # Provisioning/Updating/Reconciling = active reconciliation in progress
        # Failed = terminal state, no point health-checking
        if current_phase not in (
            "Failed",
            "Pending",
            "Unknown",
            "Provisioning",
            "Updating",
            "Reconciling",
        ):
            await _run_client_health_check(
                spec, name, namespace, status, patch, meta, memo
            )

        # Wait for next interval or until stopped
        await stopped.wait(TIMER_INTERVAL_CLIENT)


async def _run_client_health_check(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    meta: dict[str, Any],
    memo: kopf.Memo,
) -> None:
    """Execute one health check iteration for a KeycloakClient."""
    current_phase = status.get("phase", "Unknown")

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

        admin_client = await get_keycloak_admin_client(
            keycloak_name, keycloak_namespace
        )
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
                logger.warning(f"Client {client_spec.client_id} enabled state mismatch")

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

                    # Note: Secret rotation is handled by the dedicated
                    # secret_rotation_daemon, not by this health check timer.

                except ApiException as e:
                    if e.status == 404:
                        logger.warning(
                            "Client credentials secret missing, triggering reconciliation to recreate it"
                        )

                        # Trigger reconciliation by updating an annotation
                        custom_api = client.CustomObjectsApi(k8s_client)
                        patch_body = {
                            "metadata": {
                                "annotations": {
                                    "keycloak-operator/force-reconcile": f"secret-missing-{datetime.now(UTC).timestamp()}"
                                }
                            }
                        }

                        # Use run_in_executor to avoid blocking
                        loop = asyncio.get_running_loop()
                        await loop.run_in_executor(
                            None,
                            lambda: custom_api.patch_namespaced_custom_object(
                                group="vriesdemichael.github.io",
                                version="v1",
                                namespace=namespace,
                                plural="keycloakclients",
                                name=name,
                                body=patch_body,
                            ),
                        )

                        patch.status.update(
                            {
                                "phase": "Degraded",
                                "message": "Client credentials secret missing, recreating...",
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


# Constants for rotation daemon
ROTATION_MAX_RETRIES = 5
ROTATION_INITIAL_BACKOFF_SECONDS = 2.0  # Short backoff as requested
ROTATION_MAX_BACKOFF_SECONDS = 30.0


def _parse_rotation_timestamp(timestamp_str: str | None) -> datetime | None:
    """
    Parse a rotation timestamp string to a datetime object.

    Handles ISO format timestamps and ensures timezone awareness (defaults to UTC).

    Args:
        timestamp_str: ISO format timestamp string, or None

    Returns:
        Parsed datetime with timezone, or None if input was None/invalid
    """
    if not timestamp_str:
        return None

    try:
        rotated_at = datetime.fromisoformat(timestamp_str)
        if rotated_at.tzinfo is None:
            rotated_at = rotated_at.replace(tzinfo=UTC)
        return rotated_at
    except ValueError:
        return None


def _calculate_exponential_backoff(
    retry_count: int,
    initial_backoff: float = ROTATION_INITIAL_BACKOFF_SECONDS,
    max_backoff: float = ROTATION_MAX_BACKOFF_SECONDS,
) -> float:
    """
    Calculate exponential backoff delay.

    Args:
        retry_count: Current retry attempt number (0-based)
        initial_backoff: Initial backoff delay in seconds
        max_backoff: Maximum backoff delay in seconds

    Returns:
        Backoff delay in seconds
    """
    backoff = initial_backoff * (2**retry_count)
    return min(backoff, max_backoff)


def _parse_duration(duration_str: str) -> timedelta:
    """Parse duration string (e.g. '90d', '24h', '10s') into timedelta."""
    if not duration_str:
        return timedelta(days=90)  # Default

    unit = duration_str[-1].lower()
    if unit not in ["s", "m", "h", "d"]:
        raise ValueError(
            f"Invalid duration unit in '{duration_str}'. Supported units: s, m, h, d."
        )

    value = int(duration_str[:-1])
    if value <= 0:
        raise ValueError(
            f"Invalid duration value '{duration_str}'. Duration must be a positive integer."
        )

    if unit == "s":
        return timedelta(seconds=value)
    elif unit == "m":
        return timedelta(minutes=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)

    return timedelta(days=90)  # Should be unreachable


def _calculate_seconds_until_rotation(
    spec: KeycloakClientSpec,
    rotated_at: datetime,
    logger: logging.Logger,
) -> float:
    """
    Calculate the number of seconds until the next rotation is due.

    Takes into account both the rotation period and optional rotation time window.

    Args:
        spec: Client specification with rotation settings
        rotated_at: When the secret was last rotated
        logger: Logger for debugging

    Returns:
        Seconds until rotation is due (can be 0 if already due)
    """
    rotation_period = _parse_duration(spec.secret_rotation.rotation_period)
    expiration_time = rotated_at + rotation_period
    now = datetime.now(UTC)

    # If already expired, check time window constraints
    if now >= expiration_time:
        # Check rotation time window
        if spec.secret_rotation.rotation_time:
            try:
                target_tz = ZoneInfo(spec.secret_rotation.timezone)
                expiration_in_tz = expiration_time.astimezone(target_tz)

                target_hour, target_minute = map(
                    int, spec.secret_rotation.rotation_time.split(":")
                )

                target_rotation_dt = expiration_in_tz.replace(
                    hour=target_hour, minute=target_minute, second=0, microsecond=0
                )

                # If target time is earlier than expiration, move to next day
                if target_rotation_dt < expiration_in_tz:
                    target_rotation_dt += timedelta(days=1)

                now_in_tz = now.astimezone(target_tz)
                if now_in_tz < target_rotation_dt:
                    # Still waiting for the time window
                    delta = target_rotation_dt - now_in_tz
                    return max(0.0, delta.total_seconds())

            except Exception as e:
                logger.warning(
                    f"Error calculating rotation schedule: {e}. Returning 0 for immediate rotation."
                )
                return 0.0

        # Period elapsed and no time window constraint (or past time window)
        return 0.0

    # Period not yet elapsed
    delta = expiration_time - now
    return max(0.0, delta.total_seconds())


@kopf.daemon(
    "keycloakclients",
    when=lambda spec, **_: (
        not spec.get("publicClient", False)
        and spec.get("secretRotation", {}).get("enabled", False)
    ),
)
async def secret_rotation_daemon(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    meta: dict[str, Any],
    stopped: kopf.DaemonStopped,
    patch: kopf.Patch,
    memo: kopf.Memo,
    logger: logging.Logger,
    **kwargs: Any,
) -> None:
    """
    Daemon to handle secret rotation with precise timing.

    This daemon:
    1. Reads the rotated-at annotation from the secret to determine last rotation
    2. Calculates exactly when the next rotation is due
    3. Sleeps precisely until that time (using stopped.wait for clean shutdown)
    4. Performs the rotation with retry logic
    5. On persistent failure, sets status to Degraded (manual intervention needed)

    The daemon only runs for confidential clients with secretRotation.enabled=true.
    """
    client_spec = KeycloakClientSpec.model_validate(spec)
    secret_name = f"{name}-credentials"
    k8s_client = get_kubernetes_client()
    core_api = client.CoreV1Api(k8s_client)

    logger.info(f"Secret rotation daemon started for client {name}")

    while not stopped:
        try:
            # Read the secret to get the rotated-at annotation
            try:
                secret = core_api.read_namespaced_secret(secret_name, namespace)
            except ApiException as e:
                if e.status == 404:
                    logger.info(
                        f"Secret {secret_name} not found, waiting for reconciliation to create it"
                    )
                    # Wait a bit and retry - secret may not be created yet
                    if await stopped.wait(timeout=30):
                        break
                    continue
                raise

            annotations = secret.metadata.annotations or {}
            rotated_at_str = annotations.get("keycloak-operator/rotated-at")

            if not rotated_at_str:
                logger.info(
                    f"No rotated-at annotation on secret {secret_name}, "
                    "waiting for reconciliation to set it"
                )
                # Wait for reconciliation to add the annotation
                if await stopped.wait(timeout=60):
                    break
                continue

            # Parse the rotation timestamp
            rotated_at = _parse_rotation_timestamp(rotated_at_str)
            if rotated_at is None:
                logger.warning(
                    f"Invalid rotated-at annotation '{rotated_at_str}', "
                    "waiting for reconciliation to fix it"
                )
                if await stopped.wait(timeout=60):
                    break
                continue

            # Calculate time until next rotation
            seconds_until_rotation = _calculate_seconds_until_rotation(
                client_spec, rotated_at, logger
            )

            # Update metric for next rotation timestamp
            next_rotation_timestamp = (
                datetime.now(UTC).timestamp() + seconds_until_rotation
            )
            SECRET_NEXT_ROTATION_TIMESTAMP.labels(
                namespace=namespace,
            ).set(next_rotation_timestamp)

            if seconds_until_rotation > 0:
                logger.info(
                    f"Next rotation for client {name} in {seconds_until_rotation:.0f} seconds "
                    f"({timedelta(seconds=seconds_until_rotation)})"
                )
                # Sleep until rotation time (or until stopped)
                if await stopped.wait(timeout=seconds_until_rotation):
                    break
                continue

            # Time to rotate!
            logger.info(f"Starting secret rotation for client {name}")
            rotation_start_time = time.time()

            # Get Keycloak connection details
            realm_ref = client_spec.realm_ref
            target_namespace = realm_ref.namespace or namespace

            # Get realm resource to find Keycloak instance
            custom_api = client.CustomObjectsApi(k8s_client)
            try:
                realm_resource = custom_api.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=target_namespace,
                    plural="keycloakrealms",
                    name=realm_ref.name,
                )
            except ApiException as e:
                if e.status == 404:
                    logger.error(
                        f"Realm {realm_ref.name} not found in {target_namespace}"
                    )
                    # This is a configuration error - wait and retry
                    if await stopped.wait(timeout=60):
                        break
                    continue
                raise

            realm_spec = realm_resource.get("spec", {})
            actual_realm_name = realm_spec.get("realmName", realm_ref.name)
            keycloak_ref = realm_spec.get("keycloakRef", {})
            keycloak_name = keycloak_ref.get("name")
            keycloak_namespace = keycloak_ref.get("namespace", target_namespace)

            if not keycloak_name:
                logger.error(f"Realm {realm_ref.name} has no keycloakRef")
                if await stopped.wait(timeout=60):
                    break
                continue

            # Perform rotation with retries
            rotation_success = False
            retry_count = 0

            while retry_count < ROTATION_MAX_RETRIES and not stopped:
                try:
                    admin_client = await get_keycloak_admin_client(
                        keycloak_name, keycloak_namespace
                    )
                    # Regenerate secret in Keycloak
                    new_secret = await admin_client.regenerate_client_secret(
                        client_spec.client_id,
                        actual_realm_name,
                        namespace,
                    )

                    if not new_secret:
                        raise RuntimeError(
                            f"Failed to regenerate secret for client {client_spec.client_id}"
                        )

                    # Get Keycloak instance for endpoint URL
                    keycloak_instance = validate_keycloak_reference(
                        keycloak_name, keycloak_namespace
                    )
                    if not keycloak_instance:
                        raise RuntimeError(
                            f"Keycloak instance {keycloak_name} not found or not ready"
                        )

                    # Prepare secret metadata
                    labels = None
                    new_annotations = None
                    if client_spec.secret_metadata:
                        labels = (
                            dict(client_spec.secret_metadata.labels)
                            if client_spec.secret_metadata.labels
                            else None
                        )
                        new_annotations = (
                            dict(client_spec.secret_metadata.annotations)
                            if client_spec.secret_metadata.annotations
                            else None
                        )

                    if new_annotations is None:
                        new_annotations = {}

                    # Update rotation timestamp
                    new_annotations["keycloak-operator/rotated-at"] = datetime.now(
                        UTC
                    ).isoformat()

                    # Get owner UID for ownership
                    owner_uid = meta.get("uid")

                    # Update the secret
                    create_client_secret(
                        secret_name=secret_name,
                        namespace=namespace,
                        client_id=client_spec.client_id,
                        client_secret=new_secret,
                        keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
                        realm=actual_realm_name,
                        update_existing=True,
                        labels=labels,
                        annotations=new_annotations,
                        owner_uid=owner_uid,
                        owner_name=name,
                    )

                    rotation_success = True
                    rotation_duration = time.time() - rotation_start_time

                    # Update metrics
                    SECRET_ROTATION_TOTAL.labels(
                        namespace=namespace, result="success"
                    ).inc()
                    SECRET_ROTATION_DURATION.labels(
                        namespace=namespace,
                    ).observe(rotation_duration)

                    # Update status
                    patch.status["lastSecretRotation"] = datetime.now(UTC).isoformat()
                    patch.status["phase"] = "Ready"
                    patch.status["message"] = "Secret rotated successfully"

                    logger.info(
                        f"Successfully rotated secret for client {name} "
                        f"(took {rotation_duration:.2f}s)"
                    )
                    break

                except Exception as e:
                    retry_count += 1
                    SECRET_ROTATION_RETRIES_TOTAL.labels(
                        namespace=namespace,
                    ).inc()

                    if retry_count >= ROTATION_MAX_RETRIES:
                        logger.error(
                            f"Secret rotation failed for client {name} after "
                            f"{ROTATION_MAX_RETRIES} retries: {e}"
                        )
                        break

                    backoff = _calculate_exponential_backoff(retry_count - 1)
                    logger.warning(
                        f"Rotation attempt {retry_count}/{ROTATION_MAX_RETRIES} failed "
                        f"for client {name}: {e}. Retrying in {backoff:.1f}s"
                    )

                    if await stopped.wait(timeout=backoff):
                        break

            if not rotation_success and not stopped:
                # All retries exhausted - set to Degraded
                rotation_duration = time.time() - rotation_start_time

                SECRET_ROTATION_TOTAL.labels(
                    namespace=namespace, result="failure"
                ).inc()
                SECRET_ROTATION_ERRORS_TOTAL.labels(
                    namespace=namespace,
                    error_type="max_retries_exceeded",
                ).inc()
                SECRET_ROTATION_DURATION.labels(
                    namespace=namespace,
                ).observe(rotation_duration)

                patch.status["phase"] = "Degraded"
                patch.status["message"] = (
                    f"Secret rotation failed after {ROTATION_MAX_RETRIES} retries. "
                    "Manual intervention required: delete the secret to trigger reconciliation."
                )

                logger.error(
                    f"Client {name} set to Degraded due to rotation failure. "
                    "Delete the secret to trigger reconciliation and reset the rotation timer."
                )

                # Stop the daemon - manual intervention required
                # The daemon will restart when the resource is reconciled
                break

        except Exception as e:
            logger.error(f"Unexpected error in rotation daemon for client {name}: {e}")
            SECRET_ROTATION_ERRORS_TOTAL.labels(
                namespace=namespace, error_type=type(e).__name__
            ).inc()

            # Wait before retrying the main loop
            if await stopped.wait(timeout=60):
                break

    # Clear the next rotation timestamp metric when daemon stops
    SECRET_NEXT_ROTATION_TIMESTAMP.labels(namespace=namespace).set(0)
    logger.info(f"Secret rotation daemon stopped for client {name}")
