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

import logging
from datetime import UTC, datetime
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import CLIENT_FINALIZER
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.services import KeycloakClientReconciler
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import (
    get_kubernetes_client,
)

logger = logging.getLogger(__name__)


class StatusWrapper:
    """Wrapper to make dict status compatible with StatusProtocol."""

    def __init__(self, status_dict: dict[str, Any]):
        self._status = status_dict

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._status[name] = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        return self._status.get(name)


@kopf.on.create("keycloakclients", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloakclients", group="keycloak.mdvr.nl", version="v1")
async def ensure_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Ensure KeycloakClient exists in the target Keycloak instance.

    This handler implements dynamic client provisioning across namespaces.
    It can create clients in Keycloak instances located in any namespace,
    subject to RBAC permissions.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the KeycloakClient resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        Dictionary with status information for the resource

    """
    logger.info(f"Ensuring KeycloakClient {name} in namespace {namespace}")

    # Add finalizer BEFORE creating any resources to ensure proper cleanup
    meta = kwargs.get("meta", {})
    current_finalizers = meta.get("finalizers", [])
    if CLIENT_FINALIZER not in current_finalizers:
        logger.info(f"Adding finalizer {CLIENT_FINALIZER} to KeycloakClient {name}")
        patch.metadata.setdefault("finalizers", []).append(CLIENT_FINALIZER)

    try:
        reconciler = KeycloakClientReconciler()
        status_wrapper = StatusWrapper(status)
        return await reconciler.reconcile(
            spec=spec, name=name, namespace=namespace, status=status_wrapper, **kwargs
        )
    except Exception as e:
        logger.error(f"Error in KeycloakClient reconciliation: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Reconciliation failed: {str(e)}",
            }
        )
        if "TemporaryError" in str(type(e)):
            raise kopf.TemporaryError(str(e), delay=30) from e
        elif "PermanentError" in str(type(e)):
            raise kopf.PermanentError(str(e)) from e
        else:
            raise kopf.TemporaryError(f"Client creation failed: {e}", delay=60) from e


@kopf.on.update("keycloakclients", group="keycloak.mdvr.nl", version="v1")
async def update_keycloak_client(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
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

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    logger.info(f"Updating KeycloakClient {name} in namespace {namespace}")

    # Create reconciler and delegate to service layer
    reconciler = KeycloakClientReconciler()
    status_wrapper = StatusWrapper(status)
    return await reconciler.update(
        old_spec=old.get("spec", {}),
        new_spec=new.get("spec", {}),
        diff=diff,
        name=name,
        namespace=namespace,
        status=status_wrapper,
        **kwargs,
    )


@kopf.on.delete("keycloakclients", group="keycloak.mdvr.nl", version="v1")
async def delete_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakClient deletion with proper finalizer management.

    This handler performs comprehensive cleanup of the client from Keycloak
    and any associated Kubernetes resources, removing the finalizer only
    after cleanup is complete.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
    """
    logger.info(f"Starting deletion of KeycloakClient {name} in namespace {namespace}")

    # Check if our finalizer is present
    meta = kwargs.get("meta", {})
    current_finalizers = meta.get("finalizers", [])
    if CLIENT_FINALIZER not in current_finalizers:
        logger.info(f"Finalizer {CLIENT_FINALIZER} not found, deletion already handled")
        return

    try:
        # Delegate cleanup to the reconciler service layer
        reconciler = KeycloakClientReconciler()
        status_wrapper = StatusWrapper(status)
        await reconciler.cleanup_resources(
            name=name, namespace=namespace, spec=spec, status=status_wrapper
        )

        # If cleanup succeeded, remove our finalizer to complete deletion
        logger.info(
            f"Cleanup completed successfully, removing finalizer {CLIENT_FINALIZER}"
        )
        current_finalizers = list(current_finalizers)  # Make a copy
        if CLIENT_FINALIZER in current_finalizers:
            current_finalizers.remove(CLIENT_FINALIZER)
            patch.metadata["finalizers"] = current_finalizers

        logger.info(f"Successfully deleted KeycloakClient {name}")

    except Exception as e:
        logger.error(f"Error during KeycloakClient deletion: {e}")
        # Update status to indicate deletion failure
        try:
            status["phase"] = "Failed"
            status["message"] = f"Deletion failed: {str(e)}"
        except Exception:
            pass  # Status update might fail if resource is being deleted

        # Re-raise the exception to trigger retry
        # Kopf will retry the deletion with exponential backoff
        raise kopf.TemporaryError(
            f"Failed to delete KeycloakClient {name}: {e}",
            delay=30,  # Wait 30 seconds before retry
        ) from e


@kopf.timer("keycloakclients", interval=300)  # Check every 5 minutes
def monitor_client_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Periodic health check for KeycloakClients.

    This timer verifies that clients still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed clients
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of KeycloakClient {name} in {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # Get admin client and verify connection
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # Check if client exists in Keycloak
        realm_name = client_spec.realm or "master"
        existing_client = admin_client.get_client_by_name(
            client_spec.client_id, realm_name
        )

        if not existing_client:
            logger.warning(f"Client {client_spec.client_id} missing from Keycloak")
            return {
                "phase": "Degraded",
                "message": "Client missing from Keycloak, will recreate",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

        # Verify client configuration matches spec
        # Compare current Keycloak client config with desired spec
        try:
            desired_config = client_spec.to_keycloak_config()
            config_matches = True

            # Check critical configuration fields
            if existing_client.get("enabled") != desired_config.get("enabled", True):
                config_matches = False
                logger.warning(f"Client {client_spec.client_id} enabled state mismatch")

            if existing_client.get("publicClient") != desired_config.get(
                "publicClient", False
            ):
                config_matches = False
                logger.warning(
                    f"Client {client_spec.client_id} public client setting mismatch"
                )

            # Check redirect URIs if specified
            if desired_config.get("redirectUris"):
                existing_uris = set(existing_client.get("redirectUris", []))
                desired_uris = set(desired_config.get("redirectUris", []))
                if existing_uris != desired_uris:
                    config_matches = False
                    logger.warning(
                        f"Client {client_spec.client_id} redirect URIs mismatch"
                    )

            # Check web origins if specified
            if desired_config.get("webOrigins"):
                existing_origins = set(existing_client.get("webOrigins", []))
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
                return {
                    "phase": "Degraded",
                    "message": "Configuration drift detected",
                    "lastHealthCheck": datetime.now(UTC).isoformat(),
                }

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
                        return {
                            "phase": "Degraded",
                            "message": "Client credentials secret exists but has no data",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }

                    for key in required_keys:
                        if key not in secret.data:
                            missing_keys.append(key)

                    if missing_keys:
                        return {
                            "phase": "Degraded",
                            "message": f"Client credentials secret missing keys: {', '.join(missing_keys)}",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }

                    logger.debug(f"Client credentials secret {secret_name} is valid")

                except ApiException as e:
                    if e.status == 404:
                        return {
                            "phase": "Degraded",
                            "message": "Client credentials secret missing",
                            "lastHealthCheck": datetime.now(UTC).isoformat(),
                        }
                    else:
                        logger.warning(f"Failed to check credentials secret: {e}")

            except Exception as e:
                logger.warning(f"Failed to validate credentials secret: {e}")
                # Don't fail health check for secret validation errors

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakClient {name} health check passed")
            return {
                "phase": "Ready",
                "message": "Client is healthy and properly configured",
                "lastHealthCheck": datetime.now(UTC).isoformat(),
            }

    except Exception as e:
        logger.error(f"Health check failed for KeycloakClient {name}: {e}")
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": datetime.now(UTC).isoformat(),
        }

    return None  # No status update needed
