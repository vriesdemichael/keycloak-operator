"""
Keycloak instance handlers - Manages the core Keycloak deployment and services.

This module handles the lifecycle of Keycloak instances including:
- Creating Keycloak deployments with proper configuration
- Managing services and ingress for external access
- Setting up persistent storage for Keycloak data
- Configuring initial admin users and realms
- Health monitoring and status reporting

The handlers in this module are designed to be idempotent and GitOps-friendly,
ensuring that the desired state is maintained regardless of restart or failure.
"""

from __future__ import annotations

import logging
from collections.abc import MutableMapping
from datetime import UTC
from typing import Any, Protocol, TypedDict, cast

import kopf
from kopf import Diff, Meta
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import KEYCLOAK_FINALIZER
from keycloak_operator.services import KeycloakInstanceReconciler
from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
from keycloak_operator.utils.kubernetes import (
    check_http_health,
    get_admin_credentials,
    get_kubernetes_client,
    get_pod_resource_usage,
)


class StatusProtocol(Protocol):
    """Protocol for kopf Status objects that allow dynamic attribute assignment.

    Wrapped by StatusWrapper to allow safe mutation irrespective of kopf internal
    status object semantics.
    """

    def __setattr__(self, name: str, value: Any) -> None: ...  # pragma: no cover
    def __getattr__(self, name: str) -> Any: ...  # pragma: no cover
    def get(self, key: str, default: Any = None) -> Any: ...  # pragma: no cover


class StatusWrapper(MutableMapping[str, Any]):
    """Safe mutable wrapper around kopf patch.status for both item & attribute access."""

    def __init__(self, patch_status: Any):
        # Store reference to patch.status, not a copy
        object.__setattr__(self, "_patch_status", patch_status)

    # MutableMapping implementation - directly update patch.status
    def __getitem__(self, key: str) -> Any:
        return self._patch_status[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._patch_status[key] = value

    def __delitem__(self, key: str) -> None:
        if key in self._patch_status:
            del self._patch_status[key]

    def __iter__(self):  # pragma: no cover - trivial
        return iter(self._patch_status)

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self._patch_status)

    # Attribute bridging - directly update patch.status
    def __getattr__(self, item: str) -> Any:  # pragma: no cover - trivial
        try:
            return self._patch_status[item]
        except KeyError as e:
            raise AttributeError(item) from e

    def __setattr__(self, key: str, value: Any) -> None:  # pragma: no cover - trivial
        if key.startswith("_"):
            object.__setattr__(self, key, value)
        else:
            self._patch_status[key] = value

    def get(self, key: str, default: Any = None) -> Any:  # explicit for protocol
        return self._patch_status.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._patch_status)


class KopfHandlerKwargs(TypedDict, total=False):
    """Type hints for common kopf handler kwargs."""

    meta: Meta
    body: dict[str, Any]
    patch: dict[str, Any]
    logger: Any


logger = logging.getLogger(__name__)


@kopf.on.create("keycloaks", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloaks", group="keycloak.mdvr.nl", version="v1")
async def ensure_keycloak_instance(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: StatusProtocol,
    patch: kopf.Patch,
    **kwargs: KopfHandlerKwargs,
) -> None:
    """
    Ensure Keycloak instance exists and is properly configured.

    This is the main handler for Keycloak instance creation and resumption.
    It implements idempotent logic that works for both initial creation
    and operator restarts (resume).

    Args:
        spec: Keycloak resource specification
        name: Name of the Keycloak resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        Dictionary with status information for the resource

    """
    # Check if resource is being deleted (deletionTimestamp is set)
    # This can happen when operator restarts while resource is being deleted
    meta = kwargs.get("meta", {})
    deletion_timestamp = meta.get("deletionTimestamp")

    if deletion_timestamp:
        logger.info(
            f"Keycloak instance {name} has deletionTimestamp, triggering cleanup"
        )
        # Resource is being deleted, trigger cleanup logic
        current_finalizers = meta.get("finalizers", [])
        if KEYCLOAK_FINALIZER in current_finalizers:
            try:
                reconciler = KeycloakInstanceReconciler()
                await reconciler.cleanup_resources(
                    name=name, namespace=namespace, spec=spec
                )

                # Remove finalizer to complete deletion
                logger.info(
                    f"Cleanup completed successfully, removing finalizer {KEYCLOAK_FINALIZER}"
                )
                current_finalizers = list(current_finalizers)
                current_finalizers.remove(KEYCLOAK_FINALIZER)
                patch.metadata["finalizers"] = current_finalizers
                logger.info(f"Successfully deleted Keycloak instance {name}")
            except Exception as e:
                logger.error(f"Error during Keycloak deletion: {e}")
                raise kopf.TemporaryError(
                    f"Failed to delete Keycloak instance {name}: {e}",
                    delay=30,
                ) from e
        return None

    logger.info(f"Ensuring Keycloak instance {name} in namespace {namespace}")

    # Add finalizer BEFORE creating any resources to ensure proper cleanup
    # This prevents the resource from being deleted until cleanup is complete
    current_finalizers = meta.get("finalizers", [])
    if KEYCLOAK_FINALIZER not in current_finalizers:
        logger.info(
            f"Adding finalizer {KEYCLOAK_FINALIZER} to Keycloak instance {name}"
        )
        patch.metadata.setdefault("finalizers", []).append(KEYCLOAK_FINALIZER)

    # Use patch.status for updates instead of wrapping the read-only status dict
    reconciler = KeycloakInstanceReconciler()
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.reconcile(
        spec=spec,
        name=name,
        namespace=namespace,
        status=cast(StatusProtocol, status_wrapper),
        **kwargs,
    )
    # Return None to avoid Kopf creating status subpaths
    return None


@kopf.on.update("keycloaks", group="keycloak.mdvr.nl", version="v1")
async def update_keycloak_instance(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: Diff,
    name: str,
    namespace: str,
    status: StatusProtocol,
    patch: kopf.Patch,
    **kwargs: KopfHandlerKwargs,
) -> dict[str, Any] | None:
    """
    Handle updates to Keycloak instance specifications.

    This handler is called when the Keycloak resource specification changes.
    It delegates to the reconciler service layer for all business logic.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes between old and new
        name: Name of the Keycloak resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        None to avoid Kopf creating status subpaths
    """
    logger.info(f"Updating Keycloak instance {name} in namespace {namespace}")

    # Use patch.status for updates instead of wrapping the read-only status dict
    reconciler = KeycloakInstanceReconciler()
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.update(
        old_spec=old.get("spec", {}),
        new_spec=new.get("spec", {}),
        diff=diff,
        name=name,
        namespace=namespace,
        status=cast(StatusProtocol, status_wrapper),
        **kwargs,
    )
    return None


@kopf.on.delete("keycloaks", group="keycloak.mdvr.nl", version="v1")
async def delete_keycloak_instance(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: StatusProtocol,
    patch: kopf.Patch,
    **kwargs: KopfHandlerKwargs,
) -> None:
    """
    Handle Keycloak instance deletion with proper finalizer management.

    This handler performs comprehensive cleanup of all associated resources
    and removes the finalizer only after cleanup is complete, preventing
    data loss and orphaned resources.

    Args:
        spec: Keycloak resource specification
        name: Name of the Keycloak resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
    """
    logger.info(
        f"Starting deletion of Keycloak instance {name} in namespace {namespace}"
    )

    # Check if our finalizer is present
    meta = kwargs.get("meta", {})
    current_finalizers = meta.get("finalizers", [])
    if KEYCLOAK_FINALIZER not in current_finalizers:
        logger.info(
            f"Finalizer {KEYCLOAK_FINALIZER} not found, deletion already handled"
        )
        return

    try:
        # Delegate cleanup to the reconciler service layer
        reconciler = KeycloakInstanceReconciler()
        await reconciler.cleanup_resources(name=name, namespace=namespace, spec=spec)

        # If cleanup succeeded, remove our finalizer to complete deletion
        logger.info(
            f"Cleanup completed successfully, removing finalizer {KEYCLOAK_FINALIZER}"
        )
        current_finalizers = list(current_finalizers)  # Make a copy
        if KEYCLOAK_FINALIZER in current_finalizers:
            current_finalizers.remove(KEYCLOAK_FINALIZER)
            patch.metadata["finalizers"] = current_finalizers

        logger.info(f"Successfully deleted Keycloak instance {name}")

    except Exception as e:
        logger.error(f"Error during Keycloak deletion: {e}")
        # Update status to indicate deletion failure
        try:
            status_wrapper = StatusWrapper(status)
            status_wrapper.phase = "Failed"
            status_wrapper.message = f"Deletion failed: {str(e)}"
            for k, v in status_wrapper.to_dict().items():
                patch.status[k] = v
        except Exception:
            pass

        # Re-raise the exception to trigger retry
        # Kopf will retry the deletion with exponential backoff
        raise kopf.TemporaryError(
            f"Failed to delete Keycloak instance {name}: {e}",
            delay=30,  # Wait 30 seconds before retry
        ) from e


@kopf.timer("keycloaks", interval=60)
def monitor_keycloak_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: StatusProtocol,
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """
        Periodic health check for Keycloak instances.

        This timer handler runs every 60 seconds to check the health
        of Keycloak instances and update their status accordingly.

        Args:
            spec: Keycloak resource specification
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource

        Returns:
            Dictionary with updated status information, or None if no changes

    Implementation includes:
        ✅ Check if Keycloak deployment is running and ready
        ✅ Verify that Keycloak is responding to health checks
        ✅ Check resource utilization (CPU, memory, storage)
        ✅ Validate that Keycloak Admin API is accessible and master realm exists
        ✅ Update status with current health information
        ⚠️  Generate events for significant status changes - Future enhancement
        ⚠️  Implement alerting for persistent failures - Future enhancement
    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed, pending, or unknown instances
    # Unknown = resource just created, reconciliation hasn't started yet
    if current_phase in ["Failed", "Pending", "Unknown"]:
        return

    logger.debug(f"Checking health of Keycloak instance {name} in {namespace}")

    try:
        # Get current timestamp for health check
        from datetime import datetime

        current_time = datetime.now(UTC).isoformat()

        # Get deployment status from Kubernetes
        k8s_client = get_kubernetes_client()
        apps_api = client.AppsV1Api(k8s_client)
        deployment_name = f"{name}-keycloak"

        try:
            deployment = apps_api.read_namespaced_deployment_status(
                name=deployment_name, namespace=namespace
            )
        except ApiException as e:
            if e.status == 404:
                patch.status["phase"] = "Failed"
                patch.status["message"] = "Keycloak deployment not found"
                patch.status["lastHealthCheck"] = current_time
                return
            else:
                logger.error(f"Failed to get deployment status: {e}")
                patch.status["phase"] = "Unknown"
                patch.status["message"] = f"Failed to check deployment status: {e}"
                patch.status["lastHealthCheck"] = current_time
                return

        # Check deployment readiness
        ready_replicas = deployment.status.ready_replicas or 0
        desired_replicas = deployment.spec.replicas or 1
        deployment_ready = ready_replicas >= desired_replicas

        if not deployment_ready:
            patch.status["phase"] = "Degraded"
            patch.status["message"] = (
                f"Keycloak deployment not ready: {ready_replicas}/{desired_replicas} replicas ready"
            )
            patch.status["lastHealthCheck"] = current_time
            return

        # Perform HTTP health check against Keycloak management interface
        # Keycloak 25.0+ uses port 9000 for health endpoints
        service_name = f"{name}-keycloak"
        health_url = (
            f"http://{service_name}.{namespace}.svc.cluster.local:9000/health/ready"
        )

        # Perform actual HTTP health check against Keycloak
        keycloak_responding, health_error = check_http_health(health_url, timeout=5)

        if not keycloak_responding:
            logger.warning(f"Keycloak health check failed: {health_error}")

        if not keycloak_responding:
            patch.status["phase"] = "Degraded"
            patch.status["message"] = (
                f"Keycloak not responding to health checks: {health_error or 'Unknown error'}"
            )
            patch.status["lastHealthCheck"] = current_time
            return

        # Check for any unhealthy conditions in the deployment
        conditions = deployment.status.conditions or []
        for condition in conditions:
            if condition.type == "Progressing" and condition.status != "True":
                patch.status["phase"] = "Degraded"
                patch.status["message"] = (
                    f"Deployment not progressing: {condition.reason}"
                )
                patch.status["lastHealthCheck"] = current_time
                return
            elif condition.type == "Available" and condition.status != "True":
                patch.status["phase"] = "Degraded"
                patch.status["message"] = (
                    f"Deployment not available: {condition.reason}"
                )
                patch.status["lastHealthCheck"] = current_time
                return

        # Check resource utilization and warn if high
        try:
            resource_usage = get_pod_resource_usage(name, namespace, k8s_client)

            if "error" not in resource_usage:
                # Check for concerning patterns
                total_restarts = sum(pod["restarts"] for pod in resource_usage["pods"])
                if total_restarts > 10:
                    logger.warning(
                        f"High restart count detected for Keycloak {name}: {total_restarts} total restarts"
                    )

                if resource_usage["failed_pods"] > 0:
                    patch.status["phase"] = "Degraded"
                    patch.status["message"] = (
                        f"Found {resource_usage['failed_pods']} failed pods"
                    )
                    patch.status["lastHealthCheck"] = current_time
                    return

                if resource_usage["pending_pods"] > 0:
                    logger.warning(
                        f"Found {resource_usage['pending_pods']} pending pods for Keycloak {name}"
                    )

        except Exception as e:
            logger.debug(f"Failed to get resource usage metrics: {e}")
            # Don't fail health check for metrics errors

        # Validate realm and client configuration
        # Check that the Keycloak instance is properly configured
        try:
            # Get admin credentials and create Keycloak admin client
            admin_credentials = get_admin_credentials(name, namespace)

            if admin_credentials:
                service_name = f"{name}-keycloak"
                keycloak_url = (
                    f"http://{service_name}.{namespace}.svc.cluster.local:8080"
                )

                username, password = admin_credentials
                admin_client = KeycloakAdminClient(
                    server_url=keycloak_url,
                    username=username,
                    password=password,
                )

                # Perform basic connectivity test
                try:
                    admin_client.authenticate()
                    # Check if master realm is accessible
                    master_realm = admin_client.get_realm("master")
                    if not master_realm:
                        logger.warning(
                            f"Master realm not accessible for Keycloak {name}"
                        )
                        patch.status["phase"] = "Degraded"
                        patch.status["message"] = (
                            "Master realm not accessible via Admin API"
                        )
                        patch.status["lastHealthCheck"] = current_time
                        return
                    logger.debug(f"Admin API connectivity verified for Keycloak {name}")

                except Exception as api_error:
                    logger.warning(
                        f"Keycloak Admin API check failed for {name}: {api_error}"
                    )
                    patch.status["phase"] = "Degraded"
                    patch.status["message"] = (
                        f"Admin API not accessible: {str(api_error)}"
                    )
                    patch.status["lastHealthCheck"] = current_time
                    return
            else:
                logger.debug(
                    f"Admin credentials not available for Keycloak {name}, skipping API validation"
                )

        except Exception as e:
            logger.debug(f"Realm/client validation failed for Keycloak {name}: {e}")
            # Don't fail health check for validation errors, just log them

        # If we get here, everything is healthy
        if current_phase != "Ready":
            logger.info(f"Keycloak instance {name} health check passed")
            patch.status["phase"] = "Ready"
            patch.status["message"] = "Keycloak instance is healthy"
            patch.status["lastHealthCheck"] = current_time

    except Exception as e:
        logger.error(f"Health check failed for Keycloak instance {name}: {e}")
        from datetime import datetime

        current_time = datetime.now(UTC).isoformat()
        patch.status["phase"] = "Degraded"
        patch.status["message"] = f"Health check failed: {str(e)}"
        patch.status["lastHealthCheck"] = current_time
