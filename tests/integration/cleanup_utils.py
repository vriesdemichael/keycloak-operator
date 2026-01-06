"""
Robust cleanup utilities for integration tests.

This module provides defensive cleanup strategies for Kubernetes resources,
particularly for custom resources with finalizers that may become stuck.
"""

import asyncio
import logging
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


class CleanupTracker:
    """Track failed cleanups for reporting at test end."""

    def __init__(self):
        self.failed_cleanups = []

    def record_failure(self, resource_type: str, name: str, namespace: str, error: str):
        """Record a cleanup failure."""
        self.failed_cleanups.append(
            {
                "resource_type": resource_type,
                "name": name,
                "namespace": namespace,
                "error": error,
            }
        )

    def has_failures(self) -> bool:
        """Check if any cleanups failed."""
        return len(self.failed_cleanups) > 0

    def get_report(self) -> str:
        """Generate a report of failed cleanups."""
        if not self.failed_cleanups:
            return "All resources cleaned up successfully"

        lines = ["Failed to clean up the following resources:"]
        for failure in self.failed_cleanups:
            lines.append(
                f"  - {failure['resource_type']} {failure['namespace']}/{failure['name']}: {failure['error']}"
            )
        return "\n".join(lines)


async def delete_custom_resource_with_retry(
    k8s_custom_objects: client.CustomObjectsApi,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 120,
    force_after: int | None = None,
) -> bool:
    """
    Delete a custom resource with retry.

    Force-deletion (removing finalizers) is disabled by default. Finalizers
    should complete within the timeout if the operator is working correctly.
    If deletion fails, this indicates a real bug that should be investigated.

    Args:
        k8s_custom_objects: Kubernetes custom objects API client
        group: API group (e.g., 'vriesdemichael.github.io')
        version: API version (e.g., 'v1')
        namespace: Resource namespace
        plural: Resource plural name (e.g., 'keycloakrealms')
        name: Resource name
        timeout: Total timeout for deletion (seconds)
        force_after: Seconds to wait before force-deleting (removing finalizers).
                     If None (default), force-deletion is disabled.
                     Only use for emergency cleanup, not in regular test teardown.

    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        # First, try graceful deletion
        try:
            await k8s_custom_objects.delete_namespaced_custom_object(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
            logger.info(f"Initiated deletion of {plural}/{name} in {namespace}")
        except ApiException as e:
            if e.status == 404:
                logger.info(f"Resource {plural}/{name} already deleted")
                return True
            raise

        # Wait for graceful deletion
        start_time = asyncio.get_event_loop().time()
        force_delete_triggered = False

        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                resource = await k8s_custom_objects.get_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                )

                elapsed = asyncio.get_event_loop().time() - start_time

                # Log progress every 30 seconds
                if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    phase = resource.get("status", {}).get("phase", "Unknown")
                    logger.info(
                        f"Still waiting for {plural}/{name} deletion after {elapsed:.0f}s "
                        f"(phase={phase}, finalizers={finalizers})"
                    )

                # Check if we should force-delete (only if explicitly enabled)
                if (
                    force_after is not None
                    and elapsed > force_after
                    and not force_delete_triggered
                ):
                    logger.error(
                        f"FORCE DELETION triggered for {plural}/{name} after {elapsed:.0f}s. "
                        f"This indicates a finalizer bug that should be investigated!"
                    )
                    await force_remove_finalizers(
                        k8s_custom_objects,
                        group,
                        version,
                        namespace,
                        plural,
                        name,
                        resource,
                    )
                    force_delete_triggered = True

                await asyncio.sleep(2)

            except ApiException as e:
                if e.status == 404:
                    elapsed = asyncio.get_event_loop().time() - start_time
                    logger.info(
                        f"Resource {plural}/{name} deleted successfully after {elapsed:.0f}s"
                    )
                    return True
                logger.warning(f"Error checking resource deletion: {e}")
                await asyncio.sleep(2)

        # Timeout reached
        elapsed = asyncio.get_event_loop().time() - start_time
        logger.error(
            f"Timeout waiting for {plural}/{name} deletion after {elapsed:.0f}s. "
            f"This indicates a finalizer bug!"
        )
        return False

    except Exception as e:
        logger.error(f"Failed to delete {plural}/{name}: {e}")
        return False


async def force_remove_finalizers(
    k8s_custom_objects: client.CustomObjectsApi,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    resource: dict[str, Any] | None = None,
) -> bool:
    """
    Force remove finalizers from a resource.

    This is a "break glass" operation for when normal cleanup fails.

    Args:
        k8s_custom_objects: Kubernetes custom objects API client
        group: API group
        version: API version
        namespace: Resource namespace
        plural: Resource plural name
        name: Resource name
        resource: Optional existing resource object (to avoid extra GET)

    Returns:
        True if finalizers removed successfully, False otherwise
    """
    try:
        # Get current resource if not provided
        if resource is None:
            try:
                resource = await k8s_custom_objects.get_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                )
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"Resource {plural}/{name} already deleted")
                    return True
                raise

        # Check if resource has finalizers
        finalizers = resource.get("metadata", {}).get("finalizers", [])
        if not finalizers:
            logger.info(f"Resource {plural}/{name} has no finalizers")
            return True

        logger.warning(
            f"Force removing {len(finalizers)} finalizer(s) from {plural}/{name}: {finalizers}"
        )

        # Patch to remove finalizers
        patch = {"metadata": {"finalizers": []}}

        await k8s_custom_objects.patch_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
            body=patch,
        )

        logger.info(f"Successfully removed finalizers from {plural}/{name}")
        return True

    except ApiException as e:
        if e.status == 404:
            logger.info(f"Resource {plural}/{name} deleted during finalizer removal")
            return True
        logger.error(f"Failed to remove finalizers from {plural}/{name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error removing finalizers from {plural}/{name}: {e}")
        return False


async def cleanup_namespace_resources(
    k8s_custom_objects: client.CustomObjectsApi,
    namespace: str,
    timeout: int = 120,
) -> tuple[bool, list[str]]:
    """
    Clean up all Keycloak custom resources in a namespace.

    This ensures that realms and clients are deleted before namespace deletion.

    Args:
        k8s_custom_objects: Kubernetes custom objects API client
        namespace: Namespace to clean up
        timeout: Timeout for cleanup operations

    Returns:
        Tuple of (success, list of failed resources)
    """
    failed_resources = []
    resource_types = [
        ("vriesdemichael.github.io", "v1", "keycloakclients"),
        ("vriesdemichael.github.io", "v1", "keycloakrealms"),
    ]

    for group, version, plural in resource_types:
        try:
            # List all resources of this type
            resources = await k8s_custom_objects.list_namespaced_custom_object(
                group=group, version=version, namespace=namespace, plural=plural
            )

            items = resources.get("items", [])
            if not items:
                logger.info(f"No {plural} found in namespace {namespace}")
                continue

            logger.info(f"Cleaning up {len(items)} {plural} in namespace {namespace}")

            # Delete each resource
            for item in items:
                name = item["metadata"]["name"]
                success = await delete_custom_resource_with_retry(
                    k8s_custom_objects=k8s_custom_objects,
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                    timeout=timeout,
                )

                if not success:
                    failed_resources.append(f"{plural}/{name}")

        except ApiException as e:
            if e.status == 404:
                logger.info(f"Resource type {plural} not found or already cleaned up")
            else:
                logger.error(f"Error listing {plural} in {namespace}: {e}")
                failed_resources.append(f"{plural}/*")

    return len(failed_resources) == 0, failed_resources


async def force_delete_namespace(
    k8s_core_v1: client.CoreV1Api,
    namespace: str,
    timeout: int = 60,
) -> bool:
    """
    Force delete a namespace by removing its finalizers if stuck.

    Args:
        k8s_core_v1: Kubernetes core API client
        namespace: Namespace name
        timeout: Timeout for deletion

    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        # First try normal deletion
        try:
            await k8s_core_v1.delete_namespace(
                name=namespace,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
            logger.info(f"Initiated deletion of namespace {namespace}")
        except ApiException as e:
            if e.status == 404:
                logger.info(f"Namespace {namespace} already deleted")
                return True
            raise

        # Wait for deletion
        start_time = asyncio.get_event_loop().time()
        force_triggered = False

        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                ns = await k8s_core_v1.read_namespace(name=namespace)

                # Check if stuck in terminating
                elapsed = asyncio.get_event_loop().time() - start_time
                if (
                    elapsed > timeout / 2
                    and not force_triggered
                    and ns.status.phase == "Terminating"
                ):
                    logger.warning(
                        f"Namespace {namespace} stuck in Terminating, attempting force finalize"
                    )
                    # Use kubectl proxy or raw API to finalize
                    force_triggered = True

                    try:
                        logger.warning(
                            f"Force removing finalizers from namespace {namespace}"
                        )
                        # Patch the namespace to remove finalizers
                        # This is the standard way to unstick a Terminating namespace
                        patch = {"metadata": {"finalizers": []}}
                        await k8s_core_v1.patch_namespace(name=namespace, body=patch)
                        logger.info(
                            f"Successfully removed finalizers from namespace {namespace}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"Failed to remove finalizers from namespace {namespace}: {e}"
                        )

                await asyncio.sleep(2)

            except ApiException as e:
                if e.status == 404:
                    logger.info(f"Namespace {namespace} deleted successfully")
                    return True
                await asyncio.sleep(2)

        logger.error(f"Timeout waiting for namespace {namespace} deletion")
        return False

    except Exception as e:
        logger.error(f"Failed to delete namespace {namespace}: {e}")
        return False


async def ensure_clean_test_environment(
    k8s_core_v1: client.CoreV1Api,
    k8s_custom_objects: client.CustomObjectsApi,
    prefix: str = "test-",
) -> tuple[bool, str]:
    """
    Ensure the test environment is clean before running tests.

    This checks for stale test namespaces and resources from previous runs.

    Args:
        k8s_core_v1: Kubernetes core API client
        k8s_custom_objects: Kubernetes custom objects API client
        prefix: Namespace prefix for test namespaces

    Returns:
        Tuple of (is_clean, report_message)
    """
    stale_resources = []

    try:
        # Check for stale test namespaces
        namespaces = await k8s_core_v1.list_namespace()
        test_namespaces = [
            ns.metadata.name
            for ns in namespaces.items
            if ns.metadata.name.startswith(prefix)
        ]

        if test_namespaces:
            logger.warning(f"Found {len(test_namespaces)} stale test namespaces")
            stale_resources.extend([f"namespace/{ns}" for ns in test_namespaces])

        # Check for stale resources in non-test namespaces
        # (This could happen if namespace deletion failed)
        for namespace_obj in namespaces.items:
            if not namespace_obj.metadata.name.startswith(prefix):
                continue

            namespace = namespace_obj.metadata.name
            for group, version, plural in [
                ("vriesdemichael.github.io", "v1", "keycloakrealms"),
                ("vriesdemichael.github.io", "v1", "keycloakclients"),
            ]:
                try:
                    resources = await k8s_custom_objects.list_namespaced_custom_object(
                        group=group, version=version, namespace=namespace, plural=plural
                    )
                    items = resources.get("items", [])
                    if items:
                        stale_resources.extend(
                            [f"{plural}/{item['metadata']['name']}" for item in items]
                        )
                except ApiException:
                    pass

        if stale_resources:
            report = f"Found {len(stale_resources)} stale test resources:\n"
            report += "\n".join(f"  - {r}" for r in stale_resources[:10])
            if len(stale_resources) > 10:
                report += f"\n  ... and {len(stale_resources) - 10} more"
            return False, report

        return True, "Test environment is clean"

    except Exception as e:
        logger.error(f"Error checking test environment: {e}")
        return False, f"Error checking environment: {e}"
