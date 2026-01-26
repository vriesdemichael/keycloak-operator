"""Consolidated wait helpers for integration tests with automatic debugging.

This module provides a unified wait helper that:
- Waits for Kubernetes resources to reach expected state
- Automatically collects operator logs when waits timeout
- Automatically collects k8s events for the resource
- Raises informative exceptions with debugging context
- Tracks deletion state with detailed diagnostics (DeletionState)
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import tempfile
from collections.abc import Callable
from typing import Any

from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


class ResourceNotReadyError(Exception):
    """Raised when a resource doesn't reach the expected state within timeout."""

    pass


async def _collect_operator_logs(
    operator_namespace: str, tail_lines: int = 100
) -> tuple[str, str | None]:
    """Collect recent operator logs for debugging.

    Returns:
        Tuple of (summary, log_file_path)
        - summary: Short summary for inline display
        - log_file_path: Path to temp file with full logs, or None if collection failed
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "logs",
                "-n",
                operator_namespace,
                "-l",
                "app.kubernetes.io/name=keycloak-operator",
                "--tail",
                str(tail_lines),
                "--prefix",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            # Write full logs to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".log", prefix="operator-logs-", delete=False
            ) as log_file:
                log_file.write(result.stdout)
                log_path = log_file.name

            # Get last 5 lines for summary
            lines = result.stdout.strip().split("\n")
            last_lines = lines[-5:] if len(lines) > 5 else lines
            summary = "\n".join(last_lines)

            return summary, log_path
        return f"Failed to collect logs: {result.stderr[:200]}", None
    except Exception as e:
        return f"Error collecting operator logs: {e}", None


async def _collect_resource_events(
    namespace: str, resource_name: str, resource_kind: str
) -> tuple[str, str | None]:
    """Collect k8s events related to a specific resource.

    Returns:
        Tuple of (summary, event_file_path)
        - summary: Event summary for inline display
        - event_file_path: Path to temp file with full events, or None if collection failed
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "get",
                "events",
                "-n",
                namespace,
                "--field-selector",
                f"involvedObject.name={resource_name},involvedObject.kind={resource_kind}",
                "--sort-by",
                ".lastTimestamp",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            # Write full events to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix=f"events-{resource_name}-", delete=False
            ) as event_file:
                event_file.write(result.stdout)
                event_path = event_file.name

            # Get last 3 events for summary
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:  # Skip header
                event_lines = lines[-3:] if len(lines) > 4 else lines[1:]
                summary = "\n".join(event_lines)
            else:
                summary = "No events found"

            return summary, event_path
        return "No events found", None
    except Exception as e:
        return f"Error collecting events: {e}", None


async def _get_resource_status(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
) -> dict[str, Any] | None:
    """Get the status section of a custom resource."""
    try:
        resource = await k8s_custom_objects.get_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
        )
        return resource.get("status", {}) or {}
    except ApiException:
        return None


async def wait_for_resource_condition(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    condition_func: Callable[[dict[str, Any]], bool],
    timeout: int = 120,
    interval: int = 3,
    operator_namespace: str | None = None,
    expected_phases: tuple[str, ...] = ("Ready", "Degraded"),
) -> dict[str, Any]:
    """Wait for a custom resource to meet a condition, with automatic debugging.

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group (e.g., "vriesdemichael.github.io")
        version: API version (e.g., "v1")
        namespace: Resource namespace
        plural: Resource plural name (e.g., "keycloakrealms")
        name: Resource name
        condition_func: Function that takes resource dict and returns True when condition is met
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        operator_namespace: Namespace where operator is running (for log collection)
        expected_phases: Tuple of expected phase values for error messages

    Returns:
        The resource dict when condition is met

    Raises:
        ResourceNotReadyError: When timeout is reached, includes debugging info
    """
    import time

    start_time = time.time()
    last_status = None
    last_resource = None
    last_exception = None

    while time.time() - start_time < timeout:
        try:
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
            )

            last_resource = resource
            last_status = resource.get("status", {}) or {}

            if condition_func(resource):
                return resource

        except ApiException as exc:
            if exc.status != 404:
                # Unexpected error - save it and continue, will report if timeout
                last_exception = exc
            # Resource doesn't exist yet (404), keep waiting

        await asyncio.sleep(interval)

    # Timeout reached - collect debugging info before raising
    logger.error(
        f"Resource {plural}/{name} in namespace {namespace} did not meet condition within {timeout}s"
    )

    debug_info = []
    debug_files = []

    # Resource status
    if last_status:
        debug_info.append(f"Last status: {last_status}")
    elif last_resource:
        debug_info.append(
            f"Resource exists but has no status: {last_resource.get('metadata', {}).get('name')}"
        )
    else:
        debug_info.append("Resource not found (404)")

    # Last exception if any
    if last_exception:
        debug_info.append(f"\nLast error: {last_exception}")

    # K8s events
    resource_kind = plural.rstrip("s").title()  # Simple conversion
    try:
        event_summary, event_file = await _collect_resource_events(
            namespace, name, resource_kind
        )
        debug_info.append(f"\nRecent Events:\n{event_summary}")
        if event_file:
            debug_files.append(f"Full events: {event_file}")
    except Exception as e:
        debug_info.append(f"\nFailed to collect events: {e}")

    # Operator logs if namespace provided
    if operator_namespace:
        try:
            log_summary, log_file = await _collect_operator_logs(
                operator_namespace, tail_lines=100
            )
            debug_info.append(f"\nOperator Logs (last 5 lines):\n{log_summary}")
            if log_file:
                debug_files.append(f"Full operator logs: {log_file}")
        except Exception as e:
            debug_info.append(f"\nFailed to collect operator logs: {e}")

    # Build error message
    error_parts = [
        f"Resource {plural}/{name} did not reach expected state ({', '.join(expected_phases)}) within {timeout}s.",
        "",
        *debug_info,
    ]

    if debug_files:
        error_parts.append("\n" + "=" * 70)
        error_parts.append("Debugging files (full logs/events):")
        error_parts.extend(debug_files)
        error_parts.append("=" * 70)

    error_message = "\n".join(error_parts)

    raise ResourceNotReadyError(error_message)


async def wait_for_resource_ready(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 120,
    interval: int = 3,
    operator_namespace: str | None = None,
    allow_degraded: bool = True,
) -> dict[str, Any]:
    """Wait for a custom resource to reach Ready (or optionally Degraded) phase.

    Convenience wrapper around wait_for_resource_condition for the common case
    of waiting for phase=Ready.

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group (e.g., "vriesdemichael.github.io")
        version: API version (e.g., "v1")
        namespace: Resource namespace
        plural: Resource plural name (e.g., "keycloakrealms")
        name: Resource name
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        operator_namespace: Namespace where operator is running (for log collection)
        allow_degraded: Whether to accept "Degraded" phase as ready

    Returns:
        The resource dict when ready

    Raises:
        ResourceNotReadyError: When timeout is reached, includes debugging info
    """
    expected_phases = ("Ready", "Degraded") if allow_degraded else ("Ready",)

    def _condition(resource: dict[str, Any]) -> bool:
        status = resource.get("status", {}) or {}
        phase = status.get("phase")
        return phase in expected_phases

    return await wait_for_resource_condition(
        k8s_custom_objects=k8s_custom_objects,
        group=group,
        version=version,
        namespace=namespace,
        plural=plural,
        name=name,
        condition_func=_condition,
        timeout=timeout,
        interval=interval,
        operator_namespace=operator_namespace,
        expected_phases=expected_phases,
    )


async def wait_for_resource_failed(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 120,
    interval: int = 3,
    operator_namespace: str | None = None,
) -> dict[str, Any]:
    """Wait for a custom resource to reach Failed phase.

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group (e.g., "vriesdemichael.github.io")
        version: API version (e.g., "v1")
        namespace: Resource namespace
        plural: Resource plural name (e.g., "keycloakrealms")
        name: Resource name
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        operator_namespace: Namespace where operator is running (for log collection)

    Returns:
        The resource dict when failed

    Raises:
        ResourceNotReadyError: When timeout is reached, includes debugging info
    """

    def _condition(resource: dict[str, Any]) -> bool:
        status = resource.get("status", {}) or {}
        phase = status.get("phase")
        return phase == "Failed"

    return await wait_for_resource_condition(
        k8s_custom_objects=k8s_custom_objects,
        group=group,
        version=version,
        namespace=namespace,
        plural=plural,
        name=name,
        condition_func=_condition,
        timeout=timeout,
        interval=interval,
        operator_namespace=operator_namespace,
        expected_phases=("Failed",),
    )


class DeletionState:
    """Represents the state of a resource deletion."""

    NOT_TRIGGERED = "not_triggered"  # No deletionTimestamp set
    BLOCKED_BY_FINALIZER = "blocked_by_finalizer"  # Has deletionTimestamp but blocked
    DELETED = "deleted"  # Resource is gone (404)

    def __init__(
        self,
        state: str,
        finalizers: list[str] | None = None,
        deletion_timestamp: str | None = None,
    ):
        self.state = state
        self.finalizers = finalizers or []
        self.deletion_timestamp = deletion_timestamp

    def __str__(self) -> str:
        if self.state == self.NOT_TRIGGERED:
            return "Deletion not triggered (no deletionTimestamp)"
        elif self.state == self.BLOCKED_BY_FINALIZER:
            finalizer_list = ", ".join(self.finalizers) if self.finalizers else "none"
            return (
                f"Deletion blocked by finalizer(s): [{finalizer_list}] "
                f"(deletionTimestamp: {self.deletion_timestamp})"
            )
        else:
            return "Resource deleted successfully"


async def get_deletion_state(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
) -> DeletionState:
    """Check the deletion state of a resource.

    Returns:
        DeletionState indicating whether deletion was triggered and if it's blocked.
    """
    try:
        resource = await k8s_custom_objects.get_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
        )
        metadata = resource.get("metadata", {})
        deletion_timestamp = metadata.get("deletionTimestamp")
        finalizers = metadata.get("finalizers", [])

        if deletion_timestamp:
            return DeletionState(
                state=DeletionState.BLOCKED_BY_FINALIZER,
                finalizers=finalizers,
                deletion_timestamp=deletion_timestamp,
            )
        else:
            return DeletionState(state=DeletionState.NOT_TRIGGERED)

    except ApiException as exc:
        if exc.status == 404:
            return DeletionState(state=DeletionState.DELETED)
        raise


async def wait_for_resource_deleted(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 120,
    interval: int = 3,
    operator_namespace: str | None = None,
) -> None:
    """Wait for a custom resource to be deleted.

    This function provides detailed state tracking:
    - Verifies deletionTimestamp is set (deletion was triggered)
    - Tracks which finalizers are blocking deletion
    - Collects operator logs on timeout for debugging

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group (e.g., "vriesdemichael.github.io")
        version: API version (e.g., "v1")
        namespace: Resource namespace
        plural: Resource plural name (e.g., "keycloakrealms")
        name: Resource name
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        operator_namespace: Namespace where operator is running (for log collection)

    Raises:
        ResourceNotReadyError: When timeout is reached, includes detailed state info
    """
    import time

    start_time = time.time()
    last_state: DeletionState | None = None
    deletion_triggered = False

    while time.time() - start_time < timeout:
        state = await get_deletion_state(
            k8s_custom_objects, group, version, namespace, plural, name
        )
        last_state = state

        if state.state == DeletionState.DELETED:
            logger.debug(f"Resource {plural}/{name} deleted successfully")
            return

        if state.state == DeletionState.BLOCKED_BY_FINALIZER and not deletion_triggered:
            deletion_triggered = True
            logger.debug(
                f"Deletion triggered for {plural}/{name}, "
                f"waiting for finalizers: {state.finalizers}"
            )

        await asyncio.sleep(interval)

    # Timeout reached - build detailed error message
    debug_info = []

    if last_state:
        debug_info.append(f"Final state: {last_state}")

        if last_state.state == DeletionState.NOT_TRIGGERED:
            debug_info.append(
                "ERROR: Deletion was never triggered! "
                "The delete API call may have failed silently."
            )
        elif last_state.state == DeletionState.BLOCKED_BY_FINALIZER:
            debug_info.append(
                f"Deletion is blocked by {len(last_state.finalizers)} finalizer(s):"
            )
            for finalizer in last_state.finalizers:
                debug_info.append(f"  - {finalizer}")
            debug_info.append(
                "The operator's delete handler may not be running or may be stuck."
            )

    debug_files = []

    # Collect operator logs if namespace provided
    if operator_namespace:
        try:
            log_summary, log_file = await _collect_operator_logs(
                operator_namespace, tail_lines=200
            )
            debug_info.append(f"\nOperator Logs (last 5 lines):\n{log_summary}")
            if log_file:
                debug_files.append(f"Full operator logs: {log_file}")
        except Exception as e:
            debug_info.append(f"\nFailed to collect operator logs: {e}")

    # Build error message
    error_parts = [
        f"Resource {plural}/{name} was not deleted within {timeout}s.",
        "",
        *debug_info,
    ]

    if debug_files:
        error_parts.append("\n" + "=" * 70)
        error_parts.append("Debugging files (full logs):")
        error_parts.extend(debug_files)
        error_parts.append("=" * 70)

    error_message = "\n".join(error_parts)

    raise ResourceNotReadyError(error_message)


async def wait_for_reconciliation_complete(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    min_generation: int | None = None,
    timeout: int = 120,
    interval: int = 3,
    operator_namespace: str | None = None,
) -> dict[str, Any]:
    """Wait for a resource to complete reconciliation after an update.

    This function waits for:
    1. status.observedGeneration >= min_generation (or metadata.generation if not provided)
    2. status.phase to be "Ready" or "Degraded"

    This is more robust than wait_for_resource_ready when you need to ensure
    a new reconciliation cycle has completed after patching a resource.

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group (e.g., "vriesdemichael.github.io")
        version: API version (e.g., "v1")
        namespace: Resource namespace
        plural: Resource plural name (e.g., "keycloakrealms")
        name: Resource name
        min_generation: Minimum generation to wait for. If None, uses current
                        metadata.generation from the resource.
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        operator_namespace: Namespace where operator is running (for log collection)

    Returns:
        The resource dict when reconciliation is complete

    Raises:
        ResourceNotReadyError: When timeout is reached, includes debugging info
    """

    def _condition(resource: dict[str, Any]) -> bool:
        metadata = resource.get("metadata", {})
        status = resource.get("status", {}) or {}
        generation = metadata.get("generation", 0)
        observed_generation = status.get("observedGeneration", 0)
        phase = status.get("phase")

        # If min_generation is provided, use it; otherwise use current generation
        target_generation = min_generation if min_generation is not None else generation

        # Must have processed at least the target generation AND be in a ready state
        return observed_generation >= target_generation and phase in (
            "Ready",
            "Degraded",
        )

    return await wait_for_resource_condition(
        k8s_custom_objects=k8s_custom_objects,
        group=group,
        version=version,
        namespace=namespace,
        plural=plural,
        name=name,
        condition_func=_condition,
        timeout=timeout,
        interval=interval,
        operator_namespace=operator_namespace,
        expected_phases=("Ready", "Degraded"),
    )


class KeycloakResourceNotFoundError(Exception):
    """Raised when a Keycloak resource is not found (expected state for deletion waits)."""

    pass


class KeycloakResourceTimeoutError(Exception):
    """Raised when waiting for a Keycloak resource state times out."""

    pass


async def wait_for_keycloak_resource_deleted(
    keycloak_admin_client,
    resource_type: str,
    resource_name: str,
    realm_name: str,
    namespace: str,
    timeout: int = 60,
    interval: float = 1.0,
) -> None:
    """Wait for a Keycloak resource (client, realm, etc.) to be deleted.

    Polls the Keycloak API until the resource no longer exists.

    Args:
        keycloak_admin_client: KeycloakAdminClient instance
        resource_type: Type of resource ("client", "realm", "identity_provider")
        resource_name: Name/ID of the resource (client_id for clients, realm name for realms)
        realm_name: Realm name (ignored for realm resource type)
        namespace: Kubernetes namespace for admin client
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Raises:
        KeycloakResourceTimeoutError: When timeout is reached and resource still exists
    """
    import time

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            if resource_type == "realm":
                resource = await keycloak_admin_client.get_realm(
                    resource_name, namespace
                )
            elif resource_type == "client":
                resource = await keycloak_admin_client.get_client_by_name(
                    resource_name, realm_name, namespace
                )
            elif resource_type == "identity_provider":
                idps = await keycloak_admin_client.get_identity_providers(
                    realm_name, namespace
                )
                resource = next((i for i in idps if i.alias == resource_name), None)
            else:
                raise ValueError(f"Unknown resource type: {resource_type}")

            if resource is None:
                logger.debug(
                    f"Keycloak {resource_type} '{resource_name}' deleted successfully"
                )
                return

        except Exception as e:
            # If we get an error that indicates resource not found, treat as success
            if "not found" in str(e).lower() or "404" in str(e):
                logger.debug(
                    f"Keycloak {resource_type} '{resource_name}' deleted (got {e})"
                )
                return
            # Log but continue polling for other errors
            logger.debug(f"Error checking {resource_type} '{resource_name}': {e}")

        await asyncio.sleep(interval)

    raise KeycloakResourceTimeoutError(
        f"Keycloak {resource_type} '{resource_name}' was not deleted within {timeout}s"
    )


async def wait_for_keycloak_client_state(
    keycloak_admin_client,
    client_name: str,
    realm_name: str,
    namespace: str,
    condition_func: Callable[[Any], bool],
    condition_description: str,
    timeout: int = 60,
    interval: float = 1.0,
) -> Any:
    """Wait for a Keycloak client to reach a specific state.

    Polls the Keycloak API until the client matches the condition.

    Args:
        keycloak_admin_client: KeycloakAdminClient instance
        client_name: Client ID (name) in Keycloak
        realm_name: Realm name
        namespace: Kubernetes namespace for admin client
        condition_func: Function that takes client object and returns True when condition met
        condition_description: Human-readable description of the expected state
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        The client object when condition is met

    Raises:
        KeycloakResourceTimeoutError: When timeout is reached
    """
    import time

    start_time = time.time()
    last_client = None

    while time.time() - start_time < timeout:
        try:
            client = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            last_client = client

            if client is not None and condition_func(client):
                logger.debug(
                    f"Keycloak client '{client_name}' reached state: {condition_description}"
                )
                return client

        except Exception as e:
            logger.debug(f"Error checking client '{client_name}': {e}")

        await asyncio.sleep(interval)

    last_state = "not found" if last_client is None else str(last_client)
    raise KeycloakResourceTimeoutError(
        f"Keycloak client '{client_name}' did not reach state '{condition_description}' "
        f"within {timeout}s. Last state: {last_state}"
    )


async def wait_for_keycloak_realm_state(
    keycloak_admin_client,
    realm_name: str,
    namespace: str,
    condition_func: Callable[[Any], bool],
    condition_description: str,
    timeout: int = 60,
    interval: float = 1.0,
) -> Any:
    """Wait for a Keycloak realm to reach a specific state.

    Polls the Keycloak API until the realm matches the condition.

    Args:
        keycloak_admin_client: KeycloakAdminClient instance
        realm_name: Realm name
        namespace: Kubernetes namespace for admin client
        condition_func: Function that takes realm object and returns True when condition met
        condition_description: Human-readable description of the expected state
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        The realm object when condition is met

    Raises:
        KeycloakResourceTimeoutError: When timeout is reached
    """
    import time

    start_time = time.time()
    last_realm = None

    while time.time() - start_time < timeout:
        try:
            realm = await keycloak_admin_client.get_realm(realm_name, namespace)
            last_realm = realm

            if realm is not None and condition_func(realm):
                logger.debug(
                    f"Keycloak realm '{realm_name}' reached state: {condition_description}"
                )
                return realm

        except Exception as e:
            logger.debug(f"Error checking realm '{realm_name}': {e}")

        await asyncio.sleep(interval)

    last_state = "not found" if last_realm is None else str(last_realm)
    raise KeycloakResourceTimeoutError(
        f"Keycloak realm '{realm_name}' did not reach state '{condition_description}' "
        f"within {timeout}s. Last state: {last_state}"
    )


async def wait_for_port_forward_ready(
    local_port: int,
    timeout: int = 30,
    interval: float = 0.5,
) -> None:
    """Wait for a port-forward to become ready by testing TCP connectivity.

    Args:
        local_port: Local port that should be forwarded
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Raises:
        TimeoutError: When timeout is reached and port is still not accessible
    """
    import socket
    import time

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex(("127.0.0.1", local_port))
            sock.close()
            if result == 0:
                logger.debug(f"Port-forward ready on port {local_port}")
                return
        except Exception:
            pass

        await asyncio.sleep(interval)

    raise TimeoutError(
        f"Port-forward to localhost:{local_port} did not become ready within {timeout}s"
    )


async def wait_for_cr_phase_change(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    from_phase: str = "Unknown",
    timeout: int = 60,
    interval: float = 2.0,
) -> dict[str, Any]:
    """Wait for a CR to transition from a specific phase to any other phase.

    This is useful for waiting until reconciliation starts processing a resource.

    Args:
        k8s_custom_objects: Kubernetes CustomObjectsApi client
        group: API group
        version: API version
        namespace: Resource namespace
        plural: Resource plural name
        name: Resource name
        from_phase: The phase to transition FROM (default "Unknown")
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        The resource dict when phase has changed

    Raises:
        ResourceNotReadyError: When timeout is reached
    """
    import time

    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
            )
            status = resource.get("status", {}) or {}
            phase = status.get("phase", "Unknown")

            if phase != from_phase:
                logger.debug(
                    f"Resource {plural}/{name} transitioned from {from_phase} to {phase}"
                )
                return resource

        except ApiException as e:
            if e.status != 404:
                logger.debug(f"Error checking resource {plural}/{name}: {e}")

        await asyncio.sleep(interval)

    raise ResourceNotReadyError(
        f"Resource {plural}/{name} did not transition from phase '{from_phase}' "
        f"within {timeout}s"
    )
