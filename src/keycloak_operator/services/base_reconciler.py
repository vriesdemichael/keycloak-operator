"""
Base reconciler class providing common patterns for resource reconciliation.

This module defines the BaseReconciler class that implements standard
patterns for status management, error handling, and retry logic.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Protocol

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import (
    KubernetesAPIError,
    OperatorError,
    TemporaryError,
)
from ..observability.logging import OperatorLogger


class StatusProtocol(Protocol):
    """Protocol for kopf Status objects that allow dynamic attribute assignment."""

    def __setattr__(self, name: str, value: Any) -> None: ...
    def __getattr__(self, name: str) -> Any: ...


class BaseReconciler(ABC):
    """
    Base class for all resource reconcilers.

    Provides common patterns for:
    - Status management with conditions
    - Error handling and retry logic
    - Kubernetes client management
    - Reconciliation lifecycle hooks
    """

    def __init__(self, k8s_client: client.ApiClient | None = None):
        """
        Initialize base reconciler.

        Args:
            k8s_client: Kubernetes API client, will be created if not provided
        """
        self.k8s_client = k8s_client
        self.logger = OperatorLogger(self.__class__.__name__)

    @property
    def kubernetes_client(self) -> client.ApiClient:
        """Get or create Kubernetes API client."""
        if self.k8s_client is None:
            from ..utils.kubernetes import get_kubernetes_client

            self.k8s_client = get_kubernetes_client()
        return self.k8s_client

    async def reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Main reconciliation entry point with metrics tracking.

        Args:
            spec: Resource specification
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource
        """
        from ..observability.metrics import metrics_collector

        # Determine resource type from class name
        resource_type = self.__class__.__name__.replace("Reconciler", "").lower()
        start_time = time.time()

        # Start reconciliation with correlation ID tracking
        self.logger.log_reconciliation_start(
            resource_type=resource_type, resource_name=name, namespace=namespace
        )

        # Use metrics context manager to track reconciliation
        # Extract generation from metadata for ObservedGeneration tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        async with metrics_collector.track_reconciliation(
            resource_type=resource_type,
            namespace=namespace,
            name=name,
            operation="reconcile",
        ):
            try:
                # Update status to indicate reconciliation started
                self.update_status_reconciling(
                    status, "Starting reconciliation", generation
                )

                # Perform the actual reconciliation
                result = await self.do_reconcile(
                    spec, name, namespace, status, **kwargs
                )

                # Update status to indicate success
                self.update_status_ready(
                    status, "Reconciliation completed successfully", generation
                )

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Ready"
                )

                # Log successful completion with duration
                duration = time.time() - start_time
                self.logger.log_reconciliation_success(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    duration=duration,
                )

                return result

            except OperatorError as e:
                duration = time.time() - start_time
                self.logger.log_reconciliation_error(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    error=e,
                    duration=duration,
                )
                self.update_status_failed(status, str(e), generation)

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Failed"
                )

                raise e.as_kopf_error() from e

            except ApiException as e:
                http_status = getattr(e, "status", None)
                error = KubernetesAPIError(
                    message=str(e),
                    reason=getattr(e, "reason", None),
                    retryable=http_status is not None
                    and http_status >= 500,  # 5xx errors are retryable
                )
                duration = time.time() - start_time
                self.logger.log_reconciliation_error(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    error=error,
                    duration=duration,
                )
                self.update_status_failed(status, str(error))

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Failed"
                )

                raise error.as_kopf_error() from e

            except Exception as e:
                # Wrap unexpected errors as temporary to allow retry
                error = TemporaryError(
                    f"Unexpected error during reconciliation: {str(e)}"
                )
                duration = time.time() - start_time
                self.logger.log_reconciliation_error(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    error=error,
                    duration=duration,
                )
                self.update_status_failed(status, str(error))

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Failed"
                )

                raise error.as_kopf_error() from e

    async def update(
        self,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        diff: Any,
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any] | None:
        """
        Main update entry point with metrics tracking and standardized flow.

        Args:
            old_spec: Previous resource specification
            new_spec: New resource specification
            diff: List of changes between old and new
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource, or None if no changes needed
        """
        from ..observability.metrics import metrics_collector

        resource_type = self.__class__.__name__.replace("Reconciler", "").lower()
        start_time = time.time()

        # Start correlation ID for this operation
        _correlation_id = self.logger.log_reconciliation_start(
            resource_type=resource_type,
            resource_name=name,
            namespace=namespace,
        )

        # Extract generation from metadata for ObservedGeneration tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        async with metrics_collector.track_reconciliation(
            resource_type=resource_type,
            namespace=namespace,
            name=name,
            operation="update",
        ):
            try:
                # Update status to indicate update started
                self.update_status_reconciling(
                    status, "Processing configuration changes", generation
                )

                # Perform the actual update
                result = await self.do_update(
                    old_spec, new_spec, diff, name, namespace, status, **kwargs
                )

                # Update status to indicate success
                self.update_status_ready(
                    status, "Update completed successfully", generation
                )

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Ready"
                )

                # Log successful completion with duration
                duration = time.time() - start_time
                self.logger.log_reconciliation_success(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    duration=duration,
                )

                return result

            except OperatorError as e:
                duration = time.time() - start_time
                self.logger.log_reconciliation_error(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    error=e,
                    duration=duration,
                )
                self.update_status_failed(status, str(e), generation)

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Failed"
                )

                raise e.as_kopf_error() from e

            except Exception as e:
                # Wrap unexpected errors as temporary to allow retry
                error = TemporaryError(f"Unexpected error during update: {str(e)}")
                duration = time.time() - start_time
                self.logger.log_reconciliation_error(
                    resource_type=resource_type,
                    resource_name=name,
                    namespace=namespace,
                    error=error,
                    duration=duration,
                )
                self.update_status_failed(status, str(error))

                # Update resource status metrics
                metrics_collector.update_resource_status(
                    resource_type=resource_type, namespace=namespace, phase="Failed"
                )

                raise error.as_kopf_error() from e

    @abstractmethod
    async def do_reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Perform the actual reconciliation logic.

        This method must be implemented by subclasses to provide
        resource-specific reconciliation logic.

        Args:
            spec: Resource specification
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource
        """
        raise NotImplementedError("Subclasses must implement do_reconcile method")

    async def do_update(
        self,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        diff: Any,
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any] | None:
        """
        Perform the actual update logic.

        Default implementation delegates to reconcile with new spec.
        Subclasses can override for more efficient update handling.

        Args:
            old_spec: Previous resource specification
            new_spec: New resource specification
            diff: List of changes between old and new
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource, or None if no changes needed
        """
        # Default implementation: just reconcile with the new spec
        return await self.do_reconcile(new_spec, name, namespace, status, **kwargs)

    async def reconcile_with_retry(
        self,
        operation_name: str,
        operation_func,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        initial_delay: float = 1.0,
    ):
        """
        Execute an operation with exponential backoff retry.

        Args:
            operation_name: Description of the operation for logging
            operation_func: Async function to execute
            max_retries: Maximum number of retry attempts
            backoff_factor: Multiplier for delay between retries
            initial_delay: Initial delay before first retry

        Returns:
            Result of the operation function

        Raises:
            Last exception encountered if all retries fail
        """
        last_exception = None
        delay = initial_delay

        for attempt in range(max_retries + 1):  # +1 for initial attempt
            try:
                return await operation_func()
            except TemporaryError as e:
                last_exception = e
                if attempt < max_retries:
                    self.logger.warning(
                        f"{operation_name} attempt {attempt + 1} failed, "
                        f"retrying in {delay}s: {e}"
                    )
                    await asyncio.sleep(delay)
                    delay *= backoff_factor
                else:
                    self.logger.error(
                        f"{operation_name} failed after {max_retries} retries"
                    )
                    raise
            except Exception as e:
                # Non-retryable errors are re-raised immediately
                self.logger.error(
                    f"{operation_name} failed with non-retryable error: {e}"
                )
                raise

        # This should never be reached, but just in case
        if last_exception:
            raise last_exception

    def update_status_reconciling(
        self, status: StatusProtocol, message: str, generation: int = 0
    ) -> None:
        """Update status to indicate reconciliation is in progress."""
        status.phase = "Reconciling"
        status.message = message
        timestamp = datetime.now(UTC).isoformat()
        status.last_reconcile_time = timestamp
        status.lastUpdated = timestamp
        # Track ObservedGeneration for GitOps compatibility
        status.observedGeneration = generation
        self._add_condition(
            status,
            "Reconciling",
            "True",
            "ReconciliationInProgress",
            message,
            generation,
        )
        # Add standard Kubernetes condition for progressing state
        self._add_condition(
            status,
            "Progressing",
            "True",
            "ReconciliationInProgress",
            f"Resource is progressing: {message}",
            generation,
        )
        # Clear any completed state markers while reconciliation is active
        self._remove_condition(status, "Ready")
        # Clear previous states during reconciliation
        self._remove_condition(status, "Available")
        self._remove_condition(status, "Degraded")

    def update_status_ready(
        self,
        status: StatusProtocol,
        message: str = "Resource is ready",
        generation: int = 0,
    ) -> None:
        """Update status to indicate resource is ready."""
        status.phase = "Ready"
        status.message = message
        timestamp = datetime.now(UTC).isoformat()
        status.last_reconcile_time = timestamp
        status.lastUpdated = timestamp
        # Track ObservedGeneration for GitOps compatibility
        status.observedGeneration = generation
        self._add_condition(
            status, "Ready", "True", "ReconciliationSucceeded", message, generation
        )
        self._remove_condition(status, "Reconciling")
        # Add standard Kubernetes condition for availability
        self._add_condition(
            status,
            "Available",
            "True",
            "ReconciliationSucceeded",
            f"Resource is available: {message}",
            generation,
        )
        self._remove_condition(status, "Progressing")
        self._remove_condition(status, "Degraded")

    def update_status_failed(
        self, status: StatusProtocol, message: str, generation: int = 0
    ) -> None:
        """Update status to indicate reconciliation failed."""
        status.phase = "Failed"
        status.message = message
        timestamp = datetime.now(UTC).isoformat()
        status.last_reconcile_time = timestamp
        status.lastUpdated = timestamp
        # Track ObservedGeneration for GitOps compatibility
        status.observedGeneration = generation
        self._add_condition(
            status, "Ready", "False", "ReconciliationFailed", message, generation
        )
        self._remove_condition(status, "Reconciling")
        # Add standard Kubernetes conditions for failed state
        self._add_condition(
            status,
            "Available",
            "False",
            "ReconciliationFailed",
            f"Resource unavailable: {message}",
            generation,
        )
        self._add_condition(
            status,
            "Degraded",
            "True",
            "ReconciliationFailed",
            f"Resource degraded: {message}",
            generation,
        )
        self._remove_condition(status, "Progressing")

    def update_status_degraded(
        self, status: StatusProtocol, message: str, generation: int = 0
    ) -> None:
        """Update status to indicate resource is degraded but partially functional."""
        status.phase = "Degraded"
        status.message = message
        timestamp = datetime.now(UTC).isoformat()
        status.last_reconcile_time = timestamp
        status.lastUpdated = timestamp
        # Track ObservedGeneration for GitOps compatibility
        status.observedGeneration = generation
        # Resource is not ready but still partially available
        self._add_condition(
            status, "Ready", "False", "PartialFunctionality", message, generation
        )
        self._add_condition(
            status,
            "Available",
            "True",
            "PartialFunctionality",
            f"Resource partially available: {message}",
            generation,
        )
        self._add_condition(
            status,
            "Degraded",
            "True",
            "PartialFunctionality",
            f"Resource degraded: {message}",
            generation,
        )
        self._remove_condition(status, "Reconciling")
        self._remove_condition(status, "Progressing")

    def _add_condition(
        self,
        status: StatusProtocol,
        condition_type: str,
        condition_status: str,
        reason: str,
        message: str,
        generation: int = 0,
    ) -> None:
        """Add or update a status condition with observedGeneration tracking."""
        # Ensure conditions is an initialized mutable list
        existing = getattr(status, "conditions", None)
        if existing is None or not isinstance(existing, list):
            try:
                # Attempt to coerce iterable to list if possible
                if existing is not None:
                    status.conditions = list(existing)  # type: ignore[arg-type]
                else:
                    status.conditions = []
            except Exception:
                status.conditions = []

        # Defensive: guarantee list post-initialization
        if not isinstance(status.conditions, list):  # pragma: no cover - safety net
            status.conditions = []

        # Remove existing condition of same type (ignore malformed entries safely)
        filtered: list[dict[str, Any]] = []
        for c in status.conditions:
            if isinstance(c, dict) and c.get("type") != condition_type:
                filtered.append(c)
        status.conditions = filtered

        # Add new condition following Kubernetes 2025 best practices
        condition = {
            "type": condition_type,
            "status": condition_status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": datetime.now(UTC).isoformat(),
            "observedGeneration": generation,  # 2025 best practice: per-condition observedGeneration
        }
        status.conditions.append(condition)

    def _remove_condition(self, status: StatusProtocol, condition_type: str) -> None:
        """Remove a status condition."""
        existing = getattr(status, "conditions", None)
        if not existing:
            return
        try:
            status.conditions = [
                c
                for c in existing
                if isinstance(c, dict) and c.get("type") != condition_type
            ]
        except Exception:  # pragma: no cover - defensive
            status.conditions = []

    def get_condition(
        self, status: StatusProtocol, condition_type: str
    ) -> dict[str, Any] | None:
        """Get a specific status condition."""
        if not hasattr(status, "conditions"):
            return None

        for condition in status.conditions:
            if condition.get("type") == condition_type:
                return condition
        return None

    def is_ready(self, status: StatusProtocol) -> bool:
        """Check if resource is in ready state."""
        ready_condition = self.get_condition(status, "Ready")
        return ready_condition is not None and ready_condition.get("status") == "True"

    def is_available(self, status: StatusProtocol) -> bool:
        """Check if resource is available (following Kubernetes conventions)."""
        available_condition = self.get_condition(status, "Available")
        return (
            available_condition is not None
            and available_condition.get("status") == "True"
        )

    def is_progressing(self, status: StatusProtocol) -> bool:
        """Check if resource is in progressing state."""
        progressing_condition = self.get_condition(status, "Progressing")
        return (
            progressing_condition is not None
            and progressing_condition.get("status") == "True"
        )

    def is_degraded(self, status: StatusProtocol) -> bool:
        """Check if resource is in degraded state."""
        degraded_condition = self.get_condition(status, "Degraded")
        return (
            degraded_condition is not None
            and degraded_condition.get("status") == "True"
        )

    async def validate_rbac_permissions(
        self,
        source_namespace: str,
        target_namespace: str | None,
        operations: list[dict[str, str]],
        resource_name: str = "",
    ) -> None:
        """
        Validate RBAC permissions for cross-namespace operations with audit logging.

        Args:
            source_namespace: Namespace where the request originates
            target_namespace: Target namespace (None means same namespace)
            operations: List of operations to validate, each with 'resource' and 'verb'
            resource_name: Name of the resource being accessed (for audit logging)

        Raises:
            RBACError: If any required permission is missing
        """
        from ..errors import RBACError
        from ..utils.kubernetes import check_rbac_permissions

        # If target namespace is not specified, use source namespace
        if target_namespace is None:
            target_namespace = source_namespace

        # Same namespace operations don't require cross-namespace RBAC
        if target_namespace == source_namespace:
            self.logger.debug(
                f"RBAC validation skipped for same-namespace operation in {source_namespace}"
            )
            return

        failed_operations = []
        successful_operations = []

        for operation in operations:
            resource = operation.get("resource", "")
            verb = operation.get("verb", "")

            has_permission = check_rbac_permissions(
                namespace=source_namespace,
                target_namespace=target_namespace,
                resource=resource,
                verb=verb,
            )

            operation_desc = f"{verb} {resource}"
            if has_permission:
                successful_operations.append(operation_desc)
                self.logger.debug(
                    f"RBAC permission granted: {operation_desc} in {target_namespace}",
                    operation=operation_desc,
                    target_namespace=target_namespace,
                    permission_result="granted",
                )
            else:
                failed_operations.append(operation_desc)
                self.logger.warning(
                    f"RBAC permission denied: {operation_desc} in {target_namespace}",
                    operation=operation_desc,
                    target_namespace=target_namespace,
                    permission_result="denied",
                )

        # Use structured RBAC audit logging
        self.logger.log_rbac_audit(
            operation="cross-namespace access validation",
            source_namespace=source_namespace,
            target_namespace=target_namespace,
            resource_name=resource_name,
            success=len(failed_operations) == 0,
            details={
                "successful_operations": successful_operations,
                "failed_operations": failed_operations,
                "total_operations": len(successful_operations) + len(failed_operations),
            },
        )

        # Raise error if any operations failed
        if failed_operations:
            raise RBACError(
                operation=f"cross-namespace access ({', '.join(failed_operations)})",
                resource=f"{target_namespace}/{resource_name}"
                if resource_name
                else target_namespace,
                namespace=target_namespace,
            )

        self.logger.info(
            f"RBAC validation passed for cross-namespace operations: "
            f"{source_namespace} -> {target_namespace}",
            source_namespace=source_namespace,
            target_namespace=target_namespace,
            operation="rbac_validation_success",
        )

    async def validate_namespace_isolation(
        self,
        source_namespace: str,
        target_namespace: str | None,
        resource_type: str,
        resource_name: str = "",
    ) -> None:
        """
        Validate namespace isolation policies.

        Args:
            source_namespace: Source namespace
            target_namespace: Target namespace (None means same namespace)
            resource_type: Type of resource being accessed
            resource_name: Name of the resource being accessed

        Raises:
            RBACError: If namespace isolation policies are violated
        """
        from ..errors import RBACError

        # If target namespace is not specified, use source namespace
        if target_namespace is None:
            target_namespace = source_namespace

        # Same namespace operations are always allowed
        if target_namespace == source_namespace:
            return

        # Check for namespace isolation labels/annotations
        try:
            from kubernetes import client

            core_api = client.CoreV1Api(self.kubernetes_client)

            # Check target namespace for isolation policies
            target_ns = core_api.read_namespace(name=target_namespace)

            # Check for isolation annotations
            annotations = target_ns.metadata.annotations or {}
            isolation_mode = annotations.get("keycloak.mdvr.nl/isolation", "")

            if isolation_mode == "strict":
                # Strict isolation - only allow access from explicitly allowed namespaces
                allowed_namespaces = annotations.get(
                    "keycloak.mdvr.nl/allowed-namespaces", ""
                ).split(",")
                allowed_namespaces = [
                    ns.strip() for ns in allowed_namespaces if ns.strip()
                ]

                if source_namespace not in allowed_namespaces:
                    self.logger.error(
                        f"Namespace isolation violation: {source_namespace} -> {target_namespace} "
                        f"(strict isolation, not in allowed list: {allowed_namespaces})"
                    )
                    raise RBACError(
                        operation=f"access {resource_type}",
                        resource=f"{target_namespace}/{resource_name}",
                        namespace=target_namespace,
                    )

            elif isolation_mode == "deny":
                # Complete isolation - no cross-namespace access allowed
                self.logger.error(
                    f"Namespace isolation violation: {source_namespace} -> {target_namespace} "
                    f"(complete isolation mode)"
                )
                raise RBACError(
                    operation=f"access {resource_type}",
                    resource=f"{target_namespace}/{resource_name}",
                    namespace=target_namespace,
                )

            self.logger.info(
                f"Namespace isolation validation passed: {source_namespace} -> {target_namespace} "
                f"(mode: {isolation_mode or 'default'})"
            )

        except Exception as e:
            if "RBACError" in str(type(e)):
                raise  # Re-raise RBAC errors

            # Log warning for namespace validation errors but don't fail
            self.logger.warning(
                f"Failed to validate namespace isolation policies: {e}. "
                f"Proceeding with RBAC validation only."
            )
