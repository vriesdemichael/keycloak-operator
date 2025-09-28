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
        async with metrics_collector.track_reconciliation(
            resource_type=resource_type,
            namespace=namespace,
            name=name,
            operation="reconcile",
        ):
            try:
                # Update status to indicate reconciliation started
                self.update_status_reconciling(status, "Starting reconciliation")

                # Perform the actual reconciliation
                result = await self.do_reconcile(
                    spec, name, namespace, status, **kwargs
                )

                # Update status to indicate success
                self.update_status_ready(
                    status, "Reconciliation completed successfully"
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
                self.update_status_failed(status, str(e))

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

        async with metrics_collector.track_reconciliation(
            resource_type=resource_type,
            namespace=namespace,
            name=name,
            operation="update",
        ):
            try:
                # Update status to indicate update started
                self.update_status_reconciling(
                    status, "Processing configuration changes"
                )

                # Perform the actual update
                result = await self.do_update(
                    old_spec, new_spec, diff, name, namespace, status, **kwargs
                )

                # Update status to indicate success
                self.update_status_ready(status, "Update completed successfully")

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
                self.update_status_failed(status, str(e))

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
        pass

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

    def update_status_reconciling(self, status: StatusProtocol, message: str) -> None:
        """Update status to indicate reconciliation is in progress."""
        status.phase = "Reconciling"
        status.message = message
        status.last_reconcile_time = datetime.now(UTC).isoformat()
        self._add_condition(
            status, "Reconciling", "True", "ReconciliationInProgress", message
        )

    def update_status_ready(
        self, status: StatusProtocol, message: str = "Resource is ready"
    ) -> None:
        """Update status to indicate resource is ready."""
        status.phase = "Ready"
        status.message = message
        status.last_reconcile_time = datetime.now(UTC).isoformat()
        self._add_condition(status, "Ready", "True", "ReconciliationSucceeded", message)
        self._remove_condition(status, "Reconciling")

    def update_status_failed(self, status: StatusProtocol, message: str) -> None:
        """Update status to indicate reconciliation failed."""
        status.phase = "Failed"
        status.message = message
        status.last_reconcile_time = datetime.now(UTC).isoformat()
        self._add_condition(status, "Ready", "False", "ReconciliationFailed", message)
        self._remove_condition(status, "Reconciling")

    def _add_condition(
        self,
        status: StatusProtocol,
        condition_type: str,
        condition_status: str,
        reason: str,
        message: str,
    ) -> None:
        """Add or update a status condition."""
        if not hasattr(status, "conditions"):
            status.conditions = []

        # Remove existing condition of same type
        status.conditions = [
            c for c in status.conditions if c.get("type") != condition_type
        ]

        # Add new condition
        condition = {
            "type": condition_type,
            "status": condition_status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": datetime.now(UTC).isoformat(),
        }
        status.conditions.append(condition)

    def _remove_condition(self, status: StatusProtocol, condition_type: str) -> None:
        """Remove a status condition."""
        if hasattr(status, "conditions"):
            status.conditions = [
                c for c in status.conditions if c.get("type") != condition_type
            ]

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
