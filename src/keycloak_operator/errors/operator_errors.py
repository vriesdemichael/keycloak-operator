"""
Operator error hierarchy with categorization and retry logic.

This module defines the error types used throughout the Keycloak operator,
providing clear categorization and integration with kopf's retry mechanisms.
"""

import kopf


class OperatorError(Exception):
    """
    Base error class for all operator-related exceptions.

    Provides categorization, retry behavior, and user guidance for resolution.
    """

    def __init__(
        self,
        message: str,
        category: str,
        retryable: bool = True,
        delay: int = 30,
        user_action: str | None = None,
        cause: Exception | None = None,
    ):
        """
        Initialize operator error.

        Args:
            message: Human-readable error description
            category: Error category (validation, api, configuration, external)
            retryable: Whether kopf should retry this operation
            delay: Suggested retry delay in seconds
            user_action: What user should do to resolve the issue
            cause: Underlying exception that caused this error
        """
        super().__init__(message)
        self.category = category
        self.retryable = retryable
        self.delay = delay
        self.user_action = user_action
        self.cause = cause

    def as_kopf_error(self):
        """Convert to appropriate kopf exception type."""
        if self.retryable:
            return kopf.TemporaryError(str(self), delay=self.delay)
        else:
            return kopf.PermanentError(str(self))

    def __str__(self) -> str:
        """Enhanced string representation with user guidance."""
        base_msg = super().__str__()
        if self.user_action:
            return f"{base_msg}\nAction required: {self.user_action}"
        return base_msg


class ValidationError(OperatorError):
    """Error in resource specification validation."""

    def __init__(
        self, message: str, field: str | None = None, user_action: str | None = None
    ):
        action = user_action or "Check resource specification and fix validation errors"
        if field:
            message = f"Validation error in field '{field}': {message}"
        super().__init__(
            message=message, category="validation", retryable=False, user_action=action
        )


class TemporaryError(OperatorError):
    """Temporary error that should be retried."""

    def __init__(self, message: str, delay: int = 30, user_action: str | None = None):
        super().__init__(
            message=message,
            category="temporary",
            retryable=True,
            delay=delay,
            user_action=user_action
            or "Wait for automatic retry or check system status",
        )


class PermanentError(OperatorError):
    """Permanent error that should not be retried."""

    def __init__(self, message: str, user_action: str | None = None):
        super().__init__(
            message=message,
            category="permanent",
            retryable=False,
            user_action=user_action or "Manual intervention required to resolve",
        )


class ExternalServiceError(OperatorError):
    """Error communicating with external services."""

    def __init__(
        self,
        service: str,
        message: str,
        retryable: bool = True,
        delay: int = 60,
        user_action: str | None = None,
    ):
        action = user_action or f"Check {service} connectivity and credentials"
        super().__init__(
            message=f"{service} error: {message}",
            category="external",
            retryable=retryable,
            delay=delay,
            user_action=action,
        )


class ReconciliationError(OperatorError):
    """Error raised when reconciliation cannot be completed."""

    def __init__(
        self,
        message: str,
        retryable: bool = True,
        delay: int = 60,
        user_action: str | None = None,
    ):
        super().__init__(
            message=message,
            category="reconciliation",
            retryable=retryable,
            delay=delay,
            user_action=user_action
            or "Inspect operator logs and resource specification for issues",
        )


class DatabaseValidationError(ValidationError):
    """Specific error for database configuration validation."""

    def __init__(self, db_type: str, environment: str = "production"):
        super().__init__(
            message=f"Database type '{db_type}' not suitable for {environment} environment",
            field="database.type",
            user_action="Change database.type to postgresql, mysql, mariadb, oracle, or mssql",
        )


class KeycloakAdminError(ExternalServiceError):
    """Error communicating with Keycloak Admin API."""

    def __init__(
        self, message: str, status_code: int | None = None, retryable: bool = True
    ):
        if status_code:
            message = f"HTTP {status_code}: {message}"

        # 4xx errors are generally not retryable (client errors)
        if status_code and 400 <= status_code < 500:
            retryable = False

        super().__init__(
            service="Keycloak Admin API",
            message=message,
            retryable=retryable,
            user_action="Check Keycloak instance status and admin credentials",
        )


class KubernetesAPIError(ExternalServiceError):
    """Error communicating with Kubernetes API."""

    def __init__(self, message: str, reason: str | None = None, retryable: bool = True):
        if reason:
            message = f"{message} (reason: {reason})"

        # Some K8s errors are not retryable
        non_retryable_reasons = {"Forbidden", "Unauthorized", "Invalid"}
        if reason in non_retryable_reasons:
            retryable = False

        super().__init__(
            service="Kubernetes API",
            message=message,
            retryable=retryable,
            user_action="Check RBAC permissions and cluster connectivity",
        )


class ConfigurationError(OperatorError):
    """Error in operator or resource configuration."""

    def __init__(
        self, message: str, retryable: bool = False, user_action: str | None = None
    ):
        super().__init__(
            message=message,
            category="configuration",
            retryable=retryable,
            user_action=user_action or "Review and correct configuration",
        )


class RBACError(OperatorError):
    """Error related to RBAC permissions."""

    def __init__(
        self,
        operation: str,
        resource: str,
        namespace: str,
        user_action: str | None = None,
    ):
        message = f"Insufficient permissions for {operation} on {resource} in namespace {namespace}"
        action = (
            user_action or "Check service account permissions and RBAC configuration"
        )

        super().__init__(
            message=message, category="rbac", retryable=False, user_action=action
        )


class AuthorizationError(OperatorError):
    """Error related to token-based authorization."""

    def __init__(
        self,
        message: str,
        retryable: bool = False,
        user_action: str | None = None,
    ):
        action = user_action or "Check authorization token validity and permissions"

        super().__init__(
            message=message,
            category="authorization",
            retryable=retryable,
            user_action=action,
        )
