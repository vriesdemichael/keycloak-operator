"""
Error handling module for the Keycloak operator.

This module provides a comprehensive error hierarchy that integrates with kopf
and provides clear categorization for different types of failures.
"""

from .operator_errors import (
    AuthorizationError,
    ConfigurationError,
    DatabaseValidationError,
    ExternalServiceError,
    KeycloakAdminError,
    KubernetesAPIError,
    OperatorError,
    PermanentError,
    RBACError,
    ReconciliationError,
    TemporaryError,
    ValidationError,
)

__all__ = [
    "OperatorError",
    "ValidationError",
    "TemporaryError",
    "PermanentError",
    "ExternalServiceError",
    "DatabaseValidationError",
    "KeycloakAdminError",
    "KubernetesAPIError",
    "ConfigurationError",
    "RBACError",
    "ReconciliationError",
    "AuthorizationError",
]
