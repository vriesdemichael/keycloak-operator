"""
Keycloak version compatibility layer.

This module provides version-specific adapters that handle:
- Converting canonical models to version-specific formats
- Converting version-specific data back to canonical models
- Tracking warnings and errors for CR status feedback
- Validating configurations against version capabilities
"""

from .adapters import (
    ADAPTER_REGISTRY,
    V24Adapter,
    V25Adapter,
    V26Adapter,
    get_adapter_for_version,
)
from .base import (
    KeycloakAdapter,
    ValidationResult,
    VersionWarning,
    WarningLevel,
)

__all__ = [
    # Base classes and types
    "KeycloakAdapter",
    "ValidationResult",
    "VersionWarning",
    "WarningLevel",
    # Adapters
    "V24Adapter",
    "V25Adapter",
    "V26Adapter",
    "ADAPTER_REGISTRY",
    # Factory function
    "get_adapter_for_version",
]
