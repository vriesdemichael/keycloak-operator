"""
Base adapter for Keycloak version compatibility.

This module provides the abstract base class for version-specific adapters that handle:
1. Converting canonical models to version-specific formats
2. Converting version-specific data back to canonical models
3. Tracking warnings and errors for CR status feedback
4. Validating configurations against version capabilities
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class WarningLevel(Enum):
    """Severity level for version compatibility warnings."""

    INFO = "Info"  # Feature converted, works fine
    WARNING = "Warning"  # Deprecated, recommend upgrade
    ERROR = "Error"  # Cannot proceed, invalid config


@dataclass
class VersionWarning:
    """
    Warning about version-specific behavior.

    These warnings are collected during reconciliation and added to the CR status
    so that users managing realms/clients can see compatibility issues without
    needing access to operator logs.
    """

    level: WarningLevel
    code: str  # e.g., "ClientPolicyConfigConverted"
    field_path: str  # e.g., "clientPolicies[*].conditions[*].configuration"
    message: str  # Human-readable message
    keycloak_version: str  # e.g., "26.2.0"
    min_version: str | None = None  # e.g., "26.3.0" (if upgrade recommended)

    def to_condition(self) -> dict[str, Any]:
        """Convert to Kubernetes condition format for CR status."""
        return {
            "type": f"VersionCompatibility/{self.code}",
            "status": "False" if self.level == WarningLevel.ERROR else "True",
            "reason": self.code,
            "message": self.message,
            "lastTransitionTime": datetime.now(UTC).isoformat(),
        }


@dataclass
class ValidationResult:
    """Result of validating a spec against a Keycloak version."""

    valid: bool
    warnings: list[VersionWarning] = field(default_factory=list)
    errors: list[VersionWarning] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0

    @property
    def error_summary(self) -> str:
        """Get a summary of all errors for exception messages."""
        if not self.errors:
            return ""
        return "; ".join(e.message for e in self.errors)


class KeycloakAdapter(ABC):
    """
    Abstract base adapter for Keycloak version compatibility.

    Each major version has a concrete adapter that handles:
    - Endpoint path resolution (stable within major versions)
    - Model conversion (canonical to version-specific and back)
    - Validation of configurations against version capabilities
    - Collecting warnings/errors for CR status feedback
    """

    # Subclasses should define their supported version range
    SUPPORTED_RANGE: tuple[tuple[int, int, int], tuple[int, int, int]] = (
        (0, 0, 0),
        (99, 99, 99),
    )

    def __init__(self, version: str):
        """
        Initialize adapter for a specific Keycloak version.

        Args:
            version: Keycloak version string (e.g., "26.2.0")
        """
        self.version = version
        self.version_tuple = self._parse_version(version)
        self._warnings: list[VersionWarning] = []
        self._errors: list[VersionWarning] = []

    def _parse_version(self, version: str) -> tuple[int, int, int]:
        """Parse version string to tuple for comparison."""
        try:
            parts = version.split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return (major, minor, patch)
        except (ValueError, IndexError):
            logger.warning(f"Could not parse version '{version}', assuming 0.0.0")
            return (0, 0, 0)

    @property
    def major_version(self) -> int:
        """Get the major version number."""
        return self.version_tuple[0]

    @property
    def minor_version(self) -> int:
        """Get the minor version number."""
        return self.version_tuple[1]

    @property
    def patch_version(self) -> int:
        """Get the patch version number."""
        return self.version_tuple[2]

    def version_at_least(self, major: int, minor: int = 0, patch: int = 0) -> bool:
        """Check if version is at least the specified version."""
        return self.version_tuple >= (major, minor, patch)

    def version_less_than(self, major: int, minor: int = 0, patch: int = 0) -> bool:
        """Check if version is less than the specified version."""
        return self.version_tuple < (major, minor, patch)

    def add_warning(self, warning: VersionWarning) -> None:
        """Add a warning to be included in CR status."""
        self._warnings.append(warning)
        logger.info(
            f"Version compatibility warning [{warning.code}]: {warning.message}"
        )

    def add_error(self, error: VersionWarning) -> None:
        """Add an error to be included in CR status."""
        self._errors.append(error)
        logger.error(f"Version compatibility error [{error.code}]: {error.message}")

    def clear_warnings_and_errors(self) -> None:
        """Clear accumulated warnings and errors (call before each reconcile)."""
        self._warnings.clear()
        self._errors.clear()

    def get_status_conditions(self) -> list[dict[str, Any]]:
        """
        Get all version compatibility conditions for CR status.

        Returns:
            List of Kubernetes condition dicts to add to CR status
        """
        conditions = []
        for warning in self._warnings:
            conditions.append(warning.to_condition())
        for error in self._errors:
            conditions.append(error.to_condition())
        return conditions

    @property
    def warnings(self) -> list[VersionWarning]:
        """Get accumulated warnings."""
        return self._warnings.copy()

    @property
    def errors(self) -> list[VersionWarning]:
        """Get accumulated errors."""
        return self._errors.copy()

    # --- Conversion Methods ---

    def convert_to_keycloak(self, model: BaseModel, namespace: str) -> dict[str, Any]:
        """
        Convert a canonical model to version-specific format for Keycloak API.

        This method:
        1. Dumps the model to dict
        2. Applies version-specific transformations (implemented by subclasses)
        3. Collects warnings for fields that needed conversion
        4. Collects errors for fields that can't be used with this version

        Args:
            model: Canonical Pydantic model
            namespace: Originating namespace (for rate limiting context)

        Returns:
            Dict suitable for sending to this Keycloak version's API
        """
        # Start with the canonical model dump
        # mode="json" ensures enums are serialized to their values
        data = model.model_dump(exclude_none=True, by_alias=True, mode="json")

        # Apply version-specific transformations
        data = self._apply_outbound_conversions(data, type(model).__name__)

        return data

    def convert_from_keycloak(self, data: dict[str, Any], model_class: type[T]) -> T:
        """
        Convert version-specific data from Keycloak API to canonical model.

        This method:
        1. Applies version-specific transformations to upgrade data
        2. Validates against canonical model
        3. Returns typed canonical model

        Args:
            data: Raw dict from Keycloak API
            model_class: Target canonical model class

        Returns:
            Canonical Pydantic model instance
        """
        # Apply version-specific transformations
        data = self._apply_inbound_conversions(data, model_class.__name__)

        # Validate against canonical model
        return model_class.model_validate(data)

    def validate_for_version(self, spec: dict[str, Any]) -> ValidationResult:
        """
        Validate a spec dict against this Keycloak version's capabilities.

        This is called before reconciliation to catch configuration errors
        early and provide clear feedback in the CR status.

        Args:
            spec: The spec dict from the CR

        Returns:
            ValidationResult with any warnings or errors
        """
        # Clear any previous state
        self.clear_warnings_and_errors()

        # Run version-specific validation
        self._validate_spec(spec)

        return ValidationResult(
            valid=len(self._errors) == 0,
            warnings=self._warnings.copy(),
            errors=self._errors.copy(),
        )

    # --- Abstract Methods for Subclasses ---

    @abstractmethod
    def _apply_outbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply version-specific conversions when sending data to Keycloak.

        Subclasses implement this to handle downgrading canonical format
        to older version formats.

        Args:
            data: Dict from canonical model
            model_name: Name of the source model class

        Returns:
            Converted dict suitable for this Keycloak version
        """
        pass

    @abstractmethod
    def _apply_inbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply version-specific conversions when receiving data from Keycloak.

        Subclasses implement this to handle upgrading older version formats
        to canonical format.

        Args:
            data: Dict from Keycloak API
            model_name: Name of the target model class

        Returns:
            Converted dict suitable for canonical model
        """
        pass

    @abstractmethod
    def _validate_spec(self, spec: dict[str, Any]) -> None:
        """
        Validate spec against version capabilities.

        Subclasses implement this to check for fields/features that
        are not supported in this version. Should call add_warning()
        or add_error() as appropriate.

        Args:
            spec: The spec dict to validate
        """
        pass

    # --- Endpoint Resolvers ---
    # Centralizing all URL construction here to handle version-specific path changes

    # Realm
    @abstractmethod
    def get_realms_path(self) -> str:
        """Get path for realms collection."""
        pass

    @abstractmethod
    def get_realm_path(self, realm: str) -> str:
        """Get path for a specific realm."""
        pass

    @abstractmethod
    def get_admin_events_path(self, realm: str) -> str:
        """Get path for realm admin events."""
        pass

    # Client
    @abstractmethod
    def get_clients_path(self, realm: str) -> str:
        """Get path for clients collection."""
        pass

    @abstractmethod
    def get_client_path(self, realm: str, client_uuid: str) -> str:
        """Get path for a specific client."""
        pass

    @abstractmethod
    def get_client_secret_path(self, realm: str, client_uuid: str) -> str:
        """Get path for client secret."""
        pass

    @abstractmethod
    def get_client_service_account_user_path(self, realm: str, client_uuid: str) -> str:
        """Get path for client service account user."""
        pass

    # Role
    @abstractmethod
    def get_realm_role_path(self, realm: str, role_name: str) -> str:
        """Get path for a specific realm role."""
        pass

    @abstractmethod
    def get_realm_roles_path(self, realm: str) -> str:
        """Get path for realm roles."""
        pass

    @abstractmethod
    def get_realm_role_composites_path(self, realm: str, role_name: str) -> str:
        """Get path for realm role composites."""
        pass

    @abstractmethod
    def get_client_role_path(self, realm: str, client_uuid: str, role_name: str) -> str:
        """Get path for a specific client role."""
        pass

    @abstractmethod
    def get_user_realm_role_mappings_path(self, realm: str, user_id: str) -> str:
        """Get path for user realm role mappings."""
        pass

    @abstractmethod
    def get_client_role_mapping_path(
        self, realm: str, user_id: str, client_uuid: str
    ) -> str:
        """Get path for client role mappings (changed in v25)."""
        pass

    @abstractmethod
    def get_group_client_role_mapping_path(
        self, realm: str, group_id: str, client_uuid: str
    ) -> str:
        """Get path for group client role mappings (changed in v25)."""
        pass

    # Identity Provider
    @abstractmethod
    def get_identity_providers_path(self, realm: str) -> str:
        """Get path for identity providers collection."""
        pass

    @abstractmethod
    def get_identity_provider_path(self, realm: str, alias: str) -> str:
        """Get path for a specific identity provider."""
        pass

    @abstractmethod
    def get_identity_provider_mappers_path(self, realm: str, alias: str) -> str:
        """Get path for identity provider mappers."""
        pass

    @abstractmethod
    def get_identity_provider_mapper_path(
        self, realm: str, alias: str, mapper_id: str
    ) -> str:
        """Get path for a specific identity provider mapper."""
        pass

    # Authentication Flow
    @abstractmethod
    def get_authentication_flows_path(self, realm: str) -> str:
        """Get path for authentication flows."""
        pass

    @abstractmethod
    def get_authentication_flow_path(self, realm: str, flow_id: str) -> str:
        """Get path for a specific authentication flow."""
        pass

    @abstractmethod
    def get_authentication_flow_copy_path(self, realm: str, flow_alias: str) -> str:
        """Get path to copy an authentication flow."""
        pass

    @abstractmethod
    def get_authentication_flow_executions_path(
        self, realm: str, flow_alias: str
    ) -> str:
        """Get path for flow executions."""
        pass

    @abstractmethod
    def get_authentication_flow_executions_execution_path(
        self, realm: str, flow_alias: str
    ) -> str:
        """Get path to add execution to flow."""
        pass

    @abstractmethod
    def get_authentication_flow_executions_flow_path(
        self, realm: str, flow_alias: str
    ) -> str:
        """Get path to add subflow to flow."""
        pass

    @abstractmethod
    def get_authentication_execution_path(self, realm: str, execution_id: str) -> str:
        """Get path for a specific execution."""
        pass

    @abstractmethod
    def get_authentication_config_path(self, realm: str, config_id: str) -> str:
        """Get path for a specific authentication config."""
        pass

    @abstractmethod
    def get_authentication_execution_config_path(
        self, realm: str, execution_id: str
    ) -> str:
        """Get path to create config for execution."""
        pass

    # Required Actions
    @abstractmethod
    def get_authentication_required_actions_path(self, realm: str) -> str:
        """Get path for required actions."""
        pass

    @abstractmethod
    def get_authentication_required_action_path(self, realm: str, alias: str) -> str:
        """Get path for a specific required action."""
        pass

    @abstractmethod
    def get_authentication_register_required_action_path(self, realm: str) -> str:
        """Get path to register a required action."""
        pass
