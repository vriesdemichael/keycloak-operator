"""
Version-specific adapters for Keycloak compatibility.

Each adapter handles:
- Endpoint path resolution for that version
- Model conversion (canonical to version-specific and back)
- Validation of configurations against version capabilities
"""

from __future__ import annotations

import logging
from typing import Any

from .base import KeycloakAdapter, VersionWarning, WarningLevel

logger = logging.getLogger(__name__)


# =============================================================================
# Breaking Change Boundaries for 26.x
# =============================================================================
# These constants define the version boundaries where breaking changes occur.
# They are used to determine which conversions and validations to apply.

# 26.3.0: ClientPolicy*.configuration changed from list[Any] to dict[str, Any]
V26_CLIENT_POLICY_TYPE_CHANGE = (26, 3, 0)

# 26.4.0: oAuth2DevicePollingInterval and oAuth2DeviceCodeLifespan removed
V26_OAUTH2_DEVICE_REMOVED = (26, 4, 0)

# 26.5.0: Workflow API restructured, AddressClaimSet changes
V26_WORKFLOW_API_CHANGED = (26, 5, 0)

# 26.5.2: IDToken/AccessToken.address field removed
V26_ADDRESS_CLAIM_REMOVED = (26, 5, 2)


# =============================================================================
# V26 Adapter - Handles all 26.x versions with minor-version-aware conversions
# =============================================================================


class V26Adapter(KeycloakAdapter):
    """
    Adapter for Keycloak 26.x.

    This adapter handles all 26.x versions (26.0.0 through 26.99.99) with
    minor-version-aware conversions for breaking changes between minors.

    Breaking changes handled:
    - 26.3.0: ClientPolicy configuration type change (list -> dict)
    - 26.4.0: OAuth2 device flow fields removed from RealmRepresentation
    - 26.5.0: Workflow API restructured
    - 26.5.2: Address claim fields removed from tokens
    """

    SUPPORTED_RANGE = ((26, 0, 0), (26, 99, 99))

    def _apply_outbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply conversions when sending data to Keycloak.

        For older 26.x versions, we may need to:
        - Convert ClientPolicy configuration from dict to list
        - Remove fields that don't exist in older versions
        """
        # ClientPolicy configuration conversion for <26.3.0
        if self.version_less_than(*V26_CLIENT_POLICY_TYPE_CHANGE):
            if model_name in (
                "ClientPolicyConditionRepresentation",
                "ClientPolicyExecutorRepresentation",
            ):
                data = self._convert_client_policy_config_to_list(data)
            # Also handle nested structures in realm/client specs
            data = self._convert_nested_client_policies_to_list(data)

        return data

    def _apply_inbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply conversions when receiving data from Keycloak.

        For older 26.x versions, we may need to:
        - Convert ClientPolicy configuration from list to dict
        """
        # ClientPolicy configuration conversion for <26.3.0
        if self.version_less_than(*V26_CLIENT_POLICY_TYPE_CHANGE) and model_name in (
            "ClientPolicyConditionRepresentation",
            "ClientPolicyExecutorRepresentation",
        ):
            data = self._convert_client_policy_config_to_dict(data)

        return data

    def _validate_spec(self, spec: dict[str, Any]) -> None:
        """
        Validate spec against 26.x version capabilities.

        Checks for fields that are not supported in the target version
        and adds appropriate warnings or errors.
        """
        # OAuth2 device fields validation for >=26.4.0
        if self.version_at_least(*V26_OAUTH2_DEVICE_REMOVED):
            self._validate_oauth2_device_fields(spec)

        # Client policy configuration info for <26.3.0
        if self.version_less_than(*V26_CLIENT_POLICY_TYPE_CHANGE):
            self._add_client_policy_conversion_warning(spec)

    # --- ClientPolicy Configuration Conversion ---

    def _convert_client_policy_config_to_list(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Convert ClientPolicy configuration from dict to list for <26.3.0.

        In 26.2.x and earlier, configuration is type: array.
        The canonical model uses dict (26.3.0+).
        """
        if "configuration" in data and isinstance(data["configuration"], dict):
            # Convert dict to list of key-value items
            # This is a best-effort conversion - the exact format may vary
            config_list = []
            for key, value in data["configuration"].items():
                if isinstance(value, list):
                    config_list.extend(value)
                else:
                    config_list.append({key: value})
            data["configuration"] = config_list
            logger.debug(
                f"Converted ClientPolicy configuration from dict to list "
                f"for Keycloak {self.version}"
            )
        return data

    def _convert_client_policy_config_to_dict(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Convert ClientPolicy configuration from list to dict for <26.3.0.

        When reading from 26.2.x and earlier, configuration comes as array.
        We convert to dict for the canonical model.
        """
        if "configuration" in data and isinstance(data["configuration"], list):
            # Convert list to dict - merge all items
            config_dict: dict[str, Any] = {}
            for item in data["configuration"]:
                if isinstance(item, dict):
                    config_dict.update(item)
            data["configuration"] = config_dict
            logger.debug(
                f"Converted ClientPolicy configuration from list to dict "
                f"for Keycloak {self.version}"
            )
        return data

    def _convert_nested_client_policies_to_list(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Handle nested ClientPolicy structures in realm/client specs.
        """
        # Handle clientPolicies in realm config
        if "clientPolicies" in data:
            policies = data.get("clientPolicies", {})
            if isinstance(policies, dict):
                # Handle policies list
                for policy in policies.get("policies", []):
                    if isinstance(policy, dict):
                        for condition in policy.get("conditions", []):
                            if isinstance(condition, dict):
                                self._convert_client_policy_config_to_list(condition)
                        for executor in policy.get("executors", []):
                            if isinstance(executor, dict):
                                self._convert_client_policy_config_to_list(executor)
                # Handle profiles list
                for profile in policies.get("profiles", []):
                    if isinstance(profile, dict):
                        for executor in profile.get("executors", []):
                            if isinstance(executor, dict):
                                self._convert_client_policy_config_to_list(executor)
        return data

    def _add_client_policy_conversion_warning(self, spec: dict[str, Any]) -> None:
        """
        Add info warning if client policies are used on <26.3.0.
        """
        has_policies = False
        if "clientPolicies" in spec:
            policies = spec.get("clientPolicies", {})
            if isinstance(policies, dict):
                has_policies = bool(
                    policies.get("policies") or policies.get("profiles")
                )

        if has_policies:
            self.add_warning(
                VersionWarning(
                    level=WarningLevel.INFO,
                    code="ClientPolicyConfigConverted",
                    field_path="clientPolicies[*].conditions[*].configuration",
                    message=(
                        f"Client policy configuration format converted for "
                        f"Keycloak {self.version}. Configuration uses dict format "
                        f"but Keycloak <26.3.0 expects list format. "
                        f"Upgrade to 26.3.0+ recommended for native support."
                    ),
                    keycloak_version=self.version,
                    min_version="26.3.0",
                )
            )

    # --- OAuth2 Device Fields Validation ---

    def _validate_oauth2_device_fields(self, spec: dict[str, Any]) -> None:
        """
        Validate that removed OAuth2 device fields are not used on >=26.4.0.
        """
        removed_fields = []

        # Check for the removed fields (using both camelCase and snake_case)
        field_names = [
            ("oAuth2DeviceCodeLifespan", "oauth2_device_code_lifespan"),
            ("oAuth2DevicePollingInterval", "oauth2_device_polling_interval"),
        ]

        for camel_case, snake_case in field_names:
            if spec.get(camel_case) is not None or spec.get(snake_case) is not None:
                removed_fields.append(camel_case)

        if removed_fields:
            self.add_error(
                VersionWarning(
                    level=WarningLevel.ERROR,
                    code="OAuth2DeviceFieldsUnsupported",
                    field_path=", ".join(removed_fields),
                    message=(
                        f"OAuth2 device flow fields ({', '.join(removed_fields)}) "
                        f"are not supported in Keycloak {self.version}. "
                        f"These settings were removed in 26.4.0. "
                        f"Configure device flow via Authentication > Flows > "
                        f"Direct Grant > Device Code settings instead."
                    ),
                    keycloak_version=self.version,
                    min_version=None,
                )
            )

    # --- Endpoint Paths (stable for all 26.x) ---

    def get_realms_path(self) -> str:
        return "realms"

    def get_realm_path(self, realm: str) -> str:
        return f"realms/{realm}"

    def get_admin_events_path(self, realm: str) -> str:
        return f"realms/{realm}/admin-events"

    def get_clients_path(self, realm: str) -> str:
        return f"realms/{realm}/clients"

    def get_client_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}"

    def get_client_secret_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}/client-secret"

    def get_client_service_account_user_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}/service-account-user"

    def get_realm_role_path(self, realm: str, role_name: str) -> str:
        return f"realms/{realm}/roles/{role_name}"

    def get_realm_roles_path(self, realm: str) -> str:
        return f"realms/{realm}/roles"

    def get_realm_role_composites_path(self, realm: str, role_name: str) -> str:
        return f"realms/{realm}/roles/{role_name}/composites"

    def get_client_role_path(self, realm: str, client_uuid: str, role_name: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}/roles/{role_name}"

    def get_user_realm_role_mappings_path(self, realm: str, user_id: str) -> str:
        return f"realms/{realm}/users/{user_id}/role-mappings/realm"

    def get_client_role_mapping_path(
        self, realm: str, user_id: str, client_uuid: str
    ) -> str:
        return f"realms/{realm}/users/{user_id}/role-mappings/clients/{client_uuid}"

    def get_group_client_role_mapping_path(
        self, realm: str, group_id: str, client_uuid: str
    ) -> str:
        return f"realms/{realm}/groups/{group_id}/role-mappings/clients/{client_uuid}"

    def get_identity_providers_path(self, realm: str) -> str:
        return f"realms/{realm}/identity-provider/instances"

    def get_identity_provider_path(self, realm: str, alias: str) -> str:
        return f"realms/{realm}/identity-provider/instances/{alias}"

    def get_identity_provider_mappers_path(self, realm: str, alias: str) -> str:
        return f"realms/{realm}/identity-provider/instances/{alias}/mappers"

    def get_identity_provider_mapper_path(
        self, realm: str, alias: str, mapper_id: str
    ) -> str:
        return f"realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper_id}"

    def get_authentication_flows_path(self, realm: str) -> str:
        return f"realms/{realm}/authentication/flows"

    def get_authentication_flow_path(self, realm: str, flow_id: str) -> str:
        return f"realms/{realm}/authentication/flows/{flow_id}"

    def get_authentication_flow_copy_path(self, realm: str, flow_alias: str) -> str:
        return f"realms/{realm}/authentication/flows/{flow_alias}/copy"

    def get_authentication_flow_executions_path(
        self, realm: str, flow_alias: str
    ) -> str:
        return f"realms/{realm}/authentication/flows/{flow_alias}/executions"

    def get_authentication_flow_executions_execution_path(
        self, realm: str, flow_alias: str
    ) -> str:
        return f"realms/{realm}/authentication/flows/{flow_alias}/executions/execution"

    def get_authentication_flow_executions_flow_path(
        self, realm: str, flow_alias: str
    ) -> str:
        return f"realms/{realm}/authentication/flows/{flow_alias}/executions/flow"

    def get_authentication_execution_path(self, realm: str, execution_id: str) -> str:
        return f"realms/{realm}/authentication/executions/{execution_id}"

    def get_authentication_config_path(self, realm: str, config_id: str) -> str:
        return f"realms/{realm}/authentication/config/{config_id}"

    def get_authentication_execution_config_path(
        self, realm: str, execution_id: str
    ) -> str:
        return f"realms/{realm}/authentication/executions/{execution_id}/config"

    def get_authentication_required_actions_path(self, realm: str) -> str:
        return f"realms/{realm}/authentication/required-actions"

    def get_authentication_required_action_path(self, realm: str, alias: str) -> str:
        return f"realms/{realm}/authentication/required-actions/{alias}"

    def get_authentication_register_required_action_path(self, realm: str) -> str:
        return f"realms/{realm}/authentication/register-required-action"

    # Scope Mappings
    def get_scope_mappings_realm_roles_path(
        self,
        realm: str,
        client_id: str | None = None,
        client_scope_id: str | None = None,
    ) -> str:
        if client_id:
            return f"realms/{realm}/clients/{client_id}/scope-mappings/realm"
        if client_scope_id:
            return (
                f"realms/{realm}/client-scopes/{client_scope_id}/scope-mappings/realm"
            )
        return f"realms/{realm}/scope-mappings/realm"

    def get_scope_mappings_client_roles_path(
        self,
        realm: str,
        role_container_id: str,
        client_id: str | None = None,
        client_scope_id: str | None = None,
    ) -> str:
        if client_id:
            return f"realms/{realm}/clients/{client_id}/scope-mappings/clients/{role_container_id}"
        if client_scope_id:
            return f"realms/{realm}/client-scopes/{client_scope_id}/scope-mappings/clients/{role_container_id}"
        return f"realms/{realm}/scope-mappings/clients/{role_container_id}"


# =============================================================================
# V25 Adapter - Same paths as 26, minimal differences
# =============================================================================


class V25Adapter(V26Adapter):
    """
    Adapter for Keycloak 25.x.

    25.x shares most API structure with 26.x. This adapter inherits from
    V26Adapter and overrides only where necessary.
    """

    SUPPORTED_RANGE = ((25, 0, 0), (25, 99, 99))

    def _apply_outbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply conversions for 25.x.

        25.x uses the older ClientPolicy configuration format (list).
        """
        # 25.x uses list format for ClientPolicy configuration (like 26.0-26.2)
        if model_name in (
            "ClientPolicyConditionRepresentation",
            "ClientPolicyExecutorRepresentation",
        ):
            data = self._convert_client_policy_config_to_list(data)
        data = self._convert_nested_client_policies_to_list(data)

        return data

    def _apply_inbound_conversions(
        self, data: dict[str, Any], model_name: str
    ) -> dict[str, Any]:
        """
        Apply conversions for 25.x.

        Convert list configuration to dict for canonical model.
        """
        if model_name in (
            "ClientPolicyConditionRepresentation",
            "ClientPolicyExecutorRepresentation",
        ):
            data = self._convert_client_policy_config_to_dict(data)

        return data

    def _validate_spec(self, spec: dict[str, Any]) -> None:
        """
        Validate spec for 25.x.

        25.x has OAuth2 device fields (they weren't removed until 26.4.0).
        Client policies use list format.
        """
        self._add_client_policy_conversion_warning(spec)

        # Add info about features not available in 25.x
        # (Organizations, Workflows, etc. were added in 26.x)
        if spec.get("organizations") or spec.get("organizationsEnabled"):
            self.add_error(
                VersionWarning(
                    level=WarningLevel.ERROR,
                    code="OrganizationsNotSupported",
                    field_path="organizations, organizationsEnabled",
                    message=(
                        f"Organizations feature is not supported in Keycloak "
                        f"{self.version}. Organizations were introduced in 26.0.0. "
                        f"Upgrade to Keycloak 26.0.0+ to use this feature."
                    ),
                    keycloak_version=self.version,
                    min_version="26.0.0",
                )
            )


# =============================================================================
# V24 Adapter - Older API with more differences
# =============================================================================


class V24Adapter(V25Adapter):
    """
    Adapter for Keycloak 24.x.

    24.x has the same API structure as 25.x for the features this operator
    uses. Inherits from V25Adapter.
    """

    SUPPORTED_RANGE = ((24, 0, 0), (24, 99, 99))

    def _validate_spec(self, spec: dict[str, Any]) -> None:
        """
        Validate spec for 24.x.

        24.x is missing many features that were added in 25.x and 26.x.
        """
        super()._validate_spec(spec)

        # Additional features not available in 24.x
        # (Add checks here as needed for specific features)


# =============================================================================
# Adapter Registry
# =============================================================================

# Map of major version to adapter class
ADAPTER_REGISTRY: dict[int, type[KeycloakAdapter]] = {
    24: V24Adapter,
    25: V25Adapter,
    26: V26Adapter,
}


def get_adapter_for_version(version: str) -> KeycloakAdapter:
    """
    Get the appropriate adapter for a Keycloak version.

    Args:
        version: Keycloak version string (e.g., "26.2.0")

    Returns:
        Adapter instance for that version

    Raises:
        ValueError: If version is not supported
    """
    try:
        parts = version.split(".")
        major = int(parts[0])
    except (ValueError, IndexError) as e:
        raise ValueError(f"Invalid version string: {version}") from e

    adapter_class = ADAPTER_REGISTRY.get(major)
    if adapter_class is None:
        supported = sorted(ADAPTER_REGISTRY.keys())
        raise ValueError(
            f"Keycloak version {version} is not supported. "
            f"Supported major versions: {supported}"
        )

    return adapter_class(version)
