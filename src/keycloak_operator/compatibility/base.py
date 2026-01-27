import importlib
import logging
from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class KeycloakAdapter(ABC):
    """Abstract base adapter for Keycloak version compatibility."""

    def __init__(self, version: str):
        self.version = version
        # Determine module name from version (simple mapping for now)
        # Assumes standard format or set by subclass
        self.module_name = self._get_module_name(version)

    def _get_module_name(self, version: str) -> str:
        # Map version to module name (e.g. 24.0.5 -> v24_0_5)
        # This is a bit fragile if versions in yaml don't match strict pattern,
        # but robust enough for the supported set.
        return f"v{version.replace('.', '_')}"

    def get_target_model_class(
        self, source_model_class: type[BaseModel]
    ) -> type[BaseModel]:
        """Dynamically load the corresponding model class for this version."""
        try:
            module_path = f"keycloak_operator.models.generated.{self.module_name}"
            module = importlib.import_module(module_path)
            return getattr(module, source_model_class.__name__)
        except (ImportError, AttributeError) as e:
            logger.warning(
                f"Could not find target model for {source_model_class.__name__} "
                f"in {self.module_name}: {e}. "
                "Falling back to source model (no downgrading)."
            )
            return source_model_class

    def convert_to_target(
        self, source_model: BaseModel, source_model_class: type[BaseModel] | None = None
    ) -> dict[str, Any]:
        """
        Convert a source model (Canonical v26) to a target model dict (e.g. v24).

        This method:
        1. Resolves the target model class for this adapter's version.
        2. Dumps the source model to a dict (excluding unset fields).
        3. Validates it against the target model class.
        4. Identifies dropped fields that had values.
        5. Logs warnings for dropped data.
        6. Returns the clean dict suitable for the target API.
        """
        target_model_class = self.get_target_model_class(
            source_model_class or type(source_model)
        )

        # 1. Get the source data (what the user intended to send)
        source_data = source_model.model_dump(exclude_unset=True, by_alias=True)

        # 2. Try to "fit" it into the target model
        # We rely on Pydantic to ignore extra fields by default,
        # but we need to know WHICH fields were ignored to warn the user.

        # Get the set of valid field aliases in the target model
        target_fields = set()
        for name, field in target_model_class.model_fields.items():
            target_fields.add(field.alias or name)

        # 3. Check for dropped fields
        dropped_fields = []
        clean_data = {}

        for key, value in source_data.items():
            if key in target_fields:
                clean_data[key] = value
            else:
                # If the value is not None, we are losing data!
                if value is not None:
                    dropped_fields.append(key)

        if dropped_fields:
            logger.warning(
                f"Configuration fields {dropped_fields} are not supported by Keycloak "
                f"{self.version} and will be ignored. Upgrade Keycloak to use these features."
            )

        # 4. Final validation ensuring types are correct for target
        # This might seem redundant but handles type coercions if they changed
        validated_target = target_model_class.model_validate(clean_data)

        return validated_target.model_dump(exclude_none=True, by_alias=True)

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
