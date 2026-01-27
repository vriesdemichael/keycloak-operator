from .base import KeycloakAdapter


class AdapterV26(KeycloakAdapter):
    """Adapter for Keycloak 26.x (and 25.x which shares the new paths)."""

    # Realm
    def get_realms_path(self) -> str:
        return "realms"

    def get_realm_path(self, realm: str) -> str:
        return f"realms/{realm}"

    def get_admin_events_path(self, realm: str) -> str:
        return f"realms/{realm}/admin-events"

    # Client
    def get_clients_path(self, realm: str) -> str:
        return f"realms/{realm}/clients"

    def get_client_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}"

    def get_client_secret_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}/client-secret"

    def get_client_service_account_user_path(self, realm: str, client_uuid: str) -> str:
        return f"realms/{realm}/clients/{client_uuid}/service-account-user"

    # Role
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
        # v25+ uses 'clients/{client-uuid}'
        return f"realms/{realm}/users/{user_id}/role-mappings/clients/{client_uuid}"

    def get_group_client_role_mapping_path(
        self, realm: str, group_id: str, client_uuid: str
    ) -> str:
        return f"realms/{realm}/groups/{group_id}/role-mappings/clients/{client_uuid}"

    # Identity Provider
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

    # Authentication Flow
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

    # Required Actions
    def get_authentication_required_actions_path(self, realm: str) -> str:
        return f"realms/{realm}/authentication/required-actions"

    def get_authentication_required_action_path(self, realm: str, alias: str) -> str:
        return f"realms/{realm}/authentication/required-actions/{alias}"

    def get_authentication_register_required_action_path(self, realm: str) -> str:
        return f"realms/{realm}/authentication/register-required-action"


class AdapterV25(AdapterV26):
    """Adapter for Keycloak 25.x (Same paths as 26, distinct class for future drift)."""

    pass


class AdapterV24(AdapterV26):
    """Adapter for Keycloak 24.x."""

    # We override this just to be explicit, even though the logic ended up being the same
    # due to UUID usage. If we find other differences, they go here.
    def get_client_role_mapping_path(
        self, realm: str, user_id: str, client_uuid: str
    ) -> str:
        return f"realms/{realm}/users/{user_id}/role-mappings/clients/{client_uuid}"

    def get_group_client_role_mapping_path(
        self, realm: str, group_id: str, client_uuid: str
    ) -> str:
        return f"realms/{realm}/groups/{group_id}/role-mappings/clients/{client_uuid}"
