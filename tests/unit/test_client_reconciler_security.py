"""Unit tests for security restrictions in client reconciler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.errors import ValidationError
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.fixture
def mock_settings():
    with (
        patch(
            "keycloak_operator.services.client_reconciler.settings"
        ) as mock_svc_settings,
        patch("keycloak_operator.utils.keycloak_admin.settings") as mock_admin_settings,
    ):
        for s in [mock_svc_settings, mock_admin_settings]:
            s.allow_script_mappers = False
            s.drift_detection_enabled = False
            s.keycloak_url = "http://keycloak"
            s.keycloak_admin_secret = "secret"
            s.pod_namespace = "ns"
            s.allow_impersonation = False
        yield mock_svc_settings


@pytest.fixture
def reconciler(mock_settings):
    with (
        patch("keycloak_operator.utils.kubernetes.get_kubernetes_client"),
        patch("keycloak_operator.services.base_reconciler.client.ApiClient"),
    ):
        reconciler = KeycloakClientReconciler()
        reconciler.logger = MagicMock()
        reconciler.keycloak_admin_factory = AsyncMock()
        return reconciler


@pytest.mark.asyncio
async def test_admin_realm_role_blocked(reconciler):
    """Test that assigning 'admin' realm role is blocked."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"realmRoles": ["admin"]},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="(?i)restricted realm role 'admin'"):
        await reconciler.manage_service_account_roles(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_realm_admin_client_role_blocked(reconciler):
    """Test that assigning 'realm-admin' role from 'realm-management' is blocked."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["realm-admin"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(
        ValidationError, match="(?i)restricted client role 'realm-admin'"
    ):
        await reconciler.manage_service_account_roles(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_other_roles_allowed(reconciler):
    """Test that other roles are allowed."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {
            "realmRoles": ["user"],
            "clientRoles": {
                "realm-management": ["view-users"],
                "other-client": ["admin"],  # 'admin' on other clients is fine
            },
        },
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    # Mock admin client methods
    admin_client = AsyncMock()
    mock_user = MagicMock()
    mock_user.id = "user-id"
    admin_client.get_service_account_user.return_value = mock_user
    mock_client = MagicMock()
    mock_client.id = "target-client-uuid"
    admin_client.get_client_by_name.return_value = mock_client

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.manage_service_account_roles(
        spec=spec,
        client_uuid="uuid",
        name="test-client",
        namespace="test-ns",
        actual_realm_name="test-realm",
    )


@pytest.mark.asyncio
async def test_impersonation_blocked_by_default(reconciler):
    """Test that assigning 'impersonation' role is blocked by default."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["impersonation"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(
        ValidationError, match="(?i)restricted client role 'impersonation'"
    ):
        await reconciler.manage_service_account_roles(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_impersonation_allowed_when_enabled(reconciler, mock_settings):
    """Test that assigning 'impersonation' role is allowed when enabled in settings."""
    mock_settings.allow_impersonation = True

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["impersonation"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    admin_client = AsyncMock()
    mock_user = MagicMock()
    mock_user.id = "user-id"
    admin_client.get_service_account_user.return_value = mock_user
    mock_client = MagicMock()
    mock_client.id = "target-uuid"
    admin_client.get_client_by_name.return_value = mock_client

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.manage_service_account_roles(
        spec=spec,
        client_uuid="uuid",
        name="test-client",
        namespace="test-ns",
        actual_realm_name="test-realm",
    )


@pytest.mark.asyncio
async def test_script_mapper_blocked(reconciler):
    """Test that script mappers are blocked by default."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-script-based-protocol-mapper",
                "config": {"script": "1+1"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="(?i)script mapper .* not allowed"):
        await reconciler.configure_protocol_mappers(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_saml_script_mapper_blocked(reconciler):
    """Test that SAML script mappers are blocked."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "saml-script",
                "protocol": "saml",
                "protocolMapper": "saml-javascript-mapper",
                "config": {"script": "1+1"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="(?i)script mapper .* not allowed"):
        await reconciler.configure_protocol_mappers(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_case_insensitive_script_mapper_blocked(reconciler):
    """Test that script mapper check is case-insensitive."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "OIDC-SCRIPT-BASED-PROTOCOL-MAPPER",
                "config": {"script": "1+1"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="(?i)script mapper .* not allowed"):
        await reconciler.configure_protocol_mappers(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_combined_role_restrictions(reconciler):
    """Test that multiple role restrictions are enforced."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {
            "realmRoles": ["admin"],
            "clientRoles": {"realm-management": ["realm-admin"]},
        },
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError):
        await reconciler.manage_service_account_roles(
            spec=spec,
            client_uuid="uuid",
            name="test-client",
            namespace="test-ns",
            actual_realm_name="test-realm",
        )


@pytest.mark.asyncio
async def test_other_high_privilege_roles_blocked(reconciler):
    """Test that other high-privilege realm-management roles are blocked."""
    high_priv_roles = [
        "manage-realm",
        "manage-users",
        "manage-clients",
        "manage-identity-providers",
    ]

    for role in high_priv_roles:
        spec_dict = {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
            "serviceAccountRoles": {"clientRoles": {"realm-management": [role]}},
            "settings": {"serviceAccountsEnabled": True},
        }
        spec = KeycloakClientSpec.model_validate(spec_dict)

        with pytest.raises(
            ValidationError, match=f"(?i)restricted client role '{role}'"
        ):
            await reconciler.manage_service_account_roles(
                spec=spec,
                client_uuid="uuid",
                name="test-client",
                namespace="test-ns",
                actual_realm_name="test-realm",
            )


@pytest.mark.asyncio
async def test_script_mapper_allowed_with_setting(reconciler, mock_settings):
    """Test that script mappers are allowed when enabled in settings."""
    mock_settings.allow_script_mappers = True

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-script-based-protocol-mapper",
                "config": {"script": "1+1"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    admin_client = AsyncMock()
    admin_client.get_client_protocol_mappers.return_value = []
    admin_client.create_client_protocol_mapper.return_value = True
    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    await reconciler.configure_protocol_mappers(
        spec=spec,
        client_uuid="uuid",
        name="test-client",
        namespace="test-ns",
        actual_realm_name="test-realm",
    )
    admin_client.create_client_protocol_mapper.assert_called_once()
