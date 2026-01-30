"""Unit tests for security restrictions in client reconciler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.errors import ValidationError
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.fixture
def mock_settings():
    with patch(
        "keycloak_operator.services.client_reconciler.settings"
    ) as mock_settings:
        mock_settings.allow_script_mappers = False
        mock_settings.drift_detection_enabled = False
        yield mock_settings


@pytest.fixture
def reconciler(mock_settings):
    reconciler = KeycloakClientReconciler()
    reconciler.logger = MagicMock()
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

    with pytest.raises(ValidationError, match="restricted realm role 'admin'"):
        await reconciler.manage_service_account_roles(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
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

    with pytest.raises(ValidationError, match="restricted client role 'realm-admin'"):
        await reconciler.manage_service_account_roles(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
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
    # Mock get_service_account_user to return a user
    mock_user = MagicMock()
    mock_user.id = "user-id"
    admin_client.get_service_account_user.return_value = mock_user

    # Mock get_client_by_name for role assignment
    mock_client = MagicMock()
    mock_client.id = "target-client-uuid"
    admin_client.get_client_by_name.return_value = mock_client

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)
    # Mock _get_realm_info
    reconciler._get_realm_info = MagicMock(return_value=("test-realm", "ns", "kc", {}))

    # Should not raise exception
    await reconciler.manage_service_account_roles(
        spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
    )


@pytest.mark.asyncio
async def test_impersonation_blocked_by_default(reconciler, mock_settings):
    """Test that impersonation role is blocked by default."""
    mock_settings.allow_impersonation = False
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["impersonation"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="restricted client role 'impersonation'"):
        await reconciler.manage_service_account_roles(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_impersonation_allowed_when_enabled(reconciler, mock_settings):
    """Test that impersonation role is allowed when setting is enabled."""
    mock_settings.allow_impersonation = True
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["impersonation"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    # Mock admin client
    admin_client = AsyncMock()
    mock_user = MagicMock()
    mock_user.id = "user-id"
    admin_client.get_service_account_user.return_value = mock_user

    mock_client = MagicMock()
    mock_client.id = "target-client-uuid"
    admin_client.get_client_by_name.return_value = mock_client

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)
    reconciler._get_realm_info = MagicMock(return_value=("test-realm", "ns", "kc", {}))

    # Should not raise exception
    await reconciler.manage_service_account_roles(
        spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
    )


@pytest.mark.asyncio
async def test_script_mapper_blocked(reconciler, mock_settings):
    """Test that script mappers are blocked when setting is False."""
    mock_settings.allow_script_mappers = False

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-script-based-protocol-mapper",
                "config": {"script": "foo"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(
        ValidationError, match="Script mapper 'script-mapper' .* is not allowed"
    ):
        await reconciler.configure_protocol_mappers(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_saml_script_mapper_blocked(reconciler, mock_settings):
    """Test that SAML script mappers are blocked."""
    mock_settings.allow_script_mappers = False

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "saml",
                "protocolMapper": "saml-javascript-mapper",
                "config": {"script": "foo"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(
        ValidationError, match="Script mapper 'script-mapper' .* is not allowed"
    ):
        await reconciler.configure_protocol_mappers(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_case_insensitive_script_mapper_blocked(reconciler, mock_settings):
    """Test that script mappers are blocked regardless of case."""
    mock_settings.allow_script_mappers = False

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "OIDC-SCRIPT-BASED-PROTOCOL-MAPPER",
                "config": {"script": "foo"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(
        ValidationError, match="Script mapper 'script-mapper' .* is not allowed"
    ):
        await reconciler.configure_protocol_mappers(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_combined_role_restrictions(reconciler):
    """Test combined realm and client role restrictions."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {
            "realmRoles": ["admin"],
            "clientRoles": {"realm-management": ["manage-users"]},
        },
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    # Should raise error for the first violation encountered
    with pytest.raises(ValidationError):
        await reconciler.manage_service_account_roles(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_other_high_privilege_roles_blocked(reconciler):
    """Test that other high-privilege roles like manage-users are blocked."""
    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "serviceAccountRoles": {"clientRoles": {"realm-management": ["manage-users"]}},
        "settings": {"serviceAccountsEnabled": True},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ValidationError, match="restricted client role 'manage-users'"):
        await reconciler.manage_service_account_roles(
            spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
        )


@pytest.mark.asyncio
async def test_script_mapper_allowed_with_setting(reconciler, mock_settings):
    """Test that script mappers are allowed when setting is True."""
    mock_settings.allow_script_mappers = True

    spec_dict = {
        "clientId": "test-client",
        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
        "protocolMappers": [
            {
                "name": "script-mapper",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-script-based-protocol-mapper",
                "config": {"script": "foo"},
            }
        ],
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    # Mock admin client
    admin_client = AsyncMock()
    # Return existing mappers (empty list)
    admin_client.get_client_protocol_mappers.return_value = []

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)
    reconciler._get_realm_info = MagicMock(return_value=("test-realm", "ns", "kc", {}))

    # Should not raise exception
    await reconciler.configure_protocol_mappers(
        spec=spec, client_uuid="uuid", name="test-client", namespace="test-ns"
    )

    # Verify create called
    admin_client.create_client_protocol_mapper.assert_called_once()
