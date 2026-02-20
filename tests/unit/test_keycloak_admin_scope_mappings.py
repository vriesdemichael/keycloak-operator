from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.keycloak_api import RoleRepresentation
from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminClient,
)


@pytest.fixture
def mock_admin_client():
    client = KeycloakAdminClient("http://test", "admin", "password")
    client._get_client = AsyncMock()  # type: ignore
    client._ensure_authenticated = AsyncMock()  # type: ignore
    client.adapter = MagicMock()
    # Mock adapter methods
    client.adapter.get_scope_mappings_realm_roles_path = MagicMock(
        side_effect=lambda r, c=None, cs=None: (
            f"realms/{r}/scope-mappings/realm"
            if not c and not cs
            else (
                f"realms/{r}/clients/{c}/scope-mappings/realm"
                if c
                else f"realms/{r}/client-scopes/{cs}/scope-mappings/realm"
            )
        )
    )
    client.adapter.get_scope_mappings_client_roles_path = MagicMock(
        side_effect=lambda r, rc, c=None, cs=None: (
            f"realms/{r}/scope-mappings/clients/{rc}"
            if not c and not cs
            else (
                f"realms/{r}/clients/{c}/scope-mappings/clients/{rc}"
                if c
                else f"realms/{r}/client-scopes/{cs}/scope-mappings/clients/{rc}"
            )
        )
    )
    return client


@pytest.mark.asyncio
async def test_add_scope_mappings_realm_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    roles = [RoleRepresentation(name="role1", id="id1")]

    # Test client mapping
    await mock_admin_client.add_scope_mappings_realm_roles(
        "test-realm", roles, client_id="client-uuid"
    )

    mock_admin_client._make_request.assert_called_with(
        "POST",
        "realms/test-realm/clients/client-uuid/scope-mappings/realm",
        "default",
        json=[{"id": "id1", "name": "role1"}],
    )

    # Test client scope mapping
    await mock_admin_client.add_scope_mappings_realm_roles(
        "test-realm", roles, client_scope_id="scope-id"
    )

    mock_admin_client._make_request.assert_called_with(
        "POST",
        "realms/test-realm/client-scopes/scope-id/scope-mappings/realm",
        "default",
        json=[{"id": "id1", "name": "role1"}],
    )


@pytest.mark.asyncio
async def test_add_scope_mappings_client_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    roles = [RoleRepresentation(name="role1", id="id1")]

    # Test client mapping
    await mock_admin_client.add_scope_mappings_client_roles(
        "test-realm", "source-client-uuid", roles, client_id="client-uuid"
    )

    mock_admin_client._make_request.assert_called_with(
        "POST",
        "realms/test-realm/clients/client-uuid/scope-mappings/clients/source-client-uuid",
        "default",
        json=[{"id": "id1", "name": "role1"}],
    )


@pytest.mark.asyncio
async def test_remove_scope_mappings_realm_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    roles = [RoleRepresentation(name="role1", id="id1")]

    await mock_admin_client.remove_scope_mappings_realm_roles(
        "test-realm", roles, client_id="client-uuid"
    )

    mock_admin_client._make_request.assert_called_with(
        "DELETE",
        "realms/test-realm/clients/client-uuid/scope-mappings/realm",
        "default",
        json=[{"id": "id1", "name": "role1"}],
    )


@pytest.mark.asyncio
async def test_get_scope_mappings_realm_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"name": "role1", "id": "id1"}]
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    # Test client mapping
    roles = await mock_admin_client.get_scope_mappings_realm_roles(
        "test-realm", client_id="client-uuid"
    )
    assert len(roles) == 1
    assert roles[0].name == "role1"

    mock_admin_client._make_request.assert_called_with(
        "GET", "realms/test-realm/clients/client-uuid/scope-mappings/realm", "default"
    )


@pytest.mark.asyncio
async def test_get_scope_mappings_client_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"name": "role1", "id": "id1"}]
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    # Test client mapping
    roles = await mock_admin_client.get_scope_mappings_client_roles(
        "test-realm", "source-uuid", client_id="client-uuid"
    )
    assert len(roles) == 1
    assert roles[0].name == "role1"

    mock_admin_client._make_request.assert_called_with(
        "GET",
        "realms/test-realm/clients/client-uuid/scope-mappings/clients/source-uuid",
        "default",
    )


@pytest.mark.asyncio
async def test_remove_scope_mappings_client_roles(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    roles = [RoleRepresentation(name="role1", id="id1")]

    await mock_admin_client.remove_scope_mappings_client_roles(
        "test-realm", "source-uuid", roles, client_id="client-uuid"
    )

    mock_admin_client._make_request.assert_called_with(
        "DELETE",
        "realms/test-realm/clients/client-uuid/scope-mappings/clients/source-uuid",
        "default",
        json=[{"id": "id1", "name": "role1"}],
    )


@pytest.mark.asyncio
async def test_remove_realm_role_composites(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)
    mock_admin_client.adapter.get_realm_role_composites_path.return_value = (
        "realms/test-realm/roles/parent/composites"
    )

    roles = [RoleRepresentation(name="child1", id="cid1")]

    await mock_admin_client.remove_realm_role_composites("test-realm", "parent", roles)

    mock_admin_client._make_request.assert_called_with(
        "DELETE",
        "realms/test-realm/roles/parent/composites",
        "default",
        json=[{"id": "cid1", "name": "child1"}],
    )


@pytest.mark.asyncio
async def test_admin_error_handling(mock_admin_client):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_admin_client._make_request = AsyncMock(return_value=mock_response)

    # get_scope_mappings_realm_roles uses @api_get_list which swallows exceptions and returns []
    roles = await mock_admin_client.get_scope_mappings_realm_roles(
        "test-realm", client_id="client-uuid"
    )
    assert roles == []
