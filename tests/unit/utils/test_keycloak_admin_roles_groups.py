"""Unit tests for KeycloakAdminClient realm roles and groups methods."""

from unittest.mock import AsyncMock

import pytest

from keycloak_operator.models.keycloak_api import (
    GroupRepresentation,
    RoleRepresentation,
)


class MockResponse:
    """Mock HTTP response object."""

    def __init__(self, status_code: int, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def json(self):
        return self._json_data


@pytest.fixture
def mock_admin_client():
    """Create a mock KeycloakAdminClient for testing."""
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

    client = object.__new__(KeycloakAdminClient)
    client.server_url = "http://keycloak:8080"
    client.username = "admin"
    client.password = "admin"
    client.admin_realm = "master"
    client.client_id = "admin-cli"
    client.verify_ssl = True
    client.timeout = 60
    client.rate_limiter = None
    client.access_token = "test-token"
    client.refresh_token = None
    client.token_expires_at = 9999999999.0
    return client


# =============================================================================
# Realm Roles API Tests
# =============================================================================


class TestGetRealmRoles:
    """Tests for get_realm_roles method."""

    @pytest.mark.asyncio
    async def test_returns_list_of_roles(self, mock_admin_client):
        """Should return list of realm roles."""
        mock_response = MockResponse(
            200,
            [
                {"name": "admin", "description": "Administrator"},
                {"name": "user", "description": "Regular user"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = await mock_admin_client.get_realm_roles("test-realm", "default")

        assert len(roles) == 2
        assert roles[0].name == "admin"
        assert roles[1].name == "user"
        mock_admin_client._make_request.assert_called_once_with(
            "GET", "realms/test-realm/roles", "default"
        )

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_error(self, mock_admin_client):
        """Should return empty list on error response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = await mock_admin_client.get_realm_roles("test-realm", "default")

        assert roles == []


class TestGetRealmRoleByName:
    """Tests for get_realm_role_by_name method."""

    @pytest.mark.asyncio
    async def test_returns_role_when_found(self, mock_admin_client):
        """Should return role when it exists."""
        mock_response = MockResponse(
            200,
            {"name": "admin", "description": "Administrator", "composite": True},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        role = await mock_admin_client.get_realm_role_by_name(
            "test-realm", "admin", "default"
        )

        assert role is not None
        assert role.name == "admin"
        assert role.description == "Administrator"
        assert role.composite is True

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when role doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        role = await mock_admin_client.get_realm_role_by_name(
            "test-realm", "nonexistent", "default"
        )

        assert role is None


class TestCreateRealmRole:
    """Tests for create_realm_role method."""

    @pytest.mark.asyncio
    async def test_creates_role_successfully(self, mock_admin_client):
        """Should create role and return True on success."""
        mock_response = MockResponse(201)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        role = RoleRepresentation(name="admin", description="Administrator")
        result = await mock_admin_client.create_realm_role(
            "test-realm", role, "default"
        )

        assert result is True
        mock_admin_client._make_validated_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_true_on_conflict(self, mock_admin_client):
        """Should return True when role already exists (409 conflict)."""
        mock_response = MockResponse(409)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        role = RoleRepresentation(name="admin")
        result = await mock_admin_client.create_realm_role(
            "test-realm", role, "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_error(self, mock_admin_client):
        """Should return False on error response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        role = RoleRepresentation(name="admin")
        result = await mock_admin_client.create_realm_role(
            "test-realm", role, "default"
        )

        assert result is False


class TestUpdateRealmRole:
    """Tests for update_realm_role method."""

    @pytest.mark.asyncio
    async def test_updates_role_successfully(self, mock_admin_client):
        """Should update role and return True on success."""
        mock_response = MockResponse(204)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        role = RoleRepresentation(name="admin", description="Updated description")
        result = await mock_admin_client.update_realm_role(
            "test-realm", "admin", role, "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_error(self, mock_admin_client):
        """Should return False on error response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        role = RoleRepresentation(name="admin")
        result = await mock_admin_client.update_realm_role(
            "test-realm", "admin", role, "default"
        )

        assert result is False


class TestDeleteRealmRole:
    """Tests for delete_realm_role method."""

    @pytest.mark.asyncio
    async def test_deletes_role_successfully(self, mock_admin_client):
        """Should delete role and return True on success."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_realm_role(
            "test-realm", "admin", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_when_not_found(self, mock_admin_client):
        """Should return True when role doesn't exist (already deleted)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_realm_role(
            "test-realm", "nonexistent", "default"
        )

        assert result is True


class TestRealmRoleComposites:
    """Tests for composite role methods."""

    @pytest.mark.asyncio
    async def test_get_composites_returns_roles(self, mock_admin_client):
        """Should return list of composite child roles."""
        mock_response = MockResponse(
            200,
            [
                {"name": "user", "description": "User role"},
                {"name": "viewer", "description": "Viewer role"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = await mock_admin_client.get_realm_role_composites(
            "test-realm", "admin", "default"
        )

        assert len(roles) == 2
        assert roles[0].name == "user"

    @pytest.mark.asyncio
    async def test_add_composites_successfully(self, mock_admin_client):
        """Should add composite roles and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        child_roles = [RoleRepresentation(name="user", id="user-id")]
        result = await mock_admin_client.add_realm_role_composites(
            "test-realm", "admin", child_roles, "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_remove_composites_successfully(self, mock_admin_client):
        """Should remove composite roles and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        child_roles = [RoleRepresentation(name="user", id="user-id")]
        result = await mock_admin_client.remove_realm_role_composites(
            "test-realm", "admin", child_roles, "default"
        )

        assert result is True


# =============================================================================
# Groups API Tests
# =============================================================================


class TestGetGroups:
    """Tests for get_groups method."""

    @pytest.mark.asyncio
    async def test_returns_list_of_groups(self, mock_admin_client):
        """Should return list of top-level groups."""
        mock_response = MockResponse(
            200,
            [
                {"id": "group-1", "name": "engineering", "path": "/engineering"},
                {"id": "group-2", "name": "admins", "path": "/admins"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        groups = await mock_admin_client.get_groups("test-realm", "default")

        assert len(groups) == 2
        assert groups[0].name == "engineering"
        assert groups[1].name == "admins"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_error(self, mock_admin_client):
        """Should return empty list on error response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        groups = await mock_admin_client.get_groups("test-realm", "default")

        assert groups == []


class TestGetGroupById:
    """Tests for get_group_by_id method."""

    @pytest.mark.asyncio
    async def test_returns_group_when_found(self, mock_admin_client):
        """Should return group when it exists."""
        mock_response = MockResponse(
            200,
            {
                "id": "group-1",
                "name": "engineering",
                "path": "/engineering",
                "attributes": {"department": ["Engineering"]},
            },
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        group = await mock_admin_client.get_group_by_id(
            "test-realm", "group-1", "default"
        )

        assert group is not None
        assert group.name == "engineering"
        assert group.attributes == {"department": ["Engineering"]}

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when group doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        group = await mock_admin_client.get_group_by_id(
            "test-realm", "nonexistent", "default"
        )

        assert group is None


class TestGetGroupByPath:
    """Tests for get_group_by_path method."""

    @pytest.mark.asyncio
    async def test_returns_group_when_found(self, mock_admin_client):
        """Should return group when path exists."""
        mock_response = MockResponse(
            200,
            {
                "id": "group-1",
                "name": "backend",
                "path": "/engineering/backend",
            },
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        group = await mock_admin_client.get_group_by_path(
            "test-realm", "/engineering/backend", "default"
        )

        assert group is not None
        assert group.name == "backend"
        assert group.path == "/engineering/backend"


class TestCreateGroup:
    """Tests for create_group method."""

    @pytest.mark.asyncio
    async def test_creates_group_successfully(self, mock_admin_client):
        """Should create group and return group ID on success."""
        mock_response = MockResponse(
            201, headers={"Location": "http://keycloak/groups/new-group-id"}
        )
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        group = GroupRepresentation(name="engineering")
        group_id = await mock_admin_client.create_group("test-realm", group, "default")

        assert group_id == "new-group-id"

    @pytest.mark.asyncio
    async def test_returns_existing_id_on_conflict(self, mock_admin_client):
        """Should return existing group ID when group already exists."""
        mock_conflict_response = MockResponse(409)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_conflict_response
        )

        # Mock get_group_by_path to return existing group
        mock_admin_client.get_group_by_path = AsyncMock(
            return_value=GroupRepresentation(id="existing-id", name="engineering")
        )

        group = GroupRepresentation(name="engineering")
        group_id = await mock_admin_client.create_group("test-realm", group, "default")

        assert group_id == "existing-id"


class TestCreateSubgroup:
    """Tests for create_subgroup method."""

    @pytest.mark.asyncio
    async def test_creates_subgroup_successfully(self, mock_admin_client):
        """Should create subgroup and return subgroup ID."""
        mock_response = MockResponse(
            201, headers={"Location": "http://keycloak/groups/sub-group-id"}
        )
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        subgroup = GroupRepresentation(name="backend")
        group_id = await mock_admin_client.create_subgroup(
            "test-realm", "parent-id", subgroup, "default"
        )

        assert group_id == "sub-group-id"


class TestUpdateGroup:
    """Tests for update_group method."""

    @pytest.mark.asyncio
    async def test_updates_group_successfully(self, mock_admin_client):
        """Should update group and return True on success."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        group = GroupRepresentation(name="engineering", attributes={"updated": ["yes"]})
        result = await mock_admin_client.update_group(
            "test-realm", "group-id", group, "default"
        )

        assert result is True


class TestDeleteGroup:
    """Tests for delete_group method."""

    @pytest.mark.asyncio
    async def test_deletes_group_successfully(self, mock_admin_client):
        """Should delete group and return True on success."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_group(
            "test-realm", "group-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_when_not_found(self, mock_admin_client):
        """Should return True when group doesn't exist (already deleted)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_group(
            "test-realm", "nonexistent", "default"
        )

        assert result is True


class TestGroupRoleMappings:
    """Tests for group role mapping methods."""

    @pytest.mark.asyncio
    async def test_get_group_realm_role_mappings(self, mock_admin_client):
        """Should return list of assigned realm roles."""
        mock_response = MockResponse(
            200,
            [
                {"name": "user", "id": "role-1"},
                {"name": "developer", "id": "role-2"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = await mock_admin_client.get_group_realm_role_mappings(
            "test-realm", "group-id", "default"
        )

        assert len(roles) == 2
        assert roles[0].name == "user"

    @pytest.mark.asyncio
    async def test_assign_realm_roles_to_group(self, mock_admin_client):
        """Should assign realm roles to group and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = [RoleRepresentation(name="user", id="role-id")]
        result = await mock_admin_client.assign_realm_roles_to_group(
            "test-realm", "group-id", roles, "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_remove_realm_roles_from_group(self, mock_admin_client):
        """Should remove realm roles from group and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        roles = [RoleRepresentation(name="user", id="role-id")]
        result = await mock_admin_client.remove_realm_roles_from_group(
            "test-realm", "group-id", roles, "default"
        )

        assert result is True


class TestDefaultGroups:
    """Tests for default group methods."""

    @pytest.mark.asyncio
    async def test_get_default_groups(self, mock_admin_client):
        """Should return list of default groups."""
        mock_response = MockResponse(
            200,
            [
                {"id": "group-1", "name": "users", "path": "/users"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        groups = await mock_admin_client.get_default_groups("test-realm", "default")

        assert len(groups) == 1
        assert groups[0].name == "users"

    @pytest.mark.asyncio
    async def test_add_default_group(self, mock_admin_client):
        """Should add group to defaults and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.add_default_group(
            "test-realm", "group-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_remove_default_group(self, mock_admin_client):
        """Should remove group from defaults and return True."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.remove_default_group(
            "test-realm", "group-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_remove_default_group_returns_true_when_not_found(
        self, mock_admin_client
    ):
        """Should return True when group was not a default (already removed)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.remove_default_group(
            "test-realm", "nonexistent", "default"
        )

        assert result is True
