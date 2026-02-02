"""Unit tests for KeycloakAdminClient authorization methods."""

from unittest.mock import AsyncMock

import pytest

from .test_helpers import MockResponse


class TestGetAuthorizationScopes:
    """Tests for get_authorization_scopes method."""

    @pytest.mark.asyncio
    async def test_returns_scopes_on_success(self, mock_admin_client):
        """Should return list of scopes when successful."""
        mock_response = MockResponse(
            200,
            [
                {"id": "scope-1", "name": "read"},
                {"id": "scope-2", "name": "write"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        scopes = await mock_admin_client.get_authorization_scopes(
            "test-realm", "client-uuid", "default"
        )

        assert len(scopes) == 2
        assert scopes[0]["name"] == "read"
        assert scopes[1]["name"] == "write"
        mock_admin_client._make_request.assert_called_once_with(
            "GET",
            "realms/test-realm/clients/client-uuid/authz/resource-server/scope",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when resource server not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        scopes = await mock_admin_client.get_authorization_scopes(
            "test-realm", "client-uuid", "default"
        )

        assert scopes == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_error(self, mock_admin_client):
        """Should return empty list on unexpected status code (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_get_list decorator catches the error and returns []
        scopes = await mock_admin_client.get_authorization_scopes(
            "test-realm", "client-uuid", "default"
        )

        assert scopes == []


class TestCreateAuthorizationScope:
    """Tests for create_authorization_scope method."""

    @pytest.mark.asyncio
    async def test_returns_scope_on_success(self, mock_admin_client):
        """Should return created scope on success."""
        mock_response = MockResponse(
            201,
            {"id": "scope-1", "name": "read", "displayName": "Read Access"},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        scope = await mock_admin_client.create_authorization_scope(
            "test-realm",
            "client-uuid",
            {"name": "read", "displayName": "Read Access"},
            "default",
        )

        assert scope is not None
        assert scope["id"] == "scope-1"
        assert scope["name"] == "read"

    @pytest.mark.asyncio
    async def test_returns_none_on_conflict(self, mock_admin_client):
        """Should return None when scope already exists (409)."""
        mock_response = MockResponse(409)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        scope = await mock_admin_client.create_authorization_scope(
            "test-realm",
            "client-uuid",
            {"name": "read"},
            "default",
        )

        assert scope is None

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on unexpected status code (decorator catches error)."""
        mock_response = MockResponse(500, text="Internal Server Error")
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_create decorator catches the error and returns None
        scope = await mock_admin_client.create_authorization_scope(
            "test-realm",
            "client-uuid",
            {"name": "read"},
            "default",
        )

        assert scope is None


class TestDeleteAuthorizationScope:
    """Tests for delete_authorization_scope method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful deletion."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_scope(
            "test-realm", "client-uuid", "scope-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when scope doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_scope(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on unexpected status code (decorator catches error)."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_delete decorator catches the error and returns False
        result = await mock_admin_client.delete_authorization_scope(
            "test-realm", "client-uuid", "scope-id", "default"
        )

        assert result is False


class TestGetAuthorizationResources:
    """Tests for get_authorization_resources method."""

    @pytest.mark.asyncio
    async def test_returns_resources_on_success(self, mock_admin_client):
        """Should return list of resources when successful."""
        mock_response = MockResponse(
            200,
            [
                {"_id": "res-1", "name": "documents", "uris": ["/api/documents/*"]},
                {"_id": "res-2", "name": "users", "uris": ["/api/users/*"]},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        resources = await mock_admin_client.get_authorization_resources(
            "test-realm", "client-uuid", "default"
        )

        assert len(resources) == 2
        assert resources[0]["name"] == "documents"
        assert resources[1]["name"] == "users"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when resource server not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        resources = await mock_admin_client.get_authorization_resources(
            "test-realm", "client-uuid", "default"
        )

        assert resources == []


class TestCreateAuthorizationResource:
    """Tests for create_authorization_resource method."""

    @pytest.mark.asyncio
    async def test_returns_resource_on_success(self, mock_admin_client):
        """Should return created resource on success."""
        mock_response = MockResponse(
            201,
            {"_id": "res-1", "name": "documents", "uris": ["/api/documents/*"]},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        resource = await mock_admin_client.create_authorization_resource(
            "test-realm",
            "client-uuid",
            {"name": "documents", "uris": ["/api/documents/*"]},
            "default",
        )

        assert resource is not None
        assert resource["_id"] == "res-1"
        assert resource["name"] == "documents"

    @pytest.mark.asyncio
    async def test_returns_none_on_conflict(self, mock_admin_client):
        """Should return None when resource already exists (409)."""
        mock_response = MockResponse(409)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        resource = await mock_admin_client.create_authorization_resource(
            "test-realm",
            "client-uuid",
            {"name": "documents"},
            "default",
        )

        assert resource is None


class TestUpdateAuthorizationResource:
    """Tests for update_authorization_resource method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful update."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_resource(
            "test-realm",
            "client-uuid",
            "res-id",
            {"name": "documents", "uris": ["/api/docs/*"]},
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_not_found(self, mock_admin_client):
        """Should return False when resource doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_resource(
            "test-realm",
            "client-uuid",
            "nonexistent",
            {"name": "documents"},
            "default",
        )

        assert result is False


class TestDeleteAuthorizationResource:
    """Tests for delete_authorization_resource method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful deletion."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_resource(
            "test-realm", "client-uuid", "res-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when resource doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_resource(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert result is True


class TestGetAuthorizationPolicies:
    """Tests for get_authorization_policies method."""

    @pytest.mark.asyncio
    async def test_returns_policies_on_success(self, mock_admin_client):
        """Should return list of policies when successful."""
        mock_response = MockResponse(
            200,
            [
                {"id": "pol-1", "name": "admin-policy", "type": "role"},
                {"id": "pol-2", "name": "user-policy", "type": "user"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policies = await mock_admin_client.get_authorization_policies(
            "test-realm", "client-uuid", "default"
        )

        assert len(policies) == 2
        assert policies[0]["name"] == "admin-policy"
        assert policies[1]["name"] == "user-policy"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when resource server not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policies = await mock_admin_client.get_authorization_policies(
            "test-realm", "client-uuid", "default"
        )

        assert policies == []


class TestGetAuthorizationPolicyByName:
    """Tests for get_authorization_policy_by_name method."""

    @pytest.mark.asyncio
    async def test_returns_policy_when_found(self, mock_admin_client):
        """Should return policy when it exists."""
        mock_response = MockResponse(
            200,
            [{"id": "pol-1", "name": "admin-policy", "type": "role"}],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policy = await mock_admin_client.get_authorization_policy_by_name(
            "test-realm", "client-uuid", "admin-policy", "default"
        )

        assert policy is not None
        assert policy["name"] == "admin-policy"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when policy doesn't exist."""
        mock_response = MockResponse(200, [])
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policy = await mock_admin_client.get_authorization_policy_by_name(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert policy is None

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self, mock_admin_client):
        """Should return None when resource server not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policy = await mock_admin_client.get_authorization_policy_by_name(
            "test-realm", "client-uuid", "admin-policy", "default"
        )

        assert policy is None


class TestCreateAuthorizationPolicy:
    """Tests for create_authorization_policy method."""

    @pytest.mark.asyncio
    async def test_returns_policy_on_success(self, mock_admin_client):
        """Should return created policy on success."""
        mock_response = MockResponse(
            201,
            {"id": "pol-1", "name": "admin-policy", "type": "role"},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        policy = await mock_admin_client.create_authorization_policy(
            "test-realm",
            "client-uuid",
            "role",
            {"name": "admin-policy", "roles": [{"id": "role-1"}]},
            "default",
        )

        assert policy is not None
        assert policy["name"] == "admin-policy"

    @pytest.mark.asyncio
    async def test_returns_existing_on_conflict(self, mock_admin_client):
        """Should return existing policy on conflict (409)."""
        mock_conflict_response = MockResponse(409)
        mock_get_response = MockResponse(
            200,
            [{"id": "pol-1", "name": "admin-policy", "type": "role"}],
        )
        mock_admin_client._make_request = AsyncMock(
            side_effect=[mock_conflict_response, mock_get_response]
        )

        policy = await mock_admin_client.create_authorization_policy(
            "test-realm",
            "client-uuid",
            "role",
            {"name": "admin-policy", "roles": [{"id": "role-1"}]},
            "default",
        )

        assert policy is not None
        assert policy["name"] == "admin-policy"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on unexpected status code (decorator catches error)."""
        mock_response = MockResponse(500, text="Internal Server Error")
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        # The @api_create decorator catches the error and returns None
        policy = await mock_admin_client.create_authorization_policy(
            "test-realm",
            "client-uuid",
            "role",
            {"name": "admin-policy"},
            "default",
        )

        assert policy is None


class TestUpdateAuthorizationPolicy:
    """Tests for update_authorization_policy method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful update."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_policy(
            "test-realm",
            "client-uuid",
            "role",
            "pol-id",
            {"name": "admin-policy", "roles": [{"id": "role-1"}]},
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_not_found(self, mock_admin_client):
        """Should return False when policy doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_policy(
            "test-realm",
            "client-uuid",
            "role",
            "nonexistent",
            {"name": "admin-policy"},
            "default",
        )

        assert result is False


class TestDeleteAuthorizationPolicy:
    """Tests for delete_authorization_policy method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful deletion."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_policy(
            "test-realm", "client-uuid", "pol-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when policy doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_policy(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert result is True


class TestGetAuthorizationPermissions:
    """Tests for get_authorization_permissions method."""

    @pytest.mark.asyncio
    async def test_returns_permissions_on_success(self, mock_admin_client):
        """Should return list of permissions when successful."""
        mock_response = MockResponse(
            200,
            [
                {"id": "perm-1", "name": "doc-access", "type": "resource"},
                {"id": "perm-2", "name": "read-scope", "type": "scope"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        permissions = await mock_admin_client.get_authorization_permissions(
            "test-realm", "client-uuid", "default"
        )

        assert len(permissions) == 2
        assert permissions[0]["name"] == "doc-access"
        assert permissions[1]["name"] == "read-scope"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_404(self, mock_admin_client):
        """Should return empty list when resource server not found."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        permissions = await mock_admin_client.get_authorization_permissions(
            "test-realm", "client-uuid", "default"
        )

        assert permissions == []


class TestGetAuthorizationPermissionByName:
    """Tests for get_authorization_permission_by_name method."""

    @pytest.mark.asyncio
    async def test_returns_permission_when_found(self, mock_admin_client):
        """Should return permission when it exists."""
        mock_response = MockResponse(
            200,
            [{"id": "perm-1", "name": "doc-access", "type": "resource"}],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        permission = await mock_admin_client.get_authorization_permission_by_name(
            "test-realm", "client-uuid", "doc-access", "default"
        )

        assert permission is not None
        assert permission["name"] == "doc-access"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when permission doesn't exist."""
        mock_response = MockResponse(200, [])
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        permission = await mock_admin_client.get_authorization_permission_by_name(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert permission is None


class TestCreateAuthorizationPermission:
    """Tests for create_authorization_permission method."""

    @pytest.mark.asyncio
    async def test_returns_permission_on_success(self, mock_admin_client):
        """Should return created permission on success."""
        # The create method calls get_authorization_permission_by_name on success
        mock_create_response = MockResponse(201, {})
        mock_get_response = MockResponse(
            200,
            [{"id": "perm-1", "name": "doc-access", "type": "resource"}],
        )
        mock_admin_client._make_request = AsyncMock(
            side_effect=[mock_create_response, mock_get_response]
        )

        permission = await mock_admin_client.create_authorization_permission(
            "test-realm",
            "client-uuid",
            "resource",
            {"name": "doc-access", "resources": ["documents"]},
            "default",
        )

        assert permission is not None
        assert permission["name"] == "doc-access"

    @pytest.mark.asyncio
    async def test_returns_existing_on_conflict(self, mock_admin_client):
        """Should return existing permission on conflict (409)."""
        mock_conflict_response = MockResponse(409)
        mock_get_response = MockResponse(
            200,
            [{"id": "perm-1", "name": "doc-access", "type": "resource"}],
        )
        mock_admin_client._make_request = AsyncMock(
            side_effect=[mock_conflict_response, mock_get_response]
        )

        permission = await mock_admin_client.create_authorization_permission(
            "test-realm",
            "client-uuid",
            "resource",
            {"name": "doc-access", "resources": ["documents"]},
            "default",
        )

        assert permission is not None
        assert permission["name"] == "doc-access"


class TestUpdateAuthorizationPermission:
    """Tests for update_authorization_permission method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful update."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_permission(
            "test-realm",
            "client-uuid",
            "resource",
            "perm-id",
            {"name": "doc-access", "resources": ["documents", "files"]},
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_not_found(self, mock_admin_client):
        """Should return False when permission doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_authorization_permission(
            "test-realm",
            "client-uuid",
            "resource",
            "nonexistent",
            {"name": "doc-access"},
            "default",
        )

        assert result is False


class TestDeleteAuthorizationPermission:
    """Tests for delete_authorization_permission method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True on successful deletion."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_permission(
            "test-realm", "client-uuid", "perm-id", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when permission doesn't exist (idempotent)."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authorization_permission(
            "test-realm", "client-uuid", "nonexistent", "default"
        )

        assert result is True
