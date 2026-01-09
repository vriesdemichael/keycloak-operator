"""Unit tests for KeycloakAdminClient user federation methods."""

from unittest.mock import AsyncMock

import pytest

from keycloak_operator.models.keycloak_api import ComponentRepresentation
from keycloak_operator.utils.keycloak_admin import KeycloakAdminError


class MockResponse:
    """Mock HTTP response object."""

    def __init__(self, status_code: int, json_data=None, headers=None, text=""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}
        self.text = text

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


class TestTriggerUserFederationSync:
    """Tests for trigger_user_federation_sync method."""

    @pytest.mark.asyncio
    async def test_full_sync_returns_result(self, mock_admin_client):
        """Should return sync result on successful full sync."""
        sync_result = {"added": 5, "updated": 2, "removed": 0, "failed": 0}
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, sync_result)
        )

        result = await mock_admin_client.trigger_user_federation_sync(
            "test-realm", "provider-123", full_sync=True, namespace="default"
        )

        assert result == sync_result
        mock_admin_client._make_request.assert_called_once()
        # The action is passed as a query param
        call_args = mock_admin_client._make_request.call_args
        assert "sync" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_changed_users_sync(self, mock_admin_client):
        """Should trigger changed users sync when full_sync=False."""
        sync_result = {"added": 1, "updated": 0, "removed": 0, "failed": 0}
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, sync_result)
        )

        result = await mock_admin_client.trigger_user_federation_sync(
            "test-realm", "provider-123", full_sync=False, namespace="default"
        )

        assert result == sync_result
        # Verify the method was called
        mock_admin_client._make_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_failure_raises_error(self, mock_admin_client):
        """Should raise KeycloakAdminError on sync failure."""
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(400, text="Bad Request")
        )

        with pytest.raises(KeycloakAdminError):
            await mock_admin_client.trigger_user_federation_sync(
                "test-realm", "provider-123", full_sync=True, namespace="default"
            )


class TestTestLdapConnection:
    """Tests for test_ldap_connection method."""

    @pytest.mark.asyncio
    async def test_connection_success(self, mock_admin_client):
        """Should return success status on 204 response."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(204))

        result = await mock_admin_client.test_ldap_connection(
            "test-realm",
            {"connectionUrl": "ldap://localhost:389"},
            namespace="default",
        )

        assert result["status"] == "success"
        assert "successful" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_connection_failure(self, mock_admin_client):
        """Should return failed status on non-204 response."""
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(400, text="Connection refused")
        )

        result = await mock_admin_client.test_ldap_connection(
            "test-realm",
            {"connectionUrl": "ldap://invalid:389"},
            namespace="default",
        )

        assert result["status"] == "failed"


class TestTestLdapAuthentication:
    """Tests for test_ldap_authentication method."""

    @pytest.mark.asyncio
    async def test_auth_success(self, mock_admin_client):
        """Should return success status on 204 response."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(204))

        result = await mock_admin_client.test_ldap_authentication(
            "test-realm",
            {
                "connectionUrl": "ldap://localhost:389",
                "bindDn": "cn=admin,dc=example,dc=org",
                "bindCredential": "secret",
            },
            namespace="default",
        )

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_auth_failure(self, mock_admin_client):
        """Should return failed status on non-204 response."""
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(400, text="Invalid credentials")
        )

        result = await mock_admin_client.test_ldap_authentication(
            "test-realm",
            {
                "connectionUrl": "ldap://localhost:389",
                "bindDn": "cn=admin,dc=example,dc=org",
                "bindCredential": "wrong",
            },
            namespace="default",
        )

        assert result["status"] == "failed"


class TestGetUserFederationProvider:
    """Tests for get_user_federation_provider method."""

    @pytest.mark.asyncio
    async def test_returns_provider_on_success(self, mock_admin_client):
        """Should return provider on successful response."""
        provider_data = {
            "id": "provider-123",
            "name": "ldap-provider",
            "providerId": "ldap",
            "providerType": "org.keycloak.storage.UserStorageProvider",
        }
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, provider_data)
        )

        result = await mock_admin_client.get_user_federation_provider(
            "test-realm", "provider-123", namespace="default"
        )

        assert result is not None
        assert result.id == "provider-123"
        assert result.name == "ldap-provider"

    @pytest.mark.asyncio
    async def test_returns_none_on_not_found(self, mock_admin_client):
        """Should return None when provider not found."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(404))

        result = await mock_admin_client.get_user_federation_provider(
            "test-realm", "nonexistent", namespace="default"
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_raises_on_error(self, mock_admin_client):
        """Should raise KeycloakAdminError on other errors."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(500))

        with pytest.raises(KeycloakAdminError):
            await mock_admin_client.get_user_federation_provider(
                "test-realm", "provider-123", namespace="default"
            )


class TestGetUserFederationProviderByName:
    """Tests for get_user_federation_provider_by_name method."""

    @pytest.mark.asyncio
    async def test_returns_matching_provider(self, mock_admin_client):
        """Should return provider matching the name."""
        providers = [
            {
                "id": "p1",
                "name": "ldap-1",
                "providerId": "ldap",
                "providerType": "org.keycloak.storage.UserStorageProvider",
            },
            {
                "id": "p2",
                "name": "ldap-2",
                "providerId": "ldap",
                "providerType": "org.keycloak.storage.UserStorageProvider",
            },
        ]
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, providers)
        )

        result = await mock_admin_client.get_user_federation_provider_by_name(
            "test-realm", "ldap-2", namespace="default"
        )

        assert result is not None
        assert result.name == "ldap-2"
        assert result.id == "p2"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when no provider matches."""
        providers = [
            {
                "id": "p1",
                "name": "ldap-1",
                "providerId": "ldap",
                "providerType": "org.keycloak.storage.UserStorageProvider",
            },
        ]
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, providers)
        )

        result = await mock_admin_client.get_user_federation_provider_by_name(
            "test-realm", "nonexistent", namespace="default"
        )

        assert result is None


class TestCreateUserFederationProvider:
    """Tests for create_user_federation_provider method."""

    @pytest.mark.asyncio
    async def test_creates_provider_and_returns_id(self, mock_admin_client):
        """Should create provider and return ID from Location header."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(
                201, headers={"Location": "/realms/test/components/new-id-123"}
            )
        )

        config = ComponentRepresentation(
            name="new-ldap",
            provider_id="ldap",
        )
        result = await mock_admin_client.create_user_federation_provider(
            "test-realm", config, namespace="default"
        )

        assert result == "new-id-123"

    @pytest.mark.asyncio
    async def test_accepts_dict_config(self, mock_admin_client):
        """Should accept dict config and convert to model."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(
                201, headers={"Location": "/realms/test/components/dict-id"}
            )
        )

        result = await mock_admin_client.create_user_federation_provider(
            "test-realm",
            {"name": "dict-ldap", "providerId": "ldap"},
            namespace="default",
        )

        assert result == "dict-id"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on failure."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(400)
        )

        config = ComponentRepresentation(name="bad-ldap", provider_id="ldap")
        result = await mock_admin_client.create_user_federation_provider(
            "test-realm", config, namespace="default"
        )

        assert result is None


class TestUpdateUserFederationProvider:
    """Tests for update_user_federation_provider method."""

    @pytest.mark.asyncio
    async def test_updates_provider_successfully(self, mock_admin_client):
        """Should return True on successful update."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(204)
        )

        config = ComponentRepresentation(
            name="updated-ldap",
            provider_id="ldap",
        )
        result = await mock_admin_client.update_user_federation_provider(
            "test-realm", "provider-123", config, namespace="default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on failure."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(400)
        )

        config = ComponentRepresentation(name="bad-ldap", provider_id="ldap")
        result = await mock_admin_client.update_user_federation_provider(
            "test-realm", "provider-123", config, namespace="default"
        )

        assert result is False


class TestDeleteUserFederationProvider:
    """Tests for delete_user_federation_provider method."""

    @pytest.mark.asyncio
    async def test_deletes_provider_successfully(self, mock_admin_client):
        """Should return True on successful delete."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(204))

        result = await mock_admin_client.delete_user_federation_provider(
            "test-realm", "provider-123", namespace="default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when provider already deleted (404)."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(404))

        result = await mock_admin_client.delete_user_federation_provider(
            "test-realm", "nonexistent", namespace="default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_error(self, mock_admin_client):
        """Should return False on other errors."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(500))

        result = await mock_admin_client.delete_user_federation_provider(
            "test-realm", "provider-123", namespace="default"
        )

        assert result is False


class TestCreateUserFederationMapper:
    """Tests for create_user_federation_mapper method."""

    @pytest.mark.asyncio
    async def test_creates_mapper_and_returns_id(self, mock_admin_client):
        """Should create mapper and return ID."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(
                201, headers={"Location": "/realms/test/components/mapper-id"}
            )
        )

        config = ComponentRepresentation(
            name="email-mapper",
            provider_id="user-attribute-ldap-mapper",
        )
        result = await mock_admin_client.create_user_federation_mapper(
            "test-realm", "parent-id", config, namespace="default"
        )

        assert result == "mapper-id"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on failure."""
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=MockResponse(400)
        )

        config = ComponentRepresentation(name="bad-mapper", provider_id="invalid")
        result = await mock_admin_client.create_user_federation_mapper(
            "test-realm", "parent-id", config, namespace="default"
        )

        assert result is None


class TestDeleteUserFederationMapper:
    """Tests for delete_user_federation_mapper method."""

    @pytest.mark.asyncio
    async def test_deletes_mapper_successfully(self, mock_admin_client):
        """Should return True on successful delete."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(204))

        result = await mock_admin_client.delete_user_federation_mapper(
            "test-realm", "mapper-123", namespace="default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_error(self, mock_admin_client):
        """Should return False on error."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(500))

        result = await mock_admin_client.delete_user_federation_mapper(
            "test-realm", "mapper-123", namespace="default"
        )

        assert result is False


class TestGetUserFederationMappers:
    """Tests for get_user_federation_mappers method."""

    @pytest.mark.asyncio
    async def test_returns_mappers_on_success(self, mock_admin_client):
        """Should return list of mappers on success."""
        mappers = [
            {
                "id": "m1",
                "name": "email",
                "providerId": "user-attribute-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": "parent-123",
            },
        ]
        mock_admin_client._make_request = AsyncMock(
            return_value=MockResponse(200, mappers)
        )

        result = await mock_admin_client.get_user_federation_mappers(
            "test-realm", "parent-123", namespace="default"
        )

        assert len(result) == 1
        assert result[0].name == "email"

    @pytest.mark.asyncio
    async def test_returns_empty_on_not_found(self, mock_admin_client):
        """Should return empty list on 404."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(404))

        result = await mock_admin_client.get_user_federation_mappers(
            "test-realm", "nonexistent", namespace="default"
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_raises_on_error(self, mock_admin_client):
        """Should raise KeycloakAdminError on other errors."""
        mock_admin_client._make_request = AsyncMock(return_value=MockResponse(500))

        with pytest.raises(KeycloakAdminError):
            await mock_admin_client.get_user_federation_mappers(
                "test-realm", "parent-123", namespace="default"
            )
