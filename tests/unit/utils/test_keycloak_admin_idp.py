"""Unit tests for KeycloakAdminClient identity provider methods."""

from unittest.mock import AsyncMock

import pytest

from keycloak_operator.models.keycloak_api import IdentityProviderRepresentation


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
    """Create a mock KeycloakAdminClient for testing.

    Uses object.__new__ to create an uninitialized instance, then sets
    required attributes directly. This avoids calling __init__ entirely,
    which satisfies both the runtime behavior and static analysis.
    """
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

    # Create instance without calling __init__
    client = object.__new__(KeycloakAdminClient)
    # Set required attributes that __init__ would normally set
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


class TestGetIdentityProvider:
    """Tests for get_identity_provider method."""

    @pytest.mark.asyncio
    async def test_returns_idp_when_found(self, mock_admin_client):
        """Should return identity provider when it exists."""
        mock_response = MockResponse(
            200,
            {
                "alias": "github",
                "providerId": "github",
                "enabled": True,
                "config": {"clientId": "test-client"},
            },
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        idp = await mock_admin_client.get_identity_provider(
            "test-realm", "github", "default"
        )

        assert idp is not None
        assert idp.alias == "github"
        assert idp.provider_id == "github"
        assert idp.enabled is True
        mock_admin_client._make_request.assert_called_once_with(
            "GET",
            "realms/test-realm/identity-provider/instances/github",
            "default",
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when identity provider doesn't exist."""
        mock_response = MockResponse(404)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        idp = await mock_admin_client.get_identity_provider(
            "test-realm", "nonexistent", "default"
        )

        assert idp is None

    @pytest.mark.asyncio
    async def test_returns_none_on_error(self, mock_admin_client):
        """Should return None on unexpected error."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=Exception("Connection error")
        )

        idp = await mock_admin_client.get_identity_provider(
            "test-realm", "github", "default"
        )

        assert idp is None


class TestUpdateIdentityProvider:
    """Tests for update_identity_provider method."""

    @pytest.mark.asyncio
    async def test_updates_idp_successfully(self, mock_admin_client):
        """Should return True on successful update."""
        mock_response = MockResponse(200)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=False,
        )

        result = await mock_admin_client.update_identity_provider(
            "test-realm", "github", provider, "default"
        )

        assert result is True
        mock_admin_client._make_validated_request.assert_called_once()
        call_args = mock_admin_client._make_validated_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[0][1] == "realms/test-realm/identity-provider/instances/github"

    @pytest.mark.asyncio
    async def test_updates_idp_with_204_response(self, mock_admin_client):
        """Should return True on 204 No Content response."""
        mock_response = MockResponse(204)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )

        result = await mock_admin_client.update_identity_provider(
            "test-realm", "github", provider, "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_failure(self, mock_admin_client):
        """Should return False on non-success response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )

        result = await mock_admin_client.update_identity_provider(
            "test-realm", "github", provider, "default"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_accepts_dict_config(self, mock_admin_client):
        """Should accept dict configuration and convert to model."""
        mock_response = MockResponse(200)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        provider_dict = {
            "alias": "github",
            "providerId": "github",
            "enabled": True,
        }

        result = await mock_admin_client.update_identity_provider(
            "test-realm", "github", provider_dict, "default"
        )

        assert result is True


class TestConfigureIdentityProvider:
    """Tests for configure_identity_provider method."""

    @pytest.mark.asyncio
    async def test_creates_new_idp_when_not_exists(self, mock_admin_client):
        """Should create new identity provider when it doesn't exist."""
        # get_identity_provider returns None (not found)
        mock_admin_client.get_identity_provider = AsyncMock(return_value=None)
        # POST succeeds
        mock_post_response = MockResponse(201)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_post_response
        )

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )

        result = await mock_admin_client.configure_identity_provider(
            "test-realm", provider, "default"
        )

        assert result is True
        mock_admin_client.get_identity_provider.assert_called_once_with(
            "test-realm", "github", "default"
        )
        mock_admin_client._make_validated_request.assert_called_once()
        call_args = mock_admin_client._make_validated_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "realms/test-realm/identity-provider/instances"

    @pytest.mark.asyncio
    async def test_updates_existing_idp(self, mock_admin_client):
        """Should update identity provider when it already exists."""
        # get_identity_provider returns existing IdP
        existing_idp = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )
        mock_admin_client.get_identity_provider = AsyncMock(return_value=existing_idp)
        # update_identity_provider succeeds
        mock_admin_client.update_identity_provider = AsyncMock(return_value=True)

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=False,  # Changed
        )

        result = await mock_admin_client.configure_identity_provider(
            "test-realm", provider, "default"
        )

        assert result is True
        mock_admin_client.get_identity_provider.assert_called_once_with(
            "test-realm", "github", "default"
        )
        mock_admin_client.update_identity_provider.assert_called_once_with(
            "test-realm", "github", provider, "default"
        )

    @pytest.mark.asyncio
    async def test_accepts_dict_config(self, mock_admin_client):
        """Should accept dict configuration and convert to model."""
        mock_admin_client.get_identity_provider = AsyncMock(return_value=None)
        mock_post_response = MockResponse(201)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_post_response
        )

        provider_dict = {
            "alias": "google",
            "providerId": "google",
            "enabled": True,
        }

        result = await mock_admin_client.configure_identity_provider(
            "test-realm", provider_dict, "default"
        )

        assert result is True
        mock_admin_client.get_identity_provider.assert_called_once_with(
            "test-realm", "google", "default"
        )

    @pytest.mark.asyncio
    async def test_returns_false_on_create_failure(self, mock_admin_client):
        """Should return False when creation fails."""
        mock_admin_client.get_identity_provider = AsyncMock(return_value=None)
        mock_post_response = MockResponse(500)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_post_response
        )

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )

        result = await mock_admin_client.configure_identity_provider(
            "test-realm", provider, "default"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_update_failure(self, mock_admin_client):
        """Should return False when update fails."""
        existing_idp = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=True,
        )
        mock_admin_client.get_identity_provider = AsyncMock(return_value=existing_idp)
        mock_admin_client.update_identity_provider = AsyncMock(return_value=False)

        provider = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
            enabled=False,
        )

        result = await mock_admin_client.configure_identity_provider(
            "test-realm", provider, "default"
        )

        assert result is False
