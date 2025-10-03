"""
Unit tests for Keycloak admin client with API model validation.

This module tests that the admin client correctly uses Pydantic models
for request/response validation.
"""

from unittest.mock import MagicMock, patch

import pytest
from requests import Response

from keycloak_operator.models.keycloak_api import (
    ClientRepresentation,
    RealmRepresentation,
)
from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient


class TestAdminClientWithAPIModels:
    """Test admin client methods with Pydantic model validation."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock admin client."""
        with patch("keycloak_operator.utils.keycloak_admin.requests.Session"):
            client = KeycloakAdminClient(
                server_url="http://keycloak:8080",
                username="admin",
                password="admin",
                verify_ssl=False,
            )
            client.access_token = "test-token"
            return client

    def test_create_realm_with_pydantic_model(self, mock_client):
        """Test create_realm accepts Pydantic model and dict."""
        # Create mock response
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 201
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Test with Pydantic model
        realm_model = RealmRepresentation(
            realm="test-realm", enabled=True, display_name="Test Realm"
        )

        result = mock_client.create_realm(realm_model)

        # Verify it returns a RealmRepresentation
        assert isinstance(result, RealmRepresentation)
        assert result.realm == "test-realm"
        assert result.enabled is True

        # Verify the request was made with proper JSON
        mock_client.session.request.assert_called_once()
        call_kwargs = mock_client.session.request.call_args[1]
        assert "json" in call_kwargs
        # Should have camelCase keys for API
        assert call_kwargs["json"]["realm"] == "test-realm"
        assert call_kwargs["json"]["displayName"] == "Test Realm"

    def test_create_realm_with_dict(self, mock_client):
        """Test create_realm accepts dict and validates it."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 201
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Test with dict (backward compatibility)
        realm_dict = {
            "realm": "test-realm",
            "enabled": True,
            "displayName": "Test Realm",
        }

        result = mock_client.create_realm(realm_dict)

        # Should still return RealmRepresentation
        assert isinstance(result, RealmRepresentation)
        assert result.realm == "test-realm"

    def test_get_realm_returns_pydantic_model(self, mock_client):
        """Test get_realm returns validated Pydantic model."""
        # Mock API response
        api_response = {
            "id": "12345",
            "realm": "test-realm",
            "displayName": "Test Realm",
            "enabled": True,
        }

        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = api_response
        mock_client.session.request = MagicMock(return_value=mock_response)

        result = mock_client.get_realm("test-realm")

        # Should return validated RealmRepresentation
        assert isinstance(result, RealmRepresentation)
        assert result.id == "12345"
        assert result.realm == "test-realm"
        assert result.display_name == "Test Realm"  # snake_case in Python
        assert result.enabled is True

    def test_update_realm_with_pydantic_model(self, mock_client):
        """Test update_realm works with Pydantic models."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 204
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Update with Pydantic model
        realm_model = RealmRepresentation(
            realm="test-realm", enabled=False, display_name="Updated Realm"
        )

        result = mock_client.update_realm("test-realm", realm_model)

        assert isinstance(result, RealmRepresentation)
        assert result.enabled is False

        # Verify request payload
        call_kwargs = mock_client.session.request.call_args[1]
        assert call_kwargs["json"]["displayName"] == "Updated Realm"

    def test_create_client_with_pydantic_model(self, mock_client):
        """Test create_client accepts Pydantic model."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 201
        mock_response.headers = {
            "Location": "/admin/realms/master/clients/client-uuid-123"
        }
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Create client with Pydantic model
        client_model = ClientRepresentation(
            client_id="my-client",
            enabled=True,
            public_client=True,
            redirect_uris=["http://localhost:3000/*"],
        )

        result = mock_client.create_client(client_model, "master")

        # Should return client UUID
        assert result == "client-uuid-123"

        # Verify request payload has camelCase
        call_kwargs = mock_client.session.request.call_args[1]
        assert call_kwargs["json"]["clientId"] == "my-client"
        assert call_kwargs["json"]["publicClient"] is True
        assert call_kwargs["json"]["redirectUris"] == ["http://localhost:3000/*"]

    def test_update_client_with_dict(self, mock_client):
        """Test update_client with dict gets validated."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 204
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Update with dict
        client_dict = {
            "clientId": "my-client",
            "enabled": False,
            "redirectUris": ["http://localhost:4200/*"],
        }

        result = mock_client.update_client("client-uuid", client_dict, "master")

        assert result is True

        # Verify validation happened and camelCase preserved
        call_kwargs = mock_client.session.request.call_args[1]
        assert call_kwargs["json"]["clientId"] == "my-client"
        assert call_kwargs["json"]["redirectUris"] == ["http://localhost:4200/*"]

    def test_validation_errors_raised_on_invalid_data(self, mock_client):
        """Test that invalid data raises ValidationError."""
        from pydantic import ValidationError

        # Invalid realm data
        with pytest.raises(ValidationError):
            mock_client.create_realm({"enabled": "invalid_bool"})

        # Invalid client data
        with pytest.raises(ValidationError):
            mock_client.create_client({"redirectUris": "not-a-list"})

    def test_exclude_none_on_requests(self, mock_client):
        """Test that None values are excluded from API requests."""
        mock_response = MagicMock(spec=Response)
        mock_response.status_code = 201
        mock_client.session.request = MagicMock(return_value=mock_response)

        # Realm with only some fields set
        realm = RealmRepresentation(realm="test", enabled=True)

        mock_client.create_realm(realm)

        # Verify None fields are excluded
        call_kwargs = mock_client.session.request.call_args[1]
        json_data = call_kwargs["json"]

        assert "realm" in json_data
        assert "enabled" in json_data
        # These should be excluded (not set)
        assert "displayName" not in json_data
        assert "sslRequired" not in json_data
