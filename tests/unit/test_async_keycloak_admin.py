"""
Unit tests for async KeycloakAdminClient.

Tests async admin client with mocked HTTP responses,
rate limiting integration, and error handling.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminClient,
    KeycloakAdminError,
)
from keycloak_operator.utils.rate_limiter import RateLimiter


class TestAsyncAdminClientInitialization:
    """Test admin client initialization."""

    def test_admin_client_init(self):
        """Test basic initialization."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        assert client.server_url == "https://keycloak.example.com"
        assert client.username == "admin"
        assert client.password == "secret"
        assert client.admin_realm == "master"
        assert client._session is None  # Lazy init

    def test_admin_client_init_with_rate_limiter(self):
        """Test initialization with rate limiter."""
        rate_limiter = RateLimiter(
            global_rate=50.0,
            global_burst=100,
            namespace_rate=5.0,
            namespace_burst=10,
        )
        
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
            rate_limiter=rate_limiter,
        )
        
        assert client.rate_limiter is rate_limiter

    def test_admin_client_strips_trailing_slash(self):
        """Test that server URL trailing slash is removed."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com/",
            username="admin",
            password="secret",
        )
        
        assert client.server_url == "https://keycloak.example.com"


class TestAsyncAuthentication:
    """Test async authentication."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        """Test successful authentication."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        # Mock aiohttp session
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "access_token": "test-token",
            "refresh_token": "refresh-token",
            "expires_in": 300,
        })
        mock_response.raise_for_status = AsyncMock()
        
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            await client.authenticate()
        
        assert client.access_token == "test-token"
        assert client.refresh_token == "refresh-token"
        assert client.token_expires_at is not None

    @pytest.mark.asyncio
    async def test_authenticate_failure(self):
        """Test authentication failure."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="wrong",
        )
        
        # Mock failed auth
        mock_response = AsyncMock()
        mock_response.raise_for_status = AsyncMock(
            side_effect=aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=401,
            )
        )
        
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            with pytest.raises(KeycloakAdminError) as exc_info:
                await client.authenticate()
            
            assert "Authentication failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_token_refresh(self):
        """Test token refresh."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        # Set initial tokens
        client.refresh_token = "old-refresh-token"
        
        # Mock refresh response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "access_token": "new-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 300,
        })
        mock_response.raise_for_status = AsyncMock()
        
        mock_session = AsyncMock()
        mock_session.post = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            await client._refresh_token()
        
        assert client.access_token == "new-token"
        assert client.refresh_token == "new-refresh-token"


class TestAsyncMakeRequest:
    """Test async _make_request method."""

    @pytest.mark.asyncio
    async def test_make_request_with_rate_limiter(self):
        """Test that rate limiter is called before request."""
        rate_limiter = AsyncMock(spec=RateLimiter)
        rate_limiter.acquire = AsyncMock()
        
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
            rate_limiter=rate_limiter,
        )
        
        client.access_token = "test-token"
        client.token_expires_at = 9999999999  # Far future
        
        # Mock successful response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = AsyncMock()
        
        mock_session = AsyncMock()
        mock_session.request = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            await client._make_request("GET", "realms", "test-namespace")
        
        # Verify rate limiter was called
        rate_limiter.acquire.assert_called_once_with("test-namespace")

    @pytest.mark.asyncio
    async def test_make_request_without_rate_limiter(self):
        """Test request without rate limiter."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
            rate_limiter=None,
        )
        
        client.access_token = "test-token"
        client.token_expires_at = 9999999999
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = AsyncMock()
        
        mock_session = AsyncMock()
        mock_session.request = AsyncMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_response)
        mock_session.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            # Should not raise (no rate limiter is ok)
            await client._make_request("GET", "realms", "test-namespace")

    @pytest.mark.asyncio
    async def test_make_request_rate_limit_timeout(self):
        """Test request fails when rate limit times out."""
        rate_limiter = AsyncMock(spec=RateLimiter)
        rate_limiter.acquire = AsyncMock(side_effect=TimeoutError("Rate limit timeout"))
        
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
            rate_limiter=rate_limiter,
        )
        
        with pytest.raises(KeycloakAdminError) as exc_info:
            await client._make_request("GET", "realms", "test-namespace")
        
        assert exc_info.value.status_code == 429
        assert "Rate limit timeout" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_make_request_handles_401_retry(self):
        """Test 401 triggers re-authentication and retry."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        client.access_token = "expired-token"
        client.token_expires_at = 9999999999
        
        # First response: 401
        mock_response_401 = AsyncMock()
        mock_response_401.status = 401
        
        # Second response: 200
        mock_response_200 = AsyncMock()
        mock_response_200.status = 200
        mock_response_200.raise_for_status = AsyncMock()
        
        mock_session = AsyncMock()
        # First call returns 401, second returns 200
        mock_session.request = AsyncMock(side_effect=[
            mock_response_401,
            mock_response_200,
        ])
        mock_response_401.__aenter__ = AsyncMock(return_value=mock_response_401)
        mock_response_401.__aexit__ = AsyncMock()
        mock_response_200.__aenter__ = AsyncMock(return_value=mock_response_200)
        mock_response_200.__aexit__ = AsyncMock()
        
        with patch.object(client, '_get_session', return_value=mock_session):
            with patch.object(client, 'authenticate', new_callable=AsyncMock) as mock_auth:
                mock_auth.return_value = None
                client.access_token = "new-token"  # Simulate successful auth
                
                response = await client._make_request("GET", "realms", "test-namespace")
        
        # Should have called authenticate once
        mock_auth.assert_called_once()
        assert response == mock_response_200


class TestRealmMethods:
    """Test realm-related methods."""

    @pytest.mark.asyncio
    async def test_get_realm_success(self):
        """Test getting a realm."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        realm_data = {
            "realm": "test-realm",
            "enabled": True,
            "displayName": "Test Realm",
        }
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=realm_data)
        
        with patch.object(client, '_make_validated_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = realm_data
            
            realm = await client.get_realm("test-realm", "test-namespace")
        
        mock_request.assert_called_once()
        assert realm == realm_data

    @pytest.mark.asyncio
    async def test_get_realm_not_found(self):
        """Test getting non-existent realm returns None."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        # Mock 404 error
        error = KeycloakAdminError("Not found", status_code=404)
        
        with patch.object(client, '_make_validated_request', new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = error
            
            realm = await client.get_realm("nonexistent", "test-namespace")
        
        assert realm is None

    @pytest.mark.asyncio
    async def test_create_realm(self):
        """Test creating a realm."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        realm_config = {
            "realm": "new-realm",
            "enabled": True,
        }
        
        mock_response = AsyncMock()
        mock_response.status = 201
        
        with patch.object(client, '_make_validated_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            await client.create_realm(realm_config, "test-namespace")
        
        mock_request.assert_called_once()


class TestClientMethods:
    """Test client-related methods."""

    @pytest.mark.asyncio
    async def test_get_client_by_name(self):
        """Test getting client by name."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        clients_data = [
            {"id": "uuid1", "clientId": "client-1"},
            {"id": "uuid2", "clientId": "client-2"},
            {"id": "uuid3", "clientId": "target-client"},
        ]
        
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value=clients_data)
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await client.get_client_by_name("target-client", "test-realm", "test-namespace")
        
        assert result.client_id == "target-client"
        assert result.id == "uuid3"

    @pytest.mark.asyncio
    async def test_get_client_by_name_not_found(self):
        """Test getting non-existent client returns None."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        clients_data = [
            {"id": "uuid1", "clientId": "client-1"},
            {"id": "uuid2", "clientId": "client-2"},
        ]
        
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value=clients_data)
        
        with patch.object(client, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_response
            
            result = await client.get_client_by_name("nonexistent", "test-realm", "test-namespace")
        
        assert result is None


class TestSessionManagement:
    """Test aiohttp session management."""

    @pytest.mark.asyncio
    async def test_session_lazy_initialization(self):
        """Test session is created lazily."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        assert client._session is None
        
        # Get session
        session = await client._get_session()
        
        assert session is not None
        assert isinstance(session, aiohttp.ClientSession)

    @pytest.mark.asyncio
    async def test_session_reuse(self):
        """Test same session is reused."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        session1 = await client._get_session()
        session2 = await client._get_session()
        
        assert session1 is session2

    @pytest.mark.asyncio
    async def test_session_close(self):
        """Test session cleanup."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        session = await client._get_session()
        assert not session.closed
        
        await client.close()
        
        # Session should be closed and nulled
        assert client._session is None


class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_http_error_handling(self):
        """Test HTTP error is wrapped properly."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        client.access_token = "test-token"
        client.token_expires_at = 9999999999
        
        # Mock 500 error
        error = aiohttp.ClientResponseError(
            request_info=MagicMock(),
            history=(),
            status=500,
            message="Internal Server Error",
        )
        
        mock_session = AsyncMock()
        mock_session.request = AsyncMock(side_effect=error)
        
        with patch.object(client, '_get_session', return_value=mock_session):
            with pytest.raises(KeycloakAdminError) as exc_info:
                await client._make_request("GET", "realms", "test-namespace")
            
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test connection error handling."""
        client = KeycloakAdminClient(
            server_url="https://keycloak.example.com",
            username="admin",
            password="secret",
        )
        
        client.access_token = "test-token"
        client.token_expires_at = 9999999999
        
        # Mock connection error
        error = aiohttp.ClientConnectionError("Connection refused")
        
        mock_session = AsyncMock()
        mock_session.request = AsyncMock(side_effect=error)
        
        with patch.object(client, '_get_session', return_value=mock_session):
            with pytest.raises(KeycloakAdminError):
                await client._make_request("GET", "realms", "test-namespace")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
