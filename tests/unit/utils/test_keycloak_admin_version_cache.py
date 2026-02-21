"""Unit tests for KeycloakAdminClient server version caching."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminClient,
    _version_cache,
)


@pytest.mark.asyncio
class TestKeycloakAdminVersionCache:
    """Tests for server version detection and caching."""

    @pytest.fixture(autouse=True)
    async def setup_cache(self):
        """Reset global cache before each test."""
        _version_cache.clear()
        yield

    async def test_detect_version_cache_miss(self, mock_admin_client):
        """Should fetch from API on cache miss."""
        mock_admin_client.auto_detect_version = True
        mock_admin_client._version_detected = False

        # Mock API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"systemInfo": {"version": "25.0.0"}}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(mock_admin_client, "_get_client", return_value=mock_client):
            await mock_admin_client._detect_server_version()

            assert mock_admin_client._version_detected is True
            assert mock_admin_client.adapter.version == "25.0.0"

            # Verify cache was updated
            version = await _version_cache.get_valid_version(
                mock_admin_client.server_url
            )
            assert version == "25.0.0"

    async def test_detect_version_cache_hit(self, mock_admin_client):
        """Should use cached version on cache hit."""
        mock_admin_client.auto_detect_version = True
        mock_admin_client._version_detected = False

        # Pre-populate cache
        await _version_cache.update(mock_admin_client.server_url, "24.0.0")

        with patch.object(mock_admin_client, "_get_client") as mock_get_client:
            await mock_admin_client._detect_server_version()

            assert mock_admin_client._version_detected is True
            assert mock_admin_client.adapter.version == "24.0.0"

            # Verify no API call was made
            mock_get_client.assert_not_called()

    async def test_detect_version_cache_expired(self, mock_admin_client):
        """Should re-fetch if cache entry is expired."""
        mock_admin_client.auto_detect_version = True
        mock_admin_client._version_detected = False

        # Pre-populate with expired entry
        async with _version_cache._lock:
            _version_cache._cache[mock_admin_client.server_url] = (
                "24.0.0",
                time.monotonic() - 4000,
            )

        # Mock API response for new version
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"systemInfo": {"version": "26.0.0"}}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(mock_admin_client, "_get_client", return_value=mock_client):
            await mock_admin_client._detect_server_version()

            assert mock_admin_client._version_detected is True
            assert mock_admin_client.adapter.version == "26.0.0"

            # Verify cache was updated with new version
            version = await _version_cache.get_valid_version(
                mock_admin_client.server_url
            )
            assert version == "26.0.0"

    async def test_detect_version_invalid_cache_entry(self, mock_admin_client):
        """Should handle invalid version in cache by re-fetching."""
        mock_admin_client.auto_detect_version = True
        mock_admin_client._version_detected = False

        # Pre-populate with invalid/unsupported version string
        await _version_cache.update(mock_admin_client.server_url, "invalid-version")

        # Mock API response for fallback
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"systemInfo": {"version": "25.0.0"}}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(mock_admin_client, "_get_client", return_value=mock_client):
            # This should not raise but log warning and fetch from API
            await mock_admin_client._detect_server_version()

            assert mock_admin_client._version_detected is True
            assert mock_admin_client.adapter.version == "25.0.0"

            # Verify cache was corrected
            version = await _version_cache.get_valid_version(
                mock_admin_client.server_url
            )
            assert version == "25.0.0"

    async def test_detect_version_coalescing(self, mock_admin_client):
        """Should coalesce concurrent fetches for the same URL."""
        mock_admin_client.auto_detect_version = True

        # Mock slow API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"systemInfo": {"version": "25.0.0"}}

        async def slow_get(*args, **kwargs):
            await asyncio.sleep(0.1)
            return mock_response

        mock_client = AsyncMock()
        mock_client.get.side_effect = slow_get

        with patch.object(mock_admin_client, "_get_client", return_value=mock_client):
            # Start multiple concurrent detections
            # Use separate client instances but same server_url
            client2 = object.__new__(KeycloakAdminClient)
            client2.server_url = mock_admin_client.server_url
            client2.access_token = "token"
            client2.auto_detect_version = True
            client2._version_detected = False
            client2._get_client = mock_admin_client._get_client  # Share same mock

            # Run concurrently
            await asyncio.gather(
                mock_admin_client._detect_server_version(),
                client2._detect_server_version(),
            )

            # Verify API was only called ONCE
            assert mock_client.get.call_count == 1

            assert mock_admin_client._version_detected is True
            assert client2._version_detected is True
            assert mock_admin_client.adapter.version == "25.0.0"
            assert client2.adapter.version == "25.0.0"

    async def test_detect_version_unsupported_wont_poison_cache(
        self, mock_admin_client
    ):
        """Should not write to cache if version is unsupported."""
        mock_admin_client.auto_detect_version = True
        mock_admin_client._version_detected = False

        # Mock API response with unsupported version (e.g. major too old)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"systemInfo": {"version": "1.0.0"}}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch.object(mock_admin_client, "_get_client", return_value=mock_client):
            # This should log a warning but not poison cache
            await mock_admin_client._detect_server_version()

            # Verify cache remains empty for this URL
            version = await _version_cache.get_valid_version(
                mock_admin_client.server_url
            )
            assert version is None
