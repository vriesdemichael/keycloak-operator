import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from keycloak_operator.settings import settings
from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminClient,
    KeycloakAdminError,
)


@pytest.fixture
def mock_httpx_client():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    return client


@pytest.fixture
def admin_client(mock_httpx_client):
    # Mock settings to ensure circuit breaker is enabled
    settings.api_circuit_breaker_enabled = True
    settings.api_circuit_breaker_failure_threshold = 2
    settings.api_circuit_breaker_recovery_timeout = 1  # Int value
    settings.api_timeout_seconds = 10

    with patch("keycloak_operator.utils.keycloak_admin._httpx_client_cache", {}):
        with patch(
            "keycloak_operator.utils.keycloak_admin.httpx.AsyncClient",
            return_value=mock_httpx_client,
        ):
            client = KeycloakAdminClient(
                server_url="http://test-server",
                username="admin",
                password="password",
                keycloak_name="test-instance",
                keycloak_namespace="test-namespace",
            )
            # Mock authentication to avoid real network calls
            client.access_token = "fake-token"
            # Use time.time() instead of asyncio loop time for robustness in fixtures
            client.token_expires_at = time.time() + 3600
            yield client


@pytest.mark.asyncio
async def test_circuit_breaker_opens_on_failures(admin_client, mock_httpx_client):
    """Test that circuit breaker opens after threshold failures."""
    # Setup mock to raise exceptions
    mock_httpx_client.request.side_effect = httpx.ConnectError("Connection failed")

    # Fail 1
    with pytest.raises(KeycloakAdminError):
        await admin_client._make_request("GET", "realms", "default")

    # Fail 2 (threshold reached)
    with pytest.raises(KeycloakAdminError):
        await admin_client._make_request("GET", "realms", "default")

    # Should be open now
    assert admin_client.circuit_breaker.current_state == "open"

    # Next call should fail fast with 503 from KeycloakAdminError (wrapping CircuitBreakerError)
    # We reset side effect to ensure it's the circuit breaker raising, not the mock
    mock_httpx_client.request.side_effect = None

    with pytest.raises(KeycloakAdminError) as exc_info:
        await admin_client._make_request("GET", "realms", "default")

    assert exc_info.value.status_code == 503
    assert "Circuit breaker open" in str(exc_info.value)


@pytest.mark.asyncio
async def test_retry_on_401_bypasses_circuit_breaker(admin_client, mock_httpx_client):
    """Test that 401 retry logic doesn't double-count against circuit breaker."""
    # First request returns 401, second returns 200
    mock_response_401 = MagicMock(spec=httpx.Response)
    mock_response_401.status_code = 401

    mock_response_200 = MagicMock(spec=httpx.Response)
    mock_response_200.status_code = 200
    mock_response_200.json.return_value = {"token": "new-token"}

    # Mock authenticate to avoid recursion
    with patch.object(admin_client, "authenticate", new_callable=AsyncMock):
        # Sequence:
        # 1. First request -> 401
        # 2. Authenticate called
        # 3. Retry request -> 200
        mock_httpx_client.request.side_effect = [mock_response_401, mock_response_200]

        response = await admin_client._make_request("GET", "realms", "default")

        assert response.status_code == 200
        # Circuit breaker should still be closed (401 is not a failure for CB)
        assert admin_client.circuit_breaker.current_state == "closed"

        # Should have called request twice
        assert mock_httpx_client.request.call_count == 2


@pytest.mark.asyncio
async def test_metrics_updated_on_state_change(admin_client, mock_httpx_client):
    """Test that Prometheus metrics are updated when circuit state changes."""
    from keycloak_operator.observability.metrics import CIRCUIT_BREAKER_STATE

    # Verify initial metric state
    # Reset metric for this test
    CIRCUIT_BREAKER_STATE.clear()
    # Initialize it (constructor does this)
    CIRCUIT_BREAKER_STATE.labels(
        keycloak_instance="test-instance",
        keycloak_namespace="test-namespace",
    ).set(0)

    # Make it fail
    mock_httpx_client.request.side_effect = httpx.ConnectError("Connection failed")

    # Fail until open
    for _ in range(2):
        with pytest.raises(KeycloakAdminError):
            await admin_client._make_request("GET", "realms", "default")

    # Check metric is now 1 (Open)
    metrics = list(CIRCUIT_BREAKER_STATE.collect())
    samples = metrics[0].samples if metrics else []
    for sample in samples:
        if (
            sample.labels["keycloak_instance"] == "test-instance"
            and sample.labels["keycloak_namespace"] == "test-namespace"
        ):
            assert sample.value == 1.0
            break
    else:
        pytest.fail("Metric not found")
