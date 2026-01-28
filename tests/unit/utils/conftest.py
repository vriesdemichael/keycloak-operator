"""Shared pytest fixtures for Keycloak admin client tests."""

import pytest

from keycloak_operator.compatibility import get_adapter_for_version


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
    # Add the adapter for version compatibility
    client.adapter = get_adapter_for_version("26.5.2")
    return client
