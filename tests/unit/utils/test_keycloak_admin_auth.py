"""Unit tests for KeycloakAdminClient authentication flow methods."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.models.keycloak_api import (
    AuthenticationFlowRepresentation,
    AuthenticatorConfigRepresentation,
    RequiredActionProviderRepresentation,
)
from keycloak_operator.utils.keycloak_admin import KeycloakAdminError


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
    """Create a mock KeycloakAdminClient client for testing.

    Patches __init__ to bypass normal initialization, then sets required
    attributes directly.
    """
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

    with patch.object(KeycloakAdminClient, "__init__", lambda self: None):
        client = KeycloakAdminClient()
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


class TestGetAuthenticationFlows:
    """Tests for get_authentication_flows method."""

    @pytest.mark.asyncio
    async def test_returns_flows_on_success(self, mock_admin_client):
        """Should return list of flows on successful response."""
        mock_response = MockResponse(
            200,
            [
                {"alias": "browser", "providerId": "basic-flow", "topLevel": True},
                {"alias": "direct grant", "providerId": "basic-flow", "topLevel": True},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        flows = await mock_admin_client.get_authentication_flows(
            "test-realm", "default"
        )

        assert len(flows) == 2
        assert flows[0].alias == "browser"
        assert flows[1].alias == "direct grant"

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_failure(self, mock_admin_client):
        """Should return empty list on non-200 response."""
        mock_response = MockResponse(500)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        flows = await mock_admin_client.get_authentication_flows(
            "test-realm", "default"
        )

        assert flows == []


class TestGetAuthenticationFlowByAlias:
    """Tests for get_authentication_flow_by_alias method."""

    @pytest.mark.asyncio
    async def test_returns_flow_when_found(self, mock_admin_client):
        """Should return flow when alias matches."""
        mock_response = MockResponse(
            200,
            [
                {"alias": "browser", "providerId": "basic-flow"},
                {"alias": "my-flow", "providerId": "basic-flow"},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        flow = await mock_admin_client.get_authentication_flow_by_alias(
            "test-realm", "my-flow", "default"
        )

        assert flow is not None
        assert flow.alias == "my-flow"

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self, mock_admin_client):
        """Should return None when alias not found."""
        mock_response = MockResponse(
            200,
            [{"alias": "browser", "providerId": "basic-flow"}],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        flow = await mock_admin_client.get_authentication_flow_by_alias(
            "test-realm", "nonexistent-flow", "default"
        )

        assert flow is None


class TestCreateAuthenticationFlow:
    """Tests for create_authentication_flow method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True when flow is created."""
        mock_response = MockResponse(201)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        result = await mock_admin_client.create_authentication_flow(
            "test-realm",
            AuthenticationFlowRepresentation(alias="new-flow"),
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_conflict(self, mock_admin_client):
        """Should return False when flow already exists (409)."""
        mock_admin_client._make_validated_request = AsyncMock(
            side_effect=KeycloakAdminError("Conflict", 409)
        )

        result = await mock_admin_client.create_authentication_flow(
            "test-realm",
            AuthenticationFlowRepresentation(alias="existing-flow"),
            "default",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_accepts_dict_config(self, mock_admin_client):
        """Should accept dict and convert to model."""
        mock_response = MockResponse(201)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        result = await mock_admin_client.create_authentication_flow(
            "test-realm",
            {"alias": "new-flow", "providerId": "basic-flow"},
            "default",
        )

        assert result is True


class TestDeleteAuthenticationFlow:
    """Tests for delete_authentication_flow method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True when flow is deleted."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_authentication_flow(
            "test-realm", "flow-id-123", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when flow not found (already deleted)."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Not found", 404)
        )

        result = await mock_admin_client.delete_authentication_flow(
            "test-realm", "nonexistent-flow", "default"
        )

        assert result is True  # Idempotent delete


class TestCopyAuthenticationFlow:
    """Tests for copy_authentication_flow method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True when flow is copied."""
        mock_response = MockResponse(201)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.copy_authentication_flow(
            "test-realm", "browser", "my-browser-copy", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_conflict(self, mock_admin_client):
        """Should return False when target flow already exists."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Conflict", 409)
        )

        result = await mock_admin_client.copy_authentication_flow(
            "test-realm", "browser", "existing-flow", "default"
        )

        assert result is False


class TestGetFlowExecutions:
    """Tests for get_flow_executions method."""

    @pytest.mark.asyncio
    async def test_returns_executions_on_success(self, mock_admin_client):
        """Should return list of executions."""
        mock_response = MockResponse(
            200,
            [
                {
                    "id": "exec-1",
                    "providerId": "auth-cookie",
                    "requirement": "ALTERNATIVE",
                },
                {
                    "id": "exec-2",
                    "providerId": "auth-spnego",
                    "requirement": "DISABLED",
                },
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        executions = await mock_admin_client.get_flow_executions(
            "test-realm", "browser", "default"
        )

        assert len(executions) == 2
        assert executions[0].provider_id == "auth-cookie"
        assert executions[1].provider_id == "auth-spnego"


class TestAddExecutionToFlow:
    """Tests for add_execution_to_flow method."""

    @pytest.mark.asyncio
    async def test_returns_execution_id_on_success(self, mock_admin_client):
        """Should return execution ID from Location header."""
        mock_response = MockResponse(
            201,
            headers={"Location": "http://kc/admin/flows/browser/executions/exec-123"},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        exec_id = await mock_admin_client.add_execution_to_flow(
            "test-realm", "browser", "auth-cookie", "default"
        )

        assert exec_id == "exec-123"

    @pytest.mark.asyncio
    async def test_returns_none_on_failure(self, mock_admin_client):
        """Should return None on failure."""
        mock_response = MockResponse(400)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        exec_id = await mock_admin_client.add_execution_to_flow(
            "test-realm", "browser", "invalid-auth", "default"
        )

        assert exec_id is None


class TestUpdateExecutionRequirement:
    """Tests for update_execution_requirement method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True when requirement is updated."""
        # Mock get_flow_executions to return the execution
        mock_admin_client.get_flow_executions = AsyncMock(
            return_value=[
                MagicMock(
                    id="exec-123", provider_id="auth-cookie", requirement="DISABLED"
                )
            ]
        )
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.update_execution_requirement(
            "test-realm", "browser", "exec-123", "ALTERNATIVE", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_execution_not_found(self, mock_admin_client):
        """Should return False when execution not found."""
        mock_admin_client.get_flow_executions = AsyncMock(return_value=[])

        result = await mock_admin_client.update_execution_requirement(
            "test-realm", "browser", "nonexistent-exec", "ALTERNATIVE", "default"
        )

        assert result is False


class TestDeleteExecution:
    """Tests for delete_execution method."""

    @pytest.mark.asyncio
    async def test_returns_true_on_success(self, mock_admin_client):
        """Should return True when execution is deleted."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.delete_execution(
            "test-realm", "exec-123", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_not_found(self, mock_admin_client):
        """Should return True when execution not found (already deleted)."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Not found", 404)
        )

        result = await mock_admin_client.delete_execution(
            "test-realm", "nonexistent-exec", "default"
        )

        assert result is True


class TestRequiredActionMethods:
    """Tests for required action management methods."""

    @pytest.mark.asyncio
    async def test_get_required_actions_returns_list(self, mock_admin_client):
        """Should return list of required actions."""
        mock_response = MockResponse(
            200,
            [
                {"alias": "CONFIGURE_TOTP", "name": "Configure OTP", "enabled": True},
                {"alias": "VERIFY_EMAIL", "name": "Verify Email", "enabled": True},
            ],
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        actions = await mock_admin_client.get_required_actions("test-realm", "default")

        assert len(actions) == 2
        assert actions[0].alias == "CONFIGURE_TOTP"

    @pytest.mark.asyncio
    async def test_get_required_action_returns_action(self, mock_admin_client):
        """Should return single required action."""
        mock_response = MockResponse(
            200, {"alias": "CONFIGURE_TOTP", "name": "Configure OTP", "enabled": True}
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        action = await mock_admin_client.get_required_action(
            "test-realm", "CONFIGURE_TOTP", "default"
        )

        assert action is not None
        assert action.alias == "CONFIGURE_TOTP"

    @pytest.mark.asyncio
    async def test_get_required_action_returns_none_on_404(self, mock_admin_client):
        """Should return None when action not found."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Not found", 404)
        )

        action = await mock_admin_client.get_required_action(
            "test-realm", "NONEXISTENT", "default"
        )

        assert action is None

    @pytest.mark.asyncio
    async def test_update_required_action_returns_true(self, mock_admin_client):
        """Should return True when action is updated."""
        mock_response = MockResponse(204)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        result = await mock_admin_client.update_required_action(
            "test-realm",
            "CONFIGURE_TOTP",
            RequiredActionProviderRepresentation(alias="CONFIGURE_TOTP", enabled=True),
            "default",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_register_required_action_returns_true(self, mock_admin_client):
        """Should return True when action is registered."""
        mock_response = MockResponse(204)
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        result = await mock_admin_client.register_required_action(
            "test-realm", "custom-action", "Custom Action", "default"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_register_required_action_returns_true_on_conflict(
        self, mock_admin_client
    ):
        """Should return True when action already registered (idempotent)."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Conflict", 409)
        )

        result = await mock_admin_client.register_required_action(
            "test-realm", "existing-action", "Existing Action", "default"
        )

        assert result is True


class TestAuthenticatorConfigMethods:
    """Tests for authenticator config management methods."""

    @pytest.mark.asyncio
    async def test_get_authenticator_config_returns_config(self, mock_admin_client):
        """Should return authenticator config."""
        mock_response = MockResponse(
            200,
            {"id": "config-123", "alias": "otp-config", "config": {"otpType": "totp"}},
        )
        mock_admin_client._make_request = AsyncMock(return_value=mock_response)

        config = await mock_admin_client.get_authenticator_config(
            "test-realm", "config-123", "default"
        )

        assert config is not None
        assert config.alias == "otp-config"

    @pytest.mark.asyncio
    async def test_get_authenticator_config_returns_none_on_404(
        self, mock_admin_client
    ):
        """Should return None when config not found."""
        mock_admin_client._make_request = AsyncMock(
            side_effect=KeycloakAdminError("Not found", 404)
        )

        config = await mock_admin_client.get_authenticator_config(
            "test-realm", "nonexistent", "default"
        )

        assert config is None

    @pytest.mark.asyncio
    async def test_create_authenticator_config_returns_id(self, mock_admin_client):
        """Should return config ID on success."""
        mock_response = MockResponse(
            201, headers={"Location": "http://kc/config/config-456"}
        )
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        config_id = await mock_admin_client.create_authenticator_config(
            "test-realm",
            "exec-123",
            AuthenticatorConfigRepresentation(alias="otp-config", config={}),
            "default",
        )

        assert config_id == "config-456"

    @pytest.mark.asyncio
    async def test_update_authenticator_config_returns_true(self, mock_admin_client):
        """Should return True when config is updated."""
        mock_response = MockResponse(204)
        mock_admin_client._make_validated_request = AsyncMock(
            return_value=mock_response
        )

        result = await mock_admin_client.update_authenticator_config(
            "test-realm",
            "config-123",
            AuthenticatorConfigRepresentation(
                alias="otp-config", config={"otpType": "hotp"}
            ),
            "default",
        )

        assert result is True
