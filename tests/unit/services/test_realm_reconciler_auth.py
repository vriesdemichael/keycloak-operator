"""Unit tests for KeycloakRealmReconciler authentication flow methods."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.realm import (
    AuthenticationExecutionExport,
    AuthenticatorConfigInfo,
    KeycloakAuthenticationFlow,
    KeycloakRealmSpec,
    OperatorRef,
    RequiredActionProvider,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client with authentication flow methods."""
    mock = MagicMock()

    # Authentication flow methods
    mock.get_authentication_flow_by_alias = AsyncMock(return_value=None)
    mock.create_authentication_flow = AsyncMock(return_value=True)
    mock.copy_authentication_flow = AsyncMock(return_value=True)
    mock.delete_authentication_flow = AsyncMock(return_value=True)
    mock.get_flow_executions = AsyncMock(return_value=[])
    mock.add_execution_to_flow = AsyncMock(return_value="exec-id-123")
    mock.add_subflow_to_flow = AsyncMock(return_value="subflow-id-456")
    mock.update_execution_requirement = AsyncMock(return_value=True)

    # Authenticator config methods
    mock.get_authenticator_config = AsyncMock(return_value=None)
    mock.create_authenticator_config = AsyncMock(return_value="config-id-789")
    mock.update_authenticator_config = AsyncMock(return_value=True)

    # Required action methods
    mock.get_required_action = AsyncMock(return_value=None)
    mock.get_required_actions = AsyncMock(return_value=[])
    mock.update_required_action = AsyncMock(return_value=True)
    mock.register_required_action = AsyncMock(return_value=True)

    # Realm methods
    mock.update_realm = AsyncMock(return_value=True)

    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakRealmReconciler:
    """KeycloakRealmReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace, rate_limiter=None):
        return admin_mock

    reconciler_instance = KeycloakRealmReconciler(
        keycloak_admin_factory=mock_factory,
    )
    reconciler_instance.logger = MagicMock()

    return reconciler_instance


class TestConfigureAuthentication:
    """Tests for configure_authentication method."""

    @pytest.mark.asyncio
    async def test_configure_authentication_creates_new_flow(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New flow should be created when it doesn't exist."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            authentication_flows=[
                KeycloakAuthenticationFlow(
                    alias="my-flow",
                    description="Test flow",
                    provider_id="basic-flow",
                    top_level=True,
                )
            ],
        )

        await reconciler.configure_authentication(spec, "test-realm", "default")

        admin_mock.get_authentication_flow_by_alias.assert_called_once()
        admin_mock.create_authentication_flow.assert_called_once()

    @pytest.mark.asyncio
    async def test_configure_authentication_copies_existing_flow(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Flow should be copied when copyFrom is specified."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            authentication_flows=[
                KeycloakAuthenticationFlow(
                    alias="custom-browser",
                    copy_from="browser",
                )
            ],
        )

        await reconciler.configure_authentication(spec, "test-realm", "default")

        admin_mock.copy_authentication_flow.assert_called_once_with(
            "test-realm", "browser", "custom-browser", "default"
        )

    @pytest.mark.asyncio
    async def test_configure_authentication_skips_existing_flow(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing flow should not be recreated."""
        # Mock that flow already exists
        existing_flow = MagicMock()
        existing_flow.alias = "my-flow"
        existing_flow.id = "flow-id-123"
        admin_mock.get_authentication_flow_by_alias = AsyncMock(
            return_value=existing_flow
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            authentication_flows=[
                KeycloakAuthenticationFlow(
                    alias="my-flow",
                    description="Test flow",
                )
            ],
        )

        await reconciler.configure_authentication(spec, "test-realm", "default")

        # Should not create or copy since flow exists
        admin_mock.create_authentication_flow.assert_not_called()
        admin_mock.copy_authentication_flow.assert_not_called()


class TestAddFlowExecutions:
    """Tests for _add_flow_executions method."""

    @pytest.mark.asyncio
    async def test_add_authenticator_execution(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Authenticator execution should be added to flow."""
        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",
                    priority=10,
                )
            ],
        )

        await reconciler._add_flow_executions(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.add_execution_to_flow.assert_called_once_with(
            "test-realm", "my-flow", "auth-cookie", "default"
        )
        admin_mock.update_execution_requirement.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_subflow_execution(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Sub-flow execution should be added to flow."""
        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    flow_alias="my-subflow",
                    authenticator_flow=True,
                    requirement="REQUIRED",
                    priority=10,
                )
            ],
        )

        await reconciler._add_flow_executions(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.add_subflow_to_flow.assert_called_once()
        admin_mock.add_execution_to_flow.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_execution_skips_disabled_requirement_update(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """DISABLED executions should not update requirement."""
        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-spnego",
                    requirement="DISABLED",
                    priority=10,
                )
            ],
        )

        await reconciler._add_flow_executions(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.add_execution_to_flow.assert_called_once()
        # Should NOT update requirement for DISABLED
        admin_mock.update_execution_requirement.assert_not_called()


class TestSyncFlowExecutions:
    """Tests for _sync_flow_executions method."""

    @pytest.mark.asyncio
    async def test_sync_updates_execution_requirement(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Execution requirement should be updated when different."""
        # Mock existing execution
        existing_exec = MagicMock()
        existing_exec.id = "exec-id-123"
        existing_exec.provider_id = "auth-cookie"
        existing_exec.alias = None
        existing_exec.display_name = None
        existing_exec.requirement = "DISABLED"
        admin_mock.get_flow_executions = AsyncMock(return_value=[existing_exec])

        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",  # Different from current DISABLED
                )
            ],
        )

        await reconciler._sync_flow_executions(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.update_execution_requirement.assert_called_once_with(
            "test-realm", "my-flow", "exec-id-123", "ALTERNATIVE", "default"
        )

    @pytest.mark.asyncio
    async def test_sync_skips_matching_requirement(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Execution requirement should not be updated when same."""
        existing_exec = MagicMock()
        existing_exec.id = "exec-id-123"
        existing_exec.provider_id = "auth-cookie"
        existing_exec.alias = None
        existing_exec.display_name = None
        existing_exec.requirement = "ALTERNATIVE"  # Same as desired
        admin_mock.get_flow_executions = AsyncMock(return_value=[existing_exec])

        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",
                )
            ],
        )

        await reconciler._sync_flow_executions(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.update_execution_requirement.assert_not_called()


class TestConfigureAuthenticatorConfigs:
    """Tests for _configure_authenticator_configs method."""

    @pytest.mark.asyncio
    async def test_creates_new_authenticator_config(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New authenticator config should be created."""
        # Mock execution without existing config
        existing_exec = MagicMock()
        existing_exec.id = "exec-id-123"
        existing_exec.provider_id = "auth-otp-form"
        existing_exec.authentication_config = None  # No existing config
        admin_mock.get_flow_executions = AsyncMock(return_value=[existing_exec])

        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-otp-form",
                    requirement="REQUIRED",
                    authenticator_config="otp-settings",
                )
            ],
            authenticator_config=[
                AuthenticatorConfigInfo(
                    alias="otp-settings",
                    config={"otpType": "totp", "otpLength": "6"},
                )
            ],
        )

        await reconciler._configure_authenticator_configs(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.create_authenticator_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_authenticator_config(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing authenticator config should be updated."""
        # Mock execution with existing config
        existing_exec = MagicMock()
        existing_exec.id = "exec-id-123"
        existing_exec.provider_id = "auth-otp-form"
        existing_exec.authentication_config = "existing-config-id"  # Has config
        admin_mock.get_flow_executions = AsyncMock(return_value=[existing_exec])

        flow_config = KeycloakAuthenticationFlow(
            alias="my-flow",
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-otp-form",
                    requirement="REQUIRED",
                    authenticator_config="otp-settings",
                )
            ],
            authenticator_config=[
                AuthenticatorConfigInfo(
                    alias="otp-settings",
                    config={"otpType": "hotp", "otpLength": "8"},
                )
            ],
        )

        await reconciler._configure_authenticator_configs(
            admin_mock, "test-realm", "my-flow", flow_config, "default"
        )

        admin_mock.update_authenticator_config.assert_called_once()


class TestConfigureRequiredActions:
    """Tests for configure_required_actions method."""

    @pytest.mark.asyncio
    async def test_updates_existing_required_action(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing required action should be updated."""
        # Mock that action exists
        existing_action = MagicMock()
        existing_action.alias = "CONFIGURE_TOTP"
        existing_action.name = "Configure OTP"
        existing_action.enabled = False
        admin_mock.get_required_action = AsyncMock(return_value=existing_action)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            required_actions=[
                RequiredActionProvider(
                    alias="CONFIGURE_TOTP",
                    name="Configure OTP",
                    enabled=True,
                    default_action=True,
                )
            ],
        )

        await reconciler.configure_required_actions(spec, "test-realm", "default")

        admin_mock.update_required_action.assert_called_once()
        admin_mock.register_required_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_registers_new_required_action(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New required action should be registered."""
        # Mock that action doesn't exist
        admin_mock.get_required_action = AsyncMock(return_value=None)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            required_actions=[
                RequiredActionProvider(
                    alias="CUSTOM_ACTION",
                    name="Custom Action",
                    provider_id="custom-action-provider",
                    enabled=True,
                )
            ],
        )

        await reconciler.configure_required_actions(spec, "test-realm", "default")

        admin_mock.register_required_action.assert_called_once()


class TestHasFlowBindings:
    """Tests for _has_flow_bindings method."""

    def test_returns_true_when_browser_flow_set(
        self,
        reconciler: KeycloakRealmReconciler,
    ) -> None:
        """Should return True when browserFlow is set."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            browser_flow="custom-browser",
        )
        assert reconciler._has_flow_bindings(spec) is True

    def test_returns_true_when_direct_grant_flow_set(
        self,
        reconciler: KeycloakRealmReconciler,
    ) -> None:
        """Should return True when directGrantFlow is set."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            direct_grant_flow="custom-direct",
        )
        assert reconciler._has_flow_bindings(spec) is True

    def test_returns_false_when_no_bindings(
        self,
        reconciler: KeycloakRealmReconciler,
    ) -> None:
        """Should return False when no flow bindings set."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
        )
        assert reconciler._has_flow_bindings(spec) is False


class TestApplyFlowBindings:
    """Tests for apply_flow_bindings method."""

    @pytest.mark.asyncio
    async def test_applies_browser_flow_binding(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Browser flow binding should be applied."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            browser_flow="custom-browser",
        )

        await reconciler.apply_flow_bindings(spec, "test-realm", "default")

        admin_mock.update_realm.assert_called_once()
        call_args = admin_mock.update_realm.call_args
        payload = call_args[0][1]
        assert payload["browserFlow"] == "custom-browser"

    @pytest.mark.asyncio
    async def test_applies_multiple_flow_bindings(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Multiple flow bindings should be applied."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            browser_flow="custom-browser",
            direct_grant_flow="custom-direct",
            reset_credentials_flow="custom-reset",
        )

        await reconciler.apply_flow_bindings(spec, "test-realm", "default")

        admin_mock.update_realm.assert_called_once()
        call_args = admin_mock.update_realm.call_args
        payload = call_args[0][1]
        assert payload["browserFlow"] == "custom-browser"
        assert payload["directGrantFlow"] == "custom-direct"
        assert payload["resetCredentialsFlow"] == "custom-reset"
