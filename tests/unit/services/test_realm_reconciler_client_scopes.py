"""Unit tests for KeycloakRealmReconciler client scopes methods."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.keycloak_api import (
    ClientScopeRepresentation,
    ProtocolMapperRepresentation,
)
from keycloak_operator.models.realm import (
    KeycloakClientScope,
    KeycloakProtocolMapper,
    KeycloakRealmSpec,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client with client scope methods."""
    mock = MagicMock()

    # Client scope methods
    mock.get_client_scopes = AsyncMock(return_value=[])
    mock.get_client_scope_by_name = AsyncMock(return_value=None)
    mock.get_client_scope_by_id = AsyncMock(return_value=None)
    mock.create_client_scope = AsyncMock(return_value="new-scope-id")
    mock.update_client_scope = AsyncMock(return_value=True)
    mock.delete_client_scope = AsyncMock(return_value=True)

    # Realm default/optional client scopes
    mock.get_realm_default_client_scopes = AsyncMock(return_value=[])
    mock.add_realm_default_client_scope = AsyncMock(return_value=True)
    mock.remove_realm_default_client_scope = AsyncMock(return_value=True)
    mock.get_realm_optional_client_scopes = AsyncMock(return_value=[])
    mock.add_realm_optional_client_scope = AsyncMock(return_value=True)
    mock.remove_realm_optional_client_scope = AsyncMock(return_value=True)

    # Protocol mapper methods
    mock.get_client_scope_protocol_mappers = AsyncMock(return_value=[])
    mock.create_client_scope_protocol_mapper = AsyncMock(return_value="new-mapper-id")
    mock.update_client_scope_protocol_mapper = AsyncMock(return_value=True)
    mock.delete_client_scope_protocol_mapper = AsyncMock(return_value=True)

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


# =============================================================================
# Client Scopes Tests
# =============================================================================


class TestConfigureClientScopes:
    """Tests for configure_client_scopes method."""

    @pytest.mark.asyncio
    async def test_creates_new_client_scope(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New client scope should be created when it doesn't exist."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Read access to API",
                    protocol="openid-connect",
                )
            ],
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.create_client_scope.assert_called_once()
        call_args = admin_mock.create_client_scope.call_args
        assert call_args[0][0] == "test-realm"  # realm_name
        created_scope = call_args[0][1]
        assert created_scope.name == "api.read"
        assert created_scope.description == "Read access to API"

    @pytest.mark.asyncio
    async def test_updates_existing_client_scope(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing client scope should be updated."""
        existing_scope = ClientScopeRepresentation(
            id="existing-scope-id",
            name="api.read",
            description="Old description",
            protocol="openid-connect",
        )
        admin_mock.get_client_scopes = AsyncMock(return_value=[existing_scope])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Updated description",
                    protocol="openid-connect",
                )
            ],
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.update_client_scope.assert_called_once()
        call_args = admin_mock.update_client_scope.call_args
        assert call_args[0][0] == "test-realm"  # realm_name
        assert call_args[0][1] == "existing-scope-id"  # scope_id

    @pytest.mark.asyncio
    async def test_deletes_scope_no_longer_in_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Scope should be deleted when removed from spec (non-builtin)."""
        existing_scope = ClientScopeRepresentation(
            id="old-scope-id",
            name="old-custom-scope",
            protocol="openid-connect",
        )
        admin_mock.get_client_scopes = AsyncMock(return_value=[existing_scope])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[
                KeycloakClientScope(
                    name="new-scope",
                    protocol="openid-connect",
                )
            ],
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.delete_client_scope.assert_called_once_with(
            "test-realm", "old-scope-id", "default"
        )

    @pytest.mark.asyncio
    async def test_skips_builtin_scopes_on_delete(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Built-in scopes should not be deleted."""
        builtin_scope = ClientScopeRepresentation(
            id="builtin-scope-id",
            name="profile",  # Built-in scope
            protocol="openid-connect",
        )
        admin_mock.get_client_scopes = AsyncMock(return_value=[builtin_scope])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[],  # No custom scopes
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.delete_client_scope.assert_not_called()

    @pytest.mark.asyncio
    async def test_creates_scope_with_protocol_mappers(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Client scope with protocol mappers should have mappers created."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Read access",
                    protocol="openid-connect",
                    protocol_mappers=[
                        KeycloakProtocolMapper(
                            name="audience-mapper",
                            protocol="openid-connect",
                            protocol_mapper="oidc-audience-mapper",
                            config={"included.custom.audience": "api"},
                        )
                    ],
                )
            ],
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.create_client_scope.assert_called_once()
        admin_mock.create_client_scope_protocol_mapper.assert_called_once()

    @pytest.mark.asyncio
    async def test_empty_client_scopes_returns_early(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """No client scopes should skip processing."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            client_scopes=[],
        )

        await reconciler.configure_client_scopes(spec, "test-realm", "default")

        admin_mock.get_client_scopes.assert_not_called()


# =============================================================================
# Realm Default/Optional Client Scopes Tests
# =============================================================================


class TestConfigureRealmDefaultClientScopes:
    """Tests for configure_realm_default_client_scopes method."""

    @pytest.mark.asyncio
    async def test_adds_new_default_scope(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New default scope should be added to realm."""
        # Available scopes in the realm
        admin_mock.get_client_scopes = AsyncMock(
            return_value=[
                ClientScopeRepresentation(id="scope-1", name="api.read"),
                ClientScopeRepresentation(id="scope-2", name="api.write"),
            ]
        )
        # Currently no default scopes
        admin_mock.get_realm_default_client_scopes = AsyncMock(return_value=[])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_client_scopes=["api.read"],
        )

        await reconciler.configure_realm_default_client_scopes(
            spec, "test-realm", "default"
        )

        admin_mock.add_realm_default_client_scope.assert_called_once_with(
            "test-realm", "scope-1", "default"
        )

    @pytest.mark.asyncio
    async def test_removes_scope_from_defaults(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Scope should be removed from defaults when not in spec."""
        admin_mock.get_client_scopes = AsyncMock(
            return_value=[
                ClientScopeRepresentation(id="scope-1", name="api.read"),
                ClientScopeRepresentation(id="scope-2", name="api.write"),
            ]
        )
        # Currently api.read is a default scope
        admin_mock.get_realm_default_client_scopes = AsyncMock(
            return_value=[ClientScopeRepresentation(id="scope-1", name="api.read")]
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_client_scopes=["api.write"],  # Only api.write, api.read removed
        )

        await reconciler.configure_realm_default_client_scopes(
            spec, "test-realm", "default"
        )

        admin_mock.remove_realm_default_client_scope.assert_called_once_with(
            "test-realm", "scope-1", "default"
        )

    @pytest.mark.asyncio
    async def test_adds_new_optional_scope(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New optional scope should be added to realm."""
        admin_mock.get_client_scopes = AsyncMock(
            return_value=[
                ClientScopeRepresentation(id="scope-2", name="api.write"),
            ]
        )
        admin_mock.get_realm_optional_client_scopes = AsyncMock(return_value=[])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            optional_client_scopes=["api.write"],
        )

        await reconciler.configure_realm_default_client_scopes(
            spec, "test-realm", "default"
        )

        admin_mock.add_realm_optional_client_scope.assert_called_once_with(
            "test-realm", "scope-2", "default"
        )

    @pytest.mark.asyncio
    async def test_warns_on_missing_scope(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Warning should be logged when scope doesn't exist."""
        admin_mock.get_client_scopes = AsyncMock(return_value=[])  # No scopes exist
        admin_mock.get_realm_default_client_scopes = AsyncMock(return_value=[])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_client_scopes=["nonexistent-scope"],
        )

        await reconciler.configure_realm_default_client_scopes(
            spec, "test-realm", "default"
        )

        admin_mock.add_realm_default_client_scope.assert_not_called()
        reconciler.logger.warning.assert_called()


# =============================================================================
# Protocol Mappers Sync Tests
# =============================================================================


class TestSyncClientScopeProtocolMappers:
    """Tests for _sync_client_scope_protocol_mappers method."""

    @pytest.mark.asyncio
    async def test_creates_new_mapper(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New protocol mapper should be created."""
        admin_mock.get_client_scope_protocol_mappers = AsyncMock(return_value=[])

        desired_mappers = [
            KeycloakProtocolMapper(
                name="new-mapper",
                protocol="openid-connect",
                protocol_mapper="oidc-usermodel-attribute-mapper",
                config={"claim.name": "custom_claim"},
            )
        ]

        await reconciler._sync_client_scope_protocol_mappers(
            admin_mock, "test-realm", "scope-id", desired_mappers, "default"
        )

        admin_mock.create_client_scope_protocol_mapper.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_mapper(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing protocol mapper should be updated."""
        existing_mapper = ProtocolMapperRepresentation(
            id="existing-mapper-id",
            name="existing-mapper",
            protocol="openid-connect",
            protocol_mapper="oidc-usermodel-attribute-mapper",
        )
        admin_mock.get_client_scope_protocol_mappers = AsyncMock(
            return_value=[existing_mapper]
        )

        desired_mappers = [
            KeycloakProtocolMapper(
                name="existing-mapper",
                protocol="openid-connect",
                protocol_mapper="oidc-usermodel-attribute-mapper",
                config={"claim.name": "updated_claim"},
            )
        ]

        await reconciler._sync_client_scope_protocol_mappers(
            admin_mock, "test-realm", "scope-id", desired_mappers, "default"
        )

        admin_mock.update_client_scope_protocol_mapper.assert_called_once()

    @pytest.mark.asyncio
    async def test_deletes_removed_mapper(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Protocol mapper should be deleted when removed from spec."""
        existing_mapper = ProtocolMapperRepresentation(
            id="old-mapper-id",
            name="old-mapper",
            protocol="openid-connect",
            protocol_mapper="oidc-usermodel-attribute-mapper",
        )
        admin_mock.get_client_scope_protocol_mappers = AsyncMock(
            return_value=[existing_mapper]
        )

        desired_mappers = []  # No mappers desired

        await reconciler._sync_client_scope_protocol_mappers(
            admin_mock, "test-realm", "scope-id", desired_mappers, "default"
        )

        admin_mock.delete_client_scope_protocol_mapper.assert_called_once_with(
            "test-realm", "scope-id", "old-mapper-id", "default"
        )
