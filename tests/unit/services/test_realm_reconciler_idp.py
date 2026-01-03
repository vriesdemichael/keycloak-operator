"""Unit tests for realm reconciler identity provider lifecycle management."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.realm import (
    KeycloakIdentityProvider,
    KeycloakIdentityProviderMapper,
    KeycloakRealmSpec,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def mock_admin_client():
    """Create a mock admin client."""
    client = MagicMock()
    client.get_identity_providers = AsyncMock(return_value=[])
    client.get_identity_provider_mappers = AsyncMock(return_value=[])
    client.configure_identity_provider = AsyncMock(return_value=True)
    client.delete_identity_provider = AsyncMock(return_value=True)
    client.configure_identity_provider_mapper = AsyncMock(return_value=True)
    client.delete_identity_provider_mapper = AsyncMock(return_value=True)
    return client


@pytest.fixture
def mock_reconciler(mock_admin_client):
    """Create a realm reconciler with mocked dependencies."""
    reconciler = KeycloakRealmReconciler(
        k8s_client=MagicMock(),
        keycloak_admin_factory=AsyncMock(return_value=mock_admin_client),
        rate_limiter=None,
    )
    # Mock _fetch_secret_value to avoid K8s calls
    # type: ignore[method-assign] - intentional mock for testing
    reconciler._fetch_secret_value = AsyncMock(return_value="secret-value")  # type: ignore[method-assign]
    return reconciler


class TestConfigureIdentityProviders:
    """Tests for configure_identity_providers method."""

    @pytest.mark.asyncio
    async def test_creates_new_idp(self, mock_reconciler, mock_admin_client):
        """Should create new IDP when it doesn't exist."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak"),
            identity_providers=[
                KeycloakIdentityProvider(
                    alias="github",
                    provider_id="github",
                    enabled=True,
                ),
            ],
        )

        await mock_reconciler.configure_identity_providers(spec, "test", "default")

        mock_admin_client.configure_identity_provider.assert_called_once()

    @pytest.mark.asyncio
    async def test_deletes_removed_idp(self, mock_reconciler, mock_admin_client):
        """Should delete IDP when removed from spec."""
        from keycloak_operator.models.keycloak_api import IdentityProviderRepresentation

        # Existing IDP in Keycloak
        existing_idp = IdentityProviderRepresentation(
            alias="old-idp",
            provider_id="github",
        )
        mock_admin_client.get_identity_providers = AsyncMock(
            return_value=[existing_idp]
        )

        # Spec has no IDPs
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak"),
            identity_providers=[],
        )

        await mock_reconciler.configure_identity_providers(spec, "test", "default")

        mock_admin_client.delete_identity_provider.assert_called_once_with(
            "test-realm", "old-idp", "default"
        )

    @pytest.mark.asyncio
    async def test_keeps_idp_in_spec(self, mock_reconciler, mock_admin_client):
        """Should not delete IDP that is still in spec."""
        from keycloak_operator.models.keycloak_api import IdentityProviderRepresentation

        # Existing IDP in Keycloak
        existing_idp = IdentityProviderRepresentation(
            alias="github",
            provider_id="github",
        )
        mock_admin_client.get_identity_providers = AsyncMock(
            return_value=[existing_idp]
        )

        # Spec still has the IDP
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak"),
            identity_providers=[
                KeycloakIdentityProvider(
                    alias="github",
                    provider_id="github",
                ),
            ],
        )

        await mock_reconciler.configure_identity_providers(spec, "test", "default")

        mock_admin_client.delete_identity_provider.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_no_idps_in_spec(self, mock_reconciler, mock_admin_client):
        """Should handle spec with no IDPs gracefully."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak"),
        )

        # Should not raise
        await mock_reconciler.configure_identity_providers(spec, "test", "default")


class TestConfigureIdentityProviderMappers:
    """Tests for _configure_identity_provider_mappers method."""

    @pytest.mark.asyncio
    async def test_creates_new_mapper(self, mock_reconciler, mock_admin_client):
        """Should create new mapper when it doesn't exist."""
        mappers = [
            KeycloakIdentityProviderMapper(
                name="email-mapper",
                identity_provider_mapper="oidc-user-attribute-idp-mapper",
            ),
        ]

        await mock_reconciler._configure_identity_provider_mappers(
            admin_client=mock_admin_client,
            realm_name="test-realm",
            idp_alias="github",
            desired_mappers=mappers,
            namespace="default",
        )

        mock_admin_client.configure_identity_provider_mapper.assert_called_once()

    @pytest.mark.asyncio
    async def test_deletes_removed_mapper(self, mock_reconciler, mock_admin_client):
        """Should delete mapper when removed from spec."""
        from keycloak_operator.models.keycloak_api import (
            IdentityProviderMapperRepresentation,
        )

        # Existing mapper in Keycloak
        existing_mapper = IdentityProviderMapperRepresentation(
            id="mapper-1",
            name="old-mapper",
            identity_provider_alias="github",
        )
        mock_admin_client.get_identity_provider_mappers = AsyncMock(
            return_value=[existing_mapper]
        )

        # Spec has no mappers
        await mock_reconciler._configure_identity_provider_mappers(
            admin_client=mock_admin_client,
            realm_name="test-realm",
            idp_alias="github",
            desired_mappers=[],
            namespace="default",
        )

        mock_admin_client.delete_identity_provider_mapper.assert_called_once_with(
            "test-realm", "github", "mapper-1", "default"
        )

    @pytest.mark.asyncio
    async def test_keeps_mapper_in_spec(self, mock_reconciler, mock_admin_client):
        """Should not delete mapper that is still in spec."""
        from keycloak_operator.models.keycloak_api import (
            IdentityProviderMapperRepresentation,
        )

        # Existing mapper in Keycloak
        existing_mapper = IdentityProviderMapperRepresentation(
            id="mapper-1",
            name="email-mapper",
            identity_provider_alias="github",
        )
        mock_admin_client.get_identity_provider_mappers = AsyncMock(
            return_value=[existing_mapper]
        )

        # Spec still has the mapper
        mappers = [
            KeycloakIdentityProviderMapper(
                name="email-mapper",
                identity_provider_mapper="oidc-user-attribute-idp-mapper",
            ),
        ]

        await mock_reconciler._configure_identity_provider_mappers(
            admin_client=mock_admin_client,
            realm_name="test-realm",
            idp_alias="github",
            desired_mappers=mappers,
            namespace="default",
        )

        mock_admin_client.delete_identity_provider_mapper.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_empty_mappers(self, mock_reconciler, mock_admin_client):
        """Should handle empty mapper list gracefully."""
        await mock_reconciler._configure_identity_provider_mappers(
            admin_client=mock_admin_client,
            realm_name="test-realm",
            idp_alias="github",
            desired_mappers=[],
            namespace="default",
        )

        mock_admin_client.configure_identity_provider_mapper.assert_not_called()


class TestFullIdpLifecycle:
    """Tests for full IDP lifecycle with mappers."""

    @pytest.mark.asyncio
    async def test_idp_with_mappers(self, mock_reconciler, mock_admin_client):
        """Should configure IDP and its mappers."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak"),
            identity_providers=[
                KeycloakIdentityProvider(
                    alias="github",
                    provider_id="github",
                    mappers=[
                        KeycloakIdentityProviderMapper(
                            name="email-mapper",
                            identity_provider_mapper="oidc-user-attribute-idp-mapper",
                        ),
                    ],
                ),
            ],
        )

        await mock_reconciler.configure_identity_providers(spec, "test", "default")

        # Should configure IDP
        mock_admin_client.configure_identity_provider.assert_called_once()
        # Should configure mapper
        mock_admin_client.configure_identity_provider_mapper.assert_called_once()
