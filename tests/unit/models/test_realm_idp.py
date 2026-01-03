"""Unit tests for KeycloakIdentityProvider and KeycloakIdentityProviderMapper models."""

import pytest

from keycloak_operator.models.realm import (
    KeycloakIdentityProvider,
    KeycloakIdentityProviderMapper,
    KeycloakIdentityProviderSecretRef,
)


class TestKeycloakIdentityProviderMapper:
    """Tests for KeycloakIdentityProviderMapper model."""

    def test_creates_valid_mapper(self):
        """Should create a valid mapper with required fields."""
        mapper = KeycloakIdentityProviderMapper(
            name="email-mapper",
            identity_provider_mapper="oidc-user-attribute-idp-mapper",
            config={"claim": "email", "user.attribute": "email"},
        )

        assert mapper.name == "email-mapper"
        assert mapper.identity_provider_mapper == "oidc-user-attribute-idp-mapper"
        assert mapper.config["claim"] == "email"

    def test_mapper_with_empty_config(self):
        """Should allow empty config dict."""
        mapper = KeycloakIdentityProviderMapper(
            name="simple-mapper",
            identity_provider_mapper="hardcoded-attribute-idp-mapper",
        )

        assert mapper.config == {}

    def test_mapper_rejects_empty_name(self):
        """Should reject empty name."""
        with pytest.raises(ValueError, match="Mapper name must be a non-empty string"):
            KeycloakIdentityProviderMapper(
                name="",
                identity_provider_mapper="oidc-user-attribute-idp-mapper",
            )

    def test_mapper_rejects_empty_mapper_type(self):
        """Should reject empty mapper type."""
        with pytest.raises(ValueError, match="Mapper type must be a non-empty string"):
            KeycloakIdentityProviderMapper(
                name="test-mapper",
                identity_provider_mapper="",
            )

    def test_mapper_serializes_with_alias(self):
        """Should serialize with camelCase alias."""
        mapper = KeycloakIdentityProviderMapper(
            name="email-mapper",
            identity_provider_mapper="oidc-user-attribute-idp-mapper",
        )

        data = mapper.model_dump(by_alias=True)
        assert "identityProviderMapper" in data
        assert data["identityProviderMapper"] == "oidc-user-attribute-idp-mapper"


class TestKeycloakIdentityProviderWithMappers:
    """Tests for KeycloakIdentityProvider with mappers field."""

    def test_idp_with_empty_mappers(self):
        """Should create IDP with empty mappers list by default."""
        idp = KeycloakIdentityProvider(
            alias="github",
            provider_id="github",
        )

        assert idp.mappers == []

    def test_idp_with_mappers(self):
        """Should create IDP with mappers."""
        mappers = [
            KeycloakIdentityProviderMapper(
                name="email-mapper",
                identity_provider_mapper="oidc-user-attribute-idp-mapper",
                config={"claim": "email", "user.attribute": "email"},
            ),
            KeycloakIdentityProviderMapper(
                name="groups-mapper",
                identity_provider_mapper="oidc-group-idp-mapper",
                config={"syncMode": "INHERIT"},
            ),
        ]

        idp = KeycloakIdentityProvider(
            alias="github",
            provider_id="github",
            mappers=mappers,
        )

        assert len(idp.mappers) == 2
        assert idp.mappers[0].name == "email-mapper"
        assert idp.mappers[1].name == "groups-mapper"

    def test_idp_serializes_mappers(self):
        """Should serialize mappers correctly."""
        mapper = KeycloakIdentityProviderMapper(
            name="email-mapper",
            identity_provider_mapper="oidc-user-attribute-idp-mapper",
        )

        idp = KeycloakIdentityProvider(
            alias="github",
            provider_id="github",
            mappers=[mapper],
        )

        data = idp.model_dump(by_alias=True, exclude_unset=True)
        assert "mappers" in data
        assert len(data["mappers"]) == 1
        assert (
            data["mappers"][0]["identityProviderMapper"]
            == "oidc-user-attribute-idp-mapper"
        )

    def test_idp_with_all_fields(self):
        """Should create IDP with all fields including mappers."""
        mapper = KeycloakIdentityProviderMapper(
            name="email-mapper",
            identity_provider_mapper="oidc-user-attribute-idp-mapper",
        )

        secret_ref = KeycloakIdentityProviderSecretRef(
            name="idp-secret",
            key="clientSecret",
        )

        idp = KeycloakIdentityProvider(
            alias="azure-ad",
            provider_id="oidc",
            display_name="Azure AD",
            enabled=True,
            config={"clientId": "my-client-id"},
            config_secrets={"clientSecret": secret_ref},
            first_broker_login_flow_alias="first broker login",
            trust_email=True,
            mappers=[mapper],
        )

        assert idp.alias == "azure-ad"
        assert idp.provider_id == "oidc"
        assert len(idp.mappers) == 1
        assert "clientSecret" in idp.config_secrets
