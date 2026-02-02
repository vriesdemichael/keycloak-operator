"""Unit tests for realm organization models."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.realm import (
    Organization,
    OrganizationDomain,
    OrganizationIdentityProvider,
)


class TestOrganizationDomain:
    """Tests for OrganizationDomain model."""

    def test_valid_domain(self):
        """Should create domain with valid name."""
        domain = OrganizationDomain(name="example.com")
        assert domain.name == "example.com"
        assert domain.verified is False

    def test_domain_with_verified(self):
        """Should support verified flag."""
        domain = OrganizationDomain(name="example.com", verified=True)
        assert domain.name == "example.com"
        assert domain.verified is True


class TestOrganizationIdentityProvider:
    """Tests for OrganizationIdentityProvider model."""

    def test_valid_idp(self):
        """Should create IdP link with alias."""
        idp = OrganizationIdentityProvider(alias="google")
        assert idp.alias == "google"
        assert idp.redirect_uri is None

    def test_idp_with_redirect_uri(self):
        """Should support custom redirect URI."""
        idp = OrganizationIdentityProvider(
            alias="google", redirectUri="https://app.example.com/callback"
        )
        assert idp.alias == "google"
        assert idp.redirect_uri == "https://app.example.com/callback"


class TestOrganization:
    """Tests for Organization model."""

    def test_valid_organization(self):
        """Should create organization with valid name."""
        org = Organization(name="acme-corp")
        assert org.name == "acme-corp"
        assert org.enabled is True
        assert org.domains == []
        assert org.attributes == {}

    def test_organization_with_all_fields(self):
        """Should create organization with all optional fields."""
        org = Organization(
            name="acme-corp",
            alias="acme",
            description="ACME Corporation",
            enabled=False,
            domains=[OrganizationDomain(name="acme.com", verified=True)],
            attributes={"tier": ["enterprise"]},
        )
        assert org.name == "acme-corp"
        assert org.alias == "acme"
        assert org.description == "ACME Corporation"
        assert org.enabled is False
        assert len(org.domains) == 1
        assert org.domains[0].name == "acme.com"
        assert org.attributes == {"tier": ["enterprise"]}

    def test_empty_name_raises_error(self):
        """Should raise error for empty name."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="")
        assert "non-empty string" in str(exc_info.value)

    def test_name_too_long_raises_error(self):
        """Should raise error for name exceeding 255 characters."""
        long_name = "a" * 256
        with pytest.raises(ValidationError) as exc_info:
            Organization(name=long_name)
        assert "255 characters" in str(exc_info.value)

    def test_name_max_length_allowed(self):
        """Should allow name of exactly 255 characters."""
        name = "a" * 255
        org = Organization(name=name)
        assert org.name == name

    def test_alias_with_slash_raises_error(self):
        """Should raise error for alias containing slash."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme/corp")
        assert "invalid character: /" in str(exc_info.value)

    def test_alias_with_backslash_raises_error(self):
        """Should raise error for alias containing backslash."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme\\corp")
        assert "invalid character: \\" in str(exc_info.value)

    def test_alias_with_space_raises_error(self):
        """Should raise error for alias containing space."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme corp")
        assert "invalid character:  " in str(exc_info.value)

    def test_alias_with_question_mark_raises_error(self):
        """Should raise error for alias containing question mark."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme?corp")
        assert "invalid character: ?" in str(exc_info.value)

    def test_alias_with_hash_raises_error(self):
        """Should raise error for alias containing hash."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme#corp")
        assert "invalid character: #" in str(exc_info.value)

    def test_alias_with_percent_raises_error(self):
        """Should raise error for alias containing percent."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme%corp")
        assert "invalid character: %" in str(exc_info.value)

    def test_alias_with_ampersand_raises_error(self):
        """Should raise error for alias containing ampersand."""
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias="acme&corp")
        assert "invalid character: &" in str(exc_info.value)

    def test_alias_too_long_raises_error(self):
        """Should raise error for alias exceeding 255 characters."""
        long_alias = "a" * 256
        with pytest.raises(ValidationError) as exc_info:
            Organization(name="test", alias=long_alias)
        assert "255 characters" in str(exc_info.value)

    def test_valid_alias(self):
        """Should allow valid URL-friendly alias."""
        org = Organization(name="test", alias="acme-corp_123")
        assert org.alias == "acme-corp_123"

    def test_alias_none_allowed(self):
        """Should allow None alias (defaults to name at reconciliation)."""
        org = Organization(name="test", alias=None)
        assert org.alias is None

    def test_organization_with_identity_providers(self):
        """Should support identity providers (reserved for future use)."""
        org = Organization(
            name="test",
            identity_providers=[
                OrganizationIdentityProvider(alias="google"),
                OrganizationIdentityProvider(
                    alias="azure-ad", redirectUri="https://example.com/callback"
                ),
            ],
        )
        assert len(org.identity_providers) == 2
        assert org.identity_providers[0].alias == "google"
        assert org.identity_providers[1].alias == "azure-ad"
