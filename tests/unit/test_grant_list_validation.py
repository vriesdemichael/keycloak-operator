"""Unit tests for namespace grant list validation."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef


class TestClientAuthorizationGrants:
    """Test client authorization grants field validation."""

    def test_valid_namespace_single(self):
        """Test single valid namespace."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=["app-team"],
        )
        assert spec.client_authorization_grants == ["app-team"]

    def test_valid_namespace_multiple(self):
        """Test multiple valid namespaces."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=["app-team", "data-team", "platform-team"],
        )
        assert len(spec.client_authorization_grants) == 3

    def test_valid_namespace_with_hyphens(self):
        """Test namespace with hyphens."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=["my-app-team"],
        )
        assert spec.client_authorization_grants == ["my-app-team"]

    def test_empty_grant_list(self):
        """Test empty grant list (no namespaces authorized)."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=[],
        )
        assert spec.client_authorization_grants == []

    def test_default_grant_list(self):
        """Test default (no grant list specified)."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
        )
        assert spec.client_authorization_grants == []

    def test_invalid_namespace_too_long(self):
        """Test namespace exceeds 63 characters."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test-realm",
                operator_ref=OperatorRef(namespace="keycloak-system"),
                client_authorization_grants=["a" * 64],  # 64 chars, limit is 63
            )
        assert "exceeds 63 characters" in str(exc_info.value)

    def test_invalid_namespace_empty_string(self):
        """Test empty string in grant list."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test-realm",
                operator_ref=OperatorRef(namespace="keycloak-system"),
                client_authorization_grants=[""],
            )
        assert "cannot be empty strings" in str(exc_info.value)

    def test_invalid_namespace_starts_with_hyphen(self):
        """Test namespace starting with hyphen."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test-realm",
                operator_ref=OperatorRef(namespace="keycloak-system"),
                client_authorization_grants=["-invalid"],
            )
        assert "cannot start or end with hyphen" in str(exc_info.value)

    def test_invalid_namespace_ends_with_hyphen(self):
        """Test namespace ending with hyphen."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test-realm",
                operator_ref=OperatorRef(namespace="keycloak-system"),
                client_authorization_grants=["invalid-"],
            )
        assert "cannot start or end with hyphen" in str(exc_info.value)

    def test_invalid_namespace_special_chars(self):
        """Test namespace with invalid special characters."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test-realm",
                operator_ref=OperatorRef(namespace="keycloak-system"),
                client_authorization_grants=["app@team"],
            )
        assert "invalid characters" in str(exc_info.value)

    def test_duplicate_namespaces_allowed(self):
        """Test duplicate namespaces are allowed (idempotent)."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=["app-team", "app-team"],
        )
        # Duplicates are allowed - list is treated as-is
        assert len(spec.client_authorization_grants) == 2
        assert (
            spec.client_authorization_grants[0] == spec.client_authorization_grants[1]
        )

    def test_grant_list_max_length(self):
        """Test large grant list."""
        namespaces = [f"team-{i}" for i in range(100)]
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=namespaces,
        )
        assert len(spec.client_authorization_grants) == 100

    def test_grant_list_serialization(self):
        """Test grant list serializes correctly to dict."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=OperatorRef(namespace="keycloak-system"),
            client_authorization_grants=["app-team", "data-team"],
        )
        data = spec.model_dump(by_alias=True)
        assert data["clientAuthorizationGrants"] == ["app-team", "data-team"]
