"""
Unit tests for Keycloak API Pydantic models.

This module tests the auto-generated Pydantic models from the Keycloak OpenAPI spec
to ensure they properly validate data and handle API serialization/deserialization.
"""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.keycloak_api import (
    ClientRepresentation,
    RealmRepresentation,
)


class TestRealmRepresentation:
    """Test suite for RealmRepresentation model."""

    def test_realm_representation_basic_validation(self):
        """Test RealmRepresentation validates correctly with basic fields."""
        realm = RealmRepresentation(
            realm="test-realm", enabled=True, display_name="Test Realm"
        )

        assert realm.realm == "test-realm"
        assert realm.enabled is True
        assert realm.display_name == "Test Realm"

    def test_realm_representation_all_fields_optional(self):
        """Test that all fields are optional (can be None)."""
        # Should not raise ValidationError
        realm = RealmRepresentation()
        assert realm.realm is None
        assert realm.enabled is None

    def test_realm_representation_serialization_with_aliases(self):
        """Test RealmRepresentation serializes with camelCase aliases for API."""
        realm = RealmRepresentation(
            realm="test", display_name="Test Realm", ssl_required="external"
        )

        # Dump for API (camelCase)
        api_data = realm.model_dump(by_alias=True, exclude_none=True)

        assert "realm" in api_data
        assert "displayName" in api_data  # camelCase for API
        assert "sslRequired" in api_data
        assert api_data["displayName"] == "Test Realm"
        assert api_data["sslRequired"] == "external"

    def test_realm_representation_deserialization_from_api(self):
        """Test parsing API responses into RealmRepresentation."""
        api_response = {
            "id": "12345",
            "realm": "test",
            "displayName": "Test Realm",
            "enabled": True,
            "sslRequired": "external",
        }

        realm = RealmRepresentation.model_validate(api_response)

        assert realm.id == "12345"
        assert realm.realm == "test"
        assert realm.display_name == "Test Realm"  # snake_case in Python
        assert realm.enabled is True
        assert realm.ssl_required == "external"

    def test_realm_representation_exclude_none(self):
        """Test that exclude_none properly filters out None values."""
        realm = RealmRepresentation(realm="test", enabled=True)

        api_data = realm.model_dump(by_alias=True, exclude_none=True)

        # Only provided fields should be in output
        assert "realm" in api_data
        assert "enabled" in api_data
        # These fields were not set, so should be excluded
        assert "displayName" not in api_data
        assert "sslRequired" not in api_data

    def test_realm_representation_with_complex_fields(self):
        """Test RealmRepresentation with nested objects."""
        realm = RealmRepresentation(
            realm="test",
            enabled=True,
            # Test with various field types
            registration_allowed=True,
            registration_email_as_username=False,
            verify_email=True,
            login_with_email_allowed=True,
            duplicate_emails_allowed=False,
        )

        assert realm.registration_allowed is True
        assert realm.registration_email_as_username is False
        assert realm.verify_email is True

    def test_realm_representation_type_validation(self):
        """Test that invalid types raise ValidationError."""
        # Invalid string for bool field
        with pytest.raises(ValidationError):
            RealmRepresentation(enabled="invalid_bool")  # type: ignore[arg-type]

        # Int when string is expected
        with pytest.raises(ValidationError):
            RealmRepresentation(ssl_required=123)  # type: ignore[arg-type]


class TestClientRepresentation:
    """Test suite for ClientRepresentation model."""

    def test_client_representation_basic_validation(self):
        """Test ClientRepresentation validates correctly with basic fields."""
        client = ClientRepresentation(
            client_id="my-client", enabled=True, public_client=True
        )

        assert client.client_id == "my-client"
        assert client.enabled is True
        assert client.public_client is True

    def test_client_representation_all_fields_optional(self):
        """Test that all fields are optional (can be None)."""
        # Should not raise ValidationError
        client = ClientRepresentation()
        assert client.client_id is None
        assert client.enabled is None

    def test_client_representation_serialization_with_aliases(self):
        """Test ClientRepresentation serializes with camelCase aliases."""
        client = ClientRepresentation(
            client_id="my-client",
            public_client=True,
            redirect_uris=["http://localhost:3000/*"],
            web_origins=["http://localhost:3000"],
        )

        # Dump for API (camelCase)
        api_data = client.model_dump(by_alias=True, exclude_none=True)

        assert "clientId" in api_data  # camelCase for API
        assert "publicClient" in api_data
        assert "redirectUris" in api_data
        assert "webOrigins" in api_data
        assert api_data["clientId"] == "my-client"
        assert api_data["publicClient"] is True

    def test_client_representation_deserialization_from_api(self):
        """Test parsing API responses into ClientRepresentation."""
        api_response = {
            "id": "client-uuid-12345",
            "clientId": "my-client",
            "enabled": True,
            "publicClient": True,
            "redirectUris": ["http://localhost:3000/*"],
            "webOrigins": ["http://localhost:3000"],
        }

        client = ClientRepresentation.model_validate(api_response)

        assert client.id == "client-uuid-12345"
        assert client.client_id == "my-client"  # snake_case in Python
        assert client.enabled is True
        assert client.public_client is True
        assert client.redirect_uris == ["http://localhost:3000/*"]
        assert client.web_origins == ["http://localhost:3000"]

    def test_client_representation_exclude_none(self):
        """Test that exclude_none properly filters out None values."""
        client = ClientRepresentation(client_id="my-client", enabled=True)

        api_data = client.model_dump(by_alias=True, exclude_none=True)

        # Only provided fields should be in output
        assert "clientId" in api_data
        assert "enabled" in api_data
        # These fields were not set, so should be excluded
        assert "publicClient" not in api_data
        assert "redirectUris" not in api_data

    def test_client_representation_with_arrays(self):
        """Test ClientRepresentation with array fields."""
        client = ClientRepresentation(
            client_id="my-client",
            redirect_uris=["http://localhost:3000/*", "http://localhost:4200/*"],
            web_origins=["http://localhost:3000", "http://localhost:4200"],
            default_client_scopes=["openid", "profile", "email"],
        )

        assert client.redirect_uris is not None
        assert client.web_origins is not None
        assert client.default_client_scopes is not None
        assert len(client.redirect_uris) == 2
        assert len(client.web_origins) == 2
        assert len(client.default_client_scopes) == 3
        assert "openid" in client.default_client_scopes

    def test_client_representation_type_coercion(self):
        """Test that Pydantic performs type coercion."""
        # String "invalid" is not coercible to bool, so this should raise
        with pytest.raises(ValidationError):
            ClientRepresentation(enabled="invalid_bool")  # type: ignore[arg-type]

        # Single string is not coercible to list, so this should raise
        with pytest.raises(ValidationError):
            ClientRepresentation(redirect_uris="http://localhost:3000/*")  # type: ignore[arg-type]


class TestModelRoundTrip:
    """Test round-trip conversion between Python models and API JSON."""

    def test_realm_roundtrip(self):
        """Test realm data can round-trip through model validation."""
        # Start with API data
        api_data = {
            "realm": "my-realm",
            "displayName": "My Realm",
            "enabled": True,
            "sslRequired": "external",
            "registrationAllowed": True,
            "loginWithEmailAllowed": True,
        }

        # Parse from API
        realm = RealmRepresentation.model_validate(api_data)

        # Convert back to API format
        output_data = realm.model_dump(by_alias=True, exclude_none=True)

        # Should match original data
        assert output_data["realm"] == api_data["realm"]
        assert output_data["displayName"] == api_data["displayName"]
        assert output_data["enabled"] == api_data["enabled"]
        assert output_data["sslRequired"] == api_data["sslRequired"]

    def test_client_roundtrip(self):
        """Test client data can round-trip through model validation."""
        # Start with API data
        api_data = {
            "clientId": "my-client",
            "enabled": True,
            "publicClient": False,
            "redirectUris": ["http://localhost:3000/*"],
            "webOrigins": ["http://localhost:3000"],
        }

        # Parse from API
        client = ClientRepresentation.model_validate(api_data)

        # Convert back to API format
        output_data = client.model_dump(by_alias=True, exclude_none=True)

        # Should match original data
        assert output_data["clientId"] == api_data["clientId"]
        assert output_data["enabled"] == api_data["enabled"]
        assert output_data["publicClient"] == api_data["publicClient"]
        assert output_data["redirectUris"] == api_data["redirectUris"]


class TestModelIntegrationWithAdminClient:
    """Test integration scenarios with the admin client."""

    def test_dict_to_model_conversion(self):
        """Test converting legacy dict configs to models."""
        # Legacy dict-based config
        legacy_realm_config = {
            "realm": "test",
            "displayName": "Test Realm",
            "enabled": True,
        }

        # Convert to model
        realm = RealmRepresentation.model_validate(legacy_realm_config)

        # Should validate successfully
        assert realm.realm == "test"
        assert realm.display_name == "Test Realm"

    def test_model_to_api_json(self):
        """Test models produce correct API JSON format."""
        # Create model
        client = ClientRepresentation(
            client_id="test-client",
            enabled=True,
            public_client=True,
            redirect_uris=["http://localhost/*"],
        )

        # Convert to API JSON
        api_json = client.model_dump(by_alias=True, exclude_none=True)

        # Verify API format
        assert isinstance(api_json, dict)
        assert "clientId" in api_json
        assert "publicClient" in api_json
        assert api_json["clientId"] == "test-client"

    def test_partial_update_scenario(self):
        """Test partial updates exclude None values."""
        # Partial update with only a few fields
        realm = RealmRepresentation(realm="test", enabled=False)

        # Dump for API - should only include set fields
        update_data = realm.model_dump(by_alias=True, exclude_none=True)

        # Only these fields should be present
        assert len(update_data) == 2
        assert "realm" in update_data
        assert "enabled" in update_data
        # All other fields should be excluded
        assert "displayName" not in update_data
        assert "sslRequired" not in update_data
