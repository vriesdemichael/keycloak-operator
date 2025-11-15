"""
Unit tests for Pydantic models.

These tests verify that the data models correctly validate input
and provide proper error messages for invalid configurations.
"""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.client import KeycloakClient, KeycloakClientSpec, RealmRef
from keycloak_operator.models.keycloak import (
    Keycloak,
    KeycloakResourceRequirements,
    KeycloakServiceConfig,
    KeycloakSpec,
)
from keycloak_operator.models.realm import KeycloakRealm, KeycloakRealmSpec, OperatorRef


# Helper functions for test data
def _make_operator_ref(namespace="keycloak-system"):
    """Create a test OperatorRef."""
    return OperatorRef(
        namespace=namespace,
    )


def _make_realm_ref(name="test-realm", namespace="default"):
    """Create a test RealmRef."""
    return RealmRef(
        name=name,
        namespace=namespace,
    )


class TestKeycloakModels:
    """Test cases for Keycloak instance models."""

    def test_keycloak_spec_defaults(self):
        """Test that KeycloakSpec has sensible defaults."""
        from keycloak_operator.models.keycloak import KeycloakDatabaseConfig

        spec = KeycloakSpec(
            database=KeycloakDatabaseConfig(
                type="postgresql",
                host="postgres",
                database="keycloak",
                username="keycloak",
                credentials_secret="db-secret",
            )
        )

        assert spec.image == "quay.io/keycloak/keycloak:26.4.0"
        assert spec.replicas == 1
        assert spec.service.type == "ClusterIP"
        assert spec.service.http_port == 8080

    def test_keycloak_spec_validation(self):
        """Test KeycloakSpec validation rules."""
        from keycloak_operator.models.keycloak import KeycloakDatabaseConfig

        # Test invalid replicas
        with pytest.raises(ValidationError) as exc_info:
            KeycloakSpec(
                replicas=0,
                database=KeycloakDatabaseConfig(
                    type="postgresql",
                    host="postgres",
                    database="keycloak",
                    username="keycloak",
                    credentials_secret="db-secret",
                ),
            )
        assert "greater than or equal to 1" in str(exc_info.value)

        # Test invalid service type
        with pytest.raises(ValidationError) as exc_info:
            KeycloakSpec(
                service=KeycloakServiceConfig(type="InvalidType"),
                database=KeycloakDatabaseConfig(
                    type="postgresql",
                    host="postgres",
                    database="keycloak",
                    username="keycloak",
                    credentials_secret="db-secret",
                ),
            )
        assert "Service type must be one of" in str(exc_info.value)

    def test_resource_requirements_defaults(self):
        """Test resource requirements have proper defaults."""
        resources = KeycloakResourceRequirements()

        assert resources.requests["cpu"] == "500m"
        assert resources.requests["memory"] == "512Mi"
        assert resources.limits["cpu"] == "1000m"
        assert resources.limits["memory"] == "1Gi"

    def test_complete_keycloak_resource(self):
        """Test complete Keycloak resource validation."""
        keycloak_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": "test-keycloak", "namespace": "default"},
            "spec": {
                "replicas": 2,
                "image": "quay.io/keycloak/keycloak:22.0.0",
                "database": {
                    "type": "postgresql",
                    "host": "postgres",
                    "database": "keycloak",
                    "username": "keycloak",
                    "credentials_secret": "db-secret",
                },
            },
        }

        keycloak = Keycloak.model_validate(keycloak_resource)

        assert keycloak.kind == "Keycloak"
        assert keycloak.metadata["name"] == "test-keycloak"
        assert keycloak.spec.replicas == 2
        assert keycloak.spec.image == "quay.io/keycloak/keycloak:22.0.0"
        assert keycloak.spec.database.type == "postgresql"


class TestKeycloakClientModels:
    """Test cases for KeycloakClient models."""

    def test_keycloak_client_spec_validation(self):
        """Test KeycloakClientSpec validation rules."""
        # Test valid client spec
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
        )

        assert spec.client_id == "test-client"
        assert spec.realm_ref.name == "test-realm"
        assert spec.public_client is False

        # Test invalid client ID
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(client_id="", realm_ref=_make_realm_ref())
        assert "non-empty string" in str(exc_info.value)

        # Test invalid redirect URI with wildcard in domain
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["https://*.example.com/callback"],
            )
        assert "Wildcard not allowed in domain" in str(exc_info.value)

    def test_keycloak_client_to_keycloak_config(self):
        """Test conversion to Keycloak API format."""
        spec = KeycloakClientSpec(
            client_id="test-client",
            client_name="Test Client",
            realm_ref=_make_realm_ref(),
            redirect_uris=["https://example.com/callback"],
            web_origins=["https://example.com"],
        )

        config = spec.to_keycloak_config()

        assert config["clientId"] == "test-client"
        assert config["name"] == "Test Client"
        assert config["redirectUris"] == ["https://example.com/callback"]
        assert config["webOrigins"] == ["https://example.com"]
        assert config["publicClient"] is False
        assert config["enabled"] is True

    def test_complete_keycloak_client_resource(self):
        """Test complete KeycloakClient resource validation."""
        client_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": "test-client", "namespace": "default"},
            "spec": {
                "client_id": "webapp",
                "realmRef": {
                    "name": "demo-realm",
                    "namespace": "default",
                    "authorizationSecretRef": {"name": "realm-token"},
                },
                "redirect_uris": ["https://webapp.example.com/callback"],
            },
        }

        client = KeycloakClient.model_validate(client_resource)

        assert client.kind == "KeycloakClient"
        assert client.spec.client_id == "webapp"
        assert client.spec.realm_ref.name == "demo-realm"
        assert client.spec.realm_ref.namespace == "default"

    def test_redirect_uri_wildcard_validation(self):
        """Test comprehensive redirect URI wildcard validation following Keycloak rules."""

        # ✓ VALID: Wildcard in path (most common use case)
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
            redirect_uris=["http://localhost:3000/*"],
        )
        assert spec.redirect_uris == ["http://localhost:3000/*"]

        # ✓ VALID: Wildcard in nested path
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
            redirect_uris=["https://example.com/app/callback/*"],
        )
        assert spec.redirect_uris == ["https://example.com/app/callback/*"]

        # ✓ VALID: Custom scheme with wildcard
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
            redirect_uris=["myapp:/callback/*"],
        )
        assert spec.redirect_uris == ["myapp:/callback/*"]

        # ✓ VALID: Multiple URIs with and without wildcards
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
            redirect_uris=[
                "https://example.com/exact",
                "https://example.com/wildcard/*",
                "http://localhost:3000/*",
            ],
        )
        assert len(spec.redirect_uris) == 3

        # ✓ VALID: No wildcards at all
        spec = KeycloakClientSpec(
            client_id="test-client",
            realm_ref=_make_realm_ref(),
            redirect_uris=["https://example.com/callback"],
        )
        assert spec.redirect_uris == ["https://example.com/callback"]

        # ❌ INVALID: Bare wildcard (blocked since Keycloak 22.x)
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["*"],
            )
        error_msg = str(exc_info.value)
        assert "Bare wildcard" in error_msg or "not allowed" in error_msg
        assert "http://localhost:3000/*" in error_msg  # Suggests valid alternative

        # ❌ INVALID: Wildcard in domain
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["https://*.example.com"],
            )
        error_msg = str(exc_info.value)
        assert "Wildcard not allowed in domain" in error_msg
        assert "✓" in error_msg  # Has helpful examples

        # ❌ INVALID: Wildcard in subdomain
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["https://sub*.example.com/callback"],
            )
        error_msg = str(exc_info.value)
        assert "Wildcard not allowed in domain" in error_msg

        # ❌ INVALID: Wildcard in middle of URI
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["https://example.com/pa*th/callback"],
            )
        error_msg = str(exc_info.value)
        assert "Wildcard must be at the end" in error_msg

        # ❌ INVALID: Domain-only URI with wildcard
        with pytest.raises(ValidationError) as exc_info:
            KeycloakClientSpec(
                client_id="test-client",
                realm_ref=_make_realm_ref(),
                redirect_uris=["http://example.com*"],
            )
        error_msg = str(exc_info.value)
        assert "Wildcard not allowed in domain-only" in error_msg
        assert "add trailing slash" in error_msg  # Helpful suggestion


class TestKeycloakRealmModels:
    """Test cases for KeycloakRealm models."""

    def test_keycloak_realm_spec_validation(self):
        """Test KeycloakRealmSpec validation rules."""
        # Test valid realm spec
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=_make_operator_ref(),
        )

        assert spec.realm_name == "test-realm"

        # Test invalid realm name with special characters
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="test realm",  # Space not allowed
                operator_ref=_make_operator_ref(),
            )
        assert "invalid character" in str(exc_info.value)

        # Test realm name too long
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSpec(
                realm_name="a" * 256,
                operator_ref=_make_operator_ref(),
            )
        assert "255 characters or less" in str(exc_info.value)

    def test_keycloak_realm_to_keycloak_config(self):
        """Test conversion to Keycloak API format."""
        spec = KeycloakRealmSpec(
            realm_name="demo-realm",
            display_name="Demo Realm",
            operator_ref=_make_operator_ref(),
        )

        config = spec.to_keycloak_config()

        assert config["realm"] == "demo-realm"
        assert config["displayName"] == "Demo Realm"
        assert config["enabled"] is True
        assert "accessTokenLifespan" in config
        assert "registrationAllowed" in config

    def test_complete_keycloak_realm_resource(self):
        """Test complete KeycloakRealm resource validation."""
        realm_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": "demo-realm", "namespace": "default"},
            "spec": {
                "realm_name": "demo",
                "operatorRef": {
                    "namespace": "keycloak-system",
                    "authorizationSecretRef": {"name": "operator-token"},
                },
                "security": {"registration_allowed": True, "verify_email": True},
            },
        }

        realm = KeycloakRealm.model_validate(realm_resource)

        assert realm.kind == "KeycloakRealm"
        assert realm.spec.realm_name == "demo"
        assert realm.spec.operator_ref.namespace == "keycloak-system"
        assert realm.spec.security.registration_allowed is True
        assert realm.spec.security.verify_email is True

    class TestAuthorizationRefs:
        """Test cases for authorization reference models."""

        def test_operator_ref_validation(self):
            """Test OperatorRef validation."""
            ref = OperatorRef(
                namespace="keycloak-system",
            )
            assert ref.namespace == "keycloak-system"

        def test_realm_ref_validation(self):
            """Test RealmRef validation."""
            ref = RealmRef(
                name="my-realm",
                namespace="default",
            )
            assert ref.name == "my-realm"
            assert ref.namespace == "default"
