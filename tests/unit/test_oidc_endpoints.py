"""Unit tests for OIDC endpoint discovery utilities."""

from __future__ import annotations

from keycloak_operator.models.keycloak import (
    Keycloak,
    KeycloakDatabaseConfig,
    KeycloakEndpoints,
    KeycloakSpec,
    KeycloakStatus,
)
from keycloak_operator.utils.oidc_endpoints import (
    construct_oidc_endpoints,
    get_keycloak_base_url,
)


def create_test_keycloak_spec() -> KeycloakSpec:
    """Create a minimal valid KeycloakSpec for testing."""
    return KeycloakSpec(
        database=KeycloakDatabaseConfig(
            type="postgresql",
            host="postgres.default.svc.cluster.local",
            database="keycloak",
            username="keycloak",
        )
    )


class TestConstructOidcEndpoints:
    """Test OIDC endpoint construction."""

    def test_basic_endpoint_construction(self) -> None:
        """Test constructing OIDC endpoints with basic URL."""
        base_url = "https://keycloak.example.com"
        realm_name = "my-realm"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        assert endpoints == {
            "issuer": "https://keycloak.example.com/realms/my-realm",
            "auth": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/auth",
            "token": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token",
            "userinfo": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/userinfo",
            "jwks": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/certs",
            "endSession": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/logout",
            "registration": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/registrations",
        }

    def test_endpoint_construction_with_trailing_slash(self) -> None:
        """Test that trailing slashes in base URL are handled correctly."""
        base_url = "https://keycloak.example.com/"
        realm_name = "my-realm"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        # Should produce same result as without trailing slash
        assert endpoints["issuer"] == "https://keycloak.example.com/realms/my-realm"
        assert (
            endpoints["auth"]
            == "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/auth"
        )

    def test_endpoint_construction_http(self) -> None:
        """Test constructing OIDC endpoints with HTTP (non-TLS) URL."""
        base_url = "http://localhost:8080"
        realm_name = "test-realm"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        assert endpoints["issuer"] == "http://localhost:8080/realms/test-realm"
        assert (
            endpoints["token"]
            == "http://localhost:8080/realms/test-realm/protocol/openid-connect/token"
        )

    def test_endpoint_construction_with_port(self) -> None:
        """Test constructing OIDC endpoints with custom port."""
        base_url = "https://keycloak.example.com:8443"
        realm_name = "production"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        assert (
            endpoints["issuer"] == "https://keycloak.example.com:8443/realms/production"
        )
        assert (
            endpoints["userinfo"]
            == "https://keycloak.example.com:8443/realms/production/protocol/openid-connect/userinfo"
        )

    def test_endpoint_construction_cluster_dns(self) -> None:
        """Test constructing OIDC endpoints with Kubernetes cluster DNS."""
        base_url = "http://keycloak.keycloak-system.svc.cluster.local:8080"
        realm_name = "internal-realm"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        assert (
            endpoints["issuer"]
            == "http://keycloak.keycloak-system.svc.cluster.local:8080/realms/internal-realm"
        )
        assert (
            endpoints["jwks"]
            == "http://keycloak.keycloak-system.svc.cluster.local:8080/realms/internal-realm/protocol/openid-connect/certs"
        )

    def test_endpoint_construction_special_realm_names(self) -> None:
        """Test constructing endpoints with realm names containing special characters."""
        base_url = "https://keycloak.example.com"

        # Test with hyphenated realm name
        endpoints = construct_oidc_endpoints(base_url, "my-test-realm")
        assert (
            endpoints["issuer"] == "https://keycloak.example.com/realms/my-test-realm"
        )

        # Test with underscored realm name
        endpoints = construct_oidc_endpoints(base_url, "my_test_realm")
        assert (
            endpoints["issuer"] == "https://keycloak.example.com/realms/my_test_realm"
        )

        # Test with numeric realm name
        endpoints = construct_oidc_endpoints(base_url, "realm123")
        assert endpoints["issuer"] == "https://keycloak.example.com/realms/realm123"

    def test_all_required_endpoints_present(self) -> None:
        """Test that all required OIDC endpoints are included."""
        base_url = "https://keycloak.example.com"
        realm_name = "my-realm"

        endpoints = construct_oidc_endpoints(base_url, realm_name)

        # Verify all required endpoints are present
        required_endpoints = {
            "issuer",
            "auth",
            "token",
            "userinfo",
            "jwks",
            "endSession",
            "registration",
        }
        assert set(endpoints.keys()) == required_endpoints


class TestGetKeycloakBaseUrl:
    """Test extracting base URL from Keycloak instance."""

    def test_get_base_url_from_public_endpoint(self) -> None:
        """Test getting base URL when public endpoint is configured."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(
                phase="Ready",
                endpoints=KeycloakEndpoints(
                    public="https://keycloak.example.com",
                    internal="http://my-keycloak.keycloak-system.svc.cluster.local:8080",
                ),
            ),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should prefer public endpoint
        assert base_url == "https://keycloak.example.com"

    def test_get_base_url_from_internal_endpoint(self) -> None:
        """Test getting base URL when only internal endpoint is configured."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(
                phase="Ready",
                endpoints=KeycloakEndpoints(
                    internal="http://my-keycloak.keycloak-system.svc.cluster.local:8080"
                ),
            ),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should use internal endpoint when public is not available
        assert base_url == "http://my-keycloak.keycloak-system.svc.cluster.local:8080"

    def test_get_base_url_fallback_no_status(self) -> None:
        """Test fallback to service DNS when status is not available."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should construct service DNS URL
        assert base_url == "http://my-keycloak.keycloak-system.svc.cluster.local:8080"

    def test_get_base_url_fallback_no_endpoints(self) -> None:
        """Test fallback to service DNS when endpoints are not configured."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(phase="Provisioning"),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should construct service DNS URL when endpoints are not set
        assert base_url == "http://my-keycloak.keycloak-system.svc.cluster.local:8080"

    def test_get_base_url_fallback_empty_endpoints(self) -> None:
        """Test fallback to service DNS when endpoints object exists but fields are None."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(phase="Provisioning", endpoints=KeycloakEndpoints()),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should construct service DNS URL when endpoint fields are None
        assert base_url == "http://my-keycloak.keycloak-system.svc.cluster.local:8080"

    def test_get_base_url_default_namespace(self) -> None:
        """Test fallback uses 'default' namespace when not specified."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak"},
            spec=create_test_keycloak_spec(),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should use 'default' namespace in service DNS
        assert base_url == "http://my-keycloak.default.svc.cluster.local:8080"

    def test_get_base_url_default_name(self) -> None:
        """Test fallback uses 'keycloak' name when not specified."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"namespace": "test-namespace"},
            spec=create_test_keycloak_spec(),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should use 'keycloak' as default name in service DNS
        assert base_url == "http://keycloak.test-namespace.svc.cluster.local:8080"

    def test_get_base_url_priority_public_over_internal(self) -> None:
        """Test that public endpoint is preferred when both are available."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "my-keycloak", "namespace": "keycloak-system"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(
                phase="Ready",
                endpoints=KeycloakEndpoints(
                    public="https://public.example.com",
                    internal="http://internal.cluster.local:8080",
                ),
            ),
        )

        base_url = get_keycloak_base_url(keycloak)

        # Should prefer public over internal
        assert base_url == "https://public.example.com"


class TestEndToEndScenarios:
    """Test complete OIDC endpoint discovery scenarios."""

    def test_complete_flow_with_public_endpoint(self) -> None:
        """Test complete endpoint discovery flow using public endpoint."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "production-kc", "namespace": "auth"},
            spec=create_test_keycloak_spec(),
            status=KeycloakStatus(
                phase="Ready",
                endpoints=KeycloakEndpoints(
                    public="https://auth.example.com",
                ),
            ),
        )

        base_url = get_keycloak_base_url(keycloak)
        endpoints = construct_oidc_endpoints(base_url, "production-realm")

        assert endpoints["issuer"] == "https://auth.example.com/realms/production-realm"
        assert (
            endpoints["token"]
            == "https://auth.example.com/realms/production-realm/protocol/openid-connect/token"
        )

    def test_complete_flow_with_fallback(self) -> None:
        """Test complete endpoint discovery flow with service DNS fallback."""
        keycloak = Keycloak(
            api_version="vriesdemichael.github.io/v1",
            kind="Keycloak",
            metadata={"name": "dev-kc", "namespace": "development"},
            spec=create_test_keycloak_spec(),
            # No status - should trigger fallback
        )

        base_url = get_keycloak_base_url(keycloak)
        endpoints = construct_oidc_endpoints(base_url, "dev-realm")

        assert (
            endpoints["issuer"]
            == "http://dev-kc.development.svc.cluster.local:8080/realms/dev-realm"
        )
        assert (
            endpoints["auth"]
            == "http://dev-kc.development.svc.cluster.local:8080/realms/dev-realm/protocol/openid-connect/auth"
        )
