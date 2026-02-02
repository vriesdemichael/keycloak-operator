"""
Unit tests for validation utilities.

These tests verify that the validation functions correctly identify
invalid configurations and provide helpful error messages.
"""

import pytest

from keycloak_operator.utils.validation import (
    ValidationError,
    _extract_version_from_image,
    _parse_kubernetes_quantity,
    _parse_version,
    validate_client_id,
    validate_complete_resource,
    validate_cross_resource_references,
    validate_environment_variables,
    validate_image_reference,
    validate_keycloak_version,
    validate_namespace_name,
    validate_realm_name,
    validate_redirect_uris,
    validate_resource_limits,
    validate_resource_name,
    validate_security_settings,
    validate_url,
)


class TestResourceNameValidation:
    """Test cases for Kubernetes resource name validation."""

    def test_valid_resource_names(self):
        """Test that valid resource names pass validation."""
        valid_names = [
            "test",
            "test-keycloak",
            "keycloak-123",
            "a",
            "test-client-abc-123",
        ]

        for name in valid_names:
            validate_resource_name(name)  # Should not raise

    def test_invalid_resource_names(self):
        """Test that invalid resource names are rejected."""
        invalid_names = [
            "",  # Empty
            "Test",  # Uppercase
            "test_client",  # Underscore
            "-test",  # Starts with hyphen
            "test-",  # Ends with hyphen
            "test..client",  # Double dots
            "a" * 254,  # Too long
        ]

        for name in invalid_names:
            with pytest.raises(ValidationError):
                validate_resource_name(name)

    def test_resource_name_error_messages(self):
        """Test that validation errors have helpful messages."""
        with pytest.raises(ValidationError) as exc_info:
            validate_resource_name("")
        assert "cannot be empty" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            validate_resource_name("a" * 254)
        assert "too long" in str(exc_info.value)


class TestClientIdValidation:
    """Test cases for Keycloak client ID validation."""

    def test_valid_client_ids(self):
        """Test that valid client IDs pass validation."""
        valid_ids = [
            "webapp",
            "mobile-app",
            "service.account",
            "client_123",
            "my-awesome-client-2023",
        ]

        for client_id in valid_ids:
            validate_client_id(client_id)  # Should not raise

    def test_invalid_client_ids(self):
        """Test that invalid client IDs are rejected."""
        invalid_ids = [
            "",  # Empty
            "client with spaces",  # Spaces
            "client\twith\ttabs",  # Tabs
            "client\nwith\nnewlines",  # Newlines
            "a" * 256,  # Too long
        ]

        for client_id in invalid_ids:
            with pytest.raises(ValidationError):
                validate_client_id(client_id)

    def test_reserved_client_ids(self):
        """Test that reserved client IDs are rejected."""
        reserved_ids = [
            "admin-cli",
            "account",
            "account-console",
            "broker",
            "realm-management",
            "security-admin-console",
        ]

        for client_id in reserved_ids:
            with pytest.raises(ValidationError) as exc_info:
                validate_client_id(client_id)
            assert "reserved" in str(exc_info.value)


class TestRealmNameValidation:
    """Test cases for Keycloak realm name validation."""

    def test_valid_realm_names(self):
        """Test that valid realm names pass validation."""
        valid_names = [
            "demo",
            "production",
            "test-realm",
            "realm123",
            "my.realm",
        ]

        for realm_name in valid_names:
            validate_realm_name(realm_name)  # Should not raise

    def test_invalid_realm_names(self):
        """Test that invalid realm names are rejected."""
        invalid_names = [
            "",  # Empty
            "realm/with/slashes",  # Slashes
            "realm\\with\\backslashes",  # Backslashes
            "realm?with?questions",  # Question marks
            "realm#with#hashes",  # Hashes
            "realm%with%percents",  # Percents
            "realm&with&ampersands",  # Ampersands
            "realm with spaces",  # Spaces
            "a" * 256,  # Too long
        ]

        for realm_name in invalid_names:
            with pytest.raises(ValidationError):
                validate_realm_name(realm_name)


class TestUrlValidation:
    """Test cases for URL validation."""

    def test_valid_urls(self):
        """Test that valid URLs pass validation."""
        valid_urls = [
            "https://example.com",
            "http://localhost:8080",
            "https://keycloak.example.com:443/auth",
            "http://192.168.1.100:8080",
        ]

        for url in valid_urls:
            validate_url(url)  # Should not raise

    def test_invalid_urls(self):
        """Test that invalid URLs are rejected."""
        invalid_urls = [
            "",  # Empty
            "not-a-url",  # Invalid format
            "ftp://example.com",  # Invalid scheme
            "https://",  # Incomplete
        ]

        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_url(url)

    def test_url_security_warnings(self, caplog):
        """Test that security warnings are logged."""
        # Test localhost warning
        validate_url("http://localhost:8080")
        assert "localhost" in caplog.text

        # Test HTTP warning
        caplog.clear()
        validate_url("http://example.com")
        assert "unencrypted HTTP" in caplog.text


class TestRedirectUriValidation:
    """Test cases for OAuth2 redirect URI validation."""

    def test_valid_redirect_uris(self):
        """Test that valid redirect URIs pass validation."""
        valid_uris = [
            ["https://webapp.example.com/callback"],
            ["http://localhost:3000/callback", "https://app.example.com/auth"],
            ["myapp://auth/callback"],  # Custom scheme for mobile
            ["urn:ietf:wg:oauth:2.0:oob"],  # Out-of-band flow
        ]

        for uris in valid_uris:
            validate_redirect_uris(uris)  # Should not raise

    def test_invalid_redirect_uris(self):
        """Test that invalid redirect URIs are rejected."""
        invalid_uris = [
            [""],  # Empty URI
            ["https://*.example.com/callback"],  # Wildcard
            ["https://example.com/callback*"],  # Wildcard at end
        ]

        for uris in invalid_uris:
            with pytest.raises(ValidationError):
                validate_redirect_uris(uris)

    def test_empty_redirect_uris(self):
        """Test that empty redirect URI list is allowed."""
        validate_redirect_uris([])  # Should not raise


class TestImageReferenceValidation:
    """Test cases for container image reference validation."""

    def test_valid_image_references(self):
        """Test that valid image references pass validation."""
        valid_images = [
            "keycloak:22.0.0",
            "quay.io/keycloak/keycloak:latest",
            "registry.example.com/keycloak:v22.0.0",
            "keycloak@sha256:abc123def456",
        ]

        for image in valid_images:
            validate_image_reference(image)  # Should not raise

    def test_invalid_image_references(self):
        """Test that invalid image references are rejected."""
        invalid_images = [
            "",  # Empty
            "image with spaces",  # Spaces
        ]

        for image in invalid_images:
            with pytest.raises(ValidationError):
                validate_image_reference(image)

    def test_image_reference_warnings(self, caplog):
        """Test that warnings are logged for image references."""
        # Test no tag warning
        validate_image_reference("keycloak")
        assert "no explicit tag" in caplog.text

        # Test latest tag warning
        caplog.clear()
        validate_image_reference("keycloak:latest")
        assert "latest" in caplog.text


class TestParseKubernetesQuantity:
    """Test cases for Kubernetes quantity parsing."""

    def test_parse_cpu_millicores(self):
        """Test parsing CPU millicores."""
        assert _parse_kubernetes_quantity("100m") == 0.1
        assert _parse_kubernetes_quantity("500m") == 0.5
        assert _parse_kubernetes_quantity("1000m") == 1.0
        assert _parse_kubernetes_quantity("2500m") == 2.5

    def test_parse_cpu_cores(self):
        """Test parsing CPU cores."""
        assert _parse_kubernetes_quantity("1") == 1.0
        assert _parse_kubernetes_quantity("2") == 2.0
        assert _parse_kubernetes_quantity("4") == 4.0
        assert _parse_kubernetes_quantity("0.5") == 0.5

    def test_parse_memory_decimal_units(self):
        """Test parsing memory with decimal units (K, M, G, T, P)."""
        assert _parse_kubernetes_quantity("1K") == 1000
        assert _parse_kubernetes_quantity("1M") == 1000**2
        assert _parse_kubernetes_quantity("1G") == 1000**3
        assert _parse_kubernetes_quantity("1T") == 1000**4
        assert _parse_kubernetes_quantity("1P") == 1000**5
        assert _parse_kubernetes_quantity("500M") == 500 * 1000**2

    def test_parse_memory_binary_units(self):
        """Test parsing memory with binary units (Ki, Mi, Gi, Ti, Pi)."""
        assert _parse_kubernetes_quantity("1Ki") == 1024
        assert _parse_kubernetes_quantity("1Mi") == 1024**2
        assert _parse_kubernetes_quantity("1Gi") == 1024**3
        assert _parse_kubernetes_quantity("1Ti") == 1024**4
        assert _parse_kubernetes_quantity("1Pi") == 1024**5
        assert _parse_kubernetes_quantity("512Mi") == 512 * 1024**2

    def test_parse_plain_numbers(self):
        """Test parsing plain numeric values."""
        assert _parse_kubernetes_quantity("100") == 100.0
        assert _parse_kubernetes_quantity("1.5") == 1.5
        assert _parse_kubernetes_quantity("0.25") == 0.25

    def test_parse_numeric_types(self):
        """Test handling non-string numeric types."""
        # Type hint says str, but function handles numbers internally
        assert _parse_kubernetes_quantity(str(100)) == 100.0
        assert _parse_kubernetes_quantity(str(1.5)) == 1.5

    def test_invalid_quantity_format(self):
        """Test that invalid quantity formats raise ValueError."""
        invalid_quantities = [
            "invalid",
            "100x",
            "m100",
            "1.2.3",
            "",
        ]

        for quantity in invalid_quantities:
            with pytest.raises(ValueError):
                _parse_kubernetes_quantity(quantity)


class TestParseVersion:
    """Test cases for semantic version parsing."""

    def test_parse_standard_versions(self):
        """Test parsing standard semantic versions."""
        assert _parse_version("25.0.0") == (25, 0, 0)
        assert _parse_version("26.4.0") == (26, 4, 0)
        assert _parse_version("1.2.3") == (1, 2, 3)
        assert _parse_version("100.200.300") == (100, 200, 300)

    def test_parse_version_with_prerelease(self):
        """Test parsing versions with prerelease identifiers."""
        # Should extract major.minor.patch, ignoring prerelease
        assert _parse_version("26.4.0-beta.1") == (26, 4, 0)
        assert _parse_version("1.0.0-alpha") == (1, 0, 0)
        assert _parse_version("2.1.0-rc.2") == (2, 1, 0)

    def test_invalid_version_format(self):
        """Test that invalid version formats raise ValueError."""
        invalid_versions = [
            "",
            "v25.0.0",
            "latest",
            "abc",
            "1.2.a",
        ]

        for version in invalid_versions:
            with pytest.raises(ValueError):
                _parse_version(version)


class TestExtractVersionFromImage:
    """Test cases for extracting version from image references."""

    def test_extract_version_from_standard_images(self):
        """Test extracting version from standard tagged images."""
        assert _extract_version_from_image("keycloak:26.4.0") == "26.4.0"
        assert (
            _extract_version_from_image("quay.io/keycloak/keycloak:25.0.1") == "25.0.1"
        )
        assert (
            _extract_version_from_image("registry.example.com/keycloak:22.0.5")
            == "22.0.5"
        )

    def test_extract_version_from_digest_images(self):
        """Test that digest-based images return None."""
        assert _extract_version_from_image("keycloak@sha256:abc123def456") is None
        assert (
            _extract_version_from_image(
                "quay.io/keycloak/keycloak@sha256:1234567890abcdef"
            )
            is None
        )

    def test_extract_version_from_non_version_tags(self):
        """Test that non-version tags return None."""
        assert _extract_version_from_image("keycloak:latest") is None
        assert _extract_version_from_image("keycloak:nightly") is None
        assert _extract_version_from_image("keycloak:dev") is None

    def test_extract_version_no_tag(self):
        """Test that images without tags return None."""
        assert _extract_version_from_image("keycloak") is None
        assert _extract_version_from_image("quay.io/keycloak/keycloak") is None


class TestValidateKeycloakVersion:
    """Test cases for Keycloak version validation."""

    def test_valid_keycloak_versions(self):
        """Test that supported Keycloak versions pass validation."""
        valid_images = [
            "keycloak:24.0.0",
            "keycloak:24.0.5",
            "keycloak:25.0.0",
            "keycloak:25.0.1",
            "keycloak:26.4.0",
            "keycloak:30.0.0",
            "quay.io/keycloak/keycloak:24.0.0",
            "quay.io/keycloak/keycloak:25.0.0",
        ]

        for image in valid_images:
            validate_keycloak_version(image)  # Should not raise

    def test_invalid_keycloak_versions(self):
        """Test that unsupported Keycloak versions are rejected."""
        invalid_images = [
            "keycloak:23.0.5",
            "keycloak:22.0.0",
            "quay.io/keycloak/keycloak:20.0.0",
        ]

        for image in invalid_images:
            with pytest.raises(ValidationError) as exc_info:
                validate_keycloak_version(image)
            assert "not supported" in str(exc_info.value)
            assert "24.0.0" in str(exc_info.value)

    def test_version_validation_with_digest(self, caplog):
        """Test that digest-based images log a warning."""
        validate_keycloak_version("keycloak@sha256:abc123")
        assert "Could not extract version" in caplog.text
        assert "24.0.0" in caplog.text

    def test_version_validation_with_non_version_tag(self, caplog):
        """Test that non-version tags log a warning."""
        validate_keycloak_version("keycloak:latest")
        assert "Could not extract version" in caplog.text


class TestManagementPortSupport:
    """Test cases for management port version detection."""

    def test_supports_management_port_v26(self):
        """Test that Keycloak 26.x supports management port."""
        from keycloak_operator.utils.validation import supports_management_port

        assert supports_management_port("keycloak:26.4.0") is True
        assert supports_management_port("quay.io/keycloak/keycloak:26.0.0") is True

    def test_supports_management_port_v25(self):
        """Test that Keycloak 25.x supports management port."""
        from keycloak_operator.utils.validation import supports_management_port

        assert supports_management_port("keycloak:25.0.0") is True
        assert supports_management_port("keycloak:25.0.6") is True

    def test_no_management_port_v24(self):
        """Test that Keycloak 24.x does NOT support management port."""
        from keycloak_operator.utils.validation import supports_management_port

        assert supports_management_port("keycloak:24.0.0") is False
        assert supports_management_port("keycloak:24.0.5") is False

    def test_management_port_unknown_version_defaults_true(self):
        """Test that unknown versions assume management port support."""
        from keycloak_operator.utils.validation import supports_management_port

        # Digest-based images default to True (assume modern)
        assert supports_management_port("keycloak@sha256:abc123") is True
        # Non-version tags default to True
        assert supports_management_port("keycloak:latest") is True

    def test_get_health_port_v26(self):
        """Test health port for Keycloak 26.x is 9000."""
        from keycloak_operator.utils.validation import get_health_port

        assert get_health_port("keycloak:26.4.0") == 9000

    def test_get_health_port_v25(self):
        """Test health port for Keycloak 25.x is 9000."""
        from keycloak_operator.utils.validation import get_health_port

        assert get_health_port("keycloak:25.0.0") == 9000

    def test_get_health_port_v24(self):
        """Test health port for Keycloak 24.x is 8080 (main HTTP port)."""
        from keycloak_operator.utils.validation import get_health_port

        assert get_health_port("keycloak:24.0.0") == 8080
        assert get_health_port("keycloak:24.0.5") == 8080

    def test_get_health_port_unknown_defaults_9000(self):
        """Test that unknown versions default to management port 9000."""
        from keycloak_operator.utils.validation import get_health_port

        # Unknown versions default to 9000 (assume modern)
        assert get_health_port("keycloak:latest") == 9000
        assert get_health_port("keycloak@sha256:abc123") == 9000

    def test_version_override_takes_precedence(self):
        """Test that version override takes precedence over image tag."""
        from keycloak_operator.utils.validation import (
            get_health_port,
            supports_management_port,
        )

        # Custom image with 26.x tag but actually based on 24.x
        assert supports_management_port("myregistry/keycloak:v1.0.0", "24.0.5") is False
        assert get_health_port("myregistry/keycloak:v1.0.0", "24.0.5") == 8080

        # Custom image with no version but actually based on 25.x
        assert supports_management_port("myregistry/keycloak:latest", "25.0.0") is True
        assert get_health_port("myregistry/keycloak:latest", "25.0.0") == 9000

        # Override even overrides a valid version tag
        assert supports_management_port("keycloak:26.0.0", "24.0.0") is False
        assert get_health_port("keycloak:26.0.0", "24.0.0") == 8080

    def test_version_override_none_uses_image_tag(self):
        """Test that None version override falls back to image tag detection."""
        from keycloak_operator.utils.validation import (
            get_health_port,
            supports_management_port,
        )

        # None override - should use image tag
        assert supports_management_port("keycloak:24.0.5", None) is False
        assert supports_management_port("keycloak:26.0.0", None) is True
        assert get_health_port("keycloak:24.0.5", None) == 8080
        assert get_health_port("keycloak:26.0.0", None) == 9000


class TestValidateResourceLimits:
    """Test cases for Kubernetes resource limits validation."""

    def test_valid_resource_limits(self):
        """Test that valid resource specifications pass validation."""
        valid_resources = [
            {"requests": {"cpu": "100m", "memory": "512Mi"}},
            {"limits": {"cpu": "2", "memory": "4Gi"}},
            {
                "requests": {"cpu": "500m", "memory": "1Gi"},
                "limits": {"cpu": "2", "memory": "4Gi"},
            },
            {"requests": {"cpu": 1, "memory": 1024}},  # Numeric values
        ]

        for resources in valid_resources:
            validate_resource_limits(resources)  # Should not raise

    def test_invalid_quantity_format(self):
        """Test that invalid quantity formats are rejected."""
        invalid_resources = [
            {"requests": {"cpu": "invalid"}},
            {"limits": {"memory": "1.2.3"}},
            {"requests": {"cpu": "100x"}},
        ]

        for resources in invalid_resources:
            with pytest.raises(ValidationError):
                validate_resource_limits(resources)

    def test_requests_exceed_limits(self):
        """Test that requests exceeding limits are rejected."""
        invalid_resources = [
            {
                "requests": {"cpu": "4"},
                "limits": {"cpu": "2"},
            },
            {
                "requests": {"memory": "8Gi"},
                "limits": {"memory": "4Gi"},
            },
        ]

        for resources in invalid_resources:
            with pytest.raises(ValidationError) as exc_info:
                validate_resource_limits(resources)
            assert "exceeds limit" in str(exc_info.value)

    def test_empty_or_none_resources(self):
        """Test that empty or None resources are allowed."""
        # Type hint expects dict, but function handles None
        validate_resource_limits({})  # Should not raise

    def test_invalid_section_type(self):
        """Test that non-dict sections are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_resource_limits({"requests": "invalid"})
        assert "must be a dictionary" in str(exc_info.value)


class TestValidateNamespaceName:
    """Test cases for namespace name validation."""

    def test_valid_namespace_names(self):
        """Test that valid namespace names pass validation."""
        valid_namespaces = [
            "default",
            "kube-system",
            "my-namespace",
            "app-prod",
            "team-a",
        ]

        for namespace in valid_namespaces:
            validate_namespace_name(namespace)  # Should not raise

    def test_invalid_namespace_names(self):
        """Test that invalid namespace names are rejected."""
        invalid_namespaces = [
            "",
            "Namespace",  # Uppercase
            "name_space",  # Underscore
            "-namespace",  # Starts with hyphen
            "namespace-",  # Ends with hyphen
            "a" * 254,  # Too long
        ]

        for namespace in invalid_namespaces:
            with pytest.raises(ValidationError):
                validate_namespace_name(namespace)

    def test_reserved_namespace_warning(self, caplog):
        """Test that reserved namespaces log warnings."""
        reserved = ["kube-system", "kube-public", "kube-node-lease", "default"]

        for namespace in reserved:
            caplog.clear()
            validate_namespace_name(namespace)
            assert "reserved namespace" in caplog.text


class TestValidateEnvironmentVariables:
    """Test cases for environment variable validation."""

    def test_valid_environment_variables(self):
        """Test that valid environment variables pass validation."""
        valid_env_vars = [
            {"MY_VAR": "value"},
            {"DATABASE_HOST": "localhost", "DATABASE_PORT": "5432"},
            {"FEATURE_FLAG_ENABLED": "true"},
        ]

        for env_vars in valid_env_vars:
            validate_environment_variables(env_vars)  # Should not raise

    def test_naming_convention_warning(self, caplog):
        """Test that non-conventional names log warnings."""
        validate_environment_variables({"myVar": "value"})
        assert "doesn't follow naming conventions" in caplog.text

        caplog.clear()
        validate_environment_variables({"my-var": "value"})
        assert "doesn't follow naming conventions" in caplog.text

    def test_sensitive_data_warning(self, caplog):
        """Test that potential secrets log warnings."""
        sensitive_vars = [
            {"DATABASE_PASSWORD": "secret123"},
            {"API_KEY": "xyz789"},
            {"AUTH_TOKEN": "token123"},
            {"SECRET_VALUE": "shh"},
            {"USER_CREDENTIAL": "cred"},
        ]

        for env_vars in sensitive_vars:
            caplog.clear()
            validate_environment_variables(env_vars)
            assert "sensitive data" in caplog.text

    def test_empty_environment_variables(self):
        """Test that empty env vars are allowed."""
        # Type hint expects dict, but function handles None
        validate_environment_variables({})  # Should not raise


class TestValidateCrossResourceReferences:
    """Test cases for cross-resource reference validation."""

    def test_keycloak_client_references(self):
        """Test validation of KeycloakClient resource references."""
        spec = {
            "keycloakInstanceRef": {"name": "my-keycloak", "namespace": "default"},
            "clientId": "test-client",
        }

        deps = validate_cross_resource_references(spec, "KeycloakClient", "default")

        assert len(deps) == 1
        assert deps[0] == ("Keycloak", "my-keycloak", "default")

    def test_keycloak_realm_references(self):
        """Test validation of KeycloakRealm resource references."""
        spec = {
            "keycloakInstanceRef": {"name": "my-keycloak"},
            "realmName": "demo",
        }

        deps = validate_cross_resource_references(spec, "KeycloakRealm", "prod")

        assert len(deps) == 1
        assert deps[0] == ("Keycloak", "my-keycloak", "prod")

    def test_secret_references(self):
        """Test detection of secret references."""
        spec = {
            "keycloakInstanceRef": {"name": "my-keycloak"},
            "database": {
                "password_secret": {"name": "db-password", "namespace": "default"}
            },
        }

        deps = validate_cross_resource_references(spec, "KeycloakClient", "default")

        secret_deps = [d for d in deps if d[0] == "Secret"]
        assert len(secret_deps) == 1
        assert secret_deps[0] == ("Secret", "db-password", "default")

    def test_configmap_references(self):
        """Test detection of configmap references."""
        spec = {
            "keycloakInstanceRef": {"name": "my-keycloak"},
            "config_configmap": {"name": "app-config", "namespace": "config-ns"},
        }

        deps = validate_cross_resource_references(spec, "KeycloakClient", "default")

        cm_deps = [d for d in deps if d[0] == "ConfigMap"]
        assert len(cm_deps) == 1
        assert cm_deps[0] == ("ConfigMap", "app-config", "config-ns")

    def test_missing_keycloak_instance_ref(self):
        """Test that missing keycloakInstanceRef raises error."""
        spec = {"clientId": "test-client"}

        with pytest.raises(ValidationError) as exc_info:
            validate_cross_resource_references(spec, "KeycloakClient", "default")
        assert "keycloakInstanceRef" in str(exc_info.value)

    def test_invalid_resource_name_in_reference(self):
        """Test that invalid resource names in references are rejected."""
        spec = {
            "keycloakInstanceRef": {"name": "Invalid-Name-With-UPPERCASE"},
        }

        with pytest.raises(ValidationError):
            validate_cross_resource_references(spec, "KeycloakClient", "default")


class TestValidateSecuritySettings:
    """Test cases for security settings validation."""

    def test_keycloak_tls_warnings(self, caplog):
        """Test TLS-related warnings for Keycloak resources."""
        spec = {"tls": {"enabled": False}}

        validate_security_settings(spec, "Keycloak")
        assert "TLS is not enabled" in caplog.text

    def test_keycloak_ingress_tls_warning(self, caplog):
        """Test ingress TLS warnings."""
        spec = {
            "ingress": {"enabled": True, "tls_enabled": False},
        }

        validate_security_settings(spec, "Keycloak")
        assert "Ingress is enabled but TLS is not" in caplog.text

    def test_keycloak_resource_limits_warning(self, caplog):
        """Test resource limits warning."""
        spec = {"resources": {"requests": {"cpu": "100m"}}}

        validate_security_settings(spec, "Keycloak")
        assert "No resource limits" in caplog.text

    def test_keycloak_security_context_warning(self, caplog):
        """Test security context warning."""
        spec = {}

        validate_security_settings(spec, "Keycloak")
        assert "No security context" in caplog.text

    def test_client_public_with_offline_access_warning(self, caplog):
        """Test warning for public client with offline access."""
        spec = {
            "publicClient": True,
            "scopes": ["openid", "profile", "offline_access"],
        }

        validate_security_settings(spec, "KeycloakClient")
        assert "Public client with offline_access" in caplog.text

    def test_realm_no_password_policy_warning(self, caplog):
        """Test warning when no password policy is set."""
        spec = {"realmSettings": {}}

        validate_security_settings(spec, "KeycloakRealm")
        assert "No password policy" in caplog.text

    def test_realm_ssl_none_warning(self, caplog):
        """Test warning when SSL requirement is none."""
        spec = {"realmSettings": {"sslRequired": "none"}}

        validate_security_settings(spec, "KeycloakRealm")
        assert "SSL requirement set to 'none'" in caplog.text


class TestValidateCompleteResource:
    """Test cases for complete resource validation."""

    def test_valid_keycloak_client(self):
        """Test complete validation of a KeycloakClient resource."""
        resource = {
            "metadata": {"name": "test-client", "namespace": "default"},
            "spec": {
                "clientId": "webapp",
                "keycloakInstanceRef": {"name": "my-keycloak"},
                "realm": "demo",
            },
        }

        deps = validate_complete_resource(resource, "KeycloakClient", "default")
        assert len(deps) >= 1  # At least the Keycloak instance

    def test_valid_keycloak_realm(self):
        """Test complete validation of a KeycloakRealm resource."""
        resource = {
            "metadata": {"name": "demo-realm", "namespace": "prod"},
            "spec": {
                "realmName": "demo",
                "keycloakInstanceRef": {"name": "my-keycloak"},
            },
        }

        deps = validate_complete_resource(resource, "KeycloakRealm", "prod")
        assert len(deps) >= 1

    def test_valid_keycloak_instance(self):
        """Test complete validation of a Keycloak resource."""
        resource = {
            "metadata": {"name": "my-keycloak", "namespace": "default"},
            "spec": {
                "image": "quay.io/keycloak/keycloak:26.4.0",
                "resources": {
                    "requests": {"cpu": "500m", "memory": "1Gi"},
                    "limits": {"cpu": "2", "memory": "4Gi"},
                },
            },
        }

        deps = validate_complete_resource(resource, "Keycloak", "default")
        assert isinstance(deps, list)

    def test_missing_metadata(self):
        """Test that resources without metadata are rejected."""
        resource = {"spec": {"clientId": "test"}}

        with pytest.raises(ValidationError) as exc_info:
            validate_complete_resource(resource, "KeycloakClient", "default")
        assert "metadata" in str(exc_info.value)

    def test_missing_spec(self):
        """Test that resources without spec are rejected."""
        resource = {"metadata": {"name": "test"}}

        with pytest.raises(ValidationError) as exc_info:
            validate_complete_resource(resource, "KeycloakClient", "default")
        assert "spec" in str(exc_info.value)

    def test_missing_name(self):
        """Test that resources without name are rejected."""
        resource = {"metadata": {}, "spec": {"clientId": "test"}}

        with pytest.raises(ValidationError) as exc_info:
            validate_complete_resource(resource, "KeycloakClient", "default")
        assert "name" in str(exc_info.value)

    def test_invalid_client_without_client_id(self):
        """Test that KeycloakClient without clientId is rejected."""
        resource = {
            "metadata": {"name": "test"},
            "spec": {
                "keycloakInstanceRef": {"name": "my-keycloak"},
            },
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_complete_resource(resource, "KeycloakClient", "default")
        assert "clientId" in str(exc_info.value)

    def test_invalid_realm_without_realm_name(self):
        """Test that KeycloakRealm without realmName is rejected."""
        resource = {
            "metadata": {"name": "test"},
            "spec": {
                "keycloakInstanceRef": {"name": "my-keycloak"},
            },
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_complete_resource(resource, "KeycloakRealm", "default")
        assert "realmName" in str(exc_info.value)


class TestSupportsTracing:
    """Test cases for Keycloak tracing support version detection."""

    def test_supports_tracing_v26(self):
        """Test that Keycloak 26.x supports tracing."""
        from keycloak_operator.utils.validation import supports_tracing

        assert supports_tracing("keycloak:26.0.0") is True
        assert supports_tracing("keycloak:26.4.0") is True
        assert supports_tracing("quay.io/keycloak/keycloak:26.0.0") is True

    def test_supports_tracing_v27_and_beyond(self):
        """Test that Keycloak 27.x+ supports tracing."""
        from keycloak_operator.utils.validation import supports_tracing

        assert supports_tracing("keycloak:27.0.0") is True
        assert supports_tracing("keycloak:30.0.0") is True

    def test_no_tracing_v25(self):
        """Test that Keycloak 25.x does NOT support tracing."""
        from keycloak_operator.utils.validation import supports_tracing

        assert supports_tracing("keycloak:25.0.0") is False
        assert supports_tracing("keycloak:25.0.6") is False

    def test_no_tracing_v24(self):
        """Test that Keycloak 24.x does NOT support tracing."""
        from keycloak_operator.utils.validation import supports_tracing

        assert supports_tracing("keycloak:24.0.0") is False
        assert supports_tracing("keycloak:24.0.5") is False

    def test_tracing_unknown_version_defaults_true(self):
        """Test that unknown versions assume tracing support."""
        from keycloak_operator.utils.validation import supports_tracing

        # Digest-based images default to True (assume modern)
        assert supports_tracing("keycloak@sha256:abc123") is True
        # Non-version tags default to True
        assert supports_tracing("keycloak:latest") is True
        # No tag defaults to True
        assert supports_tracing("keycloak") is True

    def test_tracing_version_override_takes_precedence(self):
        """Test that version override takes precedence over image tag."""
        from keycloak_operator.utils.validation import supports_tracing

        # Custom image with 26.x tag but actually based on 25.x
        assert supports_tracing("myregistry/keycloak:v1.0.0", "25.0.0") is False
        # Custom image with no version but actually based on 26.x
        assert supports_tracing("myregistry/keycloak:latest", "26.0.0") is True
        # Override even overrides a valid version tag
        assert supports_tracing("keycloak:26.0.0", "25.0.0") is False

    def test_tracing_version_override_none_uses_image_tag(self):
        """Test that None version override falls back to image tag detection."""
        from keycloak_operator.utils.validation import supports_tracing

        # None override - should use image tag
        assert supports_tracing("keycloak:25.0.0", None) is False
        assert supports_tracing("keycloak:26.0.0", None) is True

    def test_tracing_invalid_version_defaults_true(self, caplog):
        """Test that unparseable versions default to True with warning."""
        import logging

        from keycloak_operator.utils.validation import supports_tracing

        caplog.set_level(logging.DEBUG)

        # Invalid version string that can't be parsed
        assert supports_tracing("keycloak:invalid", "not-a-version") is True
        assert "Could not parse version" in caplog.text

    def test_tracing_logs_version_detection(self, caplog):
        """Test that version detection logs are generated."""
        import logging

        from keycloak_operator.utils.validation import supports_tracing

        # Need debug level to see the logs
        caplog.set_level(logging.DEBUG)

        supports_tracing("keycloak:26.0.0")
        assert "supports" in caplog.text or "tracing" in caplog.text.lower()


class TestKeycloakPlaceholderValidation:
    """Test cases for Keycloak environment variable placeholder validation."""

    def test_valid_strings_without_placeholders(self):
        """Test that normal strings pass validation."""
        from keycloak_operator.utils.validation import validate_no_keycloak_placeholders

        # These should not raise
        validate_no_keycloak_placeholders("normal-string", "field")
        validate_no_keycloak_placeholders("https://example.com", "url")
        validate_no_keycloak_placeholders("my-client-id", "clientId")
        validate_no_keycloak_placeholders("", "empty")
        validate_no_keycloak_placeholders(None, "none")

    def test_detects_keycloak_secret_placeholder(self):
        """Test that ${keycloak:...} placeholders are detected."""
        from keycloak_operator.utils.validation import validate_no_keycloak_placeholders

        with pytest.raises(ValidationError) as exc_info:
            validate_no_keycloak_placeholders(
                "${keycloak:github-oauth-credentials:clientId}", "clientId"
            )
        assert "placeholders are not supported" in str(exc_info.value)
        assert "${keycloak:" in str(exc_info.value)

    def test_detects_env_placeholder(self):
        """Test that ${env.VAR} placeholders are detected."""
        from keycloak_operator.utils.validation import validate_no_keycloak_placeholders

        with pytest.raises(ValidationError) as exc_info:
            validate_no_keycloak_placeholders("${env.MY_SECRET}", "secret")
        assert "placeholders are not supported" in str(exc_info.value)

    def test_detects_uppercase_env_placeholder(self):
        """Test that ${ENV.VAR} placeholders are detected."""
        from keycloak_operator.utils.validation import validate_no_keycloak_placeholders

        with pytest.raises(ValidationError) as exc_info:
            validate_no_keycloak_placeholders("${ENV.MY_SECRET}", "secret")
        assert "placeholders are not supported" in str(exc_info.value)

    def test_detects_vault_placeholder(self):
        """Test that ${vault:...} placeholders are detected."""
        from keycloak_operator.utils.validation import validate_no_keycloak_placeholders

        with pytest.raises(ValidationError) as exc_info:
            validate_no_keycloak_placeholders("${vault:secret/data/myapp}", "secret")
        assert "placeholders are not supported" in str(exc_info.value)

    def test_spec_validation_finds_nested_placeholders(self):
        """Test that spec validation recursively finds placeholders."""
        from keycloak_operator.utils.validation import validate_spec_no_placeholders

        spec = {
            "clientId": "my-client",
            "settings": {
                "nested": {
                    "secret": "${keycloak:my-secret:value}",
                }
            },
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_spec_no_placeholders(spec, "KeycloakClient")
        assert "placeholders are not supported" in str(exc_info.value)

    def test_spec_validation_finds_placeholders_in_lists(self):
        """Test that spec validation finds placeholders in lists."""
        from keycloak_operator.utils.validation import validate_spec_no_placeholders

        spec = {
            "redirectUris": [
                "https://example.com/callback",
                "${env.REDIRECT_URI}",
            ],
        }

        with pytest.raises(ValidationError) as exc_info:
            validate_spec_no_placeholders(spec, "KeycloakClient")
        assert "placeholders are not supported" in str(exc_info.value)

    def test_spec_validation_passes_for_clean_spec(self):
        """Test that spec validation passes for specs without placeholders."""
        from keycloak_operator.utils.validation import validate_spec_no_placeholders

        spec = {
            "clientId": "my-client",
            "redirectUris": ["https://example.com/callback"],
            "settings": {
                "enabled": True,
                "description": "A normal description with $dollar signs",
            },
        }

        # Should not raise
        validate_spec_no_placeholders(spec, "KeycloakClient")
