"""
Unit tests for validation utilities.

These tests verify that the validation functions correctly identify
invalid configurations and provide helpful error messages.
"""

import pytest

from keycloak_operator.utils.validation import (
    ValidationError,
    validate_client_id,
    validate_image_reference,
    validate_realm_name,
    validate_redirect_uris,
    validate_resource_name,
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
