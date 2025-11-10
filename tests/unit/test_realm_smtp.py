"""Unit tests for SMTP configuration in KeycloakRealm."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.realm import (
    KeycloakRealmSpec,
    KeycloakSMTPConfig,
    KeycloakSMTPPasswordSecret,
    OperatorRef,
)


# Helper function for test data
def _make_operator_ref(namespace="keycloak-system"):
    """Create a test OperatorRef."""
    return OperatorRef(
        namespace=namespace,
    )


class TestKeycloakSMTPPasswordSecret:
    """Test KeycloakSMTPPasswordSecret model."""

    def test_create_with_required_fields(self):
        """Test creating secret reference with required fields."""
        secret = KeycloakSMTPPasswordSecret(name="smtp-secret")
        assert secret.name == "smtp-secret"
        assert secret.key == "password"  # Default value

    def test_create_with_custom_key(self):
        """Test creating secret reference with custom key."""
        secret = KeycloakSMTPPasswordSecret(name="smtp-secret", key="smtp-password")
        assert secret.name == "smtp-secret"
        assert secret.key == "smtp-password"

    def test_missing_required_name(self):
        """Test validation error when name is missing."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakSMTPPasswordSecret()
        assert "name" in str(exc_info.value)


class TestKeycloakSMTPConfig:
    """Test KeycloakSMTPConfig model."""

    def test_minimal_config_no_auth(self):
        """Test minimal SMTP config without authentication."""
        config = KeycloakSMTPConfig(
            host="smtp.example.com", port=587, from_address="noreply@example.com"
        )
        assert config.host == "smtp.example.com"
        assert config.port == 587
        assert config.from_address == "noreply@example.com"
        assert config.auth is False
        assert config.ssl is False
        assert config.starttls is False

    def test_config_with_authentication_password(self):
        """Test SMTP config with authentication using password."""
        config = KeycloakSMTPConfig(
            host="smtp.gmail.com",
            port=587,
            from_address="noreply@example.com",
            auth=True,
            user="noreply@example.com",
            password="secret123",
        )
        assert config.auth is True
        assert config.user == "noreply@example.com"
        assert config.password == "secret123"
        assert config.password_secret is None

    def test_config_with_authentication_secret(self):
        """Test SMTP config with authentication using secret reference."""
        config = KeycloakSMTPConfig(
            host="smtp.gmail.com",
            port=587,
            from_address="noreply@example.com",
            auth=True,
            user="noreply@example.com",
            password_secret=KeycloakSMTPPasswordSecret(name="smtp-secret"),
        )
        assert config.auth is True
        assert config.user == "noreply@example.com"
        assert config.password is None
        assert config.password_secret is not None
        assert config.password_secret.name == "smtp-secret"

    def test_config_with_all_fields(self):
        """Test SMTP config with all optional fields."""
        config = KeycloakSMTPConfig(
            host="smtp.example.com",
            port=465,
            from_address="noreply@example.com",
            from_display_name="My Application",
            reply_to="support@example.com",
            envelope_from="envelope@example.com",
            ssl=True,
            starttls=False,
            auth=True,
            user="noreply@example.com",
            password="secret123",
        )
        assert config.from_display_name == "My Application"
        assert config.reply_to == "support@example.com"
        assert config.envelope_from == "envelope@example.com"
        assert config.ssl is True

    def test_port_validation_too_low(self):
        """Test validation error for port below range."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakSMTPConfig(
                host="smtp.example.com", port=0, from_address="noreply@example.com"
            )
        assert "port" in str(exc_info.value).lower()

    def test_port_validation_too_high(self):
        """Test validation error for port above range."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakSMTPConfig(
                host="smtp.example.com", port=65536, from_address="noreply@example.com"
            )
        assert "port" in str(exc_info.value).lower()

    def test_auth_requires_user(self):
        """Test validation error when auth=true but no user."""
        with pytest.raises(ValueError) as exc_info:
            KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                password="secret123",
            )
        assert "user required" in str(exc_info.value).lower()

    def test_auth_requires_password_or_secret(self):
        """Test validation error when auth=true but no password or secret."""
        with pytest.raises(ValueError) as exc_info:
            KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                user="noreply@example.com",
            )
        assert "password" in str(exc_info.value).lower()

    def test_cannot_specify_both_password_and_secret(self):
        """Test validation error when both password and password_secret are set."""
        with pytest.raises(ValueError) as exc_info:
            KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                user="noreply@example.com",
                password="secret123",
                password_secret=KeycloakSMTPPasswordSecret(name="smtp-secret"),
            )
        assert "both password and password_secret" in str(exc_info.value).lower()


class TestKeycloakSMTPConfigSerialization:
    """Test SMTP config serialization for Keycloak API."""

    def test_field_alias_conversion(self):
        """Test that fields are converted to camelCase for Kubernetes API."""
        config = KeycloakSMTPConfig(
            host="smtp.example.com",
            port=587,
            from_address="noreply@example.com",
            from_display_name="My App",
            reply_to="support@example.com",
            envelope_from="envelope@example.com",
        )

        # Dump with aliases (matches Kubernetes API format)
        dumped = config.model_dump(by_alias=True, exclude_none=True)

        # Check camelCase conversion for Kubernetes
        assert (
            dumped["from"] == "noreply@example.com"
        )  # 'from' is keyword-safe in YAML/JSON
        assert dumped["fromDisplayName"] == "My App"
        assert dumped["replyTo"] == "support@example.com"
        assert dumped["envelopeFrom"] == "envelope@example.com"

    def test_password_exclusion(self):
        """Test that password fields are excluded when requested."""
        config = KeycloakSMTPConfig(
            host="smtp.example.com",
            port=587,
            from_address="noreply@example.com",
            auth=True,
            user="noreply@example.com",
            password="secret123",
        )

        # Dump excluding password fields (as done in to_keycloak_config)
        dumped = config.model_dump(
            by_alias=True, exclude_none=True, exclude={"password", "password_secret"}
        )

        # Password should not be present
        assert "password" not in dumped
        assert "password_secret" not in dumped
        assert "passwordSecret" not in dumped

        # Other fields should be present (Kubernetes format)
        assert dumped["host"] == "smtp.example.com"
        assert dumped["from"] == "noreply@example.com"
        assert dumped["auth"] is True


class TestKeycloakRealmSpecSMTP:
    """Test SMTP configuration in KeycloakRealmSpec."""

    def test_realm_with_smtp_config(self):
        """Test creating realm spec with SMTP configuration."""
        realm_spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=_make_operator_ref(),
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                user="noreply@example.com",
                password_secret=KeycloakSMTPPasswordSecret(name="smtp-secret"),
            ),
        )

        assert realm_spec.smtp_server is not None
        assert realm_spec.smtp_server.host == "smtp.example.com"
        assert realm_spec.smtp_server.password_secret is not None
        assert realm_spec.smtp_server.password_secret.name == "smtp-secret"

    def test_realm_without_smtp_config(self):
        """Test creating realm spec without SMTP configuration."""
        realm_spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=_make_operator_ref(),
        )

        assert realm_spec.smtp_server is None

    def test_to_keycloak_config_excludes_password_fields(self):
        """Test that to_keycloak_config() excludes password fields."""
        realm_spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=_make_operator_ref(),
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                from_display_name="Test App",
                auth=True,
                user="noreply@example.com",
                password="secret123",  # This should be excluded
                starttls=True,
            ),
        )

        config = realm_spec.to_keycloak_config()

        # SMTP config should be present
        assert "smtpServer" in config
        smtp_config = config["smtpServer"]

        # Check fields are present with correct casing and as strings (Keycloak API requirement)
        assert smtp_config["host"] == "smtp.example.com"
        assert smtp_config["port"] == "587"  # Converted to string
        assert smtp_config["from"] == "noreply@example.com"
        assert smtp_config["fromDisplayName"] == "Test App"
        assert smtp_config["user"] == "noreply@example.com"
        assert smtp_config["starttls"] == "true"  # Boolean as lowercase string
        assert smtp_config["auth"] == "true"  # Boolean as lowercase string

        # Password should NOT be present
        assert "password" not in smtp_config
        assert "password_secret" not in smtp_config
        assert "passwordSecret" not in smtp_config

    def test_to_keycloak_config_no_smtp(self):
        """Test that to_keycloak_config() handles missing SMTP config."""
        realm_spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref=_make_operator_ref(),
        )

        config = realm_spec.to_keycloak_config()

        # SMTP config should not be present
        assert "smtpServer" not in config
