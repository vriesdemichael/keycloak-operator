"""
Test CRD validation for Keycloak operator resources.

This module tests that CRD validation properly enforces constraints,
particularly the removal of H2 database and enforcement of production
database types.
"""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.keycloak import KeycloakDatabaseConfig


class TestDatabaseTypeValidation:
    """Test database type validation in Keycloak CRDs."""

    def test_production_databases_accepted(self):
        """Test that all production database types are accepted."""
        production_databases = [
            "postgresql",
            "mysql",
            "mariadb",
            "oracle",
            "mssql",
            "cnpg",
        ]

        for db_type in production_databases:
            # Should not raise ValidationError (minimal config for type validation)
            database_config = KeycloakDatabaseConfig(type=db_type)
            assert database_config.type == db_type

    def test_h2_database_rejected(self):
        """Test that H2 database type is rejected with proper error message."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakDatabaseConfig(type="h2")

        # Verify the error message mentions H2 is not supported
        error_message = str(exc_info.value).lower()
        assert "h2" in error_message and (
            "not supported" in error_message or "must be one of" in error_message
        )

    def test_invalid_database_types_rejected(self):
        """Test that other invalid database types are also rejected."""
        invalid_types = ["sqlite", "invalid", "", "H2", "postgres"]

        for invalid_type in invalid_types:
            with pytest.raises(ValidationError):
                KeycloakDatabaseConfig(type=invalid_type)

    def test_database_type_case_sensitive(self):
        """Test that database types are case sensitive."""
        # Uppercase should fail
        with pytest.raises(ValidationError):
            KeycloakDatabaseConfig(type="POSTGRESQL")

        # Correct lowercase should pass
        database_config = KeycloakDatabaseConfig(type="postgresql")
        assert database_config.type == "postgresql"

    def test_valid_production_types_comprehensive(self):
        """Test that exactly the expected production database types are supported."""
        # Test each production database type individually
        valid_types = ["postgresql", "mysql", "mariadb", "oracle", "mssql", "cnpg"]

        for db_type in valid_types:
            # Should create successfully
            config = KeycloakDatabaseConfig(type=db_type)
            assert config.type == db_type

        # Test that H2 and other common types are NOT in the valid list
        invalid_types = ["h2", "sqlite", "mongodb", "redis", "cassandra"]
        for invalid_type in invalid_types:
            with pytest.raises(ValidationError):
                KeycloakDatabaseConfig(type=invalid_type)


class TestPortValidation:
    """Test port validation in database configuration."""

    def test_valid_ports_accepted(self):
        """Test that valid port numbers are accepted."""
        valid_ports = [1, 5432, 3306, 1521, 1433, 65535]

        for port in valid_ports:
            database_config = KeycloakDatabaseConfig(type="postgresql", port=port)
            assert database_config.port == port

    def test_invalid_ports_rejected(self):
        """Test that invalid port numbers are rejected."""
        invalid_ports = [0, -1, 65536, 100000]

        for port in invalid_ports:
            with pytest.raises(ValidationError):
                KeycloakDatabaseConfig(type="postgresql", port=port)

    def test_default_port_behavior(self):
        """Test that port defaults work correctly."""
        # Port should be None by default
        database_config = KeycloakDatabaseConfig(type="postgresql")
        assert database_config.port is None


class TestSecurityRequirements:
    """Test security-related validation requirements."""

    def test_no_hardcoded_password_field(self):
        """Test that there is no direct password field in the model."""
        database_config = KeycloakDatabaseConfig(type="postgresql")

        # Should not have a password field
        assert not hasattr(database_config, "password")

        # Should have credential management fields instead
        assert hasattr(database_config, "credentials_secret")
        assert hasattr(database_config, "external_secret")

    def test_credential_management_options(self):
        """Test that proper credential management options are available."""
        # Test with credentials_secret
        database_config = KeycloakDatabaseConfig(
            type="postgresql", credentials_secret="my-db-secret"
        )
        assert database_config.credentials_secret == "my-db-secret"

        # Test without explicit credentials (should use defaults)
        database_config = KeycloakDatabaseConfig(type="postgresql")
        assert database_config.credentials_secret is None
        assert database_config.external_secret is None


class TestBackwardCompatibilityValidation:
    """Test that changes maintain appropriate backward compatibility."""

    def test_h2_migration_completely_blocked(self):
        """Test that H2 configurations are completely rejected."""
        # Various forms of H2 should all be rejected
        h2_variants = ["h2", "H2", "h2database"]

        for h2_variant in h2_variants:
            with pytest.raises(ValidationError):
                KeycloakDatabaseConfig(type=h2_variant)

    def test_production_database_migration_paths(self):
        """Test that migration to production databases works."""
        # All production databases should be accepted
        production_databases = [
            "postgresql",
            "mysql",
            "mariadb",
            "oracle",
            "mssql",
            "cnpg",
        ]

        for db_type in production_databases:
            # Should create successfully with minimal configuration
            config = KeycloakDatabaseConfig(type=db_type)
            assert config.type == db_type

    def test_cnpg_support_available(self):
        """Test that CloudNativePG support is available."""
        # CNPG should be a valid database type
        config = KeycloakDatabaseConfig(type="cnpg")
        assert config.type == "cnpg"

        # Should have CNPG-specific configuration options
        assert hasattr(config, "cnpg_cluster")


class TestValidationErrorMessages:
    """Test that validation error messages are helpful."""

    def test_h2_error_message_helpful(self):
        """Test that H2 rejection provides helpful error message."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakDatabaseConfig(type="h2")

        error_message = str(exc_info.value)

        # Should mention H2 is not supported
        assert "H2 is not supported" in error_message or "h2" in error_message.lower()

        # Should suggest alternatives
        assert "production" in error_message.lower()

    def test_invalid_type_shows_valid_options(self):
        """Test that invalid type errors show valid options."""
        with pytest.raises(ValidationError) as exc_info:
            KeycloakDatabaseConfig(type="invalid")

        error_message = str(exc_info.value)

        # Should show valid database types
        assert "postgresql" in error_message
        assert "mysql" in error_message
        assert "cnpg" in error_message
