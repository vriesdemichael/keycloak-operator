"""
Unit tests for database connection utilities.

These tests verify database connection management, credential resolution,
and connection testing functionality.
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.errors import ExternalServiceError
from keycloak_operator.models.keycloak import KeycloakDatabaseConfig
from keycloak_operator.utils.database import DatabaseConnectionManager


@pytest.fixture
def mock_k8s_client():
    """Create a mock Kubernetes client."""
    return MagicMock(spec=client.ApiClient)


@pytest.fixture
def db_manager(mock_k8s_client):
    """Create a database connection manager with mock client."""
    return DatabaseConnectionManager(mock_k8s_client)


class TestResolveTraditionalConnection:
    """Test cases for traditional database connection resolution."""

    @pytest.mark.asyncio
    async def test_resolve_with_credentials_secret(self, db_manager):
        """Test resolving connection with credentials secret."""
        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="db.example.com",
            port=5432,
            database="keycloak",
            credentials_secret="db-creds",
        )

        # Mock the secret credentials method
        db_manager._get_k8s_secret_credentials = AsyncMock(
            return_value={"username": "keycloak", "password": "secret123"}
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert result["type"] == "postgresql"
        assert result["host"] == "db.example.com"
        assert result["port"] == 5432
        assert result["database"] == "keycloak"
        assert result["username"] == "keycloak"
        assert result["password"] == "secret123"
        assert result["ssl_mode"] == "require"  # Default

    @pytest.mark.asyncio
    async def test_resolve_with_username_only(self, db_manager):
        """Test resolving connection with username (no secret)."""
        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="db.example.com",
            port=5432,
            database="keycloak",
            username="admin",
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert result["username"] == "admin"
        assert "password" not in result

    @pytest.mark.asyncio
    async def test_resolve_with_ssl_mode(self, db_manager):
        """Test resolving connection with custom SSL mode."""
        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="db.example.com",
            port=5432,
            database="keycloak",
            username="admin",
            ssl_mode="disable",
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert result["ssl_mode"] == "disable"

    @pytest.mark.asyncio
    async def test_resolve_with_connection_params(self, db_manager):
        """Test resolving connection with custom connection parameters."""
        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="db.example.com",
            port=5432,
            database="keycloak",
            username="admin",
            connection_params={"connect_timeout": "10", "application_name": "keycloak"},
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert result["connection_params"]["connect_timeout"] == "10"
        assert result["connection_params"]["application_name"] == "keycloak"

    @pytest.mark.asyncio
    async def test_resolve_missing_credentials(self, db_manager):
        """Test that Pydantic validates credential requirements at model level."""
        from pydantic import ValidationError

        # This test verifies that Pydantic validation catches missing credentials
        # The validation happens at the model level, not in resolve_database_connection
        with pytest.raises(ValidationError):
            KeycloakDatabaseConfig(
                type="postgresql",
                host="db.example.com",
                port=5432,
                database="keycloak",
            )


class TestGetK8sSecretCredentials:
    """Test cases for retrieving credentials from Kubernetes secrets."""

    @pytest.mark.asyncio
    async def test_get_valid_secret_credentials(self, db_manager, mock_k8s_client):
        """Test retrieving credentials from a valid secret."""
        # Mock the CoreV1Api and secret
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_secret = MagicMock()
        mock_secret.data = {
            "username": base64.b64encode(b"keycloak").decode("utf-8"),
            "password": base64.b64encode(b"secret123").decode("utf-8"),
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            credentials = await db_manager._get_k8s_secret_credentials(
                "db-creds", "default"
            )

        assert credentials["username"] == "keycloak"
        assert credentials["password"] == "secret123"
        mock_core_api.read_namespaced_secret.assert_called_once_with(
            name="db-creds", namespace="default"
        )

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self, db_manager, mock_k8s_client):
        """Test handling of secret not found error."""
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=404)

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            with pytest.raises(ExternalServiceError) as exc_info:
                await db_manager._get_k8s_secret_credentials("db-creds", "default")

        error: ExternalServiceError = exc_info.value  # type: ignore[assignment]
        assert "not found" in str(error)
        assert error.retryable  # Secret might be created later

    @pytest.mark.asyncio
    async def test_get_secret_empty_data(self, db_manager, mock_k8s_client):
        """Test handling of secret with no data."""
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_secret = MagicMock()
        mock_secret.data = None
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            with pytest.raises(ExternalServiceError) as exc_info:
                await db_manager._get_k8s_secret_credentials("db-creds", "default")

        error: ExternalServiceError = exc_info.value  # type: ignore[assignment]
        assert "has no data" in str(error)
        assert not error.retryable

    @pytest.mark.asyncio
    async def test_get_secret_missing_username(self, db_manager, mock_k8s_client):
        """Test handling of secret missing username key."""
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_secret = MagicMock()
        mock_secret.data = {
            "password": base64.b64encode(b"secret123").decode("utf-8"),
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            with pytest.raises(ExternalServiceError) as exc_info:
                await db_manager._get_k8s_secret_credentials("db-creds", "default")

        error: ExternalServiceError = exc_info.value  # type: ignore[assignment]
        assert "missing username or password" in str(error)
        assert not error.retryable

    @pytest.mark.asyncio
    async def test_get_secret_missing_password(self, db_manager, mock_k8s_client):
        """Test handling of secret missing password key."""
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_secret = MagicMock()
        mock_secret.data = {
            "username": base64.b64encode(b"keycloak").decode("utf-8"),
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            with pytest.raises(ExternalServiceError) as exc_info:
                await db_manager._get_k8s_secret_credentials("db-creds", "default")

        error: ExternalServiceError = exc_info.value  # type: ignore[assignment]
        assert "missing username or password" in str(error)
        assert not error.retryable

    @pytest.mark.asyncio
    async def test_get_secret_api_error(self, db_manager, mock_k8s_client):
        """Test handling of general API errors."""
        mock_core_api = MagicMock(spec=client.CoreV1Api)
        mock_core_api.read_namespaced_secret.side_effect = ApiException(
            status=500, reason="Internal Server Error"
        )

        with patch.object(client, "CoreV1Api", return_value=mock_core_api):
            with pytest.raises(ExternalServiceError) as exc_info:
                await db_manager._get_k8s_secret_credentials("db-creds", "default")

        error: ExternalServiceError = exc_info.value  # type: ignore[assignment]
        assert "Failed to read" in str(error)
        assert error.retryable  # Transient errors are retryable


class TestGenerateConnectionString:
    """Test cases for generating database connection strings."""

    def test_generate_postgresql_url_basic(self, db_manager):
        """Test generating basic PostgreSQL connection string."""
        connection_info = {
            "type": "postgresql",
            "host": "localhost",
            "port": 5432,
            "database": "keycloak",
            "username": "admin",
            "password": "secret",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert url.startswith("postgresql://admin:secret@localhost:5432/keycloak")
        assert "sslmode=require" in url  # Default SSL mode

    def test_generate_postgresql_url_with_ssl_mode(self, db_manager):
        """Test generating PostgreSQL URL with custom SSL mode."""
        connection_info = {
            "type": "postgresql",
            "host": "db.example.com",
            "port": 5432,
            "database": "keycloak",
            "username": "admin",
            "password": "secret",
            "ssl_mode": "disable",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert "sslmode=disable" in url

    def test_generate_postgresql_url_with_application_name(self, db_manager):
        """Test generating PostgreSQL URL with application name."""
        connection_info = {
            "type": "postgresql",
            "host": "localhost",
            "port": 5432,
            "database": "keycloak",
            "username": "admin",
            "password": "secret",
            "application_name": "my-app",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert "application_name=my-app" in url

    def test_generate_mysql_url(self, db_manager):
        """Test generating MySQL connection string."""
        connection_info = {
            "type": "mysql",
            "host": "localhost",
            "port": 3306,
            "database": "keycloak",
            "username": "root",
            "password": "secret",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert url.startswith("mysql://root:secret@localhost:3306/keycloak")
        assert "useSSL=true" in url  # Default SSL enabled

    def test_generate_mysql_url_no_ssl(self, db_manager):
        """Test generating MySQL URL with SSL disabled."""
        connection_info = {
            "type": "mysql",
            "host": "localhost",
            "port": 3306,
            "database": "keycloak",
            "username": "root",
            "password": "secret",
            "ssl_mode": "disable",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert "useSSL=false" in url

    def test_generate_mariadb_url(self, db_manager):
        """Test generating MariaDB connection string."""
        connection_info = {
            "type": "mariadb",
            "host": "localhost",
            "port": 3306,
            "database": "keycloak",
            "username": "root",
            "password": "secret",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert url.startswith("mysql://root:secret@localhost:3306/keycloak")

    def test_generate_generic_jdbc_url(self, db_manager):
        """Test generating generic JDBC URL for unknown database type."""
        connection_info = {
            "type": "oracle",
            "host": "localhost",
            "port": 1521,
            "database": "keycloak",
            "username": "admin",
            "password": "secret",
        }

        url = db_manager.generate_connection_string(connection_info)

        assert url == "jdbc:oracle://localhost:1521/keycloak"


class TestConnectionPooling:
    """Test cases for connection pool configuration."""

    @pytest.mark.asyncio
    async def test_default_connection_pool_settings(self, db_manager):
        """Test that default connection pool settings are applied."""
        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="localhost",
            port=5432,
            database="keycloak",
            username="admin",
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert "connection_pool" in result
        assert isinstance(result["connection_pool"], dict)

    @pytest.mark.asyncio
    async def test_custom_connection_pool_settings(self, db_manager):
        """Test custom connection pool settings."""
        from keycloak_operator.models.keycloak import ConnectionPoolConfig

        db_config = KeycloakDatabaseConfig(
            type="postgresql",
            host="localhost",
            port=5432,
            database="keycloak",
            username="admin",
            connection_pool=ConnectionPoolConfig(
                max_connections=50,
                min_connections=10,
                connection_timeout="60s",
            ),
        )

        result = await db_manager.resolve_database_connection(db_config, "default")

        assert result["connection_pool"]["maxConnections"] == 50
        assert result["connection_pool"]["minConnections"] == 10
        assert result["connection_pool"]["connectionTimeout"] == "60s"
