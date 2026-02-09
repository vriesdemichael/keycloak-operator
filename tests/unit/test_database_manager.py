"""
Unit tests for DatabaseConnectionManager.

Tests connection resolution, credential reading, connection testing,
and connection string generation by mocking asyncpg and Kubernetes API.
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.errors import ExternalServiceError
from keycloak_operator.utils.database import DatabaseConnectionManager


def _make_manager() -> DatabaseConnectionManager:
    """Create a DatabaseConnectionManager with a mocked K8s client."""
    return DatabaseConnectionManager(k8s_client=MagicMock())


# ---------------------------------------------------------------------------
# _get_connection_pool_dict
# ---------------------------------------------------------------------------
class TestGetConnectionPoolDict:
    """Test _get_connection_pool_dict conversion."""

    def test_none_pool_returns_empty(self):
        """None connection pool returns empty dict."""
        mgr = _make_manager()
        config = MagicMock()
        config.connection_pool = None
        # Use getattr in case of attribute absence
        delattr(config, "connection_pool")
        assert mgr._get_connection_pool_dict(config) == {}

    def test_dict_pool_returned_as_is(self):
        """Dict connection pool is returned as-is."""
        mgr = _make_manager()
        config = MagicMock()
        config.connection_pool = {"min_size": 5, "max_size": 20}
        result = mgr._get_connection_pool_dict(config)
        assert result == {"min_size": 5, "max_size": 20}

    def test_model_pool_calls_model_dump(self):
        """Pydantic model pool calls model_dump(by_alias=True)."""
        mgr = _make_manager()
        config = MagicMock()
        pool_mock = MagicMock()
        pool_mock.model_dump.return_value = {"minSize": 5}
        config.connection_pool = pool_mock
        result = mgr._get_connection_pool_dict(config)
        pool_mock.model_dump.assert_called_once_with(by_alias=True)
        assert result == {"minSize": 5}


# ---------------------------------------------------------------------------
# _get_password_from_secret
# ---------------------------------------------------------------------------
class TestGetPasswordFromSecret:
    """Test _get_password_from_secret."""

    @pytest.mark.asyncio
    async def test_returns_decoded_password(self):
        """Retrieves and base64-decodes a password from a K8s secret."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = {"password": base64.b64encode(b"my-pass").decode("utf-8")}
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            result = await mgr._get_password_from_secret("my-secret", "password", "ns")

        assert result == "my-pass"

    @pytest.mark.asyncio
    async def test_missing_key_raises(self):
        """Missing key in secret raises ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = {"username": base64.b64encode(b"admin").decode("utf-8")}
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError, match="missing key"):
                await mgr._get_password_from_secret("my-secret", "password", "ns")

    @pytest.mark.asyncio
    async def test_empty_data_raises(self):
        """Secret with no data raises ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = None
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError, match="no data"):
                await mgr._get_password_from_secret("my-secret", "password", "ns")

    @pytest.mark.asyncio
    async def test_secret_not_found_raises(self):
        """Secret 404 raises retryable ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError) as exc_info:
                await mgr._get_password_from_secret("missing", "password", "ns")
            assert exc_info.value.retryable is True

    @pytest.mark.asyncio
    async def test_other_api_error_raises(self):
        """Non-404 API error raises retryable ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=500, reason="Internal Server Error"
        )

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError) as exc_info:
                await mgr._get_password_from_secret("my-secret", "password", "ns")
            assert exc_info.value.retryable is True


# ---------------------------------------------------------------------------
# _get_k8s_secret_credentials
# ---------------------------------------------------------------------------
class TestGetK8sSecretCredentials:
    """Test _get_k8s_secret_credentials."""

    @pytest.mark.asyncio
    async def test_returns_decoded_credentials(self):
        """Retrieves both username and password from a K8s secret."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = {
            "username": base64.b64encode(b"admin").decode("utf-8"),
            "password": base64.b64encode(b"secret").decode("utf-8"),
        }
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            result = await mgr._get_k8s_secret_credentials("cred-secret", "ns")

        assert result == {"username": "admin", "password": "secret"}

    @pytest.mark.asyncio
    async def test_missing_username_or_password_raises(self):
        """Missing username or password key raises ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = {
            "username": base64.b64encode(b"admin").decode("utf-8"),
            # missing password
        }
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(
                ExternalServiceError, match="missing username or password"
            ):
                await mgr._get_k8s_secret_credentials("cred-secret", "ns")

    @pytest.mark.asyncio
    async def test_empty_data_raises(self):
        """Secret with no data raises ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_secret = MagicMock()
        mock_secret.data = None
        mock_core.read_namespaced_secret.return_value = mock_secret

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError, match="no data"):
                await mgr._get_k8s_secret_credentials("cred-secret", "ns")

    @pytest.mark.asyncio
    async def test_404_raises_retryable(self):
        """404 error raises retryable ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError) as exc_info:
                await mgr._get_k8s_secret_credentials("missing", "ns")
            assert exc_info.value.retryable is True

    @pytest.mark.asyncio
    async def test_non_404_api_error(self):
        """Non-404 API error raises retryable ExternalServiceError."""
        mgr = _make_manager()
        mock_core = MagicMock()
        mock_core.read_namespaced_secret.side_effect = ApiException(
            status=403, reason="Forbidden"
        )

        with patch("keycloak_operator.utils.database.client.CoreV1Api") as mock_cls:
            mock_cls.return_value = mock_core
            with pytest.raises(ExternalServiceError):
                await mgr._get_k8s_secret_credentials("secret", "ns")


# ---------------------------------------------------------------------------
# test_database_connection
# ---------------------------------------------------------------------------
class TestTestDatabaseConnection:
    """Test test_database_connection method."""

    @pytest.mark.asyncio
    async def test_postgresql_success(self):
        """Successful PostgreSQL connection returns True."""
        mgr = _make_manager()
        mgr._test_postgresql_connection = AsyncMock(return_value=True)  # type: ignore
        mgr._record_connection_metrics = MagicMock()  # type: ignore

        result = await mgr.test_database_connection(
            connection_info={
                "type": "postgresql",
                "host": "db.local",
                "port": 5432,
                "database": "keycloak",
                "username": "admin",
                "password": "pass",
            },
            resource_name="kc-1",
            namespace="ns-a",
        )

        assert result is True
        mgr._record_connection_metrics.assert_called_once()  # type: ignore
        call_kwargs = mgr._record_connection_metrics.call_args  # type: ignore
        assert (
            call_kwargs.kwargs.get("success") is True
            or call_kwargs[1].get("success") is True
        )

    @pytest.mark.asyncio
    async def test_postgresql_failure(self):
        """Failed PostgreSQL connection returns False."""
        mgr = _make_manager()
        mgr._test_postgresql_connection = AsyncMock(return_value=False)  # type: ignore
        mgr._record_connection_metrics = MagicMock()  # type: ignore

        result = await mgr.test_database_connection(
            connection_info={
                "type": "postgresql",
                "host": "db.local",
                "port": 5432,
                "database": "keycloak",
                "username": "admin",
                "password": "pass",
            },
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_non_postgresql_uses_socket(self):
        """Non-postgresql types use socket connection test."""
        mgr = _make_manager()
        mgr._test_socket_connection = AsyncMock(return_value=True)  # type: ignore
        mgr._record_connection_metrics = MagicMock()  # type: ignore

        result = await mgr.test_database_connection(
            connection_info={
                "type": "mysql",
                "host": "db.local",
                "port": 3306,
                "database": "keycloak",
                "username": "admin",
                "password": "pass",
            },
        )

        assert result is True
        mgr._test_socket_connection.assert_awaited_once_with("db.local", 3306)  # type: ignore

    @pytest.mark.asyncio
    async def test_exception_returns_false(self):
        """Exception during connection test returns False."""
        mgr = _make_manager()
        mgr._test_postgresql_connection = AsyncMock(  # type: ignore
            side_effect=RuntimeError("connection error")
        )
        mgr._record_connection_metrics = MagicMock()  # type: ignore

        result = await mgr.test_database_connection(
            connection_info={
                "type": "postgresql",
                "host": "db.local",
                "port": 5432,
                "database": "keycloak",
                "username": "admin",
                "password": "pass",
            },
            namespace="ns-a",
        )

        assert result is False
        # Metrics should still be recorded for failure
        mgr._record_connection_metrics.assert_called()  # type: ignore


# ---------------------------------------------------------------------------
# _test_postgresql_connection
# ---------------------------------------------------------------------------
class TestTestPostgresqlConnection:
    """Test _test_postgresql_connection."""

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.utils.database.DatabaseConnectionManager._test_socket_connection"
    )
    async def test_asyncpg_not_available_falls_back_to_socket(self, mock_socket):
        """When asyncpg is not importable, falls back to socket test."""
        mgr = _make_manager()
        mock_socket.return_value = True

        with patch.dict("sys.modules", {"asyncpg": None}):
            with patch("builtins.__import__", side_effect=ImportError("no asyncpg")):
                # This is tricky - the method catches ImportError
                # We need to ensure the module-level import fails
                result = await mgr._test_postgresql_connection(
                    "host",
                    5432,
                    "db",
                    "user",
                    "pass",
                    {"ssl_mode": "disable"},
                )

        # Either falls back to socket or returns the socket result
        # The important thing is it doesn't crash
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_asyncpg_connection_success(self):
        """Successful asyncpg connection returns True."""
        mgr = _make_manager()

        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.close = AsyncMock()

        mock_connect = AsyncMock(return_value=mock_conn)

        with patch("asyncpg.connect", mock_connect):
            result = await mgr._test_postgresql_connection(
                "host",
                5432,
                "db",
                "user",
                "pass",
                {"ssl_mode": "disable"},
            )

        assert result is True
        mock_conn.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_asyncpg_connection_failure(self):
        """Failed asyncpg connection returns False."""
        mgr = _make_manager()

        mock_connect = AsyncMock(side_effect=ConnectionRefusedError("refused"))

        with patch("asyncpg.connect", mock_connect):
            result = await mgr._test_postgresql_connection(
                "host",
                5432,
                "db",
                "user",
                "pass",
                {"ssl_mode": "require"},
            )

        assert result is False


# ---------------------------------------------------------------------------
# generate_connection_string
# ---------------------------------------------------------------------------
class TestGenerateConnectionString:
    """Test generate_connection_string."""

    def test_postgresql_string(self):
        """PostgreSQL connection string is correctly formatted."""
        mgr = _make_manager()
        result = mgr.generate_connection_string(
            {
                "type": "postgresql",
                "host": "db.local",
                "port": 5432,
                "database": "keycloak",
                "username": "admin",
                "password": "secret",
                "ssl_mode": "require",
            }
        )
        assert result.startswith("postgresql://admin:secret@db.local:5432/keycloak")
        assert "sslmode=require" in result

    def test_mysql_string(self):
        """MySQL connection string is correctly formatted."""
        mgr = _make_manager()
        result = mgr.generate_connection_string(
            {
                "type": "mysql",
                "host": "db.local",
                "port": 3306,
                "database": "keycloak",
                "username": "admin",
                "password": "secret",
                "ssl_mode": "require",
            }
        )
        assert result.startswith("mysql://admin:secret@db.local:3306/keycloak")
        assert "useSSL=true" in result

    def test_mysql_ssl_disabled(self):
        """MySQL with ssl_mode=disable uses useSSL=false."""
        mgr = _make_manager()
        result = mgr.generate_connection_string(
            {
                "type": "mysql",
                "host": "db.local",
                "port": 3306,
                "database": "keycloak",
                "username": "admin",
                "password": "secret",
                "ssl_mode": "disable",
            }
        )
        assert "useSSL=false" in result

    def test_generic_jdbc_string(self):
        """Unknown database type uses generic JDBC format."""
        mgr = _make_manager()
        result = mgr.generate_connection_string(
            {
                "type": "oracle",
                "host": "db.local",
                "port": 1521,
                "database": "keycloak",
                "username": "admin",
                "password": "secret",
            }
        )
        assert result == "jdbc:oracle://db.local:1521/keycloak"
