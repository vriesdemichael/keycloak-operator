"""
Database connection utilities for Keycloak operator.

This module provides utilities for managing database connections,
including CloudNativePG integration and connection string generation.
"""

import asyncio
import time
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import ExternalServiceError, TemporaryError
from ..models.keycloak import (
    CloudNativePGReference,
    ExternalSecretReference,
    KeycloakDatabaseConfig,
)
from ..observability.logging import OperatorLogger

logger = OperatorLogger(__name__)


class DatabaseConnectionManager:
    """Manages database connections and configuration for Keycloak instances."""

    def __init__(self, k8s_client: client.ApiClient):
        """
        Initialize database connection manager.

        Args:
            k8s_client: Kubernetes API client
        """
        self.k8s_client = k8s_client

    async def resolve_database_connection(
        self, db_config: KeycloakDatabaseConfig, namespace: str
    ) -> dict[str, Any]:
        """
        Resolve database connection information from configuration.

        Args:
            db_config: Database configuration
            namespace: Namespace context

        Returns:
            Dictionary with connection details including host, port, database, credentials

        Raises:
            ExternalServiceError: If database configuration cannot be resolved
        """
        if db_config.type == "cnpg":
            if db_config.cnpg_cluster is None:
                raise ExternalServiceError(
                    service="Database",
                    message="CNPG database type requires cnpg_cluster configuration",
                    retryable=False,
                    user_action="Configure database.cnpg_cluster with valid CloudNativePG cluster reference",
                )
            return await self._resolve_cnpg_connection(
                db_config.cnpg_cluster, namespace
            )
        else:
            return await self._resolve_traditional_connection(db_config, namespace)

    async def _resolve_cnpg_connection(
        self, cnpg_ref: CloudNativePGReference, namespace: str
    ) -> dict[str, Any]:
        """
        Resolve CloudNativePG cluster connection details.

        Args:
            cnpg_ref: CNPG cluster reference
            namespace: Namespace context

        Returns:
            Dictionary with connection details
        """
        target_namespace = cnpg_ref.namespace or namespace
        cluster_name = cnpg_ref.name

        logger.info(
            f"Resolving CNPG cluster '{cluster_name}' in namespace '{target_namespace}'"
        )

        try:
            # Use dynamic client to access CNPG resources
            from kubernetes import dynamic

            dyn_client = dynamic.DynamicClient(self.k8s_client)

            # Get CNPG Cluster resource
            cluster_api = dyn_client.resources.get(
                api_version="postgresql.cnpg.io/v1", kind="Cluster"
            )

            try:
                cluster = cluster_api.get(name=cluster_name, namespace=target_namespace)
            except ApiException as e:
                if e.status == 404:
                    raise ExternalServiceError(
                        service="CloudNativePG",
                        message=f"CNPG Cluster '{cluster_name}' not found in namespace '{target_namespace}'",
                        retryable=True,
                        user_action=f"Create CNPG Cluster '{cluster_name}' or check the cluster reference",
                    ) from e
                else:
                    raise ExternalServiceError(
                        service="CloudNativePG",
                        message=f"Failed to access CNPG Cluster: {e}",
                        retryable=True,
                        user_action="Check Kubernetes API connectivity and RBAC permissions",
                    ) from e

            # Validate cluster is ready
            cluster_status = cluster.get("status", {})
            phase = cluster_status.get("phase", "Unknown")

            if phase != "Cluster in healthy state":
                logger.warning(
                    f"CNPG Cluster '{cluster_name}' is not in healthy state: {phase}"
                )
                raise TemporaryError(
                    f"CNPG Cluster '{cluster_name}' is not ready (phase: {phase}). "
                    f"Waiting for cluster to become healthy."
                )

            # Extract connection details
            connection_info = {
                "type": "postgresql",  # CNPG is always PostgreSQL
                "host": f"{cluster_name}-rw.{target_namespace}.svc.cluster.local",
                "port": 5432,
                "database": cnpg_ref.database,
                "ssl_mode": "require",  # CNPG enables SSL by default
                "application_name": cnpg_ref.application_name,
            }

            # Get credentials from CNPG-generated secret
            secret_name = f"{cluster_name}-app"  # CNPG default app secret name
            credentials = await self._get_cnpg_credentials(
                secret_name, target_namespace
            )
            connection_info.update(credentials)

            logger.info(
                f"Successfully resolved CNPG connection for cluster '{cluster_name}'"
            )
            return connection_info

        except Exception as e:
            if isinstance(e, (ExternalServiceError, TemporaryError)):
                raise

            logger.error(f"Failed to resolve CNPG cluster connection: {e}")
            raise ExternalServiceError(
                service="CloudNativePG",
                message=f"Failed to resolve CNPG cluster connection: {str(e)}",
                retryable=True,
                user_action="Check CNPG operator installation and cluster configuration",
            ) from e

    async def _get_cnpg_credentials(
        self, secret_name: str, namespace: str
    ) -> dict[str, str]:
        """
        Get database credentials from CNPG-generated secret.

        Args:
            secret_name: Name of the CNPG secret
            namespace: Namespace of the secret

        Returns:
            Dictionary with username and password
        """
        core_api = client.CoreV1Api(self.k8s_client)

        try:
            secret = core_api.read_namespaced_secret(
                name=secret_name, namespace=namespace
            )

            if not secret.data:
                raise ExternalServiceError(
                    service="CloudNativePG",
                    message=f"CNPG secret '{secret_name}' has no data",
                    retryable=True,
                    user_action="Check CNPG cluster status and secret generation",
                )

            # CNPG secrets contain username and password in base64
            import base64

            username = secret.data.get("username")
            password = secret.data.get("password")

            if not username or not password:
                raise ExternalServiceError(
                    service="CloudNativePG",
                    message=f"CNPG secret '{secret_name}' missing username or password",
                    retryable=True,
                    user_action="Check CNPG secret format and regenerate if needed",
                )

            return {
                "username": base64.b64decode(username).decode("utf-8"),
                "password": base64.b64decode(password).decode("utf-8"),
            }

        except ApiException as e:
            if e.status == 404:
                raise ExternalServiceError(
                    service="CloudNativePG",
                    message=f"CNPG credentials secret '{secret_name}' not found",
                    retryable=True,
                    user_action="Check CNPG cluster configuration and secret generation",
                ) from e
            else:
                raise ExternalServiceError(
                    service="CloudNativePG",
                    message=f"Failed to read CNPG credentials: {e}",
                    retryable=True,
                    user_action="Check Kubernetes API connectivity and RBAC permissions",
                ) from e

    async def _resolve_traditional_connection(
        self, db_config: KeycloakDatabaseConfig, namespace: str
    ) -> dict[str, Any]:
        """
        Resolve traditional database connection details.

        Args:
            db_config: Database configuration
            namespace: Namespace context

        Returns:
            Dictionary with connection details
        """
        connection_info = {
            "type": db_config.type,
            "host": db_config.host,
            "port": db_config.port,
            "database": db_config.database,
            "ssl_mode": getattr(db_config, "ssl_mode", "require"),
            "connection_params": getattr(db_config, "connection_params", {}),
            "connection_pool": getattr(db_config, "connection_pool", {}),
        }

        # Resolve credentials
        external_secret = getattr(db_config, "external_secret", None)
        credentials_secret = getattr(db_config, "credentials_secret", None)

        if external_secret:
            credentials = await self._get_external_secret_credentials(
                external_secret, namespace
            )
        elif credentials_secret:
            credentials = await self._get_k8s_secret_credentials(
                credentials_secret, namespace
            )
        elif db_config.username:
            # Username provided directly (password should be in separate secret)
            credentials = {"username": db_config.username}
        else:
            raise ExternalServiceError(
                service="Database",
                message="No valid credential source configured",
                retryable=False,
                user_action="Configure credentials_secret, external_secret, or username",
            )

        connection_info.update(credentials)
        return connection_info

    async def _get_external_secret_credentials(
        self, external_ref: ExternalSecretReference, namespace: str
    ) -> dict[str, str]:
        """
        Get credentials from ExternalSecret resource.

        Args:
            external_ref: ExternalSecret reference
            namespace: Namespace context

        Returns:
            Dictionary with credentials
        """
        target_namespace = external_ref.namespace or namespace
        secret_name = external_ref.name

        # ExternalSecrets creates a regular Kubernetes secret
        # So we can read it like a normal secret
        return await self._get_k8s_secret_credentials(secret_name, target_namespace)

    async def _get_k8s_secret_credentials(
        self, secret_name: str, namespace: str
    ) -> dict[str, str]:
        """
        Get credentials from Kubernetes secret.

        Args:
            secret_name: Name of the secret
            namespace: Namespace of the secret

        Returns:
            Dictionary with credentials
        """
        core_api = client.CoreV1Api(self.k8s_client)

        try:
            secret = core_api.read_namespaced_secret(
                name=secret_name, namespace=namespace
            )

            if not secret.data:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Database credentials secret '{secret_name}' has no data",
                    retryable=False,
                    user_action=f"Add username and password to secret '{secret_name}'",
                )

            # Extract credentials
            import base64

            credentials = {}

            for key in ["username", "password"]:
                if key in secret.data:
                    credentials[key] = base64.b64decode(secret.data[key]).decode(
                        "utf-8"
                    )

            if "username" not in credentials or "password" not in credentials:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Secret '{secret_name}' missing username or password keys",
                    retryable=False,
                    user_action=f"Ensure secret '{secret_name}' contains both 'username' and 'password' keys",
                )

            return credentials

        except ApiException as e:
            if e.status == 404:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Database credentials secret '{secret_name}' not found",
                    retryable=True,
                    user_action=f"Create secret '{secret_name}' with database credentials",
                ) from e
            else:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Failed to read database credentials: {e}",
                    retryable=True,
                    user_action="Check Kubernetes API connectivity and RBAC permissions",
                ) from e

    async def test_database_connection(
        self,
        connection_info: dict[str, Any],
        resource_name: str = "",
        namespace: str = "",
    ) -> bool:
        """
        Test database connectivity.

        Args:
            connection_info: Database connection information
            resource_name: Name of the Keycloak resource (for logging)
            namespace: Namespace (for logging)

        Returns:
            True if connection successful, False otherwise
        """
        db_type = connection_info.get("type")
        host = connection_info.get("host")
        port = connection_info.get("port")
        database = connection_info.get("database")
        username = connection_info.get("username")
        password = connection_info.get("password")

        start_time = time.time()

        logger.info(
            f"Testing {db_type} database connection to {host}:{port}/{database}",
            database_type=db_type,
            host=host,
            port=port,
            database=database,
            operation="database_connection_test",
        )

        try:
            if db_type == "postgresql":
                success = await self._test_postgresql_connection(
                    host, port, database, username, password, connection_info
                )
            else:
                # For other database types, implement basic socket connection test
                success = await self._test_socket_connection(host, port)

            duration = time.time() - start_time

            # Log the result using structured logging
            logger.log_database_operation(
                operation="connection_test",
                database_type=db_type or "unknown",
                resource_name=resource_name or "",
                namespace=namespace or "",
                success=success,
                duration=duration,
            )

            return success

        except Exception as e:
            duration = time.time() - start_time

            logger.log_database_operation(
                operation="connection_test",
                database_type=db_type or "unknown",
                resource_name=resource_name or "",
                namespace=namespace or "",
                success=False,
                duration=duration,
                error=str(e),
            )

            return False

    async def _test_postgresql_connection(
        self,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
        connection_info: dict[str, Any],
    ) -> bool:
        """Test PostgreSQL connection using asyncpg if available."""
        try:
            # Try to use asyncpg for proper PostgreSQL testing
            try:
                import asyncpg  # type: ignore
            except ImportError:
                logger.warning("asyncpg not available, falling back to socket test")
                return await self._test_socket_connection(host, port)

            ssl_mode = connection_info.get("ssl_mode", "require")
            ssl_context = None if ssl_mode == "disable" else ssl_mode

            conn = await asyncpg.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                ssl=ssl_context,
                timeout=10.0,
            )

            # Simple test query
            result = await conn.fetchval("SELECT 1")
            await conn.close()

            return result == 1

        except ImportError:
            logger.warning("asyncpg not available, falling back to socket test")
            return await self._test_socket_connection(host, port)
        except Exception as e:
            logger.warning(f"PostgreSQL connection test failed: {e}")
            return False

    async def _test_socket_connection(self, host: str, port: int) -> bool:
        """Test basic socket connectivity."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.warning(f"Socket connection test failed: {e}")
            return False

    def generate_connection_string(self, connection_info: dict[str, Any]) -> str:
        """
        Generate database connection string.

        Args:
            connection_info: Database connection information

        Returns:
            Database connection string
        """
        db_type = connection_info.get("type")
        host = connection_info.get("host")
        port = connection_info.get("port")
        database = connection_info.get("database")
        username = connection_info.get("username")
        password = connection_info.get("password")
        ssl_mode = connection_info.get("ssl_mode", "require")

        if db_type == "postgresql":
            return (
                f"postgresql://{username}:{password}@{host}:{port}/{database}"
                f"?sslmode={ssl_mode}&application_name={connection_info.get('application_name', 'keycloak')}"
            )
        elif db_type in ["mysql", "mariadb"]:
            ssl_param = "true" if ssl_mode != "disable" else "false"
            return f"mysql://{username}:{password}@{host}:{port}/{database}?useSSL={ssl_param}"
        else:
            # Generic JDBC-style connection string
            return f"jdbc:{db_type}://{host}:{port}/{database}"
