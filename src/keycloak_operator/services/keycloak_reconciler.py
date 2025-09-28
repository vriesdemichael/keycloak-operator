"""
Keycloak instance reconciler for managing core Keycloak deployments.

This module handles the lifecycle of Keycloak instances including
deployment, services, persistence, and administrative access.
"""

from typing import Any

from kubernetes import client

from ..errors import (
    DatabaseValidationError,
    ExternalServiceError,
    TemporaryError,
    ValidationError,
)
from ..models.keycloak import KeycloakSpec
from ..utils.keycloak_admin import get_keycloak_admin_client
from .base_reconciler import BaseReconciler, StatusProtocol


class KeycloakInstanceReconciler(BaseReconciler):
    """
    Reconciler for Keycloak instance resources.

    Manages the complete lifecycle of Keycloak instances including:
    - Kubernetes deployment and scaling
    - Service and ingress configuration
    - Persistent storage setup
    - Admin user initialization
    - Production environment validation
    """

    def __init__(
        self, k8s_client: client.ApiClient | None = None, keycloak_admin_factory=None
    ):
        """
        Initialize Keycloak instance reconciler.

        Args:
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients
        """
        super().__init__(k8s_client)
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )

    async def do_reconcile(
        self,
        spec: dict[str, Any],
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Reconcile Keycloak instance to desired state.

        Args:
            spec: Keycloak resource specification
            name: Resource name
            namespace: Resource namespace
            status: Resource status object
            **kwargs: Additional handler arguments

        Returns:
            Status dictionary for the resource
        """
        # Parse and validate the specification
        keycloak_spec = self._validate_spec(spec)

        # Perform production environment validation
        await self.validate_production_settings(keycloak_spec, name, namespace)

        # Ensure admin access first (required by deployment)
        await self.ensure_admin_access(keycloak_spec, name, namespace)

        # Ensure core Kubernetes resources exist
        await self.ensure_deployment(keycloak_spec, name, namespace)
        await self.ensure_service(keycloak_spec, name, namespace)

        # Setup persistent storage if configured
        if keycloak_spec.persistence.enabled:
            await self.ensure_persistence(keycloak_spec, name, namespace)

        # Setup ingress if configured
        if keycloak_spec.ingress.enabled:
            await self.ensure_ingress(keycloak_spec, name, namespace)

        # Wait for deployment to be ready
        deployment_ready = await self.wait_for_deployment_ready(name, namespace)

        if not deployment_ready:
            return {
                "phase": "Degraded",
                "message": "Deployment created but not ready within timeout",
                "deployment": f"{name}-keycloak",
                "service": f"{name}-keycloak",
                "endpoints": {
                    "admin": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
                    "public": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
                },
            }

        # Return status information
        return {
            "phase": "Running",
            "message": "Keycloak instance is running",
            "deployment": f"{name}-keycloak",
            "service": f"{name}-keycloak",
            "adminSecret": f"{name}-admin-credentials",
            "endpoints": {
                "admin": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
                "public": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
                "management": f"http://{name}-keycloak.{namespace}.svc.cluster.local:9000",
            },
        }

    def _validate_spec(self, spec: dict[str, Any]) -> KeycloakSpec:
        """
        Validate and parse Keycloak specification.

        Args:
            spec: Raw specification dictionary

        Returns:
            Validated KeycloakSpec object

        Raises:
            ValidationError: If specification is invalid
        """
        try:
            return KeycloakSpec.model_validate(spec)
        except Exception as e:
            raise ValidationError(f"Invalid Keycloak specification: {e}") from e

    async def validate_production_settings(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Validate configuration for production readiness.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace

        Raises:
            DatabaseValidationError: If using H2 database inappropriately
            ValidationError: If other production requirements not met
        """
        # Validate database production readiness (no H2 allowed)
        await self._validate_database_production_readiness(spec, namespace)

        # Validate database connectivity for all external databases
        await self._validate_database_connectivity(spec, name, namespace)

        # Additional production validation checks
        await self._validate_security_requirements(spec, namespace)

        self.logger.info(f"Production validation passed for {name}")

    async def _validate_database_production_readiness(
        self, spec: KeycloakSpec, namespace: str
    ) -> None:
        """
        Validate database configuration for production readiness.

        Args:
            spec: Keycloak specification
            namespace: Resource namespace

        Raises:
            DatabaseValidationError: If database configuration is not production-ready
        """
        # H2 is completely removed and no longer supported
        # This validation now focuses on ensuring proper external database configuration

        db_type = spec.database.type

        # Validate that a production-ready database type is used
        production_db_types = [
            "postgresql",
            "mysql",
            "mariadb",
            "oracle",
            "mssql",
            "cnpg",
        ]

        if db_type not in production_db_types:
            raise DatabaseValidationError(
                db_type,
                "production (H2 and other embedded databases are not supported)",
            )

        # Additional validation for CloudNativePG
        if db_type == "cnpg" and not spec.database.cnpg_cluster:
            from ..errors import ValidationError

            raise ValidationError(
                "CNPG database type requires cnpg_cluster configuration",
                field="database.cnpg_cluster",
                user_action="Configure database.cnpg_cluster with valid CloudNativePG cluster reference",
            )

        # Validate SSL configuration for production
        ssl_mode = getattr(spec.database, "ssl_mode", "require")
        if ssl_mode in ["disable", "allow"]:
            self.logger.warning(
                f"Database SSL mode '{ssl_mode}' is not recommended for production. "
                f"Consider using 'require' or higher for better security."
            )

        self.logger.info(
            f"Database production readiness validation passed for {db_type}"
        )

    async def _validate_database_connectivity(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Validate database connectivity using the new database connection manager.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace

        Raises:
            ExternalServiceError: If database connectivity validation fails
        """
        from ..utils.database import DatabaseConnectionManager

        self.logger.info(f"Validating database connectivity for {spec.database.type}")

        # Initialize database connection manager
        db_manager = DatabaseConnectionManager(self.kubernetes_client)

        try:
            # Resolve database connection information
            connection_info = await db_manager.resolve_database_connection(
                spec.database, namespace
            )

            self.logger.info(
                f"Resolved database connection: {connection_info['type']} "
                f"at {connection_info['host']}:{connection_info['port']}/{connection_info['database']}"
            )

            # Test actual database connectivity
            connection_test_passed = await db_manager.test_database_connection(
                connection_info, resource_name=name, namespace=namespace
            )

            if not connection_test_passed:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Database connectivity test failed for {spec.database.type}",
                    retryable=True,
                    user_action="Check database availability, credentials, and network connectivity",
                )

            self.logger.info(
                f"Database connectivity test passed for {spec.database.type}"
            )

        except (ExternalServiceError, TemporaryError):
            # Re-raise operator errors as-is
            raise
        except Exception as e:
            # Wrap unexpected errors
            raise ExternalServiceError(
                service="Database",
                message=f"Database connectivity validation failed: {str(e)}",
                retryable=True,
                user_action="Check database configuration and Kubernetes connectivity",
            ) from e

    async def _validate_database_secret(
        self, spec: KeycloakSpec, namespace: str
    ) -> None:
        """
        Validate that database credentials secret exists.

        Args:
            spec: Keycloak specification
            namespace: Resource namespace

        Raises:
            ExternalServiceError: If database secret is missing or invalid
        """
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        db_config = spec.database
        secret_name = getattr(db_config, "credentials_secret", None)

        if not secret_name:
            raise ExternalServiceError(
                service="Database",
                message="Database credentials secret not specified",
                retryable=False,
                user_action="Configure database.credentialsSecret in the Keycloak specification",
            )

        core_api = client.CoreV1Api(self.kubernetes_client)

        try:
            secret = core_api.read_namespaced_secret(
                name=secret_name, namespace=namespace
            )

            # Validate required keys are present
            required_keys = ["username", "password"]
            missing_keys = []

            if not secret.data:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Database credentials secret '{secret_name}' has no data",
                    retryable=False,
                    user_action=f"Ensure secret '{secret_name}' contains username and password",
                )

            for key in required_keys:
                if key not in secret.data:
                    missing_keys.append(key)

            if missing_keys:
                raise ExternalServiceError(
                    service="Database",
                    message=f"Database credentials secret missing keys: {', '.join(missing_keys)}",
                    retryable=False,
                    user_action=f"Add missing keys to secret '{secret_name}'",
                )

            self.logger.info(
                f"Database credentials secret '{secret_name}' validation passed"
            )

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
                    message=f"Failed to read database credentials secret: {e}",
                    retryable=True,
                    user_action="Check Kubernetes API connectivity and permissions",
                ) from e

    async def _validate_security_requirements(
        self, spec: KeycloakSpec, namespace: str
    ) -> None:
        """
        Validate security requirements for production deployments.

        Args:
            spec: Keycloak specification
            namespace: Resource namespace

        Raises:
            ValidationError: If security requirements are not met
        """

        # Check for security hardening in production-like environments
        production_indicators = [
            spec.replicas > 1,
            spec.ingress.enabled,
            any(env_name in namespace.lower() for env_name in ["prod", "production"]),
        ]

        if any(production_indicators):
            security_warnings = []

            # Recommend TLS for production
            if not spec.tls.enabled:
                security_warnings.append("TLS is not enabled")

            # Check for resource limits (good practice in production)
            if not hasattr(spec, "resources") or not getattr(spec, "resources", None):
                security_warnings.append("Resource limits not configured")

            # Log security recommendations without failing
            if security_warnings:
                self.logger.warning(
                    f"Security recommendations for production: {'; '.join(security_warnings)}"
                )

    async def ensure_deployment(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure Keycloak deployment exists and is up to date.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring deployment for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import create_keycloak_deployment

        deployment_name = f"{name}-keycloak"
        apps_api = client.AppsV1Api(self.kubernetes_client)

        try:
            apps_api.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            self.logger.info(f"Keycloak deployment {deployment_name} already exists")
        except ApiException as e:
            if e.status == 404:
                deployment = create_keycloak_deployment(
                    name=name,
                    namespace=namespace,
                    spec=spec,
                    k8s_client=self.kubernetes_client,
                )
                self.logger.info(
                    f"Created Keycloak deployment: {deployment.metadata.name}"
                )
            else:
                raise

    async def ensure_service(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure Keycloak service exists and is properly configured.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring service for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import create_keycloak_service

        service_name = f"{name}-keycloak"
        core_api = client.CoreV1Api(self.kubernetes_client)

        try:
            core_api.read_namespaced_service(name=service_name, namespace=namespace)
            self.logger.info(f"Keycloak service {service_name} already exists")
        except ApiException as e:
            if e.status == 404:
                service = create_keycloak_service(
                    name=name,
                    namespace=namespace,
                    spec=spec,
                    k8s_client=self.kubernetes_client,
                )
                self.logger.info(f"Created Keycloak service: {service.metadata.name}")
            else:
                raise

    async def ensure_persistence(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure persistent storage is configured for Keycloak data.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring persistence for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import create_persistent_volume_claim

        pvc_name = f"{name}-keycloak-data"
        core_api = client.CoreV1Api(self.kubernetes_client)

        try:
            core_api.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=namespace
            )
            self.logger.info(f"PVC {pvc_name} already exists")
        except ApiException as e:
            if e.status == 404:
                pvc = create_persistent_volume_claim(
                    name=name,
                    namespace=namespace,
                    size=getattr(spec.persistence, "size", "10Gi"),
                    storage_class=getattr(spec.persistence, "storage_class", None),
                )
                self.logger.info(f"Created PVC: {pvc.metadata.name}")
            else:
                raise

    async def ensure_ingress(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure ingress is configured for external access.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring ingress for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import create_keycloak_ingress

        ingress_name = f"{name}-keycloak"
        networking_api = client.NetworkingV1Api(self.kubernetes_client)

        try:
            networking_api.read_namespaced_ingress(
                name=ingress_name, namespace=namespace
            )
            self.logger.info(f"Ingress {ingress_name} already exists")
        except ApiException as e:
            if e.status == 404:
                ingress = create_keycloak_ingress(
                    name=name,
                    namespace=namespace,
                    spec=spec,
                    k8s_client=self.kubernetes_client,
                )
                self.logger.info(f"Created ingress: {ingress.metadata.name}")
            else:
                raise

    async def ensure_admin_access(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure admin user is configured and accessible.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring admin access for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import create_admin_secret

        admin_secret_name = f"{name}-admin-credentials"
        core_api = client.CoreV1Api(self.kubernetes_client)

        try:
            core_api.read_namespaced_secret(name=admin_secret_name, namespace=namespace)
            self.logger.info(f"Admin secret {admin_secret_name} already exists")
        except ApiException as e:
            if e.status == 404:
                admin_secret = create_admin_secret(
                    name=name,
                    namespace=namespace,
                    username=(
                        getattr(spec, "admin_access", {}).get("username", "admin")
                        if hasattr(spec, "admin_access")
                        else "admin"
                    ),
                )
                self.logger.info(f"Created admin secret: {admin_secret.metadata.name}")
            else:
                raise

    async def wait_for_deployment_ready(
        self, name: str, namespace: str, max_wait_time: int = 300
    ) -> bool:
        """
        Wait for deployment to be ready.

        Args:
            name: Resource name
            namespace: Resource namespace
            max_wait_time: Maximum wait time in seconds

        Returns:
            True if deployment became ready, False if timed out
        """
        import asyncio

        from kubernetes import client
        from kubernetes.client.rest import ApiException

        deployment_name = f"{name}-keycloak"
        apps_api = client.AppsV1Api(self.kubernetes_client)
        wait_interval = 10
        elapsed_time = 0

        self.logger.info(f"Waiting for deployment {deployment_name} to be ready...")

        while elapsed_time < max_wait_time:
            try:
                deployment_status = apps_api.read_namespaced_deployment_status(
                    name=deployment_name, namespace=namespace
                )

                ready_replicas = deployment_status.status.ready_replicas or 0
                desired_replicas = deployment_status.spec.replicas or 1

                if ready_replicas >= desired_replicas:
                    self.logger.info(
                        f"Deployment {deployment_name} is ready ({ready_replicas}/{desired_replicas})"
                    )
                    return True

                self.logger.debug(
                    f"Waiting for deployment readiness: {ready_replicas}/{desired_replicas} replicas ready"
                )

            except ApiException as e:
                self.logger.warning(f"Error checking deployment status: {e}")

            await asyncio.sleep(wait_interval)
            elapsed_time += wait_interval

        self.logger.warning(
            f"Deployment {deployment_name} did not become ready within {max_wait_time} seconds"
        )
        return False
