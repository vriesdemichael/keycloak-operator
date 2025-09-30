"""
Keycloak instance reconciler for managing core Keycloak deployments.

This module handles the lifecycle of Keycloak instances including
deployment, services, persistence, and administrative access.
"""

from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

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

    async def do_update(
        self,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        diff: Any,
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs,
    ) -> dict[str, Any] | None:
        """
        Handle updates to Keycloak instance specifications.

        Args:
            old_spec: Previous specification
            new_spec: New specification
            diff: List of changes between old and new
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource
            **kwargs: Additional handler arguments

        Returns:
            Dictionary with updated status information, or None if no changes needed
        """
        from ..models.keycloak import KeycloakSpec

        # Parse and validate the new specification
        new_keycloak_spec = KeycloakSpec.model_validate(new_spec)

        # Get Kubernetes API clients
        apps_api = client.AppsV1Api(self.kubernetes_client)
        networking_api = client.NetworkingV1Api(self.kubernetes_client)
        deployment_name = f"{name}-keycloak"

        # Track if any changes require deployment update
        deployment_needs_update = False
        deployment_changes = {}

        # Log the changes for debugging
        for operation, field_path, old_value, new_value in diff:
            self.logger.info(
                f"Change detected - {operation}: {field_path} "
                f"from {old_value} to {new_value}"
            )

        # Handle different types of updates based on the diff
        for _operation, field_path, old_value, new_value in diff:
            if field_path == ("spec", "replicas"):
                self.logger.info(
                    f"Scaling Keycloak from {old_value} to {new_value} replicas"
                )
                deployment_changes["replicas"] = new_value
                deployment_needs_update = True

            elif field_path == ("spec", "image"):
                self.logger.info(
                    f"Updating Keycloak image from {old_value} to {new_value}"
                )
                deployment_changes["image"] = new_value
                deployment_needs_update = True

            elif field_path == ("spec", "resources"):
                self.logger.info("Updating Keycloak resource requirements")
                deployment_changes["resources"] = new_value
                deployment_needs_update = True

            elif field_path[0:2] == ("spec", "ingress"):
                await self._update_ingress(
                    new_keycloak_spec, name, namespace, networking_api
                )

        # Apply deployment updates if needed
        if deployment_needs_update:
            await self._update_deployment(
                deployment_name, namespace, deployment_changes, apps_api
            )

        # Always reconcile to ensure everything is in sync
        return await self.do_reconcile(new_spec, name, namespace, status, **kwargs)

    async def _update_ingress(
        self,
        spec: KeycloakSpec,
        name: str,
        namespace: str,
        networking_api: client.NetworkingV1Api,
    ) -> None:
        """Update ingress configuration."""
        from ..utils.kubernetes import create_keycloak_ingress

        ingress_name = f"{name}-keycloak"

        try:
            if spec.ingress.enabled:
                # Try to read existing ingress
                try:
                    existing_ingress = networking_api.read_namespaced_ingress(
                        name=ingress_name, namespace=namespace
                    )
                    # Update existing ingress
                    ingress = create_keycloak_ingress(
                        name=name,
                        namespace=namespace,
                        spec=spec,
                        k8s_client=self.kubernetes_client,
                    )
                    ingress.metadata.resource_version = (
                        existing_ingress.metadata.resource_version
                    )
                    networking_api.patch_namespaced_ingress(
                        name=ingress_name, namespace=namespace, body=ingress
                    )
                    self.logger.info(f"Updated ingress {ingress_name}")
                except ApiException as e:
                    if e.status == 404:
                        # Create new ingress
                        create_keycloak_ingress(
                            name=name,
                            namespace=namespace,
                            spec=spec,
                            k8s_client=self.kubernetes_client,
                        )
                        self.logger.info(f"Created ingress {ingress_name}")
                    else:
                        raise
            else:
                # Ingress disabled, delete if exists
                try:
                    networking_api.delete_namespaced_ingress(
                        name=ingress_name, namespace=namespace
                    )
                    self.logger.info(
                        f"Deleted ingress {ingress_name} (disabled in spec)"
                    )
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete ingress {ingress_name}: {e}"
                        )

        except Exception as e:
            self.logger.error(f"Failed to update ingress: {e}")
            raise TemporaryError(
                f"Failed to update ingress configuration: {str(e)}"
            ) from e

    async def _update_deployment(
        self,
        deployment_name: str,
        namespace: str,
        deployment_changes: dict,
        apps_api: client.AppsV1Api,
    ) -> None:
        """Update deployment with changes."""
        try:
            deployment = apps_api.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )

            # Update deployment spec based on changes
            if "replicas" in deployment_changes:
                deployment.spec.replicas = deployment_changes["replicas"]

            if "image" in deployment_changes:
                deployment.spec.template.spec.containers[0].image = deployment_changes[
                    "image"
                ]

            if "resources" in deployment_changes:
                resources = deployment_changes["resources"]
                deployment.spec.template.spec.containers[
                    0
                ].resources = client.V1ResourceRequirements(
                    requests=resources.get("requests", {}),
                    limits=resources.get("limits", {}),
                )

            # Apply the update
            apps_api.patch_namespaced_deployment(
                name=deployment_name, namespace=namespace, body=deployment
            )

            self.logger.info(f"Updated deployment {deployment_name}")

            # Wait for rollout to complete for critical changes
            if "image" in deployment_changes or "resources" in deployment_changes:
                await self._wait_for_rollout(deployment_name, namespace, apps_api)

        except ApiException as e:
            self.logger.error(f"Failed to update deployment: {e}")
            raise TemporaryError(f"Failed to update deployment: {str(e)}") from e

    async def _wait_for_rollout(
        self, deployment_name: str, namespace: str, apps_api: client.AppsV1Api
    ) -> None:
        """Wait for deployment rollout to complete."""
        import asyncio

        self.logger.info("Waiting for rolling update to complete...")

        max_wait = 300  # 5 minutes
        wait_interval = 10
        elapsed = 0

        while elapsed < max_wait:
            deployment_status = apps_api.read_namespaced_deployment_status(
                name=deployment_name, namespace=namespace
            )

            ready_replicas = deployment_status.status.ready_replicas or 0
            updated_replicas = deployment_status.status.updated_replicas or 0
            desired_replicas = deployment_status.spec.replicas or 1

            if (
                ready_replicas >= desired_replicas
                and updated_replicas >= desired_replicas
            ):
                self.logger.info("Rolling update completed successfully")
                break

            self.logger.debug(
                f"Rolling update progress: {updated_replicas}/{desired_replicas} updated, {ready_replicas} ready"
            )

            await asyncio.sleep(wait_interval)
            elapsed += wait_interval
        else:
            raise TemporaryError(
                f"Deployment rollout did not complete within {max_wait} seconds"
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
        # Backward compatibility / migration mapping:
        # Older manifests (or tests) may still use 'admin_access' block instead of 'admin'.
        # Provide a non-destructive alias if 'admin' not explicitly set.
        if "admin_access" in spec and "admin" not in spec:
            # Shallow copy to avoid mutating original reference captured by kopf
            spec = {**spec, "admin": spec["admin_access"]}

        # Backward compatibility: legacy service.port -> service.http_port
        try:
            svc = spec.get("service") if isinstance(spec, dict) else None
            if isinstance(svc, dict) and "port" in svc and "http_port" not in svc:
                # Copy to new key without removing old one (non-destructive)
                migrated = {**svc, "http_port": svc["port"]}
                # Rebuild spec dict shallowly
                spec = {**spec, "service": migrated}
        except Exception:  # pragma: no cover - defensive
            pass

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

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        if not deployment_ready:
            self.update_status_degraded(
                status, "Deployment created but not ready within timeout", generation
            )
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

        # Update status to ready and return status information
        self.update_status_ready(status, "Keycloak instance is running", generation)
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

    async def cleanup_resources(
        self, name: str, namespace: str, spec: dict[str, Any]
    ) -> None:
        """
        Clean up all resources associated with a Keycloak instance.

        This method performs comprehensive cleanup in the proper order to prevent
        data loss and ensure all associated resources are properly removed.

        Args:
            name: Name of the Keycloak instance
            namespace: Namespace containing the resources
            spec: Keycloak specification for understanding deletion requirements

        Raises:
            TemporaryError: If cleanup fails but should be retried
        """
        from ..constants import (
            BACKUP_ANNOTATION,
            DEPLOYMENT_SUFFIX,
            INGRESS_SUFFIX,
            PRESERVE_DATA_ANNOTATION,
            SERVICE_SUFFIX,
        )

        self.logger.info(f"Starting cleanup of Keycloak instance {name} in {namespace}")

        try:
            keycloak_spec = KeycloakSpec.model_validate(spec)
        except Exception as e:
            raise TemporaryError(f"Failed to parse Keycloak spec: {e}") from e

        # Get Kubernetes API clients
        apps_api = client.AppsV1Api(self.kubernetes_client)
        core_api = client.CoreV1Api(self.kubernetes_client)
        networking_api = client.NetworkingV1Api(self.kubernetes_client)

        # Check for data preservation requirements
        preserve_data = (
            spec.get("metadata", {})
            .get("annotations", {})
            .get(PRESERVE_DATA_ANNOTATION, "false")
            .lower()
            == "true"
        )

        backup_requested = (
            spec.get("metadata", {})
            .get("annotations", {})
            .get(BACKUP_ANNOTATION, "false")
            .lower()
            == "true"
        )

        # Create backup if requested
        if backup_requested and not preserve_data:
            try:
                await self._create_backup(name, namespace, keycloak_spec)
            except Exception as e:
                self.logger.warning(f"Backup creation failed: {e}")
                # Continue with deletion even if backup fails

        # Delete resources in reverse order of creation to ensure clean shutdown

        # 1. Delete ingress first to stop external traffic
        ingress_name = f"{name}{INGRESS_SUFFIX}"
        try:
            await self._delete_ingress(ingress_name, namespace, networking_api)
        except Exception as e:
            self.logger.warning(f"Failed to delete ingress: {e}")

        # 2. Delete service to stop internal traffic
        service_name = f"{name}{SERVICE_SUFFIX}"
        try:
            await self._delete_service(service_name, namespace, core_api)
        except Exception as e:
            self.logger.warning(f"Failed to delete service: {e}")

        # 3. Delete deployment to stop pods
        deployment_name = f"{name}{DEPLOYMENT_SUFFIX}"
        try:
            await self._delete_deployment(deployment_name, namespace, apps_api)
        except Exception as e:
            self.logger.warning(f"Failed to delete deployment: {e}")

        # 4. Delete secrets and configmaps (unless preservation is requested)
        if not preserve_data:
            try:
                await self._delete_configuration_resources(name, namespace, core_api)
            except Exception as e:
                self.logger.warning(f"Failed to delete configuration resources: {e}")

        # 5. Handle persistent volume claims based on retention policy
        retention_policy = spec.get("persistence", {}).get("retainPolicy", "Delete")
        if retention_policy == "Delete" and not preserve_data:
            try:
                await self._delete_persistent_storage(name, namespace, core_api)
            except Exception as e:
                self.logger.warning(f"Failed to delete persistent storage: {e}")

        self.logger.info(f"Successfully completed cleanup of Keycloak instance {name}")

    async def _create_backup(
        self, name: str, namespace: str, keycloak_spec: KeycloakSpec
    ) -> None:
        """Create a backup of Keycloak data before deletion."""
        from datetime import UTC, datetime

        backup_name = f"{name}-backup-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"

        self.logger.info(f"Creating full Keycloak instance backup: {backup_name}")

        try:
            # Get admin client for this Keycloak instance
            admin_client = self.keycloak_admin_factory(name, namespace)

            # Get list of all realms
            realms = admin_client.get_realms()
            if not realms:
                self.logger.warning("No realms found for backup")
                return

            # Create backup data structure
            backup_data = {
                "keycloak_instance": {
                    "name": name,
                    "namespace": namespace,
                    "spec": keycloak_spec.model_dump()
                    if hasattr(keycloak_spec, "model_dump")
                    else str(keycloak_spec),
                },
                "realms": {},
                "backup_timestamp": datetime.now(UTC).isoformat(),
                "backup_version": "1.0",
                "backup_type": "full_instance",
            }

            # Backup each realm
            for realm_info in realms:
                realm_name = realm_info.get("realm")
                if not realm_name:
                    continue

                self.logger.info(f"Backing up realm: {realm_name}")
                realm_backup = admin_client.backup_realm(realm_name)
                if realm_backup:
                    backup_data["realms"][realm_name] = realm_backup
                else:
                    self.logger.warning(f"Failed to backup realm {realm_name}")

            # Store backup in Kubernetes secret for persistence
            await self._store_keycloak_backup_in_secret(
                backup_data, backup_name, namespace
            )

            self.logger.info(
                f"Successfully created Keycloak instance backup: {backup_name}"
            )

        except Exception as e:
            # Don't block deletion if backup fails, but log the error
            self.logger.error(
                f"Failed to create backup for Keycloak instance {name}: {e}"
            )

    async def _store_keycloak_backup_in_secret(
        self, backup_data: dict[str, Any], backup_name: str, namespace: str
    ) -> None:
        """
        Store full Keycloak instance backup data in a Kubernetes secret.

        Args:
            backup_data: Complete Keycloak instance backup data
            backup_name: Name for the backup
            namespace: Namespace to store the secret
        """
        import json

        from kubernetes import client

        try:
            k8s_client = client.CoreV1Api()

            # Create secret with backup data
            secret_data = {"backup.json": json.dumps(backup_data, indent=2)}

            secret = client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=backup_name,
                    namespace=namespace,
                    labels={
                        "keycloak.mdvr.nl/backup": "true",
                        "keycloak.mdvr.nl/backup-type": "full_instance",
                        "keycloak.mdvr.nl/keycloak-instance": backup_data[
                            "keycloak_instance"
                        ]["name"],
                    },
                ),
                string_data=secret_data,
                type="Opaque",
            )

            k8s_client.create_namespaced_secret(namespace=namespace, body=secret)
            self.logger.info(
                f"Keycloak backup {backup_name} stored as secret in namespace {namespace}"
            )

        except Exception as e:
            self.logger.error(
                f"Failed to store Keycloak backup {backup_name} in secret: {e}"
            )
            raise

    async def _delete_ingress(
        self, ingress_name: str, namespace: str, networking_api
    ) -> None:
        """Delete ingress resource."""
        try:
            networking_api.delete_namespaced_ingress(
                name=ingress_name, namespace=namespace
            )
            self.logger.info(f"Deleted ingress {ingress_name}")
        except ApiException as e:
            if e.status != 404:
                raise TemporaryError(
                    f"Failed to delete ingress {ingress_name}: {e}"
                ) from e

    async def _delete_service(
        self, service_name: str, namespace: str, core_api
    ) -> None:
        """Delete service resource."""
        try:
            core_api.delete_namespaced_service(name=service_name, namespace=namespace)
            self.logger.info(f"Deleted service {service_name}")
        except ApiException as e:
            if e.status != 404:
                raise TemporaryError(
                    f"Failed to delete service {service_name}: {e}"
                ) from e

    async def _delete_deployment(
        self, deployment_name: str, namespace: str, apps_api
    ) -> None:
        """Delete deployment and wait for pods to terminate."""
        try:
            apps_api.delete_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            self.logger.info(f"Deleted deployment {deployment_name}")

            # Wait for deployment to be fully deleted
            import asyncio

            max_wait = 60  # 1 minute
            wait_interval = 5
            elapsed = 0

            while elapsed < max_wait:
                try:
                    apps_api.read_namespaced_deployment(
                        name=deployment_name, namespace=namespace
                    )
                    await asyncio.sleep(wait_interval)
                    elapsed += wait_interval
                except ApiException as e:
                    if e.status == 404:
                        self.logger.info(f"Deployment {deployment_name} fully deleted")
                        break
                    else:
                        raise

        except ApiException as e:
            if e.status != 404:
                raise TemporaryError(
                    f"Failed to delete deployment {deployment_name}: {e}"
                ) from e

    async def _delete_configuration_resources(
        self, name: str, namespace: str, core_api
    ) -> None:
        """Delete secrets and configmaps associated with the Keycloak instance."""
        from ..constants import INSTANCE_LABEL_KEY

        label_selector = f"{INSTANCE_LABEL_KEY}={name}"

        # Delete secrets
        try:
            secrets = core_api.list_namespaced_secret(
                namespace=namespace, label_selector=label_selector
            )
            for secret in secrets.items:
                try:
                    core_api.delete_namespaced_secret(
                        name=secret.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted secret {secret.metadata.name}")
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete secret {secret.metadata.name}: {e}"
                        )

        except ApiException as e:
            self.logger.warning(f"Failed to list secrets for cleanup: {e}")

        # Delete configmaps
        try:
            configmaps = core_api.list_namespaced_config_map(
                namespace=namespace, label_selector=label_selector
            )
            for cm in configmaps.items:
                try:
                    core_api.delete_namespaced_config_map(
                        name=cm.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted configmap {cm.metadata.name}")
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete configmap {cm.metadata.name}: {e}"
                        )

        except ApiException as e:
            self.logger.warning(f"Failed to list configmaps for cleanup: {e}")

    async def _delete_persistent_storage(
        self, name: str, namespace: str, core_api
    ) -> None:
        """Delete persistent volume claims associated with the Keycloak instance."""
        from ..constants import INSTANCE_LABEL_KEY

        label_selector = f"{INSTANCE_LABEL_KEY}={name}"

        try:
            pvcs = core_api.list_namespaced_persistent_volume_claim(
                namespace=namespace, label_selector=label_selector
            )
            for pvc in pvcs.items:
                try:
                    core_api.delete_namespaced_persistent_volume_claim(
                        name=pvc.metadata.name, namespace=namespace
                    )
                    self.logger.info(f"Deleted PVC {pvc.metadata.name}")
                except ApiException as e:
                    if e.status != 404:
                        self.logger.warning(
                            f"Failed to delete PVC {pvc.metadata.name}: {e}"
                        )

        except ApiException as e:
            self.logger.warning(f"Failed to list PVCs for cleanup: {e}")
