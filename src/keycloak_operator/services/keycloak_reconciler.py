"""
Keycloak instance reconciler for managing core Keycloak deployments.

This module handles the lifecycle of Keycloak instances including
deployment, services, persistence, and administrative access.
"""

from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..constants import (
    DEFAULT_KEYCLOAK_IMAGE,
    MAINTENANCE_MODE_ANNOTATION,
    MAINTENANCE_MODE_SNIPPET_ANNOTATION,
)
from ..errors import (
    ConfigurationError,
    DatabaseValidationError,
    ExternalServiceError,
    TemporaryError,
    ValidationError,
)
from ..models.keycloak import KeycloakSpec
from ..settings import settings
from ..utils.keycloak_admin import get_keycloak_admin_client
from ..utils.validation import supports_management_port, validate_keycloak_version
from ..utils.version import (
    VersionChange,
    detect_version_change,
    get_deployment_image_from_k8s,
)
from .backup_service import PreUpgradeBackupService
from .base_reconciler import BaseReconciler, StatusProtocol
from .blue_green_service import BlueGreenUpgradeService


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
        self,
        k8s_client: client.ApiClient | None = None,
        keycloak_admin_factory: Any = None,
        rate_limiter: Any = None,
        operator_namespace: str | None = None,
    ):
        """
        Initialize Keycloak instance reconciler.

        Args:
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients
            rate_limiter: Rate limiter for Keycloak API calls
            operator_namespace: Optional operator namespace override (ADR-062)
        """
        super().__init__(k8s_client, operator_namespace=operator_namespace)
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )
        self.rate_limiter = rate_limiter
        self.backup_service = PreUpgradeBackupService(k8s_client)
        self.blue_green_service = BlueGreenUpgradeService(k8s_client)

    async def do_update(
        self,
        old_spec: dict[str, Any],
        new_spec: dict[str, Any],
        diff: Any,
        name: str,
        namespace: str,
        status: StatusProtocol,
        **kwargs: Any,
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
                deployment_changes["_running_image"] = old_value or ""
                deployment_needs_update = True

            elif field_path == ("spec", "resources"):
                self.logger.info("Updating Keycloak resource requirements")
                deployment_changes["resources"] = new_value
                deployment_needs_update = True

            elif field_path[0:2] == ("spec", "ingress"):
                await self._update_ingress(
                    new_keycloak_spec, name, namespace, networking_api
                )

        # Pre-upgrade backup check (ADR-088 Phase 2)
        # MUST run BEFORE _update_deployment() so the running image is still
        # the old one. The check inside do_reconcile is kept as safety net
        # for create/resume paths.
        if "image" in deployment_changes:
            await self._maybe_perform_pre_upgrade_backup(
                new_keycloak_spec, name, namespace, kwargs
            )

        # Blue-green upgrade orchestration (ADR-088 Phase 3 / ADR-092)
        # When strategy == "BlueGreen" and an image change is detected,
        # delegate to the blue-green service instead of the normal in-place
        # deployment update.
        if (
            "image" in deployment_changes
            and new_keycloak_spec.upgrade_policy is not None
            and new_keycloak_spec.upgrade_policy.strategy == "BlueGreen"
        ):
            running_image = deployment_changes.get("_running_image", "")
            desired_image = deployment_changes["image"]
            await self.blue_green_service.run_upgrade(
                name=name,
                namespace=namespace,
                spec=new_keycloak_spec,
                running_image=running_image,
                desired_image=desired_image,
                status=status,
            )
            # Blue-green handles its own deployment lifecycle; skip normal update
            deployment_needs_update = False

        # Apply deployment updates if needed (non-blue-green changes)
        if deployment_needs_update:
            await self._update_deployment(
                deployment_name, namespace, deployment_changes, apps_api
            )

        # Always reconcile to ensure everything is in sync
        # Remove 'spec' from kwargs to avoid duplicate argument error
        reconcile_kwargs = {k: v for k, v in kwargs.items() if k != "spec"}
        return await self.do_reconcile(
            new_spec, name, namespace, status, **reconcile_kwargs
        )

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
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Reconcile Keycloak instance."""
        # 1. Check if running in External Mode (ADR-062)
        if not settings.keycloak_managed:
            self.logger.warning(
                f"Operator is running in External Mode (managed=false). Ignoring Keycloak CR {name}."
            )

            raise ConfigurationError(
                "Operator is configured for External Keycloak (External Mode). "
                "Managing Keycloak CRs is not allowed in this mode."
            )

        # 2. Backward compatibility / migration mapping:

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

        # Validate cross-namespace permissions if targeting another namespace
        await self.validate_cross_namespace_access(keycloak_spec, name, namespace)

        # Validate Keycloak version supports management port (required for health checks)
        image = keycloak_spec.image or DEFAULT_KEYCLOAK_IMAGE
        validate_keycloak_version(image)

        # Perform production environment validation and get resolved database connection info
        db_connection_info = await self.validate_production_settings(
            keycloak_spec, name, namespace
        )

        # Pre-upgrade backup hook (ADR-088 Phase 2)
        # Only active when upgradePolicy is explicitly configured — this is
        # the opt-in switch for upgrade orchestration (backup + semver
        # enforcement in the webhook).
        if keycloak_spec.upgrade_policy is not None:
            await self._maybe_perform_pre_upgrade_backup(
                keycloak_spec, name, namespace, kwargs
            )

        # Blue-green resume (ADR-092)
        # If a blue-green upgrade was in progress when the operator
        # restarted, resume it before doing normal reconciliation.
        raw_bg = status.get("blueGreen") if hasattr(status, "get") else None  # type: ignore[union-attr]
        if isinstance(raw_bg, dict):
            from ..services.blue_green_service import STATE_COMPLETED, STATE_FAILED

            bg_state = raw_bg.get("state", "")
            if bg_state not in (STATE_COMPLETED, STATE_FAILED, "Idle", ""):
                self.logger.info(
                    f"Resuming blue-green upgrade for {name} from state={bg_state}"
                )
                await self.blue_green_service.run_upgrade(
                    name=name,
                    namespace=namespace,
                    spec=keycloak_spec,
                    running_image=raw_bg.get("blueRevision", ""),
                    desired_image=raw_bg.get("greenRevision", ""),
                    status=status,
                    db_connection_info=db_connection_info,
                )
                # After blue-green completes the canonical deployment is the
                # promoted green one — fall through to normal readiness check.

        # Ensure admin access first (required by deployment)
        await self.ensure_admin_access(keycloak_spec, name, namespace)

        # Ensure core Kubernetes resources exist
        await self.ensure_deployment(keycloak_spec, name, namespace, db_connection_info)
        await self.ensure_service(keycloak_spec, name, namespace)
        await self.ensure_discovery_service(name, namespace, keycloak_spec)

        # Setup ingress if configured
        if keycloak_spec.ingress.enabled:
            await self.ensure_ingress(keycloak_spec, name, namespace)

        # Wait for deployment to be ready
        deployment_ready, error_message = await self.wait_for_deployment_ready(
            name, namespace
        )

        # Extract generation for status tracking
        generation = kwargs.get("meta", {}).get("generation", 0)

        if not deployment_ready:
            if error_message:
                # Fatal configuration/build error detected
                raise ConfigurationError(
                    error_message,
                    user_action="Update image to match configuration or disable 'optimized' mode.",
                )
            else:
                # Timeout waiting for readiness - retry later
                raise TemporaryError(
                    "Deployment created but not ready within timeout", delay=30
                )

        # Update status to ready and set additional status information
        self.update_status_ready(status, "Keycloak instance is ready", generation)

        # Set additional status fields via StatusWrapper to avoid conflicts with Kopf
        status.deployment = f"{name}-keycloak"
        status.service = f"{name}-keycloak"
        status.adminSecret = f"{name}-admin-credentials"
        endpoints = {
            "admin": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
            "public": f"http://{name}-keycloak.{namespace}.svc.cluster.local:8080",
        }
        # Management endpoint only for Keycloak 25.x+
        version_override = keycloak_spec.keycloak_version
        if supports_management_port(image, version_override):
            endpoints["management"] = (
                f"http://{name}-keycloak.{namespace}.svc.cluster.local:9000"
            )
        status.endpoints = endpoints

        # Update capacity status
        await self._update_capacity_status(status, keycloak_spec, namespace)

        # Return empty dict - status updates are done via StatusWrapper
        return {}

    async def validate_cross_namespace_access(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Validate RBAC permissions for cross-namespace operations.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Current namespace

        Raises:
            RBACError: If insufficient permissions for cross-namespace access
        """
        # Define required operations for full Keycloak management
        required_operations = [
            {"resource": "deployments", "verb": "get"},
            {"resource": "deployments", "verb": "create"},
            {"resource": "deployments", "verb": "patch"},
            {"resource": "services", "verb": "get"},
            {"resource": "services", "verb": "create"},
            {"resource": "secrets", "verb": "get"},
            {"resource": "secrets", "verb": "create"},
            {"resource": "configmaps", "verb": "get"},
            {"resource": "configmaps", "verb": "create"},
            {"resource": "persistentvolumeclaims", "verb": "get"},
            {"resource": "persistentvolumeclaims", "verb": "create"},
        ]

        # Use source_namespace=self.operator_namespace because that's where the SA lives
        # target_namespace=namespace because that's where the Keycloak CR is
        await self.validate_rbac_permissions(
            source_namespace=self.operator_namespace,
            target_namespace=namespace,
            operations=required_operations,
            resource_name=name,
        )

        # Validate namespace isolation policies (ADR-073)
        await self.validate_namespace_isolation(
            source_namespace=self.operator_namespace,
            target_namespace=namespace,
            resource_type="keycloak",
            resource_name=name,
        )

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
    ) -> dict[str, Any] | None:
        """
        Validate configuration for production readiness.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace

        Returns:
            Dictionary with resolved database connection details, or None if database not configured

        Raises:
            DatabaseValidationError: If using H2 database inappropriately
            ValidationError: If other production requirements not met
        """
        # Validate database production readiness (no H2 allowed)
        await self._validate_database_production_readiness(spec, namespace)

        # Validate database connectivity for all external databases
        connection_info = await self._validate_database_connectivity(
            spec, name, namespace
        )

        # Additional production validation checks
        await self._validate_security_requirements(spec, namespace)

        self.logger.info(f"Production validation passed for {name}")

        return connection_info

    async def _update_capacity_status(
        self, status: StatusProtocol, spec: KeycloakSpec, namespace: str
    ) -> None:
        """
        Update realm capacity status fields.

        Args:
            status: Status object to update
            spec: Keycloak specification
            namespace: Keycloak namespace
        """
        # Count realms that reference this Keycloak operator
        try:
            custom_objects_api = client.CustomObjectsApi()
            realm_list = custom_objects_api.list_cluster_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakrealms",
            )

            # Count realms that reference this Keycloak instance (by namespace)
            realm_count = sum(
                1
                for item in realm_list.get("items", [])
                if item.get("spec", {}).get("operatorRef", {}).get("namespace")
                == namespace
            )

            status.realmCount = realm_count

            # Determine if accepting new realms
            realm_capacity = spec.realm_capacity
            if realm_capacity:
                # Check allowNewRealms flag
                accepting = realm_capacity.allow_new_realms

                # Check max realms limit
                if realm_capacity.max_realms is not None:
                    at_capacity = realm_count >= realm_capacity.max_realms
                    if at_capacity:
                        accepting = False

                status.acceptingNewRealms = accepting

                # Set capacity status message
                if not accepting:
                    if realm_capacity.max_realms is not None:
                        status.capacityStatus = f"Capacity reached: {realm_count}/{realm_capacity.max_realms} realms"
                    else:
                        status.capacityStatus = "Not accepting new realms"
                else:
                    if realm_capacity.max_realms is not None:
                        status.capacityStatus = f"Available: {realm_count}/{realm_capacity.max_realms} realms"
                    else:
                        status.capacityStatus = (
                            f"Available: {realm_count} realms (no limit)"
                        )
            else:
                # No capacity config - unlimited
                status.acceptingNewRealms = True
                status.capacityStatus = f"{realm_count} realms (unlimited)"

        except Exception as e:
            self.logger.warning(f"Failed to update capacity status: {e}")
            # Don't fail reconciliation if capacity status update fails
            status.realmCount = None
            status.acceptingNewRealms = True
            status.capacityStatus = "Unknown"

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

        # Validate SSL configuration for production
        ssl_mode = spec.database.effective_ssl_mode
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
    ) -> dict[str, Any]:
        """
        Validate database connectivity using the new database connection manager.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace

        Returns:
            Dictionary with resolved database connection details

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

            # Record CNPG cluster status for PostgreSQL databases.
            # The spec model only allows "postgresql" as the type value —
            # CNPG is the deployment mechanism (CloudNativePG operator),
            # not a separate database type. Per ADR 015, CNPG is the
            # first-class database backend for this operator.
            if spec.database.type == "postgresql":
                self._record_cnpg_status(namespace, connection_test_passed)

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

            # Return resolved connection info for use in deployment creation
            return connection_info

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

    @staticmethod
    def _record_cnpg_status(namespace: str, healthy: bool) -> None:
        """Record CNPG cluster status to Prometheus metrics."""
        try:
            from keycloak_operator.observability.metrics import CNPG_CLUSTER_STATUS

            CNPG_CLUSTER_STATUS.labels(namespace=namespace).set(1 if healthy else 0)
        except Exception:
            pass  # Metrics are optional

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

    async def _maybe_perform_pre_upgrade_backup(
        self,
        spec: KeycloakSpec,
        name: str,
        namespace: str,
        kwargs: dict[str, Any],
    ) -> None:
        """
        Check for Keycloak version upgrades and perform pre-upgrade backup if needed.

        This method reads the current deployment, compares the running image
        against the desired spec image, and — for major/minor upgrades — triggers
        a tier-appropriate backup before proceeding with the deployment update.

        Args:
            spec: Validated Keycloak specification.
            name: Resource name.
            namespace: Resource namespace.
            kwargs: Handler kwargs (contains ``meta`` with annotations).

        Raises:
            TemporaryError: If backup is pending confirmation or failed.
        """
        from kubernetes.client.rest import ApiException

        deployment_name = f"{name}-keycloak"
        apps_api = client.AppsV1Api(self.kubernetes_client)

        # Try to read the existing deployment — if it doesn't exist yet,
        # this is a fresh install, not an upgrade.
        try:
            existing_deployment = apps_api.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
        except ApiException as e:
            if e.status == 404:
                self.logger.debug(
                    f"No existing deployment for {name} — skipping upgrade check"
                )
                return
            raise

        # Extract the running image from the current deployment
        running_image = get_deployment_image_from_k8s(existing_deployment)
        if not running_image:
            self.logger.warning(
                f"Could not extract running image from deployment {deployment_name} — skipping upgrade check"
            )
            return

        # Determine the desired image from the spec
        desired_image = spec.image or DEFAULT_KEYCLOAK_IMAGE

        # No change — nothing to do
        if running_image == desired_image:
            return

        # Detect and classify the version change
        version_change: VersionChange = detect_version_change(
            running_image, desired_image
        )

        if not version_change.requires_backup:
            if version_change.is_downgrade:
                self.logger.warning(
                    f"Keycloak downgrade detected for {name}: {running_image} -> {desired_image}. "
                    f"Downgrades are unsupported by Keycloak. Proceeding without backup."
                )
            elif version_change.bump_type.value == "patch":
                self.logger.info(
                    f"Patch version change for {name}: {running_image} -> {desired_image}. No backup required."
                )
            return

        # Major or minor upgrade detected — perform pre-upgrade backup
        self.logger.info(
            f"Pre-upgrade backup required for {name}: {running_image} -> {desired_image} "
            f"({version_change.bump_type.value} upgrade)"
        )

        # Determine database tier
        db_tier = spec.database.tier

        result = await self.backup_service.perform_backup(
            keycloak_name=name,
            namespace=namespace,
            db_tier=db_tier,
            db_config=spec.database,
            upgrade_policy=spec.upgrade_policy,
        )

        # Log warnings from the backup result
        for warning in result.warnings:
            self.logger.warning(f"Pre-upgrade backup warning for {name}: {warning}")

        if not result.success:
            # Backup failed — do not proceed with the upgrade
            self.logger.error(f"Pre-upgrade backup failed for {name}: {result.message}")
            raise TemporaryError(
                f"Pre-upgrade backup failed: {result.message}",
                delay=60,
            )

        # Backup succeeded — continue with the upgrade
        self.logger.info(f"Pre-upgrade backup completed for {name}: {result.message}")

    async def ensure_deployment(
        self,
        spec: KeycloakSpec,
        name: str,
        namespace: str,
        db_connection_info: dict[str, Any] | None = None,
    ) -> None:
        """
        Ensure Keycloak deployment exists and is up to date.

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
            db_connection_info: Optional resolved database connection details
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
                try:
                    deployment = create_keycloak_deployment(
                        name=name,
                        namespace=namespace,
                        spec=spec,
                        k8s_client=self.kubernetes_client,
                        db_connection_info=db_connection_info,
                    )
                    self.logger.info(
                        f"Created Keycloak deployment: {deployment.metadata.name}"
                    )
                except ApiException as create_error:
                    if create_error.status == 409:
                        # Resource created by another reconciliation - this is fine
                        self.logger.info(
                            f"Deployment {deployment_name} already exists (created concurrently)"
                        )
                    else:
                        raise
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
                try:
                    service = create_keycloak_service(
                        name=name,
                        namespace=namespace,
                        spec=spec,
                        k8s_client=self.kubernetes_client,
                    )
                    self.logger.info(
                        f"Created Keycloak service: {service.metadata.name}"
                    )
                except ApiException as create_error:
                    if create_error.status == 409:
                        # Resource created by another reconciliation - this is fine
                        self.logger.info(
                            f"Service {service_name} already exists (created concurrently)"
                        )
                    else:
                        raise
            else:
                raise

    async def ensure_discovery_service(
        self, name: str, namespace: str, spec: KeycloakSpec | None = None
    ) -> None:
        """
        Ensure headless discovery service exists and its selector is up to date.

        This headless service enables Keycloak replicas to discover each other
        via DNS_PING for proper session replication and cache synchronization.

        When cache isolation is configured (ADR-088, ADR-090), the service
        selector includes the cache-cluster label so only pods with the same
        cluster name can discover each other.  On every reconcile the selector
        is compared to the desired cluster name and patched when they diverge —
        this covers the case where ``autoRevision`` or ``autoSuffix`` produces a
        different name after a version change.

        Args:
            name: Resource name
            namespace: Resource namespace
            spec: Optional Keycloak spec for cache isolation config
        """
        self.logger.info(f"Ensuring discovery service for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..constants import CACHE_CLUSTER_LABEL
        from ..utils.kubernetes import (
            _resolve_cache_cluster_name,
            create_keycloak_discovery_service,
        )

        discovery_service_name = f"{name}-discovery"
        core_api = client.CoreV1Api(self.kubernetes_client)

        desired_cluster = _resolve_cache_cluster_name(name, spec, self.logger)

        try:
            existing = core_api.read_namespaced_service(
                name=discovery_service_name, namespace=namespace
            )
            # Service exists — check whether the cache-cluster selector label needs updating
            current_selector = existing.spec.selector or {}
            current_cluster = current_selector.get(CACHE_CLUSTER_LABEL)

            if current_cluster != desired_cluster:
                # Patch only the cache-cluster key — set to None to explicitly
                # delete it (strategic-merge patch treats null as a delete).
                patch_body = {
                    "metadata": {"labels": {CACHE_CLUSTER_LABEL: desired_cluster}},
                    "spec": {"selector": {CACHE_CLUSTER_LABEL: desired_cluster}},
                }
                core_api.patch_namespaced_service(
                    name=discovery_service_name,
                    namespace=namespace,
                    body=patch_body,
                )
                self.logger.info(
                    f"Patched discovery service {discovery_service_name} "
                    f"selector: {current_cluster!r} → {desired_cluster!r}"
                )
            else:
                self.logger.info(
                    f"Keycloak discovery service {discovery_service_name} already exists and selector is current"
                )
        except ApiException as e:
            if e.status == 404:
                try:
                    service = create_keycloak_discovery_service(
                        name=name,
                        namespace=namespace,
                        k8s_client=self.kubernetes_client,
                        spec=spec,
                    )
                    self.logger.info(
                        f"Created Keycloak discovery service: {service.metadata.name}"
                    )
                except ApiException as create_error:
                    if create_error.status == 409:
                        # Resource created by another reconciliation - this is fine
                        self.logger.info(
                            f"Discovery service {discovery_service_name} already exists (created concurrently)"
                        )
                    else:
                        raise
            else:
                raise

    async def ensure_ingress(
        self, spec: KeycloakSpec, name: str, namespace: str
    ) -> None:
        """
        Ensure ingress is configured for external access.

        When the ingress already exists, patches annotations to keep
        maintenance mode annotations in sync with the spec (ADR-088).

        Args:
            spec: Keycloak specification
            name: Resource name
            namespace: Resource namespace
        """
        self.logger.info(f"Ensuring ingress for {name}")
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..utils.kubernetes import (
            build_maintenance_mode_annotations,
            create_keycloak_ingress,
        )

        ingress_name = f"{name}-keycloak"
        networking_api = client.NetworkingV1Api(self.kubernetes_client)

        try:
            existing_ingress = networking_api.read_namespaced_ingress(
                name=ingress_name, namespace=namespace
            )
            self.logger.info(f"Ingress {ingress_name} already exists")

            # Patch maintenance mode annotations if they've changed (ADR-088)
            desired_annotations = dict(getattr(spec.ingress, "annotations", {}) or {})
            maintenance_annotations = build_maintenance_mode_annotations(spec)
            desired_annotations.update(maintenance_annotations)

            # When maintenance mode is disabled, explicitly remove stale
            # maintenance annotations from the ingress.  A strategic merge
            # patch ignores absent keys so we must set them to None.
            current_annotations = existing_ingress.metadata.annotations or {}
            maintenance_keys = {
                MAINTENANCE_MODE_ANNOTATION,
                MAINTENANCE_MODE_SNIPPET_ANNOTATION,
            }
            for key in maintenance_keys:
                if key not in maintenance_annotations and key in current_annotations:
                    desired_annotations[key] = None

            if {
                k: current_annotations.get(k) for k in desired_annotations
            } != desired_annotations:
                patch_body = {
                    "metadata": {
                        "annotations": desired_annotations,
                    }
                }
                networking_api.patch_namespaced_ingress(
                    name=ingress_name, namespace=namespace, body=patch_body
                )
                self.logger.info(
                    f"Patched ingress {ingress_name} annotations (maintenance mode sync)"
                )

        except ApiException as e:
            if e.status == 404:
                try:
                    ingress = create_keycloak_ingress(
                        name=name,
                        namespace=namespace,
                        spec=spec,
                        k8s_client=self.kubernetes_client,
                    )
                    self.logger.info(f"Created ingress: {ingress.metadata.name}")
                except ApiException as create_error:
                    if create_error.status == 409:
                        # Resource created by another reconciliation - this is fine
                        self.logger.info(
                            f"Ingress {ingress_name} already exists (created concurrently)"
                        )
                    else:
                        raise
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
        import base64

        from kubernetes import client
        from kubernetes.client.rest import ApiException

        from ..errors.operator_errors import ConfigurationError
        from ..utils.kubernetes import create_admin_secret

        admin_secret_name = f"{name}-admin-credentials"
        core_api = client.CoreV1Api(self.kubernetes_client)

        existing_secret_name = spec.admin.existing_secret
        manual_username = "admin"
        manual_password = None
        annotations = {}

        if existing_secret_name:
            # Validate existing secret
            try:
                manual_secret = core_api.read_namespaced_secret(
                    name=existing_secret_name, namespace=namespace
                )
                if (
                    not manual_secret.data
                    or "username" not in manual_secret.data
                    or "password" not in manual_secret.data
                ):
                    raise ConfigurationError(
                        f"Existing secret {existing_secret_name} must contain 'username' and 'password' keys."
                    )
                manual_username = base64.b64decode(
                    manual_secret.data["username"]
                ).decode("utf-8")
                manual_password = base64.b64decode(
                    manual_secret.data["password"]
                ).decode("utf-8")

                if not manual_username or not manual_password:
                    raise ConfigurationError(
                        f"Existing secret {existing_secret_name} must have non-empty 'username' and 'password' values."
                    )

                annotations["vriesdemichael.github.io/credential-source"] = (
                    f"external:{existing_secret_name}"
                )
                annotations["vriesdemichael.github.io/rotation-enabled"] = "false"
            except ApiException as e:
                if e.status == 404:
                    raise ConfigurationError(
                        f"Admin secret '{existing_secret_name}' not found in namespace '{namespace}'."
                    ) from e
                raise
        else:
            annotations["vriesdemichael.github.io/credential-source"] = "generated"
            annotations["vriesdemichael.github.io/rotation-enabled"] = "true"

        # Check if the proxy secret exists and needs updating
        try:
            current_proxy = core_api.read_namespaced_secret(
                name=admin_secret_name, namespace=namespace
            )
            needs_update = False

            # If we are using an existing secret, ensure the proxy matches it exactly
            if existing_secret_name:
                current_user = (
                    base64.b64decode(current_proxy.data.get("username", b"")).decode(
                        "utf-8"
                    )
                    if current_proxy.data
                    else ""
                )
                current_pass = (
                    base64.b64decode(current_proxy.data.get("password", b"")).decode(
                        "utf-8"
                    )
                    if current_proxy.data
                    else ""
                )
                if current_user != manual_username or current_pass != manual_password:
                    needs_update = True

            # Ensure annotations are set correctly
            current_annotations = current_proxy.metadata.annotations or {}
            for k, v in annotations.items():
                if current_annotations.get(k) != v:
                    needs_update = True
                    break

            if needs_update:
                self.logger.info(f"Updating admin proxy secret {admin_secret_name}")
                if existing_secret_name and manual_password is not None:
                    if current_proxy.data is None:
                        current_proxy.data = {}
                    current_proxy.data["username"] = base64.b64encode(
                        manual_username.encode()
                    ).decode("utf-8")
                    current_proxy.data["password"] = base64.b64encode(
                        manual_password.encode()
                    ).decode("utf-8")
                if current_proxy.metadata.annotations is None:
                    current_proxy.metadata.annotations = {}
                current_proxy.metadata.annotations.update(annotations)
                core_api.replace_namespaced_secret(
                    name=admin_secret_name, namespace=namespace, body=current_proxy
                )
            else:
                self.logger.info(f"Admin secret {admin_secret_name} already up to date")

        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"Creating new admin secret {admin_secret_name}")
                create_admin_secret(
                    name=name,
                    namespace=namespace,
                    username=manual_username,
                    password=manual_password,
                    annotations=annotations,
                )
            else:
                raise

    async def wait_for_deployment_ready(
        self, name: str, namespace: str, max_wait_time: int = 300
    ) -> tuple[bool, str | None]:
        """
        Wait for deployment to be ready.

        Args:
            name: Resource name
            namespace: Resource namespace
            max_wait_time: Maximum wait time in seconds

        Returns:
            Tuple of (ready: bool, error_message: str | None)
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
                    return True, None

                # Check for fatal build/configuration errors in pod logs
                build_error = self._check_pod_logs_for_build_errors(
                    deployment_name, namespace
                )
                if build_error:
                    self.logger.error(
                        f"Deployment {deployment_name} failed: {build_error}"
                    )
                    return False, build_error

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
        return False, None

    def _check_pod_logs_for_build_errors(
        self, deployment_name: str, namespace: str
    ) -> str | None:
        """
        Check pod logs for known build/configuration mismatch errors.

        Returns:
            Error message if a known error is found, None otherwise.
        """
        from ..utils.kubernetes import get_deployment_pods, get_pod_logs

        pods = get_deployment_pods(deployment_name, namespace, self.kubernetes_client)

        # Check pods that are not ready
        for pod in pods:
            # We care about pods that are crashing or in error state
            should_check = False
            if pod.status.phase == "Failed":
                should_check = True
            elif (
                pod.status.phase in ["Running", "Pending"]
                and pod.status.container_statuses
            ):
                for status in pod.status.container_statuses:
                    if status.state.waiting and status.state.waiting.reason in [
                        "CrashLoopBackOff",
                        "CreateContainerConfigError",
                        "Error",
                    ]:
                        should_check = True
                        break
                    if (
                        status.state.terminated
                        and status.state.terminated.exit_code != 0
                    ):
                        should_check = True
                        break

            if should_check:
                logs = get_pod_logs(
                    pod.metadata.name,
                    namespace,
                    self.kubernetes_client,
                    tail_lines=50,
                )

                # Signature 1: Optimized flag mismatch
                if (
                    "The '--optimized' flag was used for first ever server start"
                    in logs
                ):
                    return (
                        "Configuration Error: The 'optimized' flag is enabled, but the image was not built with 'kc.sh build'. "
                        "Please either: 1) Use a pre-built optimized image, or 2) Set 'optimized: false' in your Keycloak spec."
                    )

                # Signature 2: Build option mismatch (Tracing, Features, etc.)
                if (
                    "The following build time options have values that differ from what is persisted"
                    in logs
                ):
                    return (
                        "Configuration Error: Requested features (e.g. Tracing, DB, Cache) differ from what was built into the image. "
                        "When using 'optimized: true', you cannot change build-time options at runtime. "
                        "Please rebuild your image with the new configuration or disable 'optimized' mode."
                    )

        return None

    async def _delete_dependent_resources(
        self, keycloak_name: str, keycloak_namespace: str
    ) -> None:
        """
        Delete all CRD resources that depend on this Keycloak instance.

        This implements cascading deletion by finding and deleting:
        1. KeycloakClients that reference this Keycloak instance
        2. KeycloakRealms that reference this Keycloak instance

        Args:
            keycloak_name: Name of the Keycloak instance being deleted
            keycloak_namespace: Namespace of the Keycloak instance
        """
        from kubernetes import client
        from kubernetes.client.rest import ApiException

        self.logger.info(
            f"Cascading deletion: Finding dependent resources for Keycloak {keycloak_name}"
        )

        custom_api = client.CustomObjectsApi(self.kubernetes_client)

        # Delete dependent KeycloakClients first (they depend on realms)
        try:
            clients = custom_api.list_cluster_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakclients",
            )

            for client_obj in clients.get("items", []):
                client_spec = client_obj.get("spec", {})
                keycloak_ref = client_spec.get("keycloak_instance_ref", {})
                ref_name = keycloak_ref.get("name")
                ref_namespace = (
                    keycloak_ref.get("namespace") or client_obj["metadata"]["namespace"]
                )

                # Check if this client references the Keycloak being deleted
                if ref_name == keycloak_name and ref_namespace == keycloak_namespace:
                    client_name = client_obj["metadata"]["name"]
                    client_ns = client_obj["metadata"]["namespace"]
                    self.logger.info(
                        f"Cascading deletion: Deleting dependent KeycloakClient {client_name} in {client_ns}"
                    )
                    try:
                        custom_api.delete_namespaced_custom_object(
                            group="vriesdemichael.github.io",
                            version="v1",
                            namespace=client_ns,
                            plural="keycloakclients",
                            name=client_name,
                        )
                    except ApiException as e:
                        if e.status != 404:  # Ignore if already deleted
                            self.logger.warning(
                                f"Failed to delete KeycloakClient {client_name}: {e}"
                            )
        except Exception as e:
            self.logger.warning(
                f"Error listing KeycloakClients for cascading deletion: {e}"
            )

        # Delete dependent KeycloakRealms
        try:
            realms = custom_api.list_cluster_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakrealms",
            )

            for realm_obj in realms.get("items", []):
                realm_spec = realm_obj.get("spec", {})
                keycloak_ref = realm_spec.get("keycloak_instance_ref", {})
                ref_name = keycloak_ref.get("name")
                ref_namespace = (
                    keycloak_ref.get("namespace") or realm_obj["metadata"]["namespace"]
                )

                # Check if this realm references the Keycloak being deleted
                if ref_name == keycloak_name and ref_namespace == keycloak_namespace:
                    realm_name = realm_obj["metadata"]["name"]
                    realm_ns = realm_obj["metadata"]["namespace"]
                    self.logger.info(
                        f"Cascading deletion: Deleting dependent KeycloakRealm {realm_name} in {realm_ns}"
                    )
                    try:
                        custom_api.delete_namespaced_custom_object(
                            group="vriesdemichael.github.io",
                            version="v1",
                            namespace=realm_ns,
                            plural="keycloakrealms",
                            name=realm_name,
                        )
                    except ApiException as e:
                        if e.status != 404:  # Ignore if already deleted
                            self.logger.warning(
                                f"Failed to delete KeycloakRealm {realm_name}: {e}"
                            )
        except Exception as e:
            self.logger.warning(
                f"Error listing KeycloakRealms for cascading deletion: {e}"
            )

        self.logger.info("Cascading deletion: Completed deleting dependent resources")

    async def cleanup_resources(
        self, name: str, namespace: str, spec: dict[str, Any]
    ) -> None:
        """
        Clean up all resources associated with a Keycloak instance.

        This method performs comprehensive cleanup in the proper order to prevent
        data loss and ensure all associated resources are properly removed.

        Implements cascading deletion:
        1. Delete dependent KeycloakClients
        2. Delete dependent KeycloakRealms
        3. Delete Kubernetes resources (deployments, services, etc.)

        Args:
            name: Name of the Keycloak instance
            namespace: Namespace containing the resources
            spec: Keycloak specification for understanding deletion requirements

        Raises:
            TemporaryError: If cleanup fails but should be retried
        """
        from ..constants import (
            DEPLOYMENT_SUFFIX,
            INGRESS_SUFFIX,
            PRESERVE_DATA_ANNOTATION,
            SERVICE_SUFFIX,
        )

        self.logger.info(f"Starting cleanup of Keycloak instance {name} in {namespace}")

        # CASCADING DELETION: Delete dependent CRD resources first
        try:
            await self._delete_dependent_resources(name, namespace)
        except Exception as e:
            self.logger.warning(f"Failed to delete some dependent resources: {e}")
            # Continue with cleanup even if some dependents fail to delete

        try:
            # Validate spec can be parsed (even though we don't use it after backup removal)
            KeycloakSpec.model_validate(spec)
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

        # 2b. Delete discovery service (headless service for JGroups clustering)
        discovery_service_name = f"{name}-discovery"
        try:
            await self._delete_service(discovery_service_name, namespace, core_api)
        except Exception as e:
            self.logger.warning(f"Failed to delete discovery service: {e}")

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
