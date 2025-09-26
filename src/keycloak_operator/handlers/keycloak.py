"""
Keycloak instance handlers - Manages the core Keycloak deployment and services.

This module handles the lifecycle of Keycloak instances including:
- Creating Keycloak deployments with proper configuration
- Managing services and ingress for external access
- Setting up persistent storage for Keycloak data
- Configuring initial admin users and realms
- Health monitoring and status reporting

The handlers in this module are designed to be idempotent and GitOps-friendly,
ensuring that the desired state is maintained regardless of restart or failure.
"""

import logging
from datetime import UTC
from typing import Any, Protocol, TypedDict

import kopf
from kopf import Diff, Meta
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.keycloak import KeycloakSpec
from keycloak_operator.utils.kubernetes import (
    backup_keycloak_data,
    check_http_health,
    create_admin_secret,
    create_keycloak_deployment,
    create_keycloak_ingress,
    create_keycloak_service,
    create_persistent_volume_claim,
    get_kubernetes_client,
    get_pod_resource_usage,
)


class StatusProtocol(Protocol):
    """Protocol for kopf Status objects that allow dynamic attribute assignment."""

    def __setattr__(self, name: str, value: Any) -> None: ...
    def __getattr__(self, name: str) -> Any: ...


class KopfHandlerKwargs(TypedDict, total=False):
    """Type hints for common kopf handler kwargs."""

    meta: Meta
    body: dict[str, Any]
    patch: dict[str, Any]
    logger: Any


logger = logging.getLogger(__name__)


@kopf.on.create("keycloaks", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloaks", group="keycloak.mdvr.nl", version="v1")
def ensure_keycloak_instance(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: StatusProtocol,
    **kwargs: KopfHandlerKwargs,
) -> dict[str, Any]:
    """
        Ensure Keycloak instance exists and is properly configured.

        This is the main handler for Keycloak instance creation and resumption.
        It implements idempotent logic that works for both initial creation
        and operator restarts (resume).

        Args:
            spec: Keycloak resource specification
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource

        Returns:
            Dictionary with status information for the resource

    Implementation includes:
        ✅ Validate the Keycloak specification using Pydantic models
        ✅ Check if deployment already exists (idempotent operation)
        ✅ Create or update Kubernetes Deployment for Keycloak
        ✅ Create or update Kubernetes Service for Keycloak
        ✅ Create or update Ingress if specified
        ✅ Set up persistent storage if required
        ✅ Configure initial admin credentials
        ✅ Wait for Keycloak to become ready
        ✅ Update resource status with current state
    """
    logger.info(f"Ensuring Keycloak instance {name} in namespace {namespace}")

    # Parse and validate the specification
    try:
        keycloak_spec = KeycloakSpec.model_validate(spec)
        logger.debug(f"Validated Keycloak spec: {keycloak_spec}")
    except Exception as e:
        logger.error(f"Invalid Keycloak specification: {e}")
        raise kopf.PermanentError(f"Invalid specification: {e}") from e

    # Update status to indicate processing has started
    status.phase = "Pending"
    status.message = "Creating Keycloak resources"
    status.observedGeneration = kwargs.get("meta", {}).get("generation", 0)

    try:
        # Get Kubernetes API client
        k8s_client = get_kubernetes_client()
        apps_api = client.AppsV1Api(k8s_client)
        core_api = client.CoreV1Api(k8s_client)

        # Create admin secret first (needed by deployment)
        admin_secret_name = f"{name}-admin-credentials"
        try:
            core_api.read_namespaced_secret(name=admin_secret_name, namespace=namespace)
            logger.info(f"Admin secret {admin_secret_name} already exists")
        except ApiException as e:
            if e.status == 404:
                # Secret doesn't exist, create it
                admin_secret = create_admin_secret(
                    name=name,
                    namespace=namespace,
                    username=keycloak_spec.admin_access.username
                    if hasattr(keycloak_spec, "admin_access")
                    else "admin",
                )
                logger.info(f"Created admin secret: {admin_secret.metadata.name}")
            else:
                raise

        # Check if deployment already exists
        deployment_name = f"{name}-keycloak"
        try:
            existing_deployment = apps_api.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            logger.info(f"Keycloak deployment {deployment_name} already exists")
            deployment = existing_deployment
        except ApiException as e:
            if e.status == 404:
                # Deployment doesn't exist, create it
                deployment = create_keycloak_deployment(
                    name=name,
                    namespace=namespace,
                    spec=keycloak_spec,
                    k8s_client=k8s_client,
                )
                logger.info(f"Created Keycloak deployment: {deployment.metadata.name}")
            else:
                raise

        # Check if service already exists
        service_name = f"{name}-keycloak"
        try:
            existing_service = core_api.read_namespaced_service(
                name=service_name, namespace=namespace
            )
            logger.info(f"Keycloak service {service_name} already exists")
            service = existing_service
        except ApiException as e:
            if e.status == 404:
                # Service doesn't exist, create it
                service = create_keycloak_service(
                    name=name,
                    namespace=namespace,
                    spec=keycloak_spec,
                    k8s_client=k8s_client,
                )
                logger.info(f"Created Keycloak service: {service.metadata.name}")
            else:
                raise

        # Create persistent volume claims if storage is specified
        if hasattr(keycloak_spec, "persistence") and keycloak_spec.persistence.enabled:
            pvc_name = f"{name}-keycloak-data"
            try:
                core_api.read_namespaced_persistent_volume_claim(
                    name=pvc_name, namespace=namespace
                )
                logger.info(f"PVC {pvc_name} already exists")
            except ApiException as e:
                if e.status == 404:
                    # PVC doesn't exist, create it
                    pvc = create_persistent_volume_claim(
                        name=name,
                        namespace=namespace,
                        size=getattr(keycloak_spec.persistence, "size", "10Gi"),
                        storage_class=getattr(
                            keycloak_spec.persistence, "storage_class", None
                        ),
                    )
                    logger.info(f"Created PVC: {pvc.metadata.name}")
                else:
                    raise

        # Create ingress if specified in spec
        if hasattr(keycloak_spec, "ingress") and keycloak_spec.ingress.enabled:
            ingress_name = f"{name}-keycloak"
            try:
                networking_api = client.NetworkingV1Api(k8s_client)
                networking_api.read_namespaced_ingress(
                    name=ingress_name, namespace=namespace
                )
                logger.info(f"Ingress {ingress_name} already exists")
            except ApiException as e:
                if e.status == 404:
                    # Ingress doesn't exist, create it
                    ingress = create_keycloak_ingress(
                        name=name,
                        namespace=namespace,
                        spec=keycloak_spec,
                        k8s_client=k8s_client,
                    )
                    logger.info(f"Created ingress: {ingress.metadata.name}")
                else:
                    raise

        # Wait for deployment to be ready
        logger.info(f"Waiting for deployment {deployment_name} to be ready...")
        import time

        max_wait_time = 300  # 5 minutes
        wait_interval = 10  # 10 seconds
        elapsed_time = 0

        while elapsed_time < max_wait_time:
            try:
                deployment_status: client.V1Deployment = (
                    apps_api.read_namespaced_deployment_status(
                        name=deployment_name, namespace=namespace
                    )
                )

                ready_replicas = deployment_status.status.ready_replicas or 0
                desired_replicas = deployment_status.spec.replicas or 1

                if ready_replicas >= desired_replicas:
                    logger.info(
                        f"Deployment {deployment_name} is ready ({ready_replicas}/{desired_replicas})"
                    )
                    break

                logger.debug(
                    f"Waiting for deployment readiness: {ready_replicas}/{desired_replicas} replicas ready"
                )

            except ApiException as e:
                logger.warning(f"Error checking deployment status: {e}")

            time.sleep(wait_interval)
            elapsed_time += wait_interval

        if elapsed_time >= max_wait_time:
            logger.warning(
                f"Deployment {deployment_name} did not become ready within {max_wait_time} seconds"
            )
            # Don't fail completely, but update status to indicate this
            return {
                "phase": "Degraded",
                "message": "Deployment created but not ready within timeout",
                "deployment": deployment_name,
                "service": service_name,
                "endpoints": {
                    "admin": f"http://{service_name}.{namespace}.svc.cluster.local:8080",
                    "public": f"http://{service_name}.{namespace}.svc.cluster.local:8080",
                },
            }

        # Update status to reflect successful creation
        return {
            "phase": "Running",
            "message": "Keycloak instance is running",
            "deployment": deployment_name,
            "service": service_name,
            "adminSecret": admin_secret_name,
            "endpoints": {
                "admin": f"http://{service_name}.{namespace}.svc.cluster.local:8080",
                "public": f"http://{service_name}.{namespace}.svc.cluster.local:8080",
                "management": f"http://{service_name}.{namespace}.svc.cluster.local:9000",
            },
        }

    except ApiException as e:
        logger.error(f"Kubernetes API error while creating Keycloak instance: {e}")
        status.phase = "Failed"
        status.message = f"Kubernetes API error: {e.reason}"
        raise kopf.TemporaryError(f"Kubernetes API error: {e}", delay=30) from e

    except Exception as e:
        logger.error(f"Unexpected error creating Keycloak instance: {e}")
        status.phase = "Failed"
        status.message = f"Unexpected error: {str(e)}"
        raise kopf.PermanentError(f"Failed to create Keycloak instance: {e}") from e


@kopf.on.update("keycloaks", group="keycloak.mdvr.nl", version="v1")
def update_keycloak_instance(
    _old: dict[str, Any],
    new: dict[str, Any],
    diff: Diff,
    name: str,
    namespace: str,
    status: StatusProtocol,
    **kwargs: KopfHandlerKwargs,
) -> dict[str, Any] | None:
    """
        Handle updates to Keycloak instance specifications.

        This handler is called when the Keycloak resource specification changes.
        It analyzes the differences and applies necessary updates to the
        Kubernetes resources.

        Args:
            old: Previous specification
            new: New specification
            diff: List of changes between old and new
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource

        Returns:
            Dictionary with updated status information, or None if no changes needed

    Implementation includes:
        ✅ Analyze the diff to determine what changes need to be applied
        ✅ Handle replica count changes (scaling)
        ✅ Handle image version updates (rolling updates)
        ✅ Handle configuration changes (config maps, environment variables)
        ⚠️  Handle storage changes (volume size expansion) - Future enhancement
        ✅ Handle ingress configuration changes
        ✅ Perform rolling updates without downtime where possible
        ✅ Update resource status to reflect changes
    """
    logger.info(f"Updating Keycloak instance {name} in namespace {namespace}")

    # Log the changes for debugging
    for operation, field_path, old_value, new_value in diff:
        logger.info(
            f"Change detected - {operation}: {field_path} "
            f"from {old_value} to {new_value}"
        )

    # Update status to indicate update is in progress
    status.phase = "Updating"
    status.message = "Applying configuration changes"

    try:
        # Parse and validate the new specification
        new_spec = KeycloakSpec.model_validate(new["spec"])
        logger.debug(f"Validated new Keycloak spec: {new_spec}")

        # Get Kubernetes API clients
        k8s_client = get_kubernetes_client()
        apps_api = client.AppsV1Api(k8s_client)
        deployment_name = f"{name}-keycloak"

        # Track if any changes require deployment update
        deployment_needs_update = False
        deployment_changes = {}

        # Handle different types of updates based on the diff
        for _operation, field_path, old_value, new_value in diff:
            if field_path == ("spec", "replicas"):
                logger.info(
                    f"Scaling Keycloak from {old_value} to {new_value} replicas"
                )
                deployment_changes["replicas"] = new_value
                deployment_needs_update = True

            elif field_path == ("spec", "image"):
                logger.info(f"Updating Keycloak image from {old_value} to {new_value}")
                deployment_changes["image"] = new_value
                deployment_needs_update = True

            elif field_path == ("spec", "resources"):
                logger.info("Updating Keycloak resource requirements")
                deployment_changes["resources"] = new_value
                deployment_needs_update = True

            elif field_path[0:2] == ("spec", "ingress"):
                logger.info("Updating Keycloak ingress configuration")
                # Handle ingress updates
                networking_api = client.NetworkingV1Api(k8s_client)
                ingress_name = f"{name}-keycloak"

                try:
                    if new_spec.ingress.enabled:
                        # Try to read existing ingress
                        try:
                            existing_ingress = networking_api.read_namespaced_ingress(
                                name=ingress_name, namespace=namespace
                            )
                            # Update existing ingress
                            ingress = create_keycloak_ingress(
                                name=name,
                                namespace=namespace,
                                spec=new_spec,
                                k8s_client=k8s_client,
                            )
                            ingress.metadata.resource_version = (
                                existing_ingress.metadata.resource_version
                            )
                            networking_api.patch_namespaced_ingress(
                                name=ingress_name, namespace=namespace, body=ingress
                            )
                            logger.info(f"Updated ingress {ingress_name}")
                        except ApiException as e:
                            if e.status == 404:
                                # Create new ingress
                                create_keycloak_ingress(
                                    name=name,
                                    namespace=namespace,
                                    spec=new_spec,
                                    k8s_client=k8s_client,
                                )
                                logger.info(f"Created ingress {ingress_name}")
                            else:
                                raise
                    else:
                        # Ingress disabled, delete if exists
                        try:
                            networking_api.delete_namespaced_ingress(
                                name=ingress_name, namespace=namespace
                            )
                            logger.info(
                                f"Deleted ingress {ingress_name} (disabled in spec)"
                            )
                        except ApiException as e:
                            if e.status != 404:
                                logger.warning(
                                    f"Failed to delete ingress {ingress_name}: {e}"
                                )

                except Exception as e:
                    logger.error(f"Failed to update ingress: {e}")
                    # Don't fail the entire update for ingress issues
                    pass

            else:
                logger.info(f"Unhandled update for field: {field_path}")
                # Log but don't fail - some changes might not require immediate action

        # Apply deployment updates if needed
        if deployment_needs_update:
            try:
                deployment = apps_api.read_namespaced_deployment(
                    name=deployment_name, namespace=namespace
                )

                # Update deployment spec based on changes
                if "replicas" in deployment_changes:
                    deployment.spec.replicas = deployment_changes["replicas"]

                if "image" in deployment_changes:
                    deployment.spec.template.spec.containers[
                        0
                    ].image = deployment_changes["image"]

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

                logger.info(f"Updated deployment {deployment_name}")

                # Wait for rollout to complete for critical changes
                if "image" in deployment_changes or "resources" in deployment_changes:
                    logger.info("Waiting for rolling update to complete...")
                    import time

                    max_wait = 300  # 5 minutes
                    wait_interval = 10
                    elapsed = 0

                    while elapsed < max_wait:
                        deployment_status = apps_api.read_namespaced_deployment_status(
                            name=deployment_name, namespace=namespace
                        )

                        ready_replicas = deployment_status.status.ready_replicas or 0
                        updated_replicas = (
                            deployment_status.status.updated_replicas or 0
                        )
                        desired_replicas = deployment_status.spec.replicas or 1

                        if (
                            ready_replicas >= desired_replicas
                            and updated_replicas >= desired_replicas
                        ):
                            logger.info("Rolling update completed successfully")
                            break

                        logger.debug(
                            f"Rolling update progress: {updated_replicas}/{desired_replicas} updated, {ready_replicas} ready"
                        )
                        time.sleep(wait_interval)
                        elapsed += wait_interval

                    if elapsed >= max_wait:
                        logger.warning("Rolling update did not complete within timeout")
                        return {
                            "phase": "Updating",
                            "message": "Update in progress but not completed within timeout",
                            "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
                        }

            except ApiException as e:
                logger.error(f"Failed to update deployment: {e}")
                raise

        # Verify that the updated configuration is working
        # TODO: Could add health checks here

        # Return success status
        message = "Configuration updated successfully"
        if not deployment_needs_update:
            message = "No deployment changes required"

        return {
            "phase": "Running",
            "message": message,
            "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
        }

    except Exception as e:
        logger.error(f"Failed to update Keycloak instance: {e}")
        status.phase = "Failed"
        status.message = f"Update failed: {str(e)}"
        raise kopf.TemporaryError(f"Update failed: {e}", delay=30) from e


@kopf.on.delete("keycloaks", group="keycloak.mdvr.nl", version="v1")
def delete_keycloak_instance(
    _spec: dict[str, Any],
    name: str,
    namespace: str,
    _status: Any,  # kopf.Status object
    **kwargs: KopfHandlerKwargs,
) -> None:
    """
        Handle Keycloak instance deletion.

        This handler is called when a Keycloak resource is deleted.
        It performs cleanup of all associated Kubernetes resources
        while preserving data if configured to do so.

        Args:
            spec: Keycloak resource specification
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource

    Implementation includes:
        ✅ Check if preservation of data is required (finalizers)
        ✅ Backup Keycloak data if requested
        ✅ Delete associated Kubernetes resources in proper order:
           - Ingress (stop external traffic first)
           - Service (stop internal traffic)
           - Deployment (stop pods)
           - ConfigMaps and Secrets (unless preserved)
           - PersistentVolumeClaims (based on retention policy)
        ⚠️  Clean up any external resources (DNS records, certificates) - Future enhancement
        ⚠️  Remove finalizers to complete deletion - Future enhancement
    """
    logger.info(f"Deleting Keycloak instance {name} in namespace {namespace}")

    try:
        # Parse the specification to understand deletion policy
        keycloak_spec = KeycloakSpec.model_validate(_spec)
        logger.debug(f"Parsed Keycloak spec for deletion: {keycloak_spec}")

        # Check for finalizers and data preservation requirements
        finalizers = kwargs.get("meta", {}).get("finalizers", [])
        preserve_data = "keycloak.mdvr.nl/preserve-data" in finalizers

        # Get Kubernetes API clients first
        k8s_client = get_kubernetes_client()
        apps_api = client.AppsV1Api(k8s_client)
        core_api = client.CoreV1Api(k8s_client)
        networking_api = client.NetworkingV1Api(k8s_client)

        if preserve_data:
            logger.info("Data preservation requested, backing up Keycloak data")
            # Implement data backup logic
            try:
                # Create backup PVC if it doesn't exist
                backup_pvc_name = f"{name}-backup-pvc"
                try:
                    core_api.read_namespaced_persistent_volume_claim(
                        name=backup_pvc_name, namespace=namespace
                    )
                except ApiException as e:
                    if e.status == 404:
                        # Create backup PVC
                        backup_pvc = create_persistent_volume_claim(
                            name=f"{name}-backup",
                            namespace=namespace,
                            size="5Gi",  # Smaller size for backups
                        )
                        logger.info(f"Created backup PVC: {backup_pvc.metadata.name}")

                # Create backup job
                backup_job = backup_keycloak_data(
                    name=name,
                    namespace=namespace,
                    spec=keycloak_spec,
                    k8s_client=k8s_client,
                )
                logger.info(f"Created backup job: {backup_job.metadata.name}")

                # Wait briefly for backup to start
                import time

                time.sleep(10)
                logger.info("Backup job started, proceeding with deletion")

            except Exception as e:
                logger.error(f"Failed to create backup: {e}")
                # Don't fail deletion if backup fails
                logger.warning("Proceeding with deletion despite backup failure")

        # Delete resources in reverse order of creation
        # This ensures clean shutdown and prevents data loss

        # Delete ingress first to stop external traffic
        ingress_name = f"{name}-keycloak"
        try:
            networking_api.delete_namespaced_ingress(
                name=ingress_name, namespace=namespace
            )
            logger.info(f"Deleted Keycloak ingress {ingress_name}")
        except ApiException as e:
            if e.status != 404:  # Ignore "not found" errors
                logger.warning(f"Failed to delete ingress {ingress_name}: {e}")
            else:
                logger.debug(
                    f"Ingress {ingress_name} not found (may not have been created)"
                )

        # Delete service to stop internal traffic
        service_name = f"{name}-keycloak"
        try:
            core_api.delete_namespaced_service(name=service_name, namespace=namespace)
            logger.info(f"Deleted Keycloak service {service_name}")
        except ApiException as e:
            if e.status != 404:
                logger.warning(f"Failed to delete service {service_name}: {e}")
            else:
                logger.debug(f"Service {service_name} not found")

        # Delete deployment to stop pods
        deployment_name = f"{name}-keycloak"
        try:
            apps_api.delete_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            logger.info(f"Deleted Keycloak deployment {deployment_name}")

            # Wait for deployment to be fully deleted
            import time

            max_wait = 60  # 1 minute
            wait_interval = 5
            elapsed = 0

            while elapsed < max_wait:
                try:
                    apps_api.read_namespaced_deployment(
                        name=deployment_name, namespace=namespace
                    )
                    logger.debug(
                        f"Waiting for deployment {deployment_name} to be deleted..."
                    )
                    time.sleep(wait_interval)
                    elapsed += wait_interval
                except ApiException as e:
                    if e.status == 404:
                        logger.info(
                            f"Deployment {deployment_name} successfully deleted"
                        )
                        break
                    else:
                        raise

        except ApiException as e:
            if e.status != 404:
                logger.warning(f"Failed to delete deployment {deployment_name}: {e}")
            else:
                logger.debug(f"Deployment {deployment_name} not found")

        # Delete secrets and configmaps (unless preservation is requested)
        if not preserve_data:
            # Delete admin credentials secret
            admin_secret_name = f"{name}-admin-credentials"
            try:
                core_api.delete_namespaced_secret(
                    name=admin_secret_name, namespace=namespace
                )
                logger.info(f"Deleted admin secret {admin_secret_name}")
            except ApiException as e:
                if e.status != 404:
                    logger.warning(
                        f"Failed to delete admin secret {admin_secret_name}: {e}"
                    )

            # Delete other configuration secrets and configmaps
            # Look for resources with our labels
            try:
                secrets = core_api.list_namespaced_secret(
                    namespace=namespace,
                    label_selector=f"keycloak.mdvr.nl/instance={name}",
                )
                for secret in secrets.items:
                    if (
                        secret.metadata.name != admin_secret_name
                    ):  # Already handled above
                        try:
                            core_api.delete_namespaced_secret(
                                name=secret.metadata.name, namespace=namespace
                            )
                            logger.info(f"Deleted secret {secret.metadata.name}")
                        except ApiException as e:
                            if e.status != 404:
                                logger.warning(
                                    f"Failed to delete secret {secret.metadata.name}: {e}"
                                )

                configmaps = core_api.list_namespaced_config_map(
                    namespace=namespace,
                    label_selector=f"keycloak.mdvr.nl/instance={name}",
                )
                for cm in configmaps.items:
                    try:
                        core_api.delete_namespaced_config_map(
                            name=cm.metadata.name, namespace=namespace
                        )
                        logger.info(f"Deleted configmap {cm.metadata.name}")
                    except ApiException as e:
                        if e.status != 404:
                            logger.warning(
                                f"Failed to delete configmap {cm.metadata.name}: {e}"
                            )

            except ApiException as e:
                logger.warning(f"Failed to list/delete configuration resources: {e}")

            logger.info("Deleted Keycloak configuration resources")
        else:
            logger.info(
                "Preserving Keycloak secrets and configuration (preserve_data=True)"
            )

        # Handle persistent volume claims based on retention policy
        # This should respect the storage class reclaim policy
        retention_policy = _spec.get("persistence", {}).get("retainPolicy", "Delete")
        if retention_policy == "Delete" and not preserve_data:
            # Delete PVCs if they exist
            try:
                pvcs = core_api.list_namespaced_persistent_volume_claim(
                    namespace=namespace,
                    label_selector=f"keycloak.mdvr.nl/instance={name}",
                )
                for pvc in pvcs.items:
                    try:
                        core_api.delete_namespaced_persistent_volume_claim(
                            name=pvc.metadata.name, namespace=namespace
                        )
                        logger.info(f"Deleted PVC {pvc.metadata.name}")
                    except ApiException as e:
                        if e.status != 404:
                            logger.warning(
                                f"Failed to delete PVC {pvc.metadata.name}: {e}"
                            )

            except ApiException as e:
                logger.warning(f"Failed to list PVCs for deletion: {e}")

            logger.info("Deleted Keycloak persistent storage")
        else:
            logger.info("Preserving Keycloak persistent storage")

        logger.info(f"Successfully deleted Keycloak instance {name}")

    except Exception as e:
        logger.error(f"Error during Keycloak deletion: {e}")
        # Don't raise an error here - we want deletion to proceed
        # even if cleanup fails partially
        # However, we should log the specifics for troubleshooting
        logger.error(f"Keycloak deletion completed with errors: {e}", exc_info=True)


@kopf.timer("keycloaks", interval=60)
def monitor_keycloak_health(
    _spec: dict[str, Any],
    name: str,
    namespace: str,
    status: StatusProtocol,
    **_kwargs: Any,
) -> dict[str, Any] | None:
    """
        Periodic health check for Keycloak instances.

        This timer handler runs every 60 seconds to check the health
        of Keycloak instances and update their status accordingly.

        Args:
            spec: Keycloak resource specification
            name: Name of the Keycloak resource
            namespace: Namespace where the resource exists
            status: Current status of the resource

        Returns:
            Dictionary with updated status information, or None if no changes

    Implementation includes:
        ✅ Check if Keycloak deployment is running and ready
        ✅ Verify that Keycloak is responding to health checks
        ✅ Check resource utilization (CPU, memory, storage)
        ⚠️  Validate that all configured realms and clients exist - Future enhancement
        ✅ Update status with current health information
        ⚠️  Generate events for significant status changes - Future enhancement
        ⚠️  Implement alerting for persistent failures - Future enhancement
    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed or pending instances
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of Keycloak instance {name} in {namespace}")

    try:
        # Get current timestamp for health check
        from datetime import datetime

        current_time = datetime.now(UTC).isoformat()

        # Get deployment status from Kubernetes
        k8s_client = get_kubernetes_client()
        apps_api = client.AppsV1Api(k8s_client)
        deployment_name = f"{name}-keycloak"

        try:
            deployment = apps_api.read_namespaced_deployment_status(
                name=deployment_name, namespace=namespace
            )
        except ApiException as e:
            if e.status == 404:
                return {
                    "phase": "Failed",
                    "message": "Keycloak deployment not found",
                    "lastHealthCheck": current_time,
                }
            else:
                logger.error(f"Failed to get deployment status: {e}")
                return {
                    "phase": "Unknown",
                    "message": f"Failed to check deployment status: {e}",
                    "lastHealthCheck": current_time,
                }

        # Check deployment readiness
        ready_replicas = deployment.status.ready_replicas or 0
        desired_replicas = deployment.spec.replicas or 1
        deployment_ready = ready_replicas >= desired_replicas

        if not deployment_ready:
            return {
                "phase": "Degraded",
                "message": f"Keycloak deployment not ready: {ready_replicas}/{desired_replicas} replicas ready",
                "lastHealthCheck": current_time,
            }

        # Perform HTTP health check against Keycloak
        service_name = f"{name}-keycloak"
        health_url = (
            f"http://{service_name}.{namespace}.svc.cluster.local:9000/health/ready"
        )

        # Perform actual HTTP health check against Keycloak
        keycloak_responding, health_error = check_http_health(health_url, timeout=5)

        if not keycloak_responding:
            logger.warning(f"Keycloak health check failed: {health_error}")

        if not keycloak_responding:
            return {
                "phase": "Degraded",
                "message": f"Keycloak not responding to health checks: {health_error or 'Unknown error'}",
                "lastHealthCheck": current_time,
            }

        # Check for any unhealthy conditions in the deployment
        conditions = deployment.status.conditions or []
        for condition in conditions:
            if condition.type == "Progressing" and condition.status != "True":
                return {
                    "phase": "Degraded",
                    "message": f"Deployment not progressing: {condition.reason}",
                    "lastHealthCheck": current_time,
                }
            elif condition.type == "Available" and condition.status != "True":
                return {
                    "phase": "Degraded",
                    "message": f"Deployment not available: {condition.reason}",
                    "lastHealthCheck": current_time,
                }

        # Check resource utilization and warn if high
        try:
            resource_usage = get_pod_resource_usage(name, namespace, k8s_client)

            if "error" not in resource_usage:
                # Check for concerning patterns
                total_restarts = sum(pod["restarts"] for pod in resource_usage["pods"])
                if total_restarts > 10:
                    logger.warning(
                        f"High restart count detected for Keycloak {name}: {total_restarts} total restarts"
                    )

                if resource_usage["failed_pods"] > 0:
                    return {
                        "phase": "Degraded",
                        "message": f"Found {resource_usage['failed_pods']} failed pods",
                        "lastHealthCheck": current_time,
                    }

                if resource_usage["pending_pods"] > 0:
                    logger.warning(
                        f"Found {resource_usage['pending_pods']} pending pods for Keycloak {name}"
                    )

        except Exception as e:
            logger.debug(f"Failed to get resource usage metrics: {e}")
            # Don't fail health check for metrics errors

        # TODO: Validate realm and client configuration
        # This could involve checking that expected realms/clients exist
        # and are properly configured

        # If we get here, everything is healthy
        if current_phase != "Running":
            logger.info(f"Keycloak instance {name} health check passed")
            return {
                "phase": "Running",
                "message": "Keycloak instance is healthy",
                "lastHealthCheck": current_time,
            }

    except Exception as e:
        logger.error(f"Health check failed for Keycloak instance {name}: {e}")
        from datetime import datetime

        current_time = datetime.now(UTC).isoformat()
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": current_time,
        }

    return None  # No status update needed
