"""
Kubernetes utilities for the Keycloak operator.

This module provides helper functions for interacting with the Kubernetes API,
including resource management, RBAC validation, and cluster operations.

Key functionality:
- Kubernetes client management and configuration
- Resource creation and management (deployments, services, secrets)
- RBAC permission validation
- Cross-namespace resource discovery
- Status and health monitoring
"""

import logging
import time
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


def get_kubernetes_client() -> client.ApiClient:
    """
    Get configured Kubernetes API client.

    This function handles both in-cluster and local development configurations.

    Returns:
        Configured Kubernetes API client

    TODO: Implement the following functionality:
    1. Try to load in-cluster configuration first
    2. Fall back to kubeconfig for development
    3. Handle configuration errors gracefully
    4. Return configured client
    """
    try:
        # Try in-cluster config first (when running in a pod)
        config.load_incluster_config()
        logger.debug("Loaded in-cluster Kubernetes configuration")
    except config.ConfigException:
        try:
            # Fall back to local kubeconfig (for development)
            config.load_kube_config()
            logger.debug("Loaded kubeconfig from local environment")
        except config.ConfigException as e:
            logger.error(f"Failed to load Kubernetes configuration: {e}")
            raise

    return client.ApiClient()


def validate_keycloak_reference(
    keycloak_name: str, namespace: str
) -> dict[str, Any] | None:
    """
    Validate that a Keycloak instance reference is valid and ready.

    Args:
        keycloak_name: Name of the Keycloak instance
        namespace: Namespace where the instance should exist

    Returns:
        Keycloak instance details if valid and ready, None otherwise

    TODO: Implement the following functionality:
    1. Look up Keycloak custom resource
    2. Check that it exists and has required status fields
    3. Verify that the instance is in "Running" phase
    4. Return instance details or None
    """
    logger.debug(f"Validating Keycloak reference: {keycloak_name} in {namespace}")

    try:
        k8s = get_kubernetes_client()
        custom_api = client.CustomObjectsApi(k8s)

        # TODO: Get Keycloak instance
        keycloak_instance = custom_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )

        # TODO: Check instance status
        status = keycloak_instance.get("status", {})
        phase = status.get("phase")

        if phase != "Running":
            logger.warning(
                f"Keycloak instance {keycloak_name} is not ready (phase: {phase})"
            )
            return None

        # TODO: Verify required endpoints exist
        endpoints = status.get("endpoints", {})
        if not endpoints.get("admin") or not endpoints.get("public"):
            logger.warning(
                f"Keycloak instance {keycloak_name} missing required endpoints"
            )
            return None

        logger.debug(f"Keycloak instance {keycloak_name} is valid and ready")
        return keycloak_instance

    except ApiException as e:
        if e.status == 404:
            logger.warning(f"Keycloak instance {keycloak_name} not found")
            return None
        logger.error(f"Error validating Keycloak reference: {e}")
        return None


def create_keycloak_deployment(
    name: str,
    namespace: str,
    spec: Any,  # KeycloakSpec type
    k8s_client: client.ApiClient,
) -> client.V1Deployment:
    """
    Create Kubernetes Deployment for a Keycloak instance.

    Args:
        name: Name of the Keycloak resource
        namespace: Target namespace
        spec: Keycloak specification
        k8s_client: Kubernetes API client

    Returns:
        Created Deployment object

    TODO: Implement the following functionality:
    1. Build Deployment manifest from Keycloak spec
    2. Configure container image, resources, environment variables
    3. Set up volume mounts for persistent storage
    4. Configure probes and security context
    5. Apply proper labels and annotations
    6. Create deployment using Kubernetes API
    7. Return created deployment
    """
    logger.info(f"Creating Keycloak deployment {name} in namespace {namespace}")

    # TODO: Build deployment manifest
    deployment_name = f"{name}-keycloak"

    # Container configuration
    container = client.V1Container(
        name="keycloak",
        image=spec.image or "quay.io/keycloak/keycloak:latest",
        ports=[
            client.V1ContainerPort(container_port=8080, name="http"),
            client.V1ContainerPort(container_port=9000, name="management"),
        ],
        env=[
            # TODO: Configure environment variables from spec
            client.V1EnvVar(name="KEYCLOAK_ADMIN", value="admin"),
            client.V1EnvVar(
                name="KEYCLOAK_ADMIN_PASSWORD",
                value_from=client.V1EnvVarSource(
                    secret_key_ref=client.V1SecretKeySelector(
                        name=f"{name}-admin-credentials",
                        key="password",
                    )
                ),
            ),
            client.V1EnvVar(name="KC_HEALTH_ENABLED", value="true"),
            client.V1EnvVar(name="KC_METRICS_ENABLED", value="true"),
        ],
        resources=client.V1ResourceRequirements(
            requests={
                "cpu": spec.resources.get("requests", {}).get("cpu", "500m"),
                "memory": spec.resources.get("requests", {}).get("memory", "512Mi"),
            },
            limits={
                "cpu": spec.resources.get("limits", {}).get("cpu", "1000m"),
                "memory": spec.resources.get("limits", {}).get("memory", "1Gi"),
            },
        ),
        liveness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(
                path="/health/live",
                port=9000,
            ),
            initial_delay_seconds=60,
            period_seconds=30,
        ),
        readiness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(
                path="/health/ready",
                port=9000,
            ),
            initial_delay_seconds=30,
            period_seconds=10,
        ),
        # TODO: Add volume mounts for persistent storage
        # TODO: Configure security context
    )

    # Pod template
    pod_template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(
            labels={
                "app": "keycloak",
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "server",
            }
        ),
        spec=client.V1PodSpec(
            containers=[container],
            # TODO: Configure service account, security context, volumes
        ),
    )

    # Deployment specification
    deployment_spec = client.V1DeploymentSpec(
        replicas=spec.replicas or 1,
        selector=client.V1LabelSelector(
            match_labels={
                "app": "keycloak",
                "keycloak.mdvr.nl/instance": name,
            }
        ),
        template=pod_template,
        strategy=client.V1DeploymentStrategy(
            type="RollingUpdate",
            rolling_update=client.V1RollingUpdateDeployment(
                max_unavailable="25%",
                max_surge="25%",
            ),
        ),
    )

    # Create deployment object
    deployment = client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=client.V1ObjectMeta(
            name=deployment_name,
            namespace=namespace,
            labels={
                "app": "keycloak",
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "server",
            },
            # TODO: Set owner reference to Keycloak resource
        ),
        spec=deployment_spec,
    )

    # Create deployment using Kubernetes API
    try:
        apps_api = client.AppsV1Api(k8s_client)
        created_deployment = apps_api.create_namespaced_deployment(
            namespace=namespace, body=deployment
        )

        logger.info(f"Created deployment {deployment_name}")
        return created_deployment

    except ApiException as e:
        logger.error(f"Failed to create deployment {deployment_name}: {e}")
        raise


def create_keycloak_service(
    name: str,
    namespace: str,
    spec: Any,  # KeycloakSpec type
    k8s_client: client.ApiClient,
) -> client.V1Service:
    """
    Create Kubernetes Service for a Keycloak instance.

    Args:
        name: Name of the Keycloak resource
        namespace: Target namespace
        spec: Keycloak specification
        k8s_client: Kubernetes API client

    Returns:
        Created Service object

    TODO: Implement the following functionality:
    1. Build Service manifest for Keycloak instance
    2. Configure ports for HTTP and management endpoints
    3. Set up proper selectors to match deployment pods
    4. Configure service type (ClusterIP, LoadBalancer, etc.)
    5. Apply labels and annotations
    6. Create service using Kubernetes API
    7. Return created service
    """
    logger.info(f"Creating Keycloak service {name} in namespace {namespace}")

    service_name = f"{name}-keycloak"

    # Service specification
    service_spec = client.V1ServiceSpec(
        selector={
            "app": "keycloak",
            "keycloak.mdvr.nl/instance": name,
        },
        ports=[
            client.V1ServicePort(
                name="http",
                port=8080,
                target_port=8080,
                protocol="TCP",
            ),
            client.V1ServicePort(
                name="management",
                port=9000,
                target_port=9000,
                protocol="TCP",
            ),
        ],
        type=spec.service.get("type", "ClusterIP")
        if hasattr(spec, "service")
        else "ClusterIP",
    )

    # Create service object
    service = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(
            name=service_name,
            namespace=namespace,
            labels={
                "app": "keycloak",
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "service",
            },
            # TODO: Set owner reference to Keycloak resource
        ),
        spec=service_spec,
    )

    # Create service using Kubernetes API
    try:
        core_api = client.CoreV1Api(k8s_client)
        created_service = core_api.create_namespaced_service(
            namespace=namespace, body=service
        )

        logger.info(f"Created service {service_name}")
        return created_service

    except ApiException as e:
        logger.error(f"Failed to create service {service_name}: {e}")
        raise


def create_client_secret(
    secret_name: str,
    namespace: str,
    client_id: str,
    client_secret: str | None,
    keycloak_url: str,
    realm: str,
    update_existing: bool = False,
) -> client.V1Secret:
    """
    Create or update a Kubernetes secret containing client credentials.

    Args:
        secret_name: Name of the secret to create
        namespace: Target namespace
        client_id: Keycloak client ID
        client_secret: Client secret (None for public clients)
        keycloak_url: Keycloak server URL
        realm: Realm name
        update_existing: Whether to update if secret already exists

    Returns:
        Created or updated Secret object

    TODO: Implement the following functionality:
    1. Build secret data with client credentials and connection info
    2. Encode sensitive data properly
    3. Set appropriate labels and annotations
    4. Handle both creation and updates
    5. Apply proper RBAC and ownership
    6. Return created/updated secret
    """
    logger.info(f"Creating client secret {secret_name} in namespace {namespace}")

    import base64

    # Prepare secret data
    secret_data = {
        "client-id": base64.b64encode(client_id.encode()).decode(),
        "keycloak-url": base64.b64encode(keycloak_url.encode()).decode(),
        "realm": base64.b64encode(realm.encode()).decode(),
    }

    # Add client secret if this is a confidential client
    if client_secret:
        secret_data["client-secret"] = base64.b64encode(client_secret.encode()).decode()

    # TODO: Add additional connection information
    # - Token endpoint URL
    # - User info endpoint URL
    # - JWKS endpoint URL
    # - Issuer URL

    # Create secret object
    secret = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/client": client_id,
                "keycloak.mdvr.nl/realm": realm,
                "keycloak.mdvr.nl/component": "client-credentials",
            },
            annotations={
                "keycloak.mdvr.nl/client-type": "confidential"
                if client_secret
                else "public",
            },
        ),
        type="Opaque",
        data=secret_data,
    )

    # Create or update secret
    try:
        k8s = get_kubernetes_client()
        core_api = client.CoreV1Api(k8s)

        if update_existing:
            # Try to update existing secret
            try:
                updated_secret = core_api.patch_namespaced_secret(
                    name=secret_name, namespace=namespace, body=secret
                )
                logger.info(f"Updated existing secret {secret_name}")
                return updated_secret
            except ApiException as e:
                if e.status == 404:
                    # Secret doesn't exist, create it
                    pass
                else:
                    raise

        # Create new secret
        created_secret = core_api.create_namespaced_secret(
            namespace=namespace, body=secret
        )
        logger.info(f"Created secret {secret_name}")
        return created_secret

    except ApiException as e:
        logger.error(f"Failed to create/update secret {secret_name}: {e}")
        raise


def check_rbac_permissions(
    service_account: str,
    namespace: str,
    target_namespace: str,
    resource: str,
    verb: str,
) -> bool:
    """
    Check if a service account has specific RBAC permissions.

    Args:
        service_account: Service account name
        namespace: Service account namespace
        target_namespace: Namespace where permission is needed
        resource: Kubernetes resource type
        verb: Action to check (get, create, update, delete)

    Returns:
        True if permission is granted, False otherwise

    TODO: Implement the following functionality:
    1. Use SubjectAccessReview to check permissions
    2. Handle both namespace-scoped and cluster-scoped resources
    3. Check for wildcard permissions
    4. Cache results for performance
    5. Log permission denials for troubleshooting
    """
    logger.debug(
        f"Checking RBAC permissions: {service_account} -> "
        f"{verb} {resource} in {target_namespace}"
    )

    try:
        k8s = get_kubernetes_client()
        auth_api = client.AuthorizationV1Api(k8s)

        # Create SubjectAccessReview
        access_review = client.V1SubjectAccessReview(
            spec=client.V1SubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(
                    namespace=target_namespace,
                    verb=verb,
                    group="keycloak.mdvr.nl",  # TODO: Make this configurable
                    resource=resource,
                ),
                user=f"system:serviceaccount:{namespace}:{service_account}",
            )
        )

        # TODO: Perform access review
        result = auth_api.create_subject_access_review(access_review)
        allowed = result.status.allowed

        if not allowed:
            logger.warning(
                f"RBAC permission denied: {service_account} cannot {verb} "
                f"{resource} in {target_namespace}"
            )
            if result.status.reason:
                logger.debug(f"Denial reason: {result.status.reason}")

        return allowed

    except ApiException as e:
        logger.error(f"Failed to check RBAC permissions: {e}")
        return False


def find_keycloak_instances(namespace: str | None = None) -> list[dict[str, Any]]:
    """
    Find Keycloak instances across namespaces.

    Args:
        namespace: Specific namespace to search, or None for cluster-wide

    Returns:
        List of Keycloak instance dictionaries

    TODO: Implement the following functionality:
    1. Search for Keycloak custom resources
    2. Filter by namespace if specified
    3. Return list of instances with status information
    4. Handle API errors gracefully
    """
    logger.debug(f"Finding Keycloak instances in namespace: {namespace or 'all'}")

    try:
        k8s = get_kubernetes_client()
        custom_api = client.CustomObjectsApi(k8s)

        if namespace:
            # Search in specific namespace
            response = custom_api.list_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
            )
        else:
            # Search cluster-wide
            response = custom_api.list_cluster_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                plural="keycloaks",
            )

        instances = response.get("items", [])
        logger.debug(f"Found {len(instances)} Keycloak instances")
        return instances

    except ApiException as e:
        logger.error(f"Failed to find Keycloak instances: {e}")
        return []


def set_owner_reference(
    resource: Any,
    owner_name: str,
    owner_uid: str,
    owner_kind: str = "Keycloak",
    api_version: str = "keycloak.mdvr.nl/v1",
) -> None:
    """
    Set owner reference for garbage collection.

    Args:
        resource: Kubernetes resource to set owner reference on
        owner_name: Name of the owner resource
        owner_uid: UID of the owner resource
        owner_kind: Kind of the owner resource
        api_version: API version of the owner resource
    """
    if (
        not hasattr(resource.metadata, "owner_references")
        or resource.metadata.owner_references is None
    ):
        resource.metadata.owner_references = []

    owner_ref = client.V1OwnerReference(
        api_version=api_version,
        kind=owner_kind,
        name=owner_name,
        uid=owner_uid,
        controller=True,
        block_owner_deletion=True,
    )

    resource.metadata.owner_references.append(owner_ref)


def create_persistent_volume_claim(
    name: str,
    namespace: str,
    size: str = "10Gi",
    storage_class: str | None = None,
) -> client.V1PersistentVolumeClaim:
    """
    Create a PersistentVolumeClaim for Keycloak data storage.

    Args:
        name: Name of the Keycloak instance
        namespace: Target namespace
        size: Storage size (e.g., "10Gi")
        storage_class: Storage class name (optional)

    Returns:
        Created PersistentVolumeClaim object
    """
    pvc_name = f"{name}-keycloak-data"

    pvc_spec = client.V1PersistentVolumeClaimSpec(
        access_modes=["ReadWriteOnce"],
        resources=client.V1ResourceRequirements(requests={"storage": size}),
    )

    if storage_class:
        pvc_spec.storage_class_name = storage_class

    pvc = client.V1PersistentVolumeClaim(
        api_version="v1",
        kind="PersistentVolumeClaim",
        metadata=client.V1ObjectMeta(
            name=pvc_name,
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "data-storage",
            },
        ),
        spec=pvc_spec,
    )

    try:
        k8s = get_kubernetes_client()
        core_api = client.CoreV1Api(k8s)
        created_pvc = core_api.create_namespaced_persistent_volume_claim(
            namespace=namespace, body=pvc
        )

        logger.info(f"Created PVC {pvc_name}")
        return created_pvc

    except ApiException as e:
        logger.error(f"Failed to create PVC {pvc_name}: {e}")
        raise


def create_keycloak_ingress(
    name: str,
    namespace: str,
    spec: Any,  # KeycloakSpec type
    k8s_client: client.ApiClient,
) -> client.V1Ingress:
    """
    Create Kubernetes Ingress for a Keycloak instance.

    Args:
        name: Name of the Keycloak resource
        namespace: Target namespace
        spec: Keycloak specification
        k8s_client: Kubernetes API client

    Returns:
        Created Ingress object
    """
    logger.info(f"Creating Keycloak ingress {name} in namespace {namespace}")

    if not hasattr(spec, "ingress") or not spec.ingress.enabled:
        raise ValueError("Ingress configuration is required but not provided")

    ingress_name = f"{name}-keycloak"
    service_name = f"{name}-keycloak"

    # Build ingress rules
    rules = []
    if spec.ingress.hostname:
        rule = client.V1IngressRule(
            host=spec.ingress.hostname,
            http=client.V1HTTPIngressRuleValue(
                paths=[
                    client.V1HTTPIngressPath(
                        path="/",
                        path_type="Prefix",
                        backend=client.V1IngressBackend(
                            service=client.V1IngressServiceBackend(
                                name=service_name,
                                port=client.V1ServiceBackendPort(number=8080),
                            )
                        ),
                    )
                ]
            ),
        )
        rules.append(rule)

    # Configure TLS if specified
    tls = []
    if getattr(spec.ingress, "tls", {}).get("enabled", False):
        tls_config = client.V1IngressTLS(
            hosts=[spec.ingress.hostname] if spec.ingress.hostname else [],
            secret_name=getattr(spec.ingress.tls, "secret_name", f"{name}-tls"),
        )
        tls.append(tls_config)

    # Create ingress object
    ingress = client.V1Ingress(
        api_version="networking.k8s.io/v1",
        kind="Ingress",
        metadata=client.V1ObjectMeta(
            name=ingress_name,
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "ingress",
            },
            annotations=getattr(spec.ingress, "annotations", {}),
        ),
        spec=client.V1IngressSpec(
            ingress_class_name=getattr(spec.ingress, "class_name", None),
            rules=rules,
            tls=tls if tls else None,
        ),
    )

    try:
        networking_api = client.NetworkingV1Api(k8s_client)
        created_ingress = networking_api.create_namespaced_ingress(
            namespace=namespace, body=ingress
        )

        logger.info(f"Created ingress {ingress_name}")
        return created_ingress

    except ApiException as e:
        logger.error(f"Failed to create ingress {ingress_name}: {e}")
        raise


def backup_keycloak_data(
    name: str,
    namespace: str,
    spec: Any,  # KeycloakSpec type
    k8s_client: client.ApiClient,
) -> client.V1Job:
    """
    Create a Kubernetes Job to backup Keycloak data.

    Args:
        name: Name of the Keycloak resource
        namespace: Target namespace
        spec: Keycloak specification
        k8s_client: Kubernetes API client

    Returns:
        Created Job object
    """
    logger.info(f"Creating Keycloak backup job for {name} in namespace {namespace}")

    job_name = f"{name}-backup-{int(time.time())}"
    service_name = f"{name}-keycloak"

    # Create backup job container
    container = client.V1Container(
        name="keycloak-backup",
        image="curlimages/curl:latest",
        command=[
            "/bin/sh",
            "-c",
            f"""
            echo "Starting Keycloak backup for {name}"

            # Get admin credentials
            ADMIN_USER=$(cat /etc/keycloak-admin/username)
            ADMIN_PASS=$(cat /etc/keycloak-admin/password)

            # Export realms using Keycloak Admin REST API
            echo "Exporting realms..."
            curl -k -X GET \
                -u "$ADMIN_USER:$ADMIN_PASS" \
                "http://{service_name}:8080/admin/realms" \
                -H "Accept: application/json" \
                > /backup/realms.json

            # Export users for each realm (simplified)
            echo "Backup completed successfully"
            ls -la /backup/
            """,
        ],
        volume_mounts=[
            client.V1VolumeMount(
                name="admin-credentials",
                mount_path="/etc/keycloak-admin",
                read_only=True,
            ),
            client.V1VolumeMount(
                name="backup-storage", mount_path="/backup", read_only=False
            ),
        ],
    )

    # Create job specification
    job_spec = client.V1JobSpec(
        template=client.V1PodTemplateSpec(
            metadata=client.V1ObjectMeta(
                labels={
                    "keycloak.mdvr.nl/instance": name,
                    "keycloak.mdvr.nl/component": "backup",
                }
            ),
            spec=client.V1PodSpec(
                restart_policy="Never",
                containers=[container],
                volumes=[
                    client.V1Volume(
                        name="admin-credentials",
                        secret=client.V1SecretVolumeSource(
                            secret_name=f"{name}-admin-credentials"
                        ),
                    ),
                    client.V1Volume(
                        name="backup-storage",
                        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                            claim_name=f"{name}-backup-pvc"
                        ),
                    ),
                ],
            ),
        ),
        backoff_limit=3,
    )

    # Create job object
    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(
            name=job_name,
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "backup",
            },
        ),
        spec=job_spec,
    )

    try:
        batch_api = client.BatchV1Api(k8s_client)
        created_job = batch_api.create_namespaced_job(namespace=namespace, body=job)

        logger.info(f"Created backup job {job_name}")
        return created_job

    except ApiException as e:
        logger.error(f"Failed to create backup job {job_name}: {e}")
        raise


def check_http_health(url: str, timeout: int = 5) -> tuple[bool, str | None]:
    """
    Perform HTTP health check against a URL.

    Args:
        url: URL to check
        timeout: Request timeout in seconds

    Returns:
        Tuple of (is_healthy, error_message)
    """
    try:
        import requests

        response = requests.get(url, timeout=timeout, verify=False)
        if response.status_code == 200:
            return True, None
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"

    except ImportError:
        # requests not available, fall back to urllib
        try:
            import urllib.error
            import urllib.request

            request = urllib.request.Request(url)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status == 200:
                    return True, None
                else:
                    return False, f"HTTP {response.status}"

        except urllib.error.URLError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    except Exception as e:
        return False, str(e)


def get_pod_resource_usage(
    name: str, namespace: str, k8s_client: client.ApiClient
) -> dict[str, Any]:
    """
    Get resource usage metrics for Keycloak pods.

    Args:
        name: Name of the Keycloak resource
        namespace: Target namespace
        k8s_client: Kubernetes API client

    Returns:
        Dictionary with resource usage information
    """
    try:
        core_api = client.CoreV1Api(k8s_client)

        # Get pods for this Keycloak instance
        label_selector = f"keycloak.mdvr.nl/instance={name}"
        pods = core_api.list_namespaced_pod(
            namespace=namespace, label_selector=label_selector
        )

        resource_usage = {
            "total_pods": len(pods.items),
            "running_pods": 0,
            "pending_pods": 0,
            "failed_pods": 0,
            "pods": [],
        }

        for pod in pods.items:
            pod_info = {
                "name": pod.metadata.name,
                "phase": pod.status.phase,
                "ready": False,
                "restarts": 0,
            }

            if pod.status.phase == "Running":
                resource_usage["running_pods"] += 1
            elif pod.status.phase == "Pending":
                resource_usage["pending_pods"] += 1
            elif pod.status.phase == "Failed":
                resource_usage["failed_pods"] += 1

            # Check container readiness and restart counts
            if pod.status.container_statuses:
                for container_status in pod.status.container_statuses:
                    if container_status.ready:
                        pod_info["ready"] = True
                    pod_info["restarts"] += container_status.restart_count

            resource_usage["pods"].append(pod_info)

        return resource_usage

    except ApiException as e:
        logger.error(f"Failed to get resource usage: {e}")
        return {"error": str(e)}


def create_admin_secret(
    name: str,
    namespace: str,
    username: str = "admin",
    password: str | None = None,
) -> client.V1Secret:
    """
    Create a secret containing Keycloak admin credentials.

    Args:
        name: Name of the Keycloak instance
        namespace: Target namespace
        username: Admin username
        password: Admin password (generated if not provided)

    Returns:
        Created Secret object

    TODO: Implement the following functionality:
    1. Generate secure password if not provided
    2. Create secret with admin credentials
    3. Set proper labels and ownership
    4. Return created secret
    """
    import base64
    import secrets
    import string

    if not password:
        # Generate secure random password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = "".join(secrets.choice(alphabet) for _ in range(16))

    secret_name = f"{name}-admin-credentials"

    secret_data = {
        "username": base64.b64encode(username.encode()).decode(),
        "password": base64.b64encode(password.encode()).decode(),
    }

    secret = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/instance": name,
                "keycloak.mdvr.nl/component": "admin-credentials",
            },
        ),
        type="Opaque",
        data=secret_data,
    )

    try:
        k8s = get_kubernetes_client()
        core_api = client.CoreV1Api(k8s)
        created_secret = core_api.create_namespaced_secret(
            namespace=namespace, body=secret
        )

        logger.info(f"Created admin secret {secret_name}")
        return created_secret

    except ApiException as e:
        logger.error(f"Failed to create admin secret: {e}")
        raise
