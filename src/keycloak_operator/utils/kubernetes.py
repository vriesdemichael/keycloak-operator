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

from keycloak_operator.constants import DEFAULT_KEYCLOAK_IMAGE

logger = logging.getLogger(__name__)


def get_kubernetes_client() -> client.ApiClient:
    """
        Get configured Kubernetes API client.

        This function handles both in-cluster and local development configurations.

        Returns:
            Configured Kubernetes API client

    This function handles both in-cluster and local development configurations.
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

    This function validates Keycloak instance readiness and availability.
    """
    logger.debug(f"Validating Keycloak reference: {keycloak_name} in {namespace}")

    try:
        k8s = get_kubernetes_client()
        custom_api = client.CustomObjectsApi(k8s)

        # Get Keycloak instance
        keycloak_instance = custom_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )

        # Check instance status
        status = keycloak_instance.get("status", {})
        phase = status.get("phase")

        if phase != "Ready":
            logger.warning(
                f"Keycloak instance {keycloak_name} is not ready (phase: {phase})"
            )
            return None

        # Verify required endpoints exist
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
    db_connection_info: dict[str, Any] | None = None,
) -> client.V1Deployment:
    """
        Create Kubernetes Deployment for a Keycloak instance.

        Args:
            name: Name of the Keycloak resource
            namespace: Target namespace
            spec: Keycloak specification
            k8s_client: Kubernetes API client
            db_connection_info: Optional resolved database connection details (for CNPG)

        Returns:
            Created Deployment object

    This function creates a complete Keycloak deployment with proper configuration.
    """
    logger.info(f"Creating Keycloak deployment {name} in namespace {namespace}")

    # Build deployment manifest
    deployment_name = f"{name}-keycloak"

    # Build environment variables list
    # Admin credentials come from operator-generated secret
    admin_secret_name = f"{name}-admin-credentials"

    env_vars = [
        # Keycloak admin bootstrap variables (support both old and new versions)
        # KEYCLOAK_ADMIN* for Keycloak <= 23
        client.V1EnvVar(
            name="KEYCLOAK_ADMIN",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name=admin_secret_name,
                    key="username",
                )
            ),
        ),
        client.V1EnvVar(
            name="KEYCLOAK_ADMIN_PASSWORD",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name=admin_secret_name,
                    key="password",
                )
            ),
        ),
        # KC_BOOTSTRAP_ADMIN* for Keycloak >= 24
        client.V1EnvVar(
            name="KC_BOOTSTRAP_ADMIN_USERNAME",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name=admin_secret_name,
                    key="username",
                )
            ),
        ),
        client.V1EnvVar(
            name="KC_BOOTSTRAP_ADMIN_PASSWORD",
            value_from=client.V1EnvVarSource(
                secret_key_ref=client.V1SecretKeySelector(
                    name=admin_secret_name,
                    key="password",
                )
            ),
        ),
    ]

    # Add other environment variables
    env_vars.extend(
        [
            # Keycloak feature configuration
            client.V1EnvVar(name="KC_HEALTH_ENABLED", value="true"),
            client.V1EnvVar(name="KC_METRICS_ENABLED", value="true"),
            # Management port for health and metrics endpoints
            client.V1EnvVar(name="KC_HTTP_MANAGEMENT_PORT", value="9000"),
            # Hostname configuration for flexibility
            client.V1EnvVar(name="KC_HOSTNAME_STRICT", value="false"),
        ]
    )

    # Add database configuration environment variables if configured
    if spec.database and spec.database.type != "h2":
        # Database type - map CRD values to Keycloak values
        db_type_mapping = {
            "postgresql": "postgres",
            "mariadb": "mariadb",
            "mysql": "mysql",
            "oracle": "oracle",
            "mssql": "mssql",
        }
        kc_db_type = db_type_mapping.get(spec.database.type, spec.database.type)
        env_vars.append(client.V1EnvVar(name="KC_DB", value=kc_db_type))

        # Database connection details
        if spec.database.host:
            env_vars.append(
                client.V1EnvVar(name="KC_DB_URL_HOST", value=spec.database.host)
            )

        if spec.database.port:
            env_vars.append(
                client.V1EnvVar(name="KC_DB_URL_PORT", value=str(spec.database.port))
            )

        if spec.database.database:
            env_vars.append(
                client.V1EnvVar(name="KC_DB_URL_DATABASE", value=spec.database.database)
            )

            if spec.database.username:
                env_vars.append(
                    client.V1EnvVar(name="KC_DB_USERNAME", value=spec.database.username)
                )

            # Database password from secret if specified (tolerate absence of attribute)
            # Derive password source precedence: explicit password_secret (legacy) -> credentials_secret -> none
            password_secret = getattr(spec.database, "password_secret", None)
            if password_secret:
                try:
                    secret_name = password_secret.name
                    secret_key = getattr(password_secret, "key", "password")
                    env_vars.append(
                        client.V1EnvVar(
                            name="KC_DB_PASSWORD",
                            value_from=client.V1EnvVarSource(
                                secret_key_ref=client.V1SecretKeySelector(
                                    name=secret_name, key=secret_key
                                )
                            ),
                        )
                    )
                except Exception as exc:  # pragma: no cover
                    logger.warning(
                        f"Legacy password_secret reference could not be applied: {exc}"
                    )
            else:
                # credentials_secret is just a secret name storing username/password (username already handled separately if provided)
                credentials_secret_name = getattr(
                    spec.database, "credentials_secret", None
                )
                if credentials_secret_name:
                    env_vars.append(
                        client.V1EnvVar(
                            name="KC_DB_PASSWORD",
                            value_from=client.V1EnvVarSource(
                                secret_key_ref=client.V1SecretKeySelector(
                                    name=credentials_secret_name, key="password"
                                )
                            ),
                        )
                    )

    # Container configuration
    # Use production mode with HTTP enabled for ingress TLS termination
    # Note: --optimized flag omitted to allow runtime database configuration
    container = client.V1Container(
        name="keycloak",
        image=spec.image or DEFAULT_KEYCLOAK_IMAGE,
        command=["/opt/keycloak/bin/kc.sh"],
        args=["start", "--http-enabled=true", "--proxy-headers=xforwarded"],
        ports=[
            client.V1ContainerPort(container_port=8080, name="http"),
            client.V1ContainerPort(container_port=9000, name="management"),
        ],
        env=env_vars,
        resources=client.V1ResourceRequirements(
            requests={
                "cpu": spec.resources.requests.get("cpu", "500m"),
                "memory": spec.resources.requests.get("memory", "512Mi"),
            },
            limits={
                "cpu": spec.resources.limits.get("cpu", "1000m"),
                "memory": spec.resources.limits.get("memory", "1Gi"),
            },
        ),
        liveness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(
                path="/health/live",
                port=9000,  # Use management port for health endpoints
            ),
            initial_delay_seconds=60,
            period_seconds=30,
        ),
        readiness_probe=client.V1Probe(
            http_get=client.V1HTTPGetAction(
                path="/health/ready",
                port=9000,  # Use management port for health endpoints
            ),
            initial_delay_seconds=30,
            period_seconds=10,
        ),
        security_context=client.V1SecurityContext(
            allow_privilege_escalation=False,
            run_as_non_root=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
        ),
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
            security_context=client.V1PodSecurityContext(
                run_as_non_root=True,
                seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"),
            ),
            # Service account and volumes can be configured as needed
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
            # Owner reference can be set by calling code
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

    This function creates a Kubernetes service with proper port configuration and selectors.
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
        type=spec.service.type
        if hasattr(spec, "service") and spec.service
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
            # Owner reference can be set by calling code
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

    Creates a Kubernetes secret containing client credentials and connection info.
    Handles both creation and updates with proper encoding and metadata.
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

    # Add additional connection information
    # Build OpenID Connect endpoint URLs
    realm_base_url = f"{keycloak_url}/realms/{realm}"
    secret_data.update(
        {
            "token-endpoint": base64.b64encode(
                f"{realm_base_url}/protocol/openid-connect/token".encode()
            ).decode(),
            "userinfo-endpoint": base64.b64encode(
                f"{realm_base_url}/protocol/openid-connect/userinfo".encode()
            ).decode(),
            "jwks-endpoint": base64.b64encode(
                f"{realm_base_url}/protocol/openid-connect/certs".encode()
            ).decode(),
            "issuer": base64.b64encode(realm_base_url.encode()).decode(),
        }
    )

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


def find_keycloak_instances(namespace: str | None = None) -> list[dict[str, Any]]:
    """
    Find Keycloak instances across namespaces.

    Args:
        namespace: Specific namespace to search, or None for cluster-wide

    Returns:
        List of Keycloak instance dictionaries

    Searches for Keycloak custom resources and returns instances with status information.
    Handles API errors gracefully and supports both namespace-specific and cluster-wide searches.
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


async def check_http_health(url: str, timeout: int = 5) -> tuple[bool, str | None]:
    """
    Perform HTTP health check against a URL.

    Args:
        url: URL to check
        timeout: Request timeout in seconds

    Returns:
        Tuple of (is_healthy, error_message)
    """
    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 200:
                return True, None
            else:
                return False, f"HTTP {response.status_code}: {response.text[:200]}"

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

    Creates a secret with admin credentials, generating secure passwords when needed.
    Sets proper labels and ownership for the secret.
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

        # Attempt create with small bounded retries for transient conflicts
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                created_secret = core_api.create_namespaced_secret(
                    namespace=namespace, body=secret
                )
                logger.info(f"Created admin secret {secret_name} (attempt {attempt})")
                return created_secret
            except ApiException as e:
                if e.status == 409:  # AlreadyExists race condition
                    # Another replica created it; treat as success
                    try:
                        existing = core_api.read_namespaced_secret(
                            name=secret_name, namespace=namespace
                        )
                        logger.info(
                            f"Admin secret {secret_name} already exists (attempt {attempt}) - using existing"
                        )
                        return existing
                    except ApiException as read_err:  # pragma: no cover
                        if attempt == max_attempts:
                            logger.error(
                                f"Failed to read existing admin secret {secret_name} after conflict: {read_err}"
                            )
                            raise
                        # brief backoff then retry
                        import time

                        time.sleep(0.2 * attempt)
                        continue
                # For other errors, only retry if it's a retryable 5xx
                status_code = getattr(e, "status", None)
                if (
                    status_code is not None
                    and isinstance(status_code, int)
                    and 500 <= status_code < 600
                    and attempt < max_attempts
                ):
                    import time

                    logger.warning(
                        f"Transient error creating admin secret {secret_name} (status {e.status}) attempt {attempt}/{max_attempts}: {e}. Retrying..."
                    )
                    time.sleep(0.2 * attempt)
                    continue
                logger.error(
                    f"Failed to create admin secret {secret_name} (attempt {attempt}): {e}"
                )
                raise
        # Should not reach here
        raise RuntimeError(
            f"Exhausted attempts creating admin secret {secret_name}"
        )  # pragma: no cover
    except ApiException as e:  # pragma: no cover - defensive outer layer
        logger.error(
            f"Failed accessing Kubernetes API for admin secret {secret_name}: {e}"
        )
        raise


def check_rbac_permissions(
    namespace: str,
    target_namespace: str,
    resource: str = "keycloaks",
    verb: str = "get",
    api_group: str | None = None,
) -> bool:
    """
    Check if the current service account has RBAC permissions for cross-namespace access.

    This function performs a Kubernetes SubjectAccessReview to validate that the operator
    has the necessary permissions to access resources in other namespaces.

    Args:
        namespace: Source namespace (where the request originates)
        target_namespace: Target namespace to access
        resource: Kubernetes resource type to check
        verb: Action to perform (get, create, update, delete, etc.)
        api_group: API group for the resource (None for auto-detection)

    Returns:
        True if permission is granted, False otherwise
    """
    if namespace == target_namespace:
        return True  # Same namespace access is always allowed

    try:
        k8s = get_kubernetes_client()
        auth_api = client.AuthorizationV1Api(k8s)

        # Auto-detect API group if not specified
        if api_group is None:
            # Core resources use empty string, custom resources use keycloak.mdvr.nl
            core_resources = {
                "secrets",
                "configmaps",
                "services",
                "pods",
                "serviceaccounts",
                "persistentvolumeclaims",
            }
            api_group = "" if resource in core_resources else "keycloak.mdvr.nl"

        # Get service account information
        sa_info = get_current_service_account_info()
        service_account_user = (
            f"system:serviceaccount:{sa_info['namespace']}:{sa_info['name']}"
        )

        # Create SubjectAccessReview to check permissions
        access_review = client.V1SubjectAccessReview(
            spec=client.V1SubjectAccessReviewSpec(
                user=service_account_user,
                resource_attributes=client.V1ResourceAttributes(
                    namespace=target_namespace,
                    verb=verb,
                    group=api_group,
                    resource=resource,
                ),
            )
        )

        result = auth_api.create_subject_access_review(access_review)
        allowed = result.status.allowed

        if not allowed:
            logger.warning(
                f"RBAC permission denied: {verb} {resource} in namespace "
                f"{target_namespace} from {namespace}. Reason: {result.status.reason}"
            )
        else:
            logger.debug(
                f"RBAC permission granted: {verb} {resource} in namespace "
                f"{target_namespace} from {namespace}"
            )

        return allowed

    except ApiException as e:
        logger.error(f"Failed to check RBAC permissions: {e}")
        # Default to deny on API errors for security
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking RBAC permissions: {e}")
        return False


def get_current_service_account_info() -> dict[str, str]:
    """
    Get information about the current service account being used by the operator.

    Returns:
        Dictionary with service account name and namespace
    """
    try:
        # Read service account info from mounted token
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as f:
            namespace = f.read().strip()

        # Read service account name from environment variable (set by Helm chart)
        # or fall back to reading from mounted service account token directory
        import os

        service_account = os.getenv("SERVICE_ACCOUNT_NAME")
        if not service_account:
            # Try to infer from mounted token path
            try:
                # The token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/
                # and the SA name can be found via the Kubernetes downward API if configured,
                # but since we control the deployment, we can use a naming convention
                service_account = f"keycloak-operator-{namespace}"
            except Exception:
                service_account = "keycloak-operator"

        return {"name": service_account, "namespace": namespace}

    except Exception as e:
        logger.warning(f"Could not determine service account info: {e}")
        return {"name": "unknown", "namespace": "default"}


def get_admin_credentials(name: str, namespace: str) -> tuple[str, str]:
    """
    Get admin credentials for a Keycloak instance.

    Args:
        name: Name of the Keycloak instance
        namespace: Namespace where the instance is deployed

    Returns:
        Tuple of (username, password)

    Raises:
        Exception: If credentials cannot be retrieved
    """
    import base64

    secret_name = f"{name}-admin-credentials"

    try:
        k8s = get_kubernetes_client()
        core_api = client.CoreV1Api(k8s)

        secret = core_api.read_namespaced_secret(name=secret_name, namespace=namespace)

        username = base64.b64decode(secret.data["username"]).decode()
        password = base64.b64decode(secret.data["password"]).decode()

        return username, password

    except ApiException as e:
        logger.error(f"Failed to get admin credentials from secret {secret_name}: {e}")
        raise
    except KeyError as e:
        logger.error(f"Missing credential field in secret {secret_name}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting admin credentials: {e}")
        raise
