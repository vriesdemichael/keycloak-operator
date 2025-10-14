"""
Pytest configuration and fixtures for integration tests.

This module provides shared fixtures and configuration for integration tests
that run against a real Kubernetes cluster.

IMPORTANT: Before writing new integration tests, read tests/integration/TESTING.md
This document contains critical rules about:
- Port-forwarding for Keycloak access (REQUIRED for host-to-cluster communication)
- Shared vs dedicated Keycloak instances (affects performance and isolation)
- Parallel test execution (requires unique resource names)
- Status phase expectations (Unknown/Pending/Ready/Degraded/Failed)
- Timeouts and cleanup patterns

Violating these rules will cause test failures, especially in parallel execution.
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import DEFAULT_KEYCLOAK_IMAGE
from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
from keycloak_operator.models.common import AuthorizationSecretRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def kube_config():
    """Load Kubernetes configuration."""
    try:
        # Try to load in-cluster config first
        config.load_incluster_config()
    except config.ConfigException:
        # Fallback to kubeconfig
        config.load_kube_config()

    return client.Configuration.get_default_copy()


@pytest.fixture(scope="session")
def k8s_client(kube_config):
    """Create Kubernetes API client."""
    return client.ApiClient(kube_config)


@pytest.fixture(scope="session")
def k8s_core_v1(k8s_client):
    """Create Core V1 API client."""
    return client.CoreV1Api(k8s_client)


@pytest.fixture(scope="session")
def k8s_apps_v1(k8s_client):
    """Create Apps V1 API client."""
    return client.AppsV1Api(k8s_client)


@pytest.fixture(scope="session")
def k8s_custom_objects(k8s_client):
    """Create Custom Objects API client."""
    return client.CustomObjectsApi(k8s_client)


@pytest.fixture(scope="session")
def k8s_rbac_v1(k8s_client):
    """Create RBAC Authorization V1 API client."""
    return client.RbacAuthorizationV1Api(k8s_client)


@pytest.fixture(scope="session")
def operator_namespace():
    """Return the namespace where the operator is running."""
    return os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")


@pytest.fixture(scope="session")
def operator_namespace_secrets(k8s_core_v1, operator_namespace) -> dict[str, str]:
    """Return references to pre-installed secrets in operator namespace.

    These secrets are created by the deployment script (scripts/deploy-test-keycloak.sh):
    - keycloak-cnpg-app: Database credentials (created by CNPG operator)

    Session-scoped to share across all tests.
    """
    secrets = {}

    # Database secret is created by CNPG operator
    db_secret_name = "keycloak-cnpg-app"
    try:
        k8s_core_v1.read_namespaced_secret(
            name=db_secret_name, namespace=operator_namespace
        )
        secrets["database"] = db_secret_name
    except ApiException as e:
        if e.status == 404:
            pytest.fail(
                f"Database secret '{db_secret_name}' not found in namespace '{operator_namespace}'. "
                f"Run 'make deploy-local' to create the test environment."
            )
        raise

    return secrets


@pytest.fixture(scope="session")
def operator_namespace_cnpg(
    k8s_client, operator_namespace, cnpg_installed
) -> dict[str, str] | None:
    """Return connection details for pre-installed CNPG cluster in operator namespace.

    This fixture expects the CNPG cluster to be created by the deployment script
    (scripts/deploy-test-keycloak.sh) as part of `make deploy-local`.

    Returns PostgreSQL connection information (type: postgresql, host: cluster-name-rw, etc)
    for use in test configurations.

    Session-scoped to share across all tests.
    """
    if not cnpg_installed:
        return None

    from kubernetes import dynamic

    dyn = dynamic.DynamicClient(k8s_client)
    cluster_api = dyn.resources.get(api_version="postgresql.cnpg.io/v1", kind="Cluster")

    cluster_name = "keycloak-cnpg"
    db_name = "keycloak"

    # Check if cluster exists and is ready
    try:
        obj = cluster_api.get(name=cluster_name, namespace=operator_namespace)
        phase = obj.to_dict().get("status", {}).get("phase")

        if phase != "Cluster in healthy state":
            pytest.fail(
                f"CNPG cluster '{cluster_name}' not ready (phase: {phase}). "
                f"Run 'make deploy-local' to create the test environment."
            )

        # Verify app secret exists
        core = client.CoreV1Api(k8s_client)
        try:
            core.read_namespaced_secret(f"{cluster_name}-app", operator_namespace)
        except ApiException:
            pytest.fail(
                f"CNPG app secret '{cluster_name}-app' not found. "
                f"Run 'make deploy-local' to create the test environment."
            )

        # Return standard PostgreSQL connection details
        return {
            "type": "postgresql",
            "host": f"{cluster_name}-rw",
            "port": 5432,
            "database": db_name,
            "username": "app",
            "password_secret": f"{cluster_name}-app",
        }

    except ApiException as e:
        if e.status == 404:
            pytest.fail(
                f"CNPG cluster '{cluster_name}' not found in namespace '{operator_namespace}'. "
                f"Run 'make deploy-local' to create the test environment."
            )
        raise


@pytest.fixture
async def test_namespace(k8s_core_v1) -> AsyncGenerator[str]:
    """Create a test namespace and clean it up after the test."""
    namespace_name = f"test-{os.urandom(4).hex()}"

    # Create namespace
    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name, labels={"test": "integration", "operator": "keycloak"}
        )
    )

    try:
        k8s_core_v1.create_namespace(namespace)
        yield namespace_name
    finally:
        # Cleanup namespace
        try:
            k8s_core_v1.delete_namespace(
                name=namespace_name,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
        except ApiException as e:
            if e.status != 404:  # Ignore not found errors
                print(f"Warning: Failed to cleanup namespace {namespace_name}: {e}")


@pytest.fixture
async def test_secrets(k8s_core_v1, test_namespace) -> dict[str, str]:
    """Create test secrets for Keycloak instances."""
    secrets = {}

    # Database secret
    db_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name="test-db-secret", namespace=test_namespace),
        string_data={"password": "test-db-password", "username": "keycloak"},
    )
    k8s_core_v1.create_namespaced_secret(test_namespace, db_secret)
    secrets["database"] = "test-db-secret"

    # Admin secret
    admin_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name="test-admin-secret", namespace=test_namespace
        ),
        string_data={"password": "admin-password", "username": "admin"},
    )
    k8s_core_v1.create_namespaced_secret(test_namespace, admin_secret)
    secrets["admin"] = "test-admin-secret"

    return secrets


@pytest.fixture(scope="session")
def cnpg_installed(k8s_client) -> bool:
    """Detect if CloudNativePG CRDs are installed in the cluster.

    We only attempt CNPG cluster creation if the CRD exists. This allows
    the test suite to skip CNPG-dependent tests gracefully when the
    operator is not present.
    """
    from kubernetes import client as k8s

    api = k8s.ApiextensionsV1Api(k8s_client)
    try:
        api.read_custom_resource_definition("clusters.postgresql.cnpg.io")
        return True
    except ApiException:
        return False


@pytest.fixture
async def cnpg_cluster(
    k8s_client, test_namespace, cnpg_installed, wait_for_condition
) -> dict[str, Any] | None:
    """Create a minimal CloudNativePG Cluster and return standard PostgreSQL connection details.

    Returns PostgreSQL connection information (type: postgresql, host: cluster-name-rw, etc)
    instead of CNPG-specific references. This allows tests to use standard database configuration.

    Returns None if CNPG is not installed.
    """
    if not cnpg_installed:
        # CNPG not available; returning None will let sample_keycloak_spec
        # fall back to traditional database configuration (which may fail
        # if connectivity is required). Tests depending on DB will be skipped.
        return None

    from kubernetes import dynamic

    dyn = dynamic.DynamicClient(k8s_client)
    cluster_api = dyn.resources.get(api_version="postgresql.cnpg.io/v1", kind="Cluster")

    cluster_name = "kc-test-cnpg"
    db_name = "keycloak"

    cluster_manifest = {
        "apiVersion": "postgresql.cnpg.io/v1",
        "kind": "Cluster",
        "metadata": {"name": cluster_name, "namespace": test_namespace},
        "spec": {
            "instances": 1,
            "primaryUpdateStrategy": "unsupervised",
            "storage": {"size": "1Gi"},
            # Minimal bootstrap with application database/user creation handled by defaults
            "bootstrap": {"initdb": {"database": db_name, "owner": "app"}},
            # Disable superuser secret creation to keep things simple
            "enableSuperuserAccess": False,
            # Resources kept tiny for CI
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "200m", "memory": "256Mi"},
            },
        },
    }

    # Create cluster (ignore AlreadyExists to allow reuse within namespace lifetime)
    try:
        cluster_api.create(body=cluster_manifest, namespace=test_namespace)
    except ApiException as e:
        if e.status != 409:  # 409 AlreadyExists
            raise

    # Wait for cluster to report healthy phase & application secret present
    async def cluster_ready():
        try:
            obj = cluster_api.get(name=cluster_name, namespace=test_namespace)
            phase = obj.to_dict().get("status", {}).get("phase")
            if phase != "Cluster in healthy state":
                return False
            # Confirm app secret existence
            core = client.CoreV1Api(k8s_client)
            try:
                core.read_namespaced_secret(f"{cluster_name}-app", test_namespace)
                return True
            except ApiException:
                return False
        except ApiException:
            return False

    ready = await wait_for_condition(cluster_ready, timeout=420, interval=5)
    if not ready:
        pytest.skip("CNPG cluster was not ready in time")

    # Return standard PostgreSQL connection details
    return {
        "type": "postgresql",
        "host": f"{cluster_name}-rw",
        "port": 5432,
        "database": db_name,
        "username": "app",
        "password_secret": f"{cluster_name}-app",
    }


@pytest.fixture
def sample_keycloak_spec(test_secrets, cnpg_cluster) -> dict[str, Any]:
    """Return a sample Keycloak resource specification using standard PostgreSQL config."""
    if cnpg_cluster:
        # Use standard PostgreSQL configuration with CNPG connection details
        database_block: dict[str, Any] = {
            "type": cnpg_cluster["type"],
            "host": cnpg_cluster["host"],
            "port": cnpg_cluster["port"],
            "database": cnpg_cluster["database"],
            "username": cnpg_cluster["username"],
            "password_secret": {
                "name": cnpg_cluster["password_secret"],
                "key": "password",
            },
        }
    else:
        # Fallback minimal traditional config (may fail if real DB not present)
        database_block = {
            "type": "postgresql",
            "host": "postgres-test",
            "database": "keycloak",
            "username": "keycloak",
            "password_secret": {"name": test_secrets["database"], "key": "password"},
        }

    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "Keycloak",
        "spec": {
            "image": DEFAULT_KEYCLOAK_IMAGE,
            "replicas": 1,
            "database": database_block,
            "admin_access": {
                "username": "admin",
                "password_secret": {"name": test_secrets["admin"], "key": "password"},
            },
            "service": {"type": "ClusterIP", "port": 8080},
        },
    }


@pytest.fixture
def sample_realm_spec() -> KeycloakRealmSpec:
    """Return a sample Keycloak realm specification using Pydantic model."""
    return KeycloakRealmSpec(
        operator_ref=OperatorRef(
            namespace="keycloak-system",
            authorization_secret_ref=AuthorizationSecretRef(
                name="keycloak-operator-auth-token",
                key="token",
            ),
        ),
        realm_name="test-realm",
        display_name="Test Realm",
    )


@pytest.fixture
def sample_client_spec() -> KeycloakClientSpec:
    """Return a sample Keycloak client specification using Pydantic model."""
    return KeycloakClientSpec(
        realm_ref=RealmRef(
            name="test-realm",
            namespace="test-namespace",  # Will be overridden by test
            authorization_secret_ref=AuthorizationSecretRef(
                name="keycloak-operator-auth-token",
                key="token",
            ),
        ),
        client_id="test-client",
        client_name="Test Client",
        public_client=False,
    )


def build_realm_manifest(
    spec: KeycloakRealmSpec, name: str, namespace: str
) -> dict[str, Any]:
    """
    Build a complete KeycloakRealm manifest from a Pydantic spec.

    Uses model_dump(by_alias=True) to convert camelCase for Kubernetes API.
    """
    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakRealm",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec.model_dump(by_alias=True, exclude_unset=True),
    }


def build_client_manifest(
    spec: KeycloakClientSpec, name: str, namespace: str
) -> dict[str, Any]:
    """
    Build a complete KeycloakClient manifest from a Pydantic spec.

    Uses model_dump(by_alias=True) to convert camelCase for Kubernetes API.
    """
    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakClient",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec.model_dump(by_alias=True, exclude_unset=True),
    }


@pytest.fixture(scope="session")
async def wait_for_condition():
    """Utility fixture for waiting for conditions with timeout (session-scoped for reuse)."""

    async def _wait(condition_func, timeout: int = 300, interval: int = 3):
        """Wait for a condition to be true."""
        import time

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                if await condition_func():
                    return True
            except Exception as e:
                print(f"Condition check failed: {e}")

            await asyncio.sleep(interval)

        return False

    return _wait


@pytest.fixture(scope="session")
def wait_for_keycloak_ready(
    k8s_custom_objects,
    k8s_apps_v1,
    k8s_core_v1,  # kept for potential future pod-level checks
    wait_for_condition,
):
    """Wait until a Keycloak instance is actually runnable.

    Success criteria (any of these):
      1. Keycloak CR status.phase in ("Running", "Ready") AND its deployment has desired ready replicas.
      2. Deployment has desired ready replicas even if CR status not yet updated (race condition tolerance).

    This fixture returns an async function: await wait_for_keycloak_ready(name, namespace, timeout=420)
    """

    async def _wait(
        name: str, namespace: str, timeout: int = 420, interval: int = 5
    ) -> bool:
        async def _condition():
            from kubernetes.client.rest import ApiException

            deployment_name = f"{name}-keycloak"
            deployment_ready = False

            # Check deployment readiness first (acts as fallback if CR status lags)
            try:
                deployment = k8s_apps_v1.read_namespaced_deployment(
                    name=deployment_name, namespace=namespace
                )
                desired = deployment.spec.replicas or 1
                ready = deployment.status.ready_replicas or 0
                if ready >= desired:
                    deployment_ready = True
            except ApiException:
                deployment_ready = False

            # Try to read CR status for phase/conditions
            try:
                kc = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=name,
                )
                status = kc.get("status", {}) or {}
                if not status:
                    # Status has not been populated yet; keep waiting even if the
                    # deployment looks healthy so tests can validate status fields.
                    return False

                phase = status.get("phase")
                # Look for condition-based readiness too
                conditions = status.get("conditions", []) or []
                ready_condition_true = any(
                    c.get("type") == "Ready" and c.get("status") == "True"
                    for c in conditions
                )
                if (
                    phase in ("Running", "Ready") or ready_condition_true
                ) and deployment_ready:
                    return True
            except ApiException:
                # CR not yet readable or transient error
                pass

            return False

        return await wait_for_condition(_condition, timeout=timeout, interval=interval)

    return _wait


# ============================================================================
# Class-scoped fixtures for shared Keycloak instances (performance optimization)
# ============================================================================


@pytest.fixture(scope="class")
def class_scoped_namespace(k8s_core_v1, request) -> str:
    """Create a test namespace that lives for entire test class.

    This allows tests within a class to share resources like Keycloak instances,
    significantly reducing test execution time.
    """
    namespace_name = f"test-{os.urandom(4).hex()}"

    # Create namespace
    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name, labels={"test": "integration", "operator": "keycloak"}
        )
    )

    k8s_core_v1.create_namespace(namespace)

    # Register cleanup finalizer
    def cleanup():
        try:
            k8s_core_v1.delete_namespace(
                name=namespace_name,
                body=client.V1DeleteOptions(propagation_policy="Foreground"),
            )
        except ApiException as e:
            if e.status != 404:  # Ignore not found errors
                print(f"Warning: Failed to cleanup namespace {namespace_name}: {e}")

    request.addfinalizer(cleanup)
    return namespace_name


@pytest.fixture(scope="class")
def class_scoped_test_secrets(k8s_core_v1, class_scoped_namespace) -> dict[str, str]:
    """Create test secrets for class-scoped Keycloak instances.

    Note: Synchronous fixture for pytest-xdist compatibility.
    """
    secrets = {}

    # Database secret
    db_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name="shared-db-secret", namespace=class_scoped_namespace
        ),
        string_data={"password": "test-db-password", "username": "keycloak"},
    )
    k8s_core_v1.create_namespaced_secret(class_scoped_namespace, db_secret)
    secrets["database"] = "shared-db-secret"

    # Admin secret
    admin_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name="shared-admin-secret", namespace=class_scoped_namespace
        ),
        string_data={"password": "admin-password", "username": "admin"},
    )
    k8s_core_v1.create_namespaced_secret(class_scoped_namespace, admin_secret)
    secrets["admin"] = "shared-admin-secret"

    return secrets


@pytest.fixture(scope="class")
def class_scoped_cnpg_cluster(
    k8s_client, class_scoped_namespace, cnpg_installed
) -> dict[str, str] | None:
    """Create a CNPG cluster that lives for entire test class."""
    if not cnpg_installed:
        return None

    import time

    from kubernetes import dynamic

    dyn = dynamic.DynamicClient(k8s_client)
    cluster_api = dyn.resources.get(api_version="postgresql.cnpg.io/v1", kind="Cluster")

    cluster_name = "kc-shared-cnpg"
    db_name = "keycloak"

    cluster_manifest = {
        "apiVersion": "postgresql.cnpg.io/v1",
        "kind": "Cluster",
        "metadata": {"name": cluster_name, "namespace": class_scoped_namespace},
        "spec": {
            "instances": 1,
            "primaryUpdateStrategy": "unsupervised",
            "storage": {"size": "1Gi"},
            "bootstrap": {"initdb": {"database": db_name, "owner": "app"}},
            "enableSuperuserAccess": False,
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "200m", "memory": "256Mi"},
            },
        },
    }

    # Create cluster
    try:
        cluster_api.create(body=cluster_manifest, namespace=class_scoped_namespace)
    except ApiException as e:
        if e.status != 409:  # 409 AlreadyExists
            raise

    # Wait for cluster to be ready (synchronous polling)
    timeout = 420
    interval = 5
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            obj = cluster_api.get(name=cluster_name, namespace=class_scoped_namespace)
            phase = obj.to_dict().get("status", {}).get("phase")
            if phase == "Cluster in healthy state":
                # Confirm app secret existence
                core = client.CoreV1Api(k8s_client)
                try:
                    core.read_namespaced_secret(
                        f"{cluster_name}-app", class_scoped_namespace
                    )
                    return {"name": cluster_name, "database": db_name}
                except ApiException:
                    pass
        except ApiException:
            pass
        time.sleep(interval)

    pytest.skip("CNPG cluster was not ready in time")


@pytest.fixture(scope="session")
def shared_operator(
    k8s_custom_objects,
    k8s_apps_v1,
    operator_namespace,
) -> dict[str, str]:
    """Verify shared Keycloak instance exists in operator namespace.

    This fixture expects the Keycloak instance to be created by the deployment script
    (scripts/deploy-test-keycloak.sh) as part of `make deploy-local`.

    Architecture: Single fixed-name "keycloak" instance in operator namespace,
    matching production deployment pattern (1-1 operator-Keycloak coupling).

    Session-scoped for parallel test workers.

    IMPORTANT RULES FOR USING SHARED OPERATOR:
    1. **NO DESTRUCTIVE OPERATIONS**: Do not delete or modify the shared Keycloak
       instance itself. If you need destructive testing, create a dedicated instance.
    2. **UNIQUE REALM NAMES**: Always use unique realm names (e.g., uuid.uuid4().hex[:8])
       to prevent collisions between parallel tests.

    Returns:
        dict with 'name' and 'namespace' of the shared Keycloak instance

    Raises:
        pytest.fail: If Keycloak instance not found or not ready
    """
    keycloak_name = "keycloak"  # Fixed name per architecture (1-1 coupling)

    # Check if Keycloak exists
    try:
        kc = k8s_custom_objects.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=operator_namespace,
            plural="keycloaks",
            name=keycloak_name,
        )
        status = kc.get("status", {}) or {}
        phase = status.get("phase")

        # Verify it's ready
        if phase not in ("Running", "Ready"):
            pytest.fail(
                f"Shared Keycloak instance not ready (phase: {phase}). "
                f"Run 'make deploy-local' to create the test environment."
            )

        # Check deployment is ready
        deployment_name = f"{keycloak_name}-keycloak"
        try:
            deployment = k8s_apps_v1.read_namespaced_deployment(
                name=deployment_name, namespace=operator_namespace
            )
            desired = deployment.spec.replicas or 1
            ready = deployment.status.ready_replicas or 0
            if ready < desired:
                pytest.fail(
                    f"Shared Keycloak deployment not ready ({ready}/{desired} replicas ready)"
                )
        except ApiException:
            pytest.fail(
                f"Shared Keycloak deployment '{deployment_name}' not found. "
                f"Run 'make deploy-local' to create the test environment."
            )

        return {"name": keycloak_name, "namespace": operator_namespace}

    except ApiException as e:
        if e.status == 404:
            pytest.fail(
                f"Shared Keycloak instance '{keycloak_name}' not found in namespace '{operator_namespace}'. "
                f"Run 'make deploy-local' to create the test environment."
            )
        raise


@pytest.fixture
def temp_manifest_file():
    """Create a temporary file for Kubernetes manifests."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        temp_path = Path(f.name)
        yield temp_path
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()


@pytest.fixture
async def keycloak_port_forward():
    """Port-forward Keycloak services to localhost for test access.

    This fixture enables tests running on the host (WSL/Linux/macOS) to access
    Keycloak instances running inside the Kind cluster by creating a kubectl
    port-forward tunnel.

    Returns:
        Async function that sets up port-forwarding:
        local_port = await keycloak_port_forward(name, namespace)

    Cleanup is automatic - all port-forwards are terminated when the test completes.
    """
    import socket
    import subprocess

    active_forwards: list[subprocess.Popen] = []

    async def _forward(name: str, namespace: str, remote_port: int = 8080) -> int:
        """Set up port-forward and return the local port."""
        # Find available local port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            local_port = s.getsockname()[1]

        service_name = f"{name}-keycloak"

        # Start port-forward in background
        cmd = [
            "kubectl",
            "port-forward",
            f"svc/{service_name}",
            f"{local_port}:{remote_port}",
            "-n",
            namespace,
        ]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Wait for port-forward to be ready
        await asyncio.sleep(2)

        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"Port-forward failed: {stderr}")

        active_forwards.append(proc)
        return local_port

    yield _forward

    # Cleanup: kill all port-forwards
    for proc in active_forwards:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
