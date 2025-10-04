"""
Pytest configuration and fixtures for integration tests.

This module provides shared fixtures and configuration for integration tests
that run against a real Kubernetes cluster.
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
def operator_namespace():
    """Return the namespace where the operator is running."""
    return os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")


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
) -> dict[str, str] | None:
    """Create a minimal CloudNativePG Cluster in the test namespace.

    Returns a dict with cluster connection info (cluster name, db name)
    or None if CNPG is not installed.
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

    return {"name": cluster_name, "database": db_name}


@pytest.fixture
def sample_keycloak_spec(test_secrets, cnpg_cluster) -> dict[str, Any]:
    """Return a sample Keycloak resource specification using CNPG when available."""
    if cnpg_cluster:
        database_block: dict[str, Any] = {
            "type": "cnpg",
            "cnpg_cluster": {
                "name": cnpg_cluster["name"],
                # namespace omitted to default to same test namespace
                "database": cnpg_cluster["database"],
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
def sample_realm_spec() -> dict[str, Any]:
    """Return a sample Keycloak realm specification."""
    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakRealm",
        "spec": {
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": None,  # Will be set by test
            },
            "realm_name": "test-realm",
            "enabled": True,
            "display_name": "Test Realm",
        },
    }


@pytest.fixture
def sample_client_spec() -> dict[str, Any]:
    """Return a sample Keycloak client specification."""
    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakClient",
        "spec": {
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": None,  # Will be set by test
            },
            "realm": "test-realm",
            "client_id": "test-client",
            "client_name": "Test Client",
            "enabled": True,
            "public_client": False,
        },
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

    Note: Synchronous fixture for pytest-xdist compatibility.
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
    k8s_client, class_scoped_namespace, cnpg_installed, wait_for_condition
) -> dict[str, str] | None:
    """Create a CNPG cluster that lives for entire test class."""
    if not cnpg_installed:
        return None

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

    # Wait for cluster to be ready
    async def cluster_ready():
        try:
            obj = cluster_api.get(name=cluster_name, namespace=class_scoped_namespace)
            phase = obj.to_dict().get("status", {}).get("phase")
            if phase != "Cluster in healthy state":
                return False
            # Confirm app secret existence
            core = client.CoreV1Api(k8s_client)
            try:
                core.read_namespaced_secret(
                    f"{cluster_name}-app", class_scoped_namespace
                )
                return True
            except ApiException:
                return False
        except ApiException:
            return False

    # Run async wait synchronously for pytest-xdist compatibility
    ready = asyncio.run(wait_for_condition(cluster_ready, timeout=420, interval=5))
    if not ready:
        pytest.skip("CNPG cluster was not ready in time")

    return {"name": cluster_name, "database": db_name}


@pytest.fixture(scope="class")
def shared_keycloak_instance(
    k8s_custom_objects,
    class_scoped_namespace,
    class_scoped_test_secrets,
    class_scoped_cnpg_cluster,
    wait_for_keycloak_ready,
) -> dict[str, str]:
    """Create a shared Keycloak instance for all tests in a class.

    This significantly reduces test execution time by reusing one Keycloak instance
    across multiple tests instead of creating a new one for each test.

    Note: Synchronous fixture for pytest-xdist compatibility.

    Returns:
        dict with 'name' and 'namespace' of the shared Keycloak instance
    """
    keycloak_name = "shared-keycloak"

    # Build Keycloak spec
    if class_scoped_cnpg_cluster:
        database_block: dict[str, Any] = {
            "type": "cnpg",
            "cnpg_cluster": {
                "name": class_scoped_cnpg_cluster["name"],
                "database": class_scoped_cnpg_cluster["database"],
            },
        }
    else:
        database_block = {
            "type": "postgresql",
            "host": "postgres-test",
            "database": "keycloak",
            "username": "keycloak",
            "password_secret": {
                "name": class_scoped_test_secrets["database"],
                "key": "password",
            },
        }

    keycloak_manifest = {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "Keycloak",
        "metadata": {"name": keycloak_name, "namespace": class_scoped_namespace},
        "spec": {
            "image": DEFAULT_KEYCLOAK_IMAGE,
            "replicas": 1,
            "database": database_block,
            "admin_access": {
                "username": "admin",
                "password_secret": {
                    "name": class_scoped_test_secrets["admin"],
                    "key": "password",
                },
            },
            "service": {"type": "ClusterIP", "port": 8080},
        },
    }

    # Create Keycloak instance
    try:
        k8s_custom_objects.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=class_scoped_namespace,
            plural="keycloaks",
            body=keycloak_manifest,
        )
    except ApiException as e:
        if e.status != 409:  # Allow already exists for class reuse
            raise

    # Wait for Keycloak to be ready (run async wait synchronously for pytest-xdist)
    ready = asyncio.run(
        wait_for_keycloak_ready(keycloak_name, class_scoped_namespace, timeout=420)
    )
    if not ready:
        pytest.fail(f"Shared Keycloak instance {keycloak_name} did not become ready")

    return {"name": keycloak_name, "namespace": class_scoped_namespace}


@pytest.fixture
def temp_manifest_file():
    """Create a temporary file for Kubernetes manifests."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        temp_path = Path(f.name)
        yield temp_path
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()
