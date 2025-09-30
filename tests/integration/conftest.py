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
async def cnpg_cluster(k8s_client, test_namespace, cnpg_installed, wait_for_condition) -> dict[str, str] | None:
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
            "image": "quay.io/keycloak/keycloak:23.0.0",
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


@pytest.fixture
async def wait_for_condition():
    """Utility fixture for waiting for conditions with timeout."""

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


@pytest.fixture
def temp_manifest_file():
    """Create a temporary file for Kubernetes manifests."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        temp_path = Path(f.name)
        yield temp_path
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()
