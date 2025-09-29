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


@pytest.fixture
def sample_keycloak_spec(test_secrets) -> dict[str, Any]:
    """Return a sample Keycloak resource specification."""
    return {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "Keycloak",
        "spec": {
            "image": "quay.io/keycloak/keycloak:23.0.0",
            "replicas": 1,
            "database": {
                "type": "postgresql",
                "host": "postgres.postgres.svc.cluster.local",
                "name": "keycloak",
                "username": "keycloak",
                "password_secret": {
                    "name": test_secrets["database"],
                    "key": "password",
                },
            },
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
