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

FIXTURE HIERARCHY
=================

Session-scoped (shared across all tests):
├── shared_operator → SharedOperatorInfo (operator + Keycloak via Helm)
├── operator_namespace → str (namespace where operator runs)
└── k8s_* clients → Async-wrapped Kubernetes API clients

Function-scoped (per test):
├── test_namespace → str (unique per test with RBAC)
├── keycloak_ready → KeycloakReadySetup (operator + port + admin client)
├── managed_* → Auto-cleanup resource creators
├── openldap_ready → dict (OpenLDAP server for LDAP federation tests)
├── openldap_ad_ready → dict (OpenLDAP with AD schema simulation)
└── kerberos_ready → dict (MIT Kerberos KDC for Kerberos tests)

Internal fixtures (prefixed with _):
├── _k8s_*_sync → Synchronous K8s clients (wrapped by async versions)
├── _helm_*_chart_path → Paths to Helm charts
└── Other implementation details

Recommended Usage:
- Simple operator tests: shared_operator + test_namespace
- Realm tests: keycloak_ready + test_namespace
- Client tests: keycloak_ready + test_namespace + managed_realm
- Drift tests: keycloak_ready + drift_detector
- LDAP federation tests: keycloak_ready + test_namespace + openldap_ready
- AD federation tests: keycloak_ready + test_namespace + openldap_ad_ready
- Kerberos federation tests: keycloak_ready + test_namespace + kerberos_ready
"""

import asyncio
import contextlib
import fcntl
import logging
import os
import tempfile
import time
from asyncio.subprocess import PIPE
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    DEFAULT_KEYCLOAK_OPTIMIZED_VERSION,
)
from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

from .cleanup_utils import (
    CleanupTracker,
    cleanup_namespace_resources,
    delete_custom_resource_with_retry,
    ensure_clean_test_environment,
    force_delete_namespace,
)

# Import user federation fixtures to make them available to tests
from .fixtures_user_federation import (  # noqa: F401
    kerberos_ready,
    openldap_ad_ready,
    openldap_ready,
)
from .models import KeycloakReadySetup, SharedOperatorInfo

# wait_helpers are imported directly in tests, not used in conftest

# ============================================================================
# Test Helper Functions
# ============================================================================


def get_recommended_fixtures(scenario: str) -> list[str]:
    """Get recommended fixtures for common test scenarios.

    This helper function provides guidance on which fixtures to use for different
    types of tests, helping new test writers get started quickly.

    Args:
        scenario: The type of test being written. Options:
            - "basic": Simple operator functionality tests
            - "realm": Realm CRUD and management tests
            - "client": Client management tests
            - "drift": Drift detection tests
            - "auth": Authorization/token system tests
            - "helm": Helm chart deployment tests
            - "ldap": LDAP user federation tests
            - "ldap_ad": Active Directory user federation tests
            - "kerberos": Kerberos user federation tests

    Returns:
        List of recommended fixture names for that scenario

    Example:
        >>> fixtures = get_recommended_fixtures("realm")
        >>> print(fixtures)
        ['keycloak_ready', 'test_namespace', 'auth_token_factory', 'realm_cr_factory']
    """
    recommendations = {
        "basic": [
            "shared_operator",  # Operator deployment info
            "test_namespace",  # Unique test namespace
        ],
        "realm": [
            "keycloak_ready",  # Complete Keycloak setup (operator + port + admin)
            "test_namespace",  # Unique test namespace
            "auth_token_factory",  # For creating auth tokens
            "realm_cr_factory",  # For creating realm manifests
        ],
        "client": [
            "keycloak_ready",  # Complete Keycloak setup
            "test_namespace",  # Unique test namespace
            "auth_token_factory",  # For creating auth tokens
            "realm_cr_factory",  # Need realm first
            "client_cr_factory",  # For creating client manifests
        ],
        "drift": [
            "keycloak_ready",  # Complete Keycloak setup
            "test_namespace",  # Unique test namespace
            "drift_detector",  # Drift detection service
            "realm_cr_factory",  # For creating test realms
        ],
        "auth": [
            "shared_operator",  # Operator info
            "test_namespace",  # Unique test namespace
            "auth_token_factory",  # For creating/testing tokens
            "k8s_core_v1",  # For secret operations
        ],
        "helm": [
            "test_namespace",  # Unique test namespace
            "helm_realm",  # Helm realm deployment helper
            "helm_client",  # Helm client deployment helper
            "cleanup_tracker",  # Track cleanup operations
        ],
        "ldap": [
            "keycloak_ready",  # Complete Keycloak setup
            "test_namespace",  # Unique test namespace
            "openldap_ready",  # OpenLDAP server with test users
            "realm_cr_factory",  # For creating realm with federation
        ],
        "ldap_ad": [
            "keycloak_ready",  # Complete Keycloak setup
            "test_namespace",  # Unique test namespace
            "openldap_ad_ready",  # OpenLDAP with AD schema simulation
            "realm_cr_factory",  # For creating realm with AD federation
        ],
        "kerberos": [
            "keycloak_ready",  # Complete Keycloak setup
            "test_namespace",  # Unique test namespace
            "kerberos_ready",  # MIT Kerberos KDC
            "openldap_ready",  # Often used together with Kerberos
            "realm_cr_factory",  # For creating realm with Kerberos
        ],
    }

    return recommendations.get(
        scenario,
        ["shared_operator", "test_namespace"],  # Safe default
    )


# ============================================================================
# Logging Configuration
# ============================================================================

logger = logging.getLogger(__name__)


class AsyncK8sClientWrapper:
    """Wrapper that makes synchronous K8s client calls async-safe using asyncio.to_thread()."""

    def __init__(self, sync_client):
        self._sync_client = sync_client

    def __getattr__(self, name):
        attr = getattr(self._sync_client, name)
        if callable(attr):

            async def async_wrapper(*args, **kwargs):
                return await asyncio.to_thread(attr, *args, **kwargs)

            return async_wrapper
        return attr


@pytest.fixture(scope="session", autouse=True)
async def check_prerequisites(k8s_client, k8s_core_v1):
    """Validate all prerequisites before running integration tests.

    Prerequisites (MUST be met before running tests):
    1. Kind cluster is available and accessible
    2. CNPG operator is installed
    3. Operator Docker image is built and loaded into Kind

    This fixture fails fast with clear error messages if any prerequisite is missing.
    """
    logger.info("Validating integration test prerequisites...")

    # 1. Check Kind cluster is available
    try:
        await k8s_core_v1.list_node()
        logger.info("✓ Kind cluster is accessible")
    except Exception as e:
        pytest.fail(
            f"Kind cluster not accessible. Run 'make kind-setup' first.\nError: {e}"
        )

    # 2. Check CNPG operator is installed
    from kubernetes import client as k8s

    api = k8s.ApiextensionsV1Api(k8s_client)
    try:
        api.read_custom_resource_definition("clusters.postgresql.cnpg.io")
        logger.info("✓ CNPG operator is installed")
    except ApiException as e:
        if e.status == 404:
            pytest.fail(
                "CNPG operator not installed. Run 'make kind-setup' which installs CNPG automatically."
            )
        raise

    # 3. Check operator image is available in Kind
    # Find the Kind cluster control plane node dynamically
    try:
        import subprocess

        # First, find the Kind control plane node name
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                "name=control-plane",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        control_plane_nodes = [
            name
            for name in result.stdout.strip().split("\n")
            if name and "control-plane" in name
        ]

        if not control_plane_nodes:
            pytest.fail(
                "No Kind control plane node found. Is the Kind cluster running?\n"
                "Run: make kind-setup"
            )

        # Use the first control plane node found
        control_plane_name = control_plane_nodes[0]
        logger.info(f"Found Kind control plane: {control_plane_name}")

        # Check if operator image exists in the node
        result = subprocess.run(
            [
                "docker",
                "exec",
                control_plane_name,
                "crictl",
                "images",
                "keycloak-operator",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if "keycloak-operator" not in result.stdout:
            pytest.fail(
                "Operator image 'keycloak-operator' not found in Kind cluster.\n"
                "Run:\n"
                "  make docker-build\n"
                "  make kind-load"
            )
        logger.info("✓ Operator image is loaded in Kind")
    except subprocess.TimeoutExpired:
        pytest.fail("Timeout checking for operator image in Kind")
    except FileNotFoundError:
        pytest.fail("Docker or crictl not available. Cannot verify operator image.")
    except Exception as e:
        logger.warning(f"Could not verify operator image: {e}")
        logger.warning("Proceeding anyway - tests will fail if image is missing")

    logger.info("✓ All prerequisites validated")


async def _retrieve_integration_coverage(
    k8s_core_v1, operator_namespace: str, logger
) -> None:
    """Retrieve coverage data from operator pod.

    This function:
    1. Forces coverage to flush all buffered data by calling .save()
    2. Retrieves the coverage files from the pod

    This must be called BEFORE any pod termination to avoid the Terminating state
    where exec commands are blocked.
    """
    import traceback

    logger.info("Starting coverage retrieval from operator pod")
    try:
        pods = await k8s_core_v1.list_namespaced_pod(
            namespace=operator_namespace,
            label_selector="app.kubernetes.io/name=keycloak-operator",
        )
        if not pods.items:
            logger.warning("No operator pod found")
            return
        pod_name = pods.items[0].metadata.name
        logger.info(f"Found operator pod: {pod_name}")

        import asyncio

        from kubernetes.stream import stream

        coverage_dir = Path(__file__).parent.parent.parent / ".tmp" / "coverage"
        coverage_dir.mkdir(parents=True, exist_ok=True)

        # Get the sync client for stream() calls
        sync_client = k8s_core_v1._sync_client

        # Step 1: Force coverage to flush all buffered data via SIGUSR1
        # This is critical - coverage.py buffers data in memory and we need to ensure
        # it's all written to disk before we retrieve files
        # We send SIGUSR1 to the main operator process which has a signal handler
        logger.info("Forcing coverage data flush via SIGUSR1...")
        try:
            # Find the main operator process PID
            find_pid_command = [
                "sh",
                "-c",
                "pgrep -f 'coverage run' | head -1 || echo 1",
            ]
            pid_resp = stream(
                sync_client.connect_get_namespaced_pod_exec,
                pod_name,
                operator_namespace,
                command=find_pid_command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True,
            )
            operator_pid = pid_resp.strip() or "1"
            logger.info(f"Found operator PID: {operator_pid}")

            # Send SIGUSR1 to trigger coverage flush
            signal_command = ["sh", "-c", f"kill -USR1 {operator_pid}"]
            stream(
                sync_client.connect_get_namespaced_pod_exec,
                pod_name,
                operator_namespace,
                command=signal_command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=True,
            )
            logger.info("SIGUSR1 signal sent successfully")
        except Exception as e:
            logger.warning(f"Failed to send SIGUSR1 (continuing anyway): {e}")

        # Give coverage a moment to complete file writes
        await asyncio.sleep(3)

        # Step 2: List and retrieve coverage files
        logger.info("Listing coverage files...")
        list_command = [
            "sh",
            "-c",
            "ls -1 /tmp/coverage/.coverage* 2>/dev/null || echo 'NO_FILES'",
        ]

        resp = stream(
            sync_client.connect_get_namespaced_pod_exec,
            pod_name,
            operator_namespace,
            command=list_command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=True,
        )

        if "NO_FILES" in resp:
            logger.warning("No coverage files found in /tmp/coverage/")
            return

        coverage_files = [f for f in resp.strip().split("\n") if f and f.strip()]
        logger.info(f"Found {len(coverage_files)} coverage file(s)")

        # Step 3: Retrieve each coverage file using kubectl cp
        import subprocess

        for coverage_file in coverage_files:
            filename = Path(coverage_file).name
            local_path = coverage_dir / filename

            try:
                subprocess.run(
                    [
                        "kubectl",
                        "cp",
                        f"{operator_namespace}/{pod_name}:{coverage_file}",
                        str(local_path),
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                file_size = local_path.stat().st_size
                logger.info(f"✓ Retrieved {filename} ({file_size} bytes)")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to copy {coverage_file}: {e.stderr}")
                continue
            except Exception as e:
                logger.error(f"Error copying {coverage_file}: {e}")
                continue

        logger.info(f"✓ Coverage files saved to {coverage_dir}")

    except Exception as e:
        logger.error(f"Coverage retrieval failed: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        # Don't re-raise - coverage failure shouldn't break test cleanup
        logger.warning("Continuing with cleanup despite coverage retrieval failure")


@pytest.fixture(scope="session")
def cleanup_tracker():
    """Track cleanup failures across all tests for final reporting."""
    tracker = CleanupTracker()
    yield tracker

    # Report any cleanup failures at the end of the session
    if tracker.has_failures():
        report = tracker.get_report()
        logger.error(f"\n{'=' * 60}\n{report}\n{'=' * 60}")
        # Don't fail tests, just warn
        print(f"\n⚠️  WARNING: {report}\n")


@pytest.fixture(scope="session", autouse=True)
async def check_test_environment(k8s_core_v1, k8s_custom_objects):
    """Check test environment is clean before running tests."""
    logger.info("Checking test environment for stale resources...")
    is_clean, report = await ensure_clean_test_environment(
        k8s_core_v1=k8s_core_v1,
        k8s_custom_objects=k8s_custom_objects,
    )

    if not is_clean:
        logger.warning(f"Test environment not clean:\n{report}")
        print(
            f"\n⚠️  WARNING: Found stale test resources. Consider running cleanup:\n{report}\n"
        )
    else:
        logger.info("✓ Test environment is clean")


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    # Clear any cached httpx clients from previous sessions to avoid
    # "Event loop is closed" errors when reusing connections bound to old loops
    from keycloak_operator.utils import keycloak_admin

    keycloak_admin._httpx_client_cache.clear()

    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def configure_env():
    """Configure environment variables for testing."""
    os.environ["OPERATOR_INSTANCE_ID"] = "keycloak-operator-test-system"
    # Ensure settings are reloaded
    from keycloak_operator.settings import settings

    settings.operator_instance_id = "keycloak-operator-test-system"


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
def _k8s_core_v1_sync(k8s_client):
    """Create Core V1 API client (synchronous, for use in non-async fixtures)."""
    return client.CoreV1Api(k8s_client)


@pytest.fixture(scope="session")
def k8s_core_v1(_k8s_core_v1_sync):
    """Create Core V1 API client (async-safe wrapper for async tests)."""
    return AsyncK8sClientWrapper(_k8s_core_v1_sync)


@pytest.fixture(scope="session")
def _k8s_apps_v1_sync(k8s_client):
    """Create Apps V1 API client (synchronous, for use in non-async fixtures)."""
    return client.AppsV1Api(k8s_client)


@pytest.fixture(scope="session")
def k8s_apps_v1(_k8s_apps_v1_sync):
    """Create Apps V1 API client (async-safe wrapper for async tests)."""
    return AsyncK8sClientWrapper(_k8s_apps_v1_sync)


@pytest.fixture(scope="session")
def _k8s_custom_objects_sync(k8s_client):
    """Create Custom Objects API client (synchronous, for use in non-async fixtures)."""
    return client.CustomObjectsApi(k8s_client)


@pytest.fixture(scope="session")
def k8s_custom_objects(_k8s_custom_objects_sync):
    """Create Custom Objects API client (async-safe wrapper for async tests)."""
    return AsyncK8sClientWrapper(_k8s_custom_objects_sync)


@pytest.fixture(scope="session")
def _k8s_rbac_v1_sync(k8s_client):
    """Create RBAC Authorization V1 API client (synchronous, for use in non-async fixtures)."""
    return client.RbacAuthorizationV1Api(k8s_client)


@pytest.fixture(scope="session")
def k8s_rbac_v1(_k8s_rbac_v1_sync):
    """Create RBAC Authorization V1 API client (async-safe wrapper for async tests)."""
    return AsyncK8sClientWrapper(_k8s_rbac_v1_sync)


@pytest.fixture(scope="session")
def operator_namespace():
    """Return the namespace where the operator will be deployed.

    Changed from reading environment to using a deterministic session-scoped name.
    This ensures consistency across xdist workers while maintaining isolation
    per test session.
    """
    # Use a fixed name for session-scoped operator
    # xdist workers will share this namespace via the cluster
    return "keycloak-test-system"


@pytest.fixture
async def test_namespace(
    k8s_core_v1, k8s_custom_objects, k8s_rbac_v1, operator_namespace, cleanup_tracker
) -> AsyncGenerator[str]:
    """
    Create a test namespace with robust cleanup and RBAC setup for realms/clients.

    This fixture ensures:
    - Unique namespace per test
    - RoleBinding for operator access (namespace-access ClusterRole)
    - Cleanup of all Keycloak resources before namespace deletion
    - Force-delete fallback if resources get stuck
    - Tracking of cleanup failures

    The RoleBinding grants the operator access to read labeled secrets,
    manage realms/clients in this namespace (new RBAC model).

    For Keycloak instances, use test_keycloak_namespace which grants full manager permissions.
    """
    namespace_name = f"test-{os.urandom(4).hex()}"

    # Create namespace
    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name, labels={"test": "integration", "operator": "keycloak"}
        )
    )

    try:
        await k8s_core_v1.create_namespace(namespace)
        logger.info(f"Created test namespace: {namespace_name}")

        # Create RoleBinding for operator access (new RBAC model)

        role_binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(
                name="keycloak-operator-access",
                namespace=namespace_name,
            ),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="ClusterRole",
                name="keycloak-operator-namespace-access",
            ),
            subjects=[
                client.RbacV1Subject(
                    kind="ServiceAccount",
                    name=f"keycloak-operator-{operator_namespace}",
                    namespace=operator_namespace,
                )
            ],
        )

        try:
            await k8s_rbac_v1.create_namespaced_role_binding(
                namespace_name, role_binding
            )
            logger.info(f"Created RoleBinding for operator access in {namespace_name}")
        except ApiException as e:
            if e.status != 409:  # Ignore AlreadyExists
                raise

        yield namespace_name
    finally:
        # Robust cleanup
        logger.info(f"Cleaning up test namespace: {namespace_name}")

        try:
            # Step 1: Clean up Keycloak resources first
            success, failed_resources = await cleanup_namespace_resources(
                k8s_custom_objects=k8s_custom_objects,
                namespace=namespace_name,
                timeout=120,
            )

            if not success:
                logger.warning(
                    f"Some resources failed to clean up in {namespace_name}: {failed_resources}"
                )
                for resource in failed_resources:
                    cleanup_tracker.record_failure(
                        resource_type="custom_resource",
                        name=resource,
                        namespace=namespace_name,
                        error="Timeout during cleanup",
                    )

            # Step 2: Delete namespace (will cascade delete remaining resources)
            success = await force_delete_namespace(
                k8s_core_v1=k8s_core_v1,
                namespace=namespace_name,
                timeout=60,
            )

            if not success:
                logger.error(f"Failed to delete namespace {namespace_name}")
                cleanup_tracker.record_failure(
                    resource_type="namespace",
                    name=namespace_name,
                    namespace="",
                    error="Timeout during namespace deletion",
                )
            else:
                logger.info(f"✓ Successfully cleaned up namespace: {namespace_name}")

        except Exception as e:
            logger.error(f"Error during namespace cleanup for {namespace_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="namespace",
                name=namespace_name,
                namespace="",
                error=str(e),
            )


@pytest.fixture
async def test_keycloak_namespace(
    k8s_core_v1,
    k8s_rbac_v1,
    k8s_custom_objects,
    operator_namespace: str,
    cleanup_tracker,
) -> AsyncGenerator[str]:
    """Create a test namespace with RBAC for Keycloak instance reconciliation.

    This fixture grants the operator manager-level permissions needed to manage
    Keycloak instances (StatefulSets, Services, ConfigMaps, etc.).

    Use this for tests that create Keycloak instances.
    For tests that only create Realms/Clients, use test_namespace instead.
    """
    logger = logging.getLogger(__name__)
    namespace_name = f"test-kc-{os.urandom(4).hex()}"

    # Create namespace
    namespace = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace_name, labels={"test": "integration", "operator": "keycloak"}
        )
    )

    try:
        await k8s_core_v1.create_namespace(namespace)
        logger.info(f"Created test Keycloak namespace: {namespace_name}")

        # Create Role with manager permissions
        # This mirrors the permissions in charts/keycloak-operator/templates/02_rbac.yaml
        role = client.V1Role(
            metadata=client.V1ObjectMeta(
                name="keycloak-operator-manager",
                namespace=namespace_name,
            ),
            rules=[
                # CRDs
                client.V1PolicyRule(
                    api_groups=["vriesdemichael.github.io"],
                    resources=["keycloaks", "keycloakclients", "keycloakrealms"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # Kubernetes core resource management
                client.V1PolicyRule(
                    api_groups=["apps"],
                    resources=["deployments", "statefulsets", "replicasets"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                client.V1PolicyRule(
                    api_groups=["apps"],
                    resources=[
                        "deployments/status",
                        "statefulsets/status",
                        "replicasets/status",
                    ],
                    verbs=["get"],
                ),
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=[
                        "services",
                        "configmaps",
                        "secrets",
                        "persistentvolumeclaims",
                    ],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                client.V1PolicyRule(
                    api_groups=[""],
                    resources=["pods", "pods/log"],
                    verbs=["get", "list", "watch"],
                ),
                # Networking
                client.V1PolicyRule(
                    api_groups=["networking.k8s.io"],
                    resources=["ingresses", "networkpolicies"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # Monitoring
                client.V1PolicyRule(
                    api_groups=["monitoring.coreos.com"],
                    resources=["servicemonitors"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # Certificate management
                client.V1PolicyRule(
                    api_groups=["cert-manager.io"],
                    resources=[
                        "certificates",
                        "certificaterequests",
                        "issuers",
                        "clusterissuers",
                    ],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # CloudNativePG
                client.V1PolicyRule(
                    api_groups=["postgresql.cnpg.io"],
                    resources=["clusters", "poolers", "backups"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # Webhook configuration
                client.V1PolicyRule(
                    api_groups=["admissionregistration.k8s.io"],
                    resources=[
                        "validatingwebhookconfigurations",
                        "mutatingwebhookconfigurations",
                    ],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # OpenShift support
                client.V1PolicyRule(
                    api_groups=["route.openshift.io"],
                    resources=["routes"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
                # Kopf peering
                client.V1PolicyRule(
                    api_groups=["kopf.dev"],
                    resources=["kopfpeerings"],
                    verbs=[
                        "get",
                        "list",
                        "watch",
                        "create",
                        "update",
                        "patch",
                        "delete",
                    ],
                ),
            ],
        )

        try:
            await k8s_rbac_v1.create_namespaced_role(namespace_name, role)
            logger.info(f"Created manager Role in {namespace_name}")
        except ApiException as e:
            if e.status != 409:
                raise

        # Create RoleBinding for operator manager access
        role_binding = client.V1RoleBinding(
            metadata=client.V1ObjectMeta(
                name="keycloak-operator-manager",
                namespace=namespace_name,
            ),
            role_ref=client.V1RoleRef(
                api_group="rbac.authorization.k8s.io",
                kind="Role",
                name="keycloak-operator-manager",
            ),
            subjects=[
                client.RbacV1Subject(
                    kind="ServiceAccount",
                    name=f"keycloak-operator-{operator_namespace}",
                    namespace=operator_namespace,
                )
            ],
        )

        try:
            await k8s_rbac_v1.create_namespaced_role_binding(
                namespace_name, role_binding
            )
            logger.info(f"Created manager RoleBinding in {namespace_name}")
        except ApiException as e:
            if e.status != 409:  # Ignore AlreadyExists
                raise

        yield namespace_name
    finally:
        # Cleanup
        logger.info(f"Cleaning up test Keycloak namespace: {namespace_name}")

        try:
            # Clean up Keycloak resources first
            success, failed_resources = await cleanup_namespace_resources(
                k8s_custom_objects=k8s_custom_objects,
                namespace=namespace_name,
                timeout=120,
            )

            if not success:
                logger.warning(
                    f"Some resources failed to clean up in {namespace_name}: {failed_resources}"
                )
                for resource in failed_resources:
                    cleanup_tracker.record_failure(
                        resource_type="custom_resource",
                        name=resource,
                        namespace=namespace_name,
                        error="Timeout during cleanup",
                    )

            # Delete namespace
            success = await force_delete_namespace(
                k8s_core_v1=k8s_core_v1,
                namespace=namespace_name,
                timeout=60,
            )

            if not success:
                logger.error(f"Failed to delete namespace {namespace_name}")
                cleanup_tracker.record_failure(
                    resource_type="namespace",
                    name=namespace_name,
                    namespace="",
                    error="Timeout during namespace deletion",
                )
            else:
                logger.info(f"✓ Successfully cleaned up namespace: {namespace_name}")

        except Exception as e:
            logger.error(f"Error during namespace cleanup for {namespace_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="namespace",
                name=namespace_name,
                namespace="",
                error=str(e),
            )


@pytest.fixture
async def test_secrets(k8s_core_v1, test_namespace) -> dict[str, str]:
    """Create test secrets for Keycloak instances with required RBAC label.

    All secrets now require the label: vriesdemichael.github.io/keycloak-allow-operator-read=true
    This is enforced by the new RBAC model.
    """
    secrets = {}

    # Database secret
    db_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name="test-db-secret",
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": "test-db-password", "username": "keycloak"},
    )
    await k8s_core_v1.create_namespaced_secret(test_namespace, db_secret)
    secrets["database"] = "test-db-secret"

    # Admin secret
    admin_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name="test-admin-secret",
            namespace=test_namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": "admin-password", "username": "admin"},
    )
    await k8s_core_v1.create_namespaced_secret(test_namespace, admin_secret)
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
def shared_cnpg_info(operator_namespace: str) -> dict[str, Any]:
    """Return connection info for the shared CNPG cluster in the operator namespace.

    This fixture provides access to the shared CNPG cluster that's deployed
    alongside the operator via Helm. Use this for tests that need to create
    Keycloak instances in separate namespaces (like test_keycloak_namespace).

    The shared CNPG cluster:
    - Is named 'keycloak-cnpg' in keycloak-test-system
    - Has app credentials in 'keycloak-cnpg-app' secret
    - Is accessible via FQDN from any namespace

    Returns:
        dict with type, host (FQDN), port, database, username, password_secret info
    """
    cluster_name = "keycloak-cnpg"
    return {
        "type": "postgresql",
        "host": f"{cluster_name}-rw.{operator_namespace}.svc.cluster.local",
        "port": 5432,
        "database": "app",
        "username": "app",
        "password_secret": f"{cluster_name}-app",
        "password_secret_namespace": operator_namespace,
    }


@pytest.fixture
async def cnpg_cluster(
    k8s_client, test_namespace, cnpg_installed
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
    import time

    start_time = time.time()
    timeout = 420
    interval = 5

    while time.time() - start_time < timeout:
        try:
            obj = cluster_api.get(name=cluster_name, namespace=test_namespace)
            phase = obj.to_dict().get("status", {}).get("phase")
            if phase == "Cluster in healthy state":
                # Confirm app secret existence
                core = client.CoreV1Api(k8s_client)
                try:
                    core.read_namespaced_secret(f"{cluster_name}-app", test_namespace)
                    break  # Success
                except ApiException:
                    pass  # Secret not ready yet, continue waiting
        except ApiException:
            pass  # Cluster status not available yet, continue waiting
        await asyncio.sleep(interval)
    else:
        pytest.skip("CNPG cluster was not ready in time")

    # Return standard PostgreSQL connection details
    # Use FQDN so that any namespace can reach the database
    return {
        "type": "postgresql",
        "host": f"{cluster_name}-rw.{test_namespace}.svc.cluster.local",
        "port": 5432,
        "database": db_name,
        "username": "app",
        "password_secret": f"{cluster_name}-app",
        "password_secret_namespace": test_namespace,
    }


@pytest.fixture
def sample_realm_spec() -> KeycloakRealmSpec:
    """Return a sample Keycloak realm specification using Pydantic model."""
    return KeycloakRealmSpec(
        operator_ref=OperatorRef(
            namespace="keycloak-system",
        ),
        realm_name="test-realm",
        display_name="Test Realm",
        client_authorization_grants=[
            "test-namespace"
        ],  # Default grant for test namespace
    )


@pytest.fixture
def sample_client_spec() -> KeycloakClientSpec:
    """Return a sample Keycloak client specification using Pydantic model."""
    return KeycloakClientSpec(
        realm_ref=RealmRef(
            name="test-realm",
            namespace="test-namespace",  # Will be overridden by test
        ),
        client_id="test-client",
        client_name="Test Client",
        public_client=False,
    )


@pytest.fixture
async def sample_keycloak_spec_factory(
    shared_cnpg_info, k8s_core_v1
) -> AsyncGenerator[Any]:
    """Factory to create sample Keycloak specs with proper secret copying.

    This factory creates a spec using the SHARED CNPG cluster in the operator
    namespace, and copies the database secret to the target namespace.

    This is used for tests that create Keycloak instances in test_keycloak_namespace
    and need to connect to the shared CNPG cluster.

    Usage:
        async def test_something(sample_keycloak_spec_factory, test_keycloak_namespace):
            spec = await sample_keycloak_spec_factory(test_keycloak_namespace)
            # Create Keycloak with spec in test_keycloak_namespace
    """
    copied_secrets: list[tuple[str, str]] = []  # Track (namespace, name) for cleanup

    async def create_spec(target_namespace: str) -> dict[str, Any]:
        """Create a Keycloak spec with the secret copied to target_namespace."""

        source_secret_name = shared_cnpg_info["password_secret"]
        source_namespace = shared_cnpg_info["password_secret_namespace"]

        # Read the source secret from operator namespace
        source_secret = await k8s_core_v1.read_namespaced_secret(
            name=source_secret_name, namespace=source_namespace
        )

        # Create a copy in target namespace with required label
        target_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=source_secret_name,
                namespace=target_namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            data=source_secret.data,
            type=source_secret.type,
        )

        try:
            await k8s_core_v1.create_namespaced_secret(target_namespace, target_secret)
            copied_secrets.append((target_namespace, source_secret_name))
        except ApiException as e:
            if e.status != 409:  # Ignore AlreadyExists
                raise

        return {
            "replicas": 1,
            "image": f"keycloak-optimized:{DEFAULT_KEYCLOAK_OPTIMIZED_VERSION}",
            "database": {
                "type": shared_cnpg_info["type"],
                "host": shared_cnpg_info["host"],
                "port": shared_cnpg_info["port"],
                "database": shared_cnpg_info["database"],
                "username": shared_cnpg_info["username"],
                "passwordSecret": {
                    "name": source_secret_name,
                    "key": "password",
                },
            },
            "resources": {
                "requests": {"cpu": "200m", "memory": "512Mi"},
                "limits": {"cpu": "500m", "memory": "1Gi"},
            },
        }

    yield create_spec

    # Cleanup copied secrets
    for namespace, name in copied_secrets:
        with contextlib.suppress(ApiException):
            await k8s_core_v1.delete_namespaced_secret(name, namespace)


@pytest.fixture
async def sample_keycloak_spec(cnpg_cluster, test_namespace) -> dict[str, Any]:
    """Return a sample Keycloak instance specification with database config.

    Uses cnpg_cluster fixture to get database connection details.
    Returns a dict ready to use as CR spec (not Pydantic model, as KeycloakSpec
    is complex and tests typically work with dict manifests).

    NOTE: This fixture creates the CNPG in test_namespace. If you need to use
    this spec in a different namespace (like test_keycloak_namespace), use
    sample_keycloak_spec_factory instead to ensure secrets are copied properly.
    """
    if cnpg_cluster is None:
        pytest.skip("CNPG not available, cannot create Keycloak instance")

    return {
        "replicas": 1,
        "image": f"keycloak-optimized:{DEFAULT_KEYCLOAK_OPTIMIZED_VERSION}",
        "database": {
            "type": cnpg_cluster["type"],
            "host": cnpg_cluster["host"],
            "port": cnpg_cluster["port"],
            "database": cnpg_cluster["database"],
            "username": cnpg_cluster["username"],
            "passwordSecret": {
                "name": cnpg_cluster["password_secret"],
                "key": "password",
            },
        },
        "resources": {
            "requests": {"cpu": "200m", "memory": "512Mi"},
            "limits": {"cpu": "500m", "memory": "1Gi"},
        },
    }


def build_realm_manifest(
    spec: KeycloakRealmSpec, name: str, namespace: str
) -> dict[str, Any]:
    """
    Build a complete KeycloakRealm manifest from a Pydantic spec.

    Uses model_dump(by_alias=True) to convert camelCase for Kubernetes API.
    """
    return {
        "apiVersion": "vriesdemichael.github.io/v1",
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
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakClient",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec.model_dump(by_alias=True, exclude_unset=True),
    }


@pytest.fixture(scope="session")
def wait_for_keycloak_ready(
    k8s_custom_objects,
    k8s_apps_v1,
    k8s_core_v1,  # kept for potential future pod-level checks
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
        import time

        from kubernetes.client.rest import ApiException

        start_time = time.time()

        while time.time() - start_time < timeout:
            deployment_name = f"{name}-keycloak"
            deployment_ready = False

            # Check deployment readiness first (acts as fallback if CR status lags)
            try:
                deployment = await k8s_apps_v1.read_namespaced_deployment(
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
                kc = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=name,
                )
                status = kc.get("status", {}) or {}
                if not status:
                    # Status has not been populated yet; keep waiting even if the
                    # deployment looks healthy so tests can validate status fields.
                    await asyncio.sleep(interval)
                    continue

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

            await asyncio.sleep(interval)

        return False

    return _wait


# ============================================================================
# Class-scoped fixtures for shared Keycloak instances (performance optimization)
# ============================================================================


@pytest.fixture(scope="session")
def coverage_enabled() -> bool:
    """Check if integration test coverage is enabled via environment variable.

    Returns:
        True if INTEGRATION_COVERAGE=true, False otherwise
    """
    return os.getenv("INTEGRATION_COVERAGE", "false").lower() == "true"


@pytest.fixture(scope="session")
def _helm_operator_chart_path() -> Path:
    """Return the path to the keycloak-operator Helm chart."""
    return Path(__file__).parent.parent.parent / "charts" / "keycloak-operator"


@pytest.fixture(scope="session", autouse=True)
async def shared_operator(
    k8s_client,
    k8s_custom_objects,
    k8s_apps_v1,
    k8s_core_v1,
    operator_namespace,
    _helm_operator_chart_path,
    cnpg_installed,
    coverage_enabled,
) -> AsyncGenerator[SharedOperatorInfo]:
    """Deploy Keycloak operator and instance via Helm for all tests.

    Prerequisites (validated by check_prerequisites fixture):
    - Kind cluster available
    - CNPG operator installed
    - Operator image built and loaded

    This fixture deploys the operator and Keycloak instance using Helm charts.

    Architecture:
    - Single operator deployment in operator namespace (default: keycloak-test-system)
    - Single Keycloak instance co-located with operator (1-1 coupling)
    - RBAC model: Minimal cluster-wide permissions + namespace Role
    - All secrets properly labeled with vriesdemichael.github.io/keycloak-allow-operator-read=true

    Session-scoped for:
    - Performance (one operator for all tests)
    - pytest-xdist compatibility (each worker gets own session)
    - Realistic production architecture

    Worker coordination:
    - Uses file-based reference counting to prevent premature cleanup
    - Each worker increments count on setup, decrements on teardown
    - Last worker (count=0) performs cleanup

    IMPORTANT RULES:
    1. **NO DESTRUCTIVE OPERATIONS** on the operator or Keycloak instance
    2. **UNIQUE REALM NAMES** for parallel test execution
    3. **CLEAN UP REALMS/CLIENTS** created during tests

    Returns:
        dict with 'name' and 'namespace' of the deployed Keycloak instance

    Raises:
        pytest.fail: If deployment fails (hard failure - no skipping)
    """
    keycloak_name = "keycloak"

    # Worker reference counting for cleanup coordination
    tmp_dir = Path(__file__).parent.parent.parent / ".tmp"
    tmp_dir.mkdir(exist_ok=True)
    worker_count_file = tmp_dir / "shared-operator-workers.count"
    worker_lock_file = tmp_dir / "shared-operator-workers.lock"

    # Increment worker count atomically
    with open(worker_lock_file, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if worker_count_file.exists():
                count = int(worker_count_file.read_text().strip())
            else:
                count = 0
            count += 1
            worker_count_file.write_text(str(count))
            logger.info(f"Worker registered. Active workers: {count}")
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    logger.info(
        f"Deploying Keycloak operator and instance via Helm in {operator_namespace}"
    )

    # Check if operator namespace already exists (xdist: another worker may have created it)
    try:
        await k8s_core_v1.read_namespace(operator_namespace)
        logger.info(f"Operator namespace {operator_namespace} already exists")
    except ApiException as e:
        if e.status == 404:
            # Create namespace (handle race condition with other workers)
            namespace = client.V1Namespace(
                metadata=client.V1ObjectMeta(
                    name=operator_namespace,
                    labels={
                        "test": "integration",
                        "operator": "keycloak",
                        "pod-security.kubernetes.io/enforce": "restricted",
                    },
                )
            )
            try:
                await k8s_core_v1.create_namespace(namespace)
                logger.info(f"Created operator namespace: {operator_namespace}")
            except ApiException as create_err:
                if create_err.status == 409:
                    # Another worker created it between our check and create - that's fine
                    logger.info(
                        f"Operator namespace {operator_namespace} created by another worker"
                    )
                else:
                    raise
        else:
            raise

    # Prepare Helm values for operator deployment
    # Use optimized Keycloak image if available for faster test startup
    # Format: "keycloak-optimized:26.4.1" or "ghcr.io/<repo>/keycloak-optimized:26.4.1"
    keycloak_image_full = os.getenv(
        "KEYCLOAK_IMAGE", f"keycloak-optimized:{DEFAULT_KEYCLOAK_OPTIMIZED_VERSION}"
    )

    # Split image and tag for Helm values
    if ":" in keycloak_image_full:
        keycloak_image, keycloak_version = keycloak_image_full.rsplit(":", 1)
    else:
        keycloak_image = keycloak_image_full
        keycloak_version = DEFAULT_KEYCLOAK_OPTIMIZED_VERSION

    helm_values = {
        "namespace": {"name": operator_namespace, "create": False},
        "keycloak": {
            # Enable Keycloak creation with CNPG database
            "enabled": True,
            "replicas": 1,
            "image": keycloak_image,  # Use optimized image for faster startup
            "version": keycloak_version,
            "database": {
                "cnpg": {
                    "enabled": cnpg_installed,
                    "clusterName": "keycloak-cnpg",  # Required for CNPG
                }
            },
        },
        "operator": {
            "replicaCount": 1,
            "image": {
                "repository": "keycloak-operator",
                "tag": "test",
                "pullPolicy": "Never",  # Use local image only
            },
            # Use short timer intervals for faster stuck finalizer detection in tests
            "reconciliation": {
                "timerIntervals": {
                    "keycloak": 10,
                    "realm": 10,
                    "client": 10,
                },
            },
        },
        "webhooks": {
            # Enable admission webhooks (default behavior)
            "enabled": True,
        },
        "monitoring": {
            # Enable drift detection with short interval for testing
            # This allows operator-side drift detection tests to exercise
            # the DriftDetector code paths in the operator pod
            "driftDetection": {
                "enabled": True,
                "intervalSeconds": 30,  # Short interval for testing
                "autoRemediate": True,  # Enable auto-remediation for testing
                # Use 1 hour minimum age so orphans created via CRs (with fresh
                # timestamps) are NOT auto-remediated. Operator-side tests that
                # WANT remediation create orphans with old timestamps (2020-01-01).
                "minimumAgeHours": 1,
                "scope": {
                    "realms": True,
                    "clients": True,
                    "identityProviders": True,
                    "roles": True,
                },
            },
        },
    }

    # Create values file
    import tempfile

    import yaml

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as values_file:
        yaml.dump(helm_values, values_file)
        values_path = values_file.name

    # Use file lock to serialize Helm operations across xdist workers
    lock_path = Path(tempfile.gettempdir()) / "keycloak-operator-helm-install.lock"

    with open(lock_path, "w") as lock_file:
        # Acquire exclusive lock (blocks until available)
        logger.info("Acquiring lock for Helm install...")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        logger.info("Lock acquired")

        try:
            # Install/upgrade operator via Helm (now serialized across workers)
            install_cmd = [
                "helm",
                "upgrade",
                "--install",
                "keycloak-operator",
                str(_helm_operator_chart_path),
                "-n",
                operator_namespace,
                "-f",
                values_path,
                "--wait",
                "--timeout",
                "3m",  # Max 3 minutes for Helm install
            ]

            logger.info("Installing/upgrading Keycloak operator via Helm...")
            proc = await asyncio.create_subprocess_exec(
                *install_cmd, stdout=PIPE, stderr=PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Helm install failed: {error_msg}")
                pytest.fail(f"Failed to install operator via Helm: {error_msg}")

            logger.info("✓ Operator installed/upgraded via Helm")
        finally:
            # Release lock (file will auto-close via context manager)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            logger.info("Lock released")

    try:
        # Wait for operator deployment to be ready
        import time

        start_time = time.time()
        timeout = 120
        interval = 3
        ready = False

        while time.time() - start_time < timeout:
            try:
                deployment = await k8s_apps_v1.read_namespaced_deployment(
                    name="keycloak-operator", namespace=operator_namespace
                )
                desired = deployment.spec.replicas or 1
                current_ready = deployment.status.ready_replicas or 0
                if current_ready >= desired:
                    ready = True
                    break
            except ApiException:
                pass
            await asyncio.sleep(interval)

        if not ready:
            pytest.fail(
                "Operator deployment not ready in time (timeout: 120s). "
                "Check if operator image was loaded correctly with 'make kind-load'."
            )

        logger.info("✓ Operator deployment ready")

        # Create operator authentication token secret for tests
        # This acts as the "admission token" that realms will use to bootstrap
        logger.info("Creating operator authentication token secret...")
        try:
            import base64
            import hashlib
            import json
            from datetime import UTC, datetime, timedelta

            operator_token = "test-operator-token-12345"
            operator_secret_name = "keycloak-operator-auth-token"

            # Check if secret already exists
            try:
                await k8s_core_v1.read_namespaced_secret(
                    name=operator_secret_name, namespace=operator_namespace
                )
                logger.info("✓ Operator auth token secret already exists")
            except ApiException as e:
                if e.status == 404:
                    # Create the secret
                    secret_body = {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {
                            "name": operator_secret_name,
                            "namespace": operator_namespace,
                            "labels": {
                                "vriesdemichael.github.io/keycloak-allow-operator-read": "true",
                                "vriesdemichael.github.io/keycloak-token-type": "admission",
                                "app.kubernetes.io/name": "keycloak-operator",
                            },
                        },
                        "type": "Opaque",
                        "data": {
                            "token": base64.b64encode(operator_token.encode()).decode(),
                        },
                    }

                    await k8s_core_v1.create_namespaced_secret(
                        namespace=operator_namespace, body=secret_body
                    )
                    logger.info("✓ Created operator auth token secret")
                else:
                    raise

            # Initialize token metadata ConfigMap
            configmap_name = "keycloak-operator-token-metadata"

            # Check if ConfigMap already exists
            try:
                await k8s_core_v1.read_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace
                )
                logger.info("✓ Token metadata ConfigMap already exists")
            except ApiException as e:
                if e.status == 404:
                    # Create the operator's token metadata
                    token_hash = hashlib.sha256(operator_token.encode()).hexdigest()

                    token_metadata = {
                        "namespace": operator_namespace,
                        "token_type": "admission",
                        "issued_at": datetime.now(UTC).isoformat(),
                        "valid_until": (
                            datetime.now(UTC) + timedelta(days=365)
                        ).isoformat(),
                        "version": 1,
                        "created_by_realm": None,
                        "revoked": False,
                        "revoked_at": None,
                    }

                    cm_body = {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {
                            "name": configmap_name,
                            "namespace": operator_namespace,
                            "labels": {
                                "app.kubernetes.io/name": "keycloak-operator",
                                "app.kubernetes.io/component": "token-metadata",
                            },
                        },
                        "data": {token_hash: json.dumps(token_metadata)},
                    }

                    try:
                        await k8s_core_v1.create_namespaced_config_map(
                            namespace=operator_namespace, body=cm_body
                        )
                        logger.info("✓ Created token metadata ConfigMap")
                    except ApiException as create_err:
                        if create_err.status == 409:
                            # Another worker created it between our check and create - that's fine
                            logger.info(
                                "✓ Token metadata ConfigMap created by another worker"
                            )
                        else:
                            raise
                else:
                    raise
        except Exception as setup_error:
            logger.error(f"Failed to setup token infrastructure: {setup_error}")
            pytest.fail(f"Failed to setup token infrastructure: {setup_error}")

        # Wait for Keycloak instance to be ready (deployed by operator chart)
        start_time = time.time()
        timeout = 200
        interval = 5
        ready = False

        while time.time() - start_time < timeout:
            try:
                kc = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=operator_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
                status = kc.get("status", {}) or {}
                phase = status.get("phase")

                if phase in ("Ready", "Degraded"):
                    # Check deployment AND that pods are actually ready
                    try:
                        deployment = await k8s_apps_v1.read_namespaced_deployment(
                            name=f"{keycloak_name}-keycloak",
                            namespace=operator_namespace,
                        )
                        desired = deployment.spec.replicas or 1
                        current_ready = deployment.status.ready_replicas or 0

                        if current_ready >= desired:
                            ready = True
                            break
                        else:
                            logger.debug(
                                f"Keycloak deployment {keycloak_name}-keycloak: {current_ready}/{desired} pods ready"
                            )
                    except ApiException as deploy_error:
                        logger.debug(f"Deployment not found or error: {deploy_error}")
            except ApiException:
                pass
            await asyncio.sleep(interval)

        if not ready:
            # Check Keycloak CR status for error details
            try:
                kc = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=operator_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
                status = kc.get("status", {})
                logger.error(f"Keycloak instance status: {status}")
                pytest.fail(
                    f"Keycloak instance not ready in time (timeout: 200s). Status: {status}"
                )
            except Exception as e:
                logger.error(f"Failed to get Keycloak status: {e}")
                pytest.fail(f"Keycloak instance not ready in time (timeout: 300s): {e}")

        logger.info("✓ Keycloak instance ready")

        # Wait for webhook server to be ready (if webhooks enabled)
        logger.info("Waiting for webhook server to be ready...")
        webhook_ready = False
        start_time = time.time()
        webhook_timeout = 60
        webhook_interval = 2

        while time.time() - start_time < webhook_timeout:
            try:
                # Try to create and immediately delete a test realm to verify webhook is responding
                test_realm_name = f"webhook-readiness-test-{int(time.time())}"
                await k8s_custom_objects.create_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=operator_namespace,
                    plural="keycloakrealms",
                    body={
                        "apiVersion": "vriesdemichael.github.io/v1",
                        "kind": "KeycloakRealm",
                        "metadata": {"name": test_realm_name},
                        "spec": {
                            "realmName": test_realm_name,
                            "operatorRef": {"namespace": operator_namespace},
                        },
                    },
                )
                # If we got here, webhook accepted the request - delete the test realm
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=operator_namespace,
                    plural="keycloakrealms",
                    name=test_realm_name,
                )
                webhook_ready = True
                logger.info("✓ Webhook server is responding")
                break
            except ApiException as webhook_error:
                # 500 errors mean webhook server not ready yet
                if (
                    webhook_error.status == 500
                    and "connection refused" in str(webhook_error.body).lower()
                ):
                    logger.debug("Webhook server not ready yet, retrying...")
                    await asyncio.sleep(webhook_interval)
                else:
                    # Other errors (like validation failures) mean webhook IS responding
                    webhook_ready = True
                    logger.info("✓ Webhook server is responding")
                    break
            except Exception as e:
                logger.debug(f"Webhook readiness check error: {e}")
                await asyncio.sleep(webhook_interval)

        if not webhook_ready:
            logger.warning(
                f"Webhook server did not become ready within {webhook_timeout}s - tests may be flaky"
            )

        yield SharedOperatorInfo(name=keycloak_name, namespace=operator_namespace)

    except Exception as e:
        logger.error(f"Error during operator deployment: {e}")
        pytest.fail(f"Failed to deploy operator: {e}")
        raise  # Unreachable but satisfies type checker

    finally:
        # Clean up values file
        Path(values_path).unlink(missing_ok=True)

        # NOTE: Cleanup is handled by pytest_sessionfinish hook to avoid race conditions
        # with pytest-xdist workers. The fixture teardown used to track worker counts
        # but this caused premature cleanup when a worker exited early (e.g., due to test errors).
        # Now we let pytest_sessionfinish handle all cleanup after coverage retrieval.


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


@pytest.fixture
async def keycloak_admin_client(shared_operator, keycloak_port_forward):
    """
    Provide a KeycloakAdminClient connected via port-forward for testing.

    This fixture automatically sets up port-forwarding to the Keycloak instance
    deployed by shared_operator, retrieves admin credentials, and creates an
    authenticated admin client that tests can use to interact with Keycloak.

    Dependencies:
        - shared_operator: Ensures Keycloak is deployed and ready
        - keycloak_port_forward: Provides port-forwarding capability

    Returns:
        KeycloakAdminClient: Authenticated admin client connected to localhost

    Usage:
        async def test_something(keycloak_admin_client):
            realm = await keycloak_admin_client.get_realm("my-realm", "my-namespace")
    """
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
    from keycloak_operator.utils.kubernetes import get_admin_credentials

    local_port = await keycloak_port_forward(
        shared_operator.name, shared_operator.namespace
    )

    username, password = get_admin_credentials(
        shared_operator.name, shared_operator.namespace
    )

    admin_client = KeycloakAdminClient(
        server_url=f"http://localhost:{local_port}",
        username=username,
        password=password,
    )

    await admin_client.authenticate()

    yield admin_client

    # Cleanup: close the admin client, catching event loop closure errors
    # that can occur when pytest-asyncio tears down between test sessions
    try:
        await admin_client.close()
    except RuntimeError as e:
        if "Event loop is closed" not in str(e):
            raise


@pytest.fixture
async def keycloak_ready(
    shared_operator: SharedOperatorInfo,
    keycloak_port_forward,
    keycloak_admin_client,
) -> KeycloakReadySetup:
    """Composite fixture providing complete Keycloak setup.

    This fixture combines shared_operator, port-forward, and admin_client into
    a single Pydantic model for convenience and type safety.

    Usage:
        async def test_something(keycloak_ready: KeycloakReadySetup):
            # Access operator info
            operator_ns = keycloak_ready.operator.namespace

            # Access port-forwarded Keycloak
            port = keycloak_ready.local_port

            # Use admin client
            realm = await keycloak_ready.admin_client.get_realm("test", "ns")

    Returns:
        KeycloakReadySetup with operator info, local port, and authenticated admin client
    """
    # Port-forward is already set up by keycloak_admin_client dependency
    # Extract the port from the admin client's server_url
    from urllib.parse import urlparse

    parsed_url = urlparse(keycloak_admin_client.server_url)
    local_port = parsed_url.port or 80

    return KeycloakReadySetup(
        operator=shared_operator,
        local_port=local_port,
        admin_client=keycloak_admin_client,
    )


# ============================================================================
# Managed Resource Fixtures (with robust cleanup)
# ============================================================================


@pytest.fixture
async def managed_realm(
    k8s_custom_objects,
    test_namespace: str,
    cleanup_tracker: CleanupTracker,
):
    """
    Create and manage a KeycloakRealm with automatic cleanup.

    Usage:
        async def test_something(managed_realm):
            realm_name, realm_manifest = await managed_realm(
                realm_name="my-realm",
                operator_namespace="keycloak-system"
            )
            # Test code here
            # Cleanup happens automatically
    """
    created_realms = []

    async def _create_realm(
        realm_name: str,
        operator_namespace: str,
        admin_secret: str = "keycloak-admin-credentials",
        **realm_spec_overrides,
    ) -> tuple[str, dict[str, Any]]:
        """
        Create a realm and track it for cleanup.

        Returns:
            Tuple of (realm_name, realm_manifest)
        """
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": test_namespace},
            "spec": {
                "realmName": realm_name,
                "operatorRef": {
                    "namespace": operator_namespace,
                    "authorizationSecretRef": {"name": admin_secret, "key": "token"},
                },
                **realm_spec_overrides,
            },
        }

        await k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_manifest,
        )

        logger.info(f"Created realm {realm_name} in namespace {test_namespace}")
        created_realms.append(realm_name)

        return realm_name, realm_manifest

    yield _create_realm

    # Cleanup all created realms
    for realm_name in created_realms:
        try:
            success = await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                force_after=60,
            )

            if not success:
                cleanup_tracker.record_failure(
                    resource_type="keycloakrealm",
                    name=realm_name,
                    namespace=test_namespace,
                    error="Cleanup timeout",
                )
            else:
                logger.info(f"✓ Cleaned up realm {realm_name}")

        except Exception as e:
            logger.error(f"Error cleaning up realm {realm_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="keycloakrealm",
                name=realm_name,
                namespace=test_namespace,
                error=str(e),
            )


@pytest.fixture
async def managed_client(
    k8s_custom_objects,
    test_namespace: str,
    cleanup_tracker: CleanupTracker,
):
    """
    Create and manage a KeycloakClient with automatic cleanup.

    Usage:
        async def test_something(managed_client):
            client_name, client_manifest = await managed_client(
                client_name="my-client",
                realm_name="my-realm",
                client_id="test-client"
            )
            # Test code here
            # Cleanup happens automatically
    """
    created_clients = []

    async def _create_client(
        client_name: str,
        realm_name: str,
        client_id: str,
        realm_namespace: str | None = None,
        auth_secret: str = "realm-auth",
        **client_spec_overrides,
    ) -> tuple[str, dict[str, Any]]:
        """
        Create a client and track it for cleanup.

        Returns:
            Tuple of (client_name, client_manifest)
        """
        if realm_namespace is None:
            realm_namespace = test_namespace

        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": test_namespace},
            "spec": {
                "clientId": client_id,
                "realmRef": {
                    "name": realm_name,
                    "namespace": realm_namespace,
                    "authorizationSecretRef": {"name": auth_secret, "key": "token"},
                },
                **client_spec_overrides,
            },
        }

        await k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            body=client_manifest,
        )

        logger.info(f"Created client {client_name} in namespace {test_namespace}")
        created_clients.append(client_name)

        return client_name, client_manifest

    yield _create_client

    # Cleanup all created clients
    for client_name in created_clients:
        try:
            success = await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=120,
                force_after=60,
            )

            if not success:
                cleanup_tracker.record_failure(
                    resource_type="keycloakclient",
                    name=client_name,
                    namespace=test_namespace,
                    error="Cleanup timeout",
                )
            else:
                logger.info(f"✓ Cleaned up client {client_name}")

        except Exception as e:
            logger.error(f"Error cleaning up client {client_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="keycloakclient",
                name=client_name,
                namespace=test_namespace,
                error=str(e),
            )


# ============================================================================
# Helm-based fixtures for realm and client management
# ============================================================================


@pytest.fixture
def _helm_realm_chart_path() -> Path:
    """Return the path to the keycloak-realm Helm chart."""
    return Path(__file__).parent.parent.parent / "charts" / "keycloak-realm"


@pytest.fixture
def _helm_client_chart_path() -> Path:
    """Return the path to the keycloak-client Helm chart."""
    return Path(__file__).parent.parent.parent / "charts" / "keycloak-client"


@pytest.fixture
async def helm_realm(
    _helm_realm_chart_path: Path,
    test_namespace: str,
    cleanup_tracker: CleanupTracker,
):
    """
    Create and manage a KeycloakRealm using Helm with automatic cleanup.

    Usage:
        async def test_something(helm_realm):
            release_name = await helm_realm(
                release_name="my-realm",
                realm_name="test-realm",
                operator_namespace="keycloak-system"
            )
            # Test code here
            # Cleanup happens automatically
    """
    created_releases: list[str] = []

    async def _install_realm(
        release_name: str,
        realm_name: str,
        operator_namespace: str = "keycloak-system",
        **values_overrides,
    ) -> str:
        """
        Install a realm via Helm and track it for cleanup.

        Returns:
            Release name
        """
        # Build Helm values
        values = {
            "realmName": realm_name,
            "operatorRef": {
                "namespace": operator_namespace,
            },
            **values_overrides,
        }

        # Create values file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as values_file:
            import yaml

            yaml.dump(values, values_file)
            values_path = values_file.name

        try:
            # Install Helm chart
            cmd = [
                "helm",
                "install",
                release_name,
                str(_helm_realm_chart_path),
                "-n",
                test_namespace,
                "-f",
                values_path,
                "--wait",
                "--timeout",
                "5m",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                raise RuntimeError(
                    f"Helm install failed: {stderr.decode() if stderr else 'Unknown error'}"
                )

            logger.info(
                f"Installed realm {realm_name} via Helm release {release_name} in namespace {test_namespace}"
            )
            created_releases.append(release_name)

            return release_name

        finally:
            # Clean up values file
            Path(values_path).unlink(missing_ok=True)

    yield _install_realm

    # Cleanup all created Helm releases
    for release_name in created_releases:
        try:
            cmd = [
                "helm",
                "uninstall",
                release_name,
                "-n",
                test_namespace,
                "--wait",
                "--timeout",
                "2m",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

            await proc.communicate()

            if proc.returncode == 0:
                logger.info(f"✓ Cleaned up Helm release {release_name}")
            else:
                cleanup_tracker.record_failure(
                    resource_type="helm_release",
                    name=release_name,
                    namespace=test_namespace,
                    error="Helm uninstall failed",
                )

        except Exception as e:
            logger.error(f"Error cleaning up Helm release {release_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="helm_release",
                name=release_name,
                namespace=test_namespace,
                error=str(e),
            )


@pytest.fixture
async def helm_client(
    _helm_client_chart_path: Path,
    test_namespace: str,
    cleanup_tracker: CleanupTracker,
):
    """
    Create and manage a KeycloakClient using Helm with automatic cleanup.

    Usage:
        async def test_something(helm_client):
            release_name = await helm_client(
                release_name="my-client",
                client_id="test-client",
                realm_name="test-realm",
                realm_namespace="test-ns"
            )
            # Test code here
            # Cleanup happens automatically
    """
    created_releases: list[str] = []

    async def _install_client(
        release_name: str,
        client_id: str,
        realm_name: str,
        realm_namespace: str,
        realm_auth_secret: str | None = None,
        **values_overrides,
    ) -> str:
        """
        Install a client via Helm and track it for cleanup.

        Returns:
            Release name
        """
        # Build Helm values
        values: dict[str, Any] = {
            "clientId": client_id,
            "realmRef": {
                "name": realm_name,
                "namespace": realm_namespace,
            },
            **values_overrides,
        }

        # Add authorization secret ref if provided
        if realm_auth_secret:
            values["realmRef"]["authorizationSecretRef"] = {
                "name": realm_auth_secret,
                "key": "token",
            }

        # Create values file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as values_file:
            import yaml

            yaml.dump(values, values_file)
            values_path = values_file.name

        try:
            # Install Helm chart
            cmd = [
                "helm",
                "install",
                release_name,
                str(_helm_client_chart_path),
                "-n",
                test_namespace,
                "-f",
                values_path,
                "--wait",
                "--timeout",
                "5m",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                raise RuntimeError(
                    f"Helm install failed: {stderr.decode() if stderr else 'Unknown error'}"
                )

            logger.info(
                f"Installed client {client_id} via Helm release {release_name} in namespace {test_namespace}"
            )
            created_releases.append(release_name)

            return release_name

        finally:
            # Clean up values file
            Path(values_path).unlink(missing_ok=True)

    yield _install_client

    # Cleanup all created Helm releases
    for release_name in created_releases:
        try:
            # First, manually delete the KeycloakClient CR to avoid finalizer issues
            # Helm-created resources follow the pattern: {release-name}-keycloak-client
            client_name = f"{release_name}-keycloak-client"

            # Try to get the custom objects API
            try:
                from kubernetes import client

                k8s_client = client.ApiClient()
                custom_api = client.CustomObjectsApi(k8s_client)

                # Try to delete the client CR with a short timeout
                try:
                    await custom_api.delete_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    logger.info(
                        f"Deleted KeycloakClient CR {client_name} before Helm uninstall"
                    )

                    # Wait a bit for the CR to be deleted
                    await asyncio.sleep(2)
                except Exception as e:
                    # CR might not exist or already deleted, that's fine
                    logger.debug(
                        f"Could not pre-delete KeycloakClient {client_name}: {e}"
                    )
            except Exception as e:
                logger.debug(f"Could not setup K8s client for pre-cleanup: {e}")

            # Now run helm uninstall with a shorter timeout since we pre-cleaned the CR
            cmd = [
                "helm",
                "uninstall",
                release_name,
                "-n",
                test_namespace,
                "--wait",
                "--timeout",
                "1m",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=PIPE,
                stderr=PIPE,
            )

            await proc.communicate()

            if proc.returncode == 0:
                logger.info(f"✓ Cleaned up Helm release {release_name}")
            else:
                cleanup_tracker.record_failure(
                    resource_type="helm_release",
                    name=release_name,
                    namespace=test_namespace,
                    error="Helm uninstall failed",
                )

        except Exception as e:
            logger.error(f"Error cleaning up Helm release {release_name}: {e}")
            cleanup_tracker.record_failure(
                resource_type="helm_release",
                name=release_name,
                namespace=test_namespace,
                error=str(e),
            )


# ============================================================================
# Auth Token Factory (Consolidated)
# ============================================================================

# ============================================================================
# Drift Detection Fixtures
# ============================================================================


@pytest.fixture
async def operator_instance_id(k8s_apps_v1, shared_operator):
    """Get the actual operator instance ID from running deployment."""
    deployment = await k8s_apps_v1.read_namespaced_deployment(
        name="keycloak-operator", namespace=shared_operator.namespace
    )

    # Extract from environment variable
    for container in deployment.spec.template.spec.containers:
        for env in container.env or []:
            if env.name == "OPERATOR_INSTANCE_ID":
                return env.value

    # Fallback to Helm chart default pattern
    return f"keycloak-operator-{shared_operator.namespace}"


# ============================================================================
# CR Factory Functions
# ============================================================================


@pytest.fixture
def realm_cr_factory(
    test_namespace: str,
    shared_operator: SharedOperatorInfo,
):
    """Factory for creating KeycloakRealm CR manifests.

    This replaces the realm_cr fixture to allow customization without modifying
    shared state.

    Usage:
        def test_something(realm_cr_factory):
            # Simple usage
            realm_manifest = realm_cr_factory(
                realm_name="custom-realm",
                settings={"enabled": False},
            )

    Args:
        realm_name: Optional custom realm name
        settings: Optional realm settings dict to merge
        **overrides: Any other spec fields to override
    """

    def _create_realm_cr(**overrides: Any) -> dict[str, Any]:
        """Create a KeycloakRealm CR manifest with optional overrides."""
        realm_name = overrides.pop(
            "realm_name", f"drift-test-realm-{int(time.time() * 1000)}"
        )

        base_manifest: dict[str, Any] = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {
                "name": f"realm-{realm_name}",
                "namespace": test_namespace,
            },
            "spec": {
                "realmName": realm_name,
                "operatorRef": {
                    "namespace": shared_operator.namespace,
                },
                "clientAuthorizationGrants": [
                    test_namespace
                ],  # Grant test namespace access
                "settings": {
                    "enabled": True,
                    "registrationAllowed": False,
                },
            },
        }

        # Apply overrides to spec
        if overrides:
            base_manifest["spec"].update(overrides)

        return base_manifest

    return _create_realm_cr


@pytest.fixture
def client_cr_factory(
    test_namespace: str,
):
    """Factory for creating KeycloakClient CR manifests.

    This replaces the client_cr fixture to allow customization without modifying
    shared state.

    Usage:
        def test_something(client_cr_factory, realm_cr_factory):
            realm_cr = realm_cr_factory()
            client_cr = client_cr_factory(
                realm_cr=realm_cr,
                client_id="my-client",
                public_client=False,
                # Optionally override the realm_token_secret
                # realm_token_secret="custom-secret-name",
            )

    Args:
        realm_cr: The realm CR dict (from realm_cr_factory)
        client_id: Optional custom client ID
        realm_token_secret: Optional secret name containing realm's operational token.
                           Defaults to "{test_namespace}-operator-token"
        **overrides: Any other spec fields to override
    """

    def _create_client_cr(realm_cr: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        """Create a KeycloakClient CR manifest with optional overrides.

        Args:
            realm_cr: The realm manifest dict
            client_id: Custom client ID (optional)
            realm_token_secret: Custom token secret name (optional,
                               defaults to "{test_namespace}-operator-token")
            **overrides: Additional spec fields to override
        """
        client_id = overrides.pop(
            "client_id", f"drift-test-client-{int(time.time() * 1000)}"
        )

        # Use realm's operational token, not admission token
        realm_token_secret = overrides.pop(
            "realm_token_secret", f"{test_namespace}-operator-token"
        )

        base_manifest: dict[str, Any] = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {
                "name": f"client-{client_id}",
                "namespace": test_namespace,
            },
            "spec": {
                "clientId": client_id,
                "realmRef": {
                    "name": realm_cr["metadata"]["name"],
                    "namespace": test_namespace,
                    "authorizationSecretRef": {
                        "name": realm_token_secret,
                        "key": "token",
                    },
                },
                "publicClient": True,
                "redirectUris": ["https://example.com/callback"],
            },
        }

        # Apply overrides to spec
        if overrides:
            base_manifest["spec"].update(overrides)

        return base_manifest

    return _create_client_cr


# ============================================================================
# Legacy CR Fixtures (Deprecated - use factory functions)
# ============================================================================


@pytest.fixture
async def realm_cr(
    realm_cr_factory,
):
    """DEPRECATED: Use realm_cr_factory instead.

    Create a KeycloakRealm CR spec for drift detection tests.
    """
    return realm_cr_factory()


@pytest.fixture
async def client_cr(
    test_namespace: str,
    realm_cr: dict,
    client_cr_factory,
):
    """DEPRECATED: Use client_cr_factory instead.

    Create a KeycloakClient CR spec for drift detection tests.
    """
    return client_cr_factory(realm_cr=realm_cr)


# ============================================================================
# Drift Detection Fixtures
# ============================================================================


@pytest.fixture
async def drift_detector(
    shared_operator,
    keycloak_port_forward,
    operator_instance_id,
    k8s_client,
):
    """Create DriftDetector with port-forwarded admin client.

    This fixture provides a factory function that creates DriftDetector instances
    with proper port-forwarding setup for host-to-cluster communication.

    Returns:
        Callable that takes DriftDetectionConfig and returns configured DriftDetector
    """
    from keycloak_operator.services.drift_detection_service import DriftDetector
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
    from keycloak_operator.utils.kubernetes import get_admin_credentials

    # Set up port-forward once for this test
    local_port = await keycloak_port_forward(
        shared_operator.name, shared_operator.namespace
    )

    # Create custom admin client factory that uses port-forwarding
    async def admin_factory(kc_name: str, namespace: str, rate_limiter=None):
        username, password = get_admin_credentials(kc_name, namespace)
        client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username=username,
            password=password,
            rate_limiter=rate_limiter,
        )
        await client.authenticate()
        return client

    # Return factory function for tests to configure detector
    def create_detector(config):
        return DriftDetector(
            config=config,
            k8s_client=k8s_client,
            keycloak_admin_factory=admin_factory,
            operator_instance_id=operator_instance_id,
            operator_namespace=shared_operator.namespace,
        )

    return create_detector


# ============================================================================
# Pytest Hooks for Coverage Collection and Log Collection
# ============================================================================

# Track if logs have been collected to avoid duplicate collection
_logs_collected = False


def _collect_operator_logs() -> None:
    """Collect operator logs to .tmp/test-logs for debugging.

    This runs at the end of pytest session to capture operator logs,
    which are essential for debugging test failures.
    """
    global _logs_collected
    if _logs_collected:
        return
    _logs_collected = True

    import subprocess
    import sys

    print("[pytest] Collecting operator logs...", file=sys.stderr)

    log_dir = Path(__file__).parent.parent.parent / ".tmp" / "test-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Collect cluster info
        with open(log_dir / "cluster-info.log", "w") as f:
            subprocess.run(
                ["kubectl", "cluster-info"],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=10,
            )

        # Collect operator logs from all pods with the operator label
        with open(log_dir / "operator-logs.log", "w") as log_file:
            result = subprocess.run(
                [
                    "kubectl",
                    "get",
                    "pods",
                    "-l",
                    "app.kubernetes.io/name=keycloak-operator",
                    "--all-namespaces",
                    "-o",
                    "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {end}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            pods = result.stdout.strip().split()
            for pod_info in pods:
                if "/" not in pod_info:
                    continue
                namespace, pod_name = pod_info.split("/", 1)
                log_file.write(f"\n{'=' * 80}\n")
                log_file.write(f"=== Logs from {namespace}/{pod_name} ===\n")
                log_file.write(f"{'=' * 80}\n")
                pod_result = subprocess.run(
                    [
                        "kubectl",
                        "logs",
                        "-n",
                        namespace,
                        pod_name,
                        "--all-containers=true",
                        "--tail=2000",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                log_file.write(pod_result.stdout)
                if pod_result.stderr:
                    log_file.write(f"\nSTDERR:\n{pod_result.stderr}")

        # Collect operator deployment status
        with open(log_dir / "operator-status.log", "w") as f:
            subprocess.run(
                [
                    "kubectl",
                    "get",
                    "deployment",
                    "-l",
                    "app.kubernetes.io/name=keycloak-operator",
                    "--all-namespaces",
                    "-o",
                    "wide",
                ],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=10,
            )

        # Collect test resources
        with open(log_dir / "test-resources.log", "w") as f:
            subprocess.run(
                [
                    "kubectl",
                    "get",
                    "keycloaks,keycloakrealms,keycloakclients",
                    "--all-namespaces",
                    "-o",
                    "wide",
                ],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=10,
            )

        # Collect events
        with open(log_dir / "events.log", "w") as f:
            subprocess.run(
                [
                    "kubectl",
                    "get",
                    "events",
                    "--all-namespaces",
                    "--sort-by=.lastTimestamp",
                ],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=10,
            )

        # Collect all pods status
        with open(log_dir / "all-pods.log", "w") as f:
            subprocess.run(
                ["kubectl", "get", "pods", "--all-namespaces", "-o", "wide"],
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=10,
            )

        print(f"[pytest] ✓ Operator logs collected to {log_dir}", file=sys.stderr)

    except Exception as e:
        print(f"[pytest] Failed to collect operator logs: {e}", file=sys.stderr)


def pytest_sessionfinish(session, exitstatus):
    """
    Hook that runs after all tests complete, before test run ends.

    This is the ONLY reliable way to retrieve coverage with pytest-xdist.
    Session-scoped fixture teardowns are unreliable with parallel execution.

    With pytest-xdist, this runs on each worker AND the controller.
    We only want to run on the controller (master) node.
    """
    import subprocess

    # Only run on the controller/master node, not on workers
    if hasattr(session.config, "workerinput"):
        # This is a worker node, skip
        return

    # Always collect operator logs for debugging (before any early returns)
    _collect_operator_logs()

    # Only retrieve coverage if enabled
    if os.getenv("INTEGRATION_COVERAGE", "false").lower() != "true":
        return

    logger = logging.getLogger("pytest_sessionfinish")
    logger.info("=" * 80)
    logger.info("Pytest session finished - retrieving integration coverage")
    logger.info("=" * 80)

    try:
        # Use the retrieve-coverage script which handles everything
        script_path = (
            Path(__file__).parent.parent.parent / "scripts" / "retrieve-coverage.sh"
        )

        result = subprocess.run(
            [str(script_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode == 0:
            logger.info("✓ Coverage retrieval completed successfully")
            # Print to stdout so it appears in pytest output
            print("\n" + result.stdout)
        else:
            logger.warning(f"Coverage retrieval returned non-zero: {result.returncode}")
            print("\n" + result.stderr)

    except Exception as e:
        logger.error(f"Failed to retrieve integration coverage: {e}")
        import traceback

        logger.error(traceback.format_exc())
