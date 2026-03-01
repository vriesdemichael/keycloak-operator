"""
Integration tests for the reconciliation pause feature.

Deploys a second operator instance configured with pause flags enabled,
then verifies that CRs receive the Paused status and that delete
operations still proceed while paused.

Following the external-operator pattern from test_external_keycloak.py:
- Deploy a namespace-scoped operator in external mode with pause flags
- Verify CRs transition to Paused phase
- Verify delete handlers still work when paused
"""

import asyncio
import base64
import contextlib
import logging
import os
import subprocess
import time
import uuid

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef
from tests.integration.conftest import build_client_manifest, build_realm_manifest
from tests.integration.wait_helpers import (
    wait_for_resource_condition,
    wait_for_resource_deleted,
)

logger = logging.getLogger(__name__)


async def _deploy_paused_operator(
    test_namespace: str,
    shared_operator,
    k8s_core_v1,
    pause_keycloak: bool = False,
    pause_realms: bool = False,
    pause_clients: bool = False,
    pause_message: str = "Reconciliation paused by operator configuration",
) -> str:
    """Deploy a second operator in external mode with pause flags enabled.

    Returns the Helm release name for cleanup.
    """
    shared_ns = shared_operator.namespace
    shared_kc_name = shared_operator.name

    # Shared Keycloak Internal URL
    external_url = (
        f"http://{shared_kc_name}-keycloak.{shared_ns}.svc.cluster.local:8080"
    )

    # Get shared admin credentials
    secret_name = f"{shared_kc_name}-admin-credentials"
    secret = await k8s_core_v1.read_namespaced_secret(secret_name, shared_ns)
    admin_username = base64.b64decode(secret.data["username"]).decode()
    admin_password = base64.b64decode(secret.data["password"]).decode()

    # Create admin secret in test namespace
    external_secret_name = f"pause-test-admin-creds-{uuid.uuid4().hex[:6]}"
    external_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=external_secret_name, namespace=test_namespace
        ),
        string_data={"username": admin_username, "password": admin_password},
        type="Opaque",
    )
    await k8s_core_v1.create_namespaced_secret(test_namespace, external_secret)

    # Clean up stale webhooks from previous failed runs
    try:
        wh_cmd = ["kubectl", "get", "validatingwebhookconfigurations", "-o", "name"]
        result = subprocess.run(wh_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            for wh in result.stdout.strip().split("\n"):
                if "pause-op-" in wh:
                    logger.warning(f"Removing stale webhook: {wh}")
                    subprocess.run(["kubectl", "delete", wh])
    except Exception as e:
        logger.warning(f"Failed to clean up stale webhooks: {e}")

    release_name = f"pause-op-{uuid.uuid4().hex[:6]}"

    # Label namespace for webhook selector isolation
    label_cmd = [
        "kubectl",
        "label",
        "namespace",
        test_namespace,
        f"pause-tenant={test_namespace}",
        "--overwrite",
    ]
    subprocess.run(label_cmd, check=True)

    helm_cmd = [
        "helm",
        "install",
        release_name,
        "charts/keycloak-operator",
        "--namespace",
        test_namespace,
        "--set",
        "keycloak.managed=false",
        "--set",
        f"keycloak.url={external_url}",
        "--set",
        f"keycloak.adminSecret={external_secret_name}",
        "--set",
        f"keycloak.adminUsername={admin_username}",
        "--set",
        "keycloak.adminPasswordKey=password",
        "--set",
        f"operator.watchNamespaces={test_namespace}",
        "--set",
        "namespace.create=false",
        "--set",
        f"namespace.name={test_namespace}",
        "--set",
        f"operator.namespace={test_namespace}",
        "--set",
        "operator.replicaCount=1",
        "--set",
        "operator.image.repository=keycloak-operator",
        "--set",
        f"operator.image.tag={os.environ.get('TEST_IMAGE_TAG', 'test')}",
        "--set",
        "webhooks.enabled=true",
        "--set",
        "webhooks.failurePolicy=Ignore",
        "--set",
        f"webhooks.namespaceSelector.matchLabels.pause-tenant={test_namespace}",
        "--set",
        "priorityClass.create=false",
        "--set",
        "crds.install=false",
        # Pause configuration
        "--set",
        f"operator.reconciliation.pause.keycloak={str(pause_keycloak).lower()}",
        "--set",
        f"operator.reconciliation.pause.realms={str(pause_realms).lower()}",
        "--set",
        f"operator.reconciliation.pause.clients={str(pause_clients).lower()}",
        "--set",
        f"operator.reconciliation.pause.message={pause_message}",
        # Fast jitter for tests (use --set-json to pass as number, not string)
        "--set-json",
        "operator.reconciliation.jitterMaxSeconds=0.1",
    ]

    logger.info(f"Deploying paused operator to {test_namespace}...")
    process = await asyncio.create_subprocess_exec(
        *helm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.error(f"Helm install failed: {stderr.decode()}")
        pytest.fail(f"Helm install failed: {stderr.decode()}")

    logger.info("Paused operator deployed successfully.")

    # Wait for operator pod to be ready
    start = time.time()
    timeout = 120
    while time.time() - start < timeout:
        try:
            pods = await k8s_core_v1.list_namespaced_pod(
                test_namespace,
                label_selector=f"app.kubernetes.io/instance={release_name}",
            )
            if pods.items:
                for pod in pods.items:
                    if pod.status.phase == "Running":
                        conditions = pod.status.conditions or []
                        ready = any(
                            c.type == "Ready" and c.status == "True" for c in conditions
                        )
                        if ready:
                            logger.info(
                                f"Paused operator pod {pod.metadata.name} is ready"
                            )
                            return release_name
        except Exception as e:
            logger.warning(f"Error checking operator pod status: {e}")
        await asyncio.sleep(3)

    pytest.fail(f"Timeout waiting for paused operator pod to be ready in {timeout}s")
    return release_name  # unreachable, for type checker


async def _cleanup_helm_release(release_name: str, namespace: str) -> None:
    """Clean up a Helm release."""
    logger.info(f"Cleaning up Helm release: {release_name}")
    subprocess.run(
        ["helm", "uninstall", release_name, "--namespace", namespace],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Give the cluster a moment to clean up
    await asyncio.sleep(2)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.requires_cluster
class TestReconciliationPauseRealms:
    """Test that realm reconciliation is paused when configured."""

    @pytest.mark.timeout(600)
    async def test_realm_gets_paused_status(
        self,
        shared_operator,
        k8s_core_v1,
        k8s_custom_objects,
        test_namespace,
    ):
        """When pause.realms is true, new realm CRs should get Paused phase."""
        release_name = None
        realm_name = f"pause-realm-{uuid.uuid4().hex[:8]}"

        try:
            release_name = await _deploy_paused_operator(
                test_namespace=test_namespace,
                shared_operator=shared_operator,
                k8s_core_v1=k8s_core_v1,
                pause_realms=True,
                pause_message="Test: realms paused",
            )

            # Create a realm CR
            realm_spec = KeycloakRealmSpec(
                realm_name=realm_name,
                operator_ref=OperatorRef(namespace=test_namespace),
                display_name="Paused Realm Test",
                client_authorization_grants=[test_namespace],
            )
            realm_manifest = build_realm_manifest(
                realm_spec, realm_name, test_namespace
            )

            logger.info(f"Creating realm {realm_name} in {test_namespace}...")
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for Paused phase
            resource = await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") == "Paused"
                ),
                expected_phases=("Paused",),
                timeout=120,
                operator_namespace=test_namespace,
            )

            status = resource.get("status", {})
            assert status["phase"] == "Paused"
            assert "Test: realms paused" in status.get("message", "")

            # Verify ReconciliationPaused condition
            conditions = status.get("conditions", [])
            paused_cond = next(
                (c for c in conditions if c["type"] == "ReconciliationPaused"),
                None,
            )
            assert paused_cond is not None
            assert paused_cond["status"] == "True"
            assert paused_cond["reason"] == "OperatorPauseConfigured"

            # Verify Ready=False
            ready_cond = next(
                (c for c in conditions if c["type"] == "Ready"),
                None,
            )
            assert ready_cond is not None
            assert ready_cond["status"] == "False"

            logger.info("Realm correctly received Paused status!")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            if release_name:
                await _cleanup_helm_release(release_name, test_namespace)

    @pytest.mark.timeout(600)
    async def test_realm_delete_works_while_paused(
        self,
        shared_operator,
        k8s_core_v1,
        k8s_custom_objects,
        test_namespace,
    ):
        """Delete handlers should proceed even when reconciliation is paused."""
        release_name = None
        realm_name = f"pause-del-{uuid.uuid4().hex[:8]}"

        try:
            release_name = await _deploy_paused_operator(
                test_namespace=test_namespace,
                shared_operator=shared_operator,
                k8s_core_v1=k8s_core_v1,
                pause_realms=True,
                pause_message="Delete test: paused",
            )

            # Create realm
            realm_spec = KeycloakRealmSpec(
                realm_name=realm_name,
                operator_ref=OperatorRef(namespace=test_namespace),
                display_name="Delete While Paused",
                client_authorization_grants=[test_namespace],
            )
            realm_manifest = build_realm_manifest(
                realm_spec, realm_name, test_namespace
            )

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for Paused phase
            await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") == "Paused"
                ),
                expected_phases=("Paused",),
                timeout=120,
                operator_namespace=test_namespace,
            )

            # Delete the realm
            logger.info(f"Deleting paused realm {realm_name}...")
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for deletion - delete should proceed even when paused
            await wait_for_resource_deleted(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=180,
                operator_namespace=test_namespace,
            )

            logger.info("Realm successfully deleted while reconciliation was paused!")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            if release_name:
                await _cleanup_helm_release(release_name, test_namespace)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.requires_cluster
class TestReconciliationPauseClients:
    """Test that client reconciliation is paused when configured."""

    @pytest.mark.timeout(600)
    async def test_client_gets_paused_status(
        self,
        shared_operator,
        k8s_core_v1,
        k8s_custom_objects,
        test_namespace,
    ):
        """When pause.clients is true, new client CRs should get Paused phase.

        The client handler checks realm ownership BEFORE checking pause state.
        So a parent realm CR must exist for the ownership check to pass.
        We pause both realms and clients to avoid needing an actual Keycloak
        realm reconciliation.
        """
        release_name = None
        realm_name = f"pause-crealm-{uuid.uuid4().hex[:8]}"
        client_name = f"pause-client-{uuid.uuid4().hex[:8]}"

        try:
            # Deploy operator with BOTH realms and clients paused
            # so the realm CR exists but doesn't need to actually reconcile
            release_name = await _deploy_paused_operator(
                test_namespace=test_namespace,
                shared_operator=shared_operator,
                k8s_core_v1=k8s_core_v1,
                pause_realms=True,
                pause_clients=True,
                pause_message="Test: clients paused",
            )

            # First create a realm CR so the client ownership check passes
            realm_spec = KeycloakRealmSpec(
                realm_name=realm_name,
                operator_ref=OperatorRef(namespace=test_namespace),
                display_name="Parent Realm for Client Pause Test",
                client_authorization_grants=[test_namespace],
            )
            realm_manifest = build_realm_manifest(
                realm_spec, realm_name, test_namespace
            )

            logger.info(f"Creating parent realm {realm_name} in {test_namespace}...")
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to reach Paused phase
            await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") == "Paused"
                ),
                expected_phases=("Paused",),
                timeout=120,
                operator_namespace=test_namespace,
            )

            # Now create the client CR referencing the paused realm
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=test_namespace),
                client_id=client_name,
                protocol="openid-connect",
            )
            client_manifest = build_client_manifest(
                client_spec, client_name, test_namespace
            )

            logger.info(f"Creating client {client_name} in {test_namespace}...")
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for Paused phase
            resource = await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") == "Paused"
                ),
                expected_phases=("Paused",),
                timeout=120,
                operator_namespace=test_namespace,
            )

            status = resource.get("status", {})
            assert status["phase"] == "Paused"
            assert "Test: clients paused" in status.get("message", "")

            # Verify conditions
            conditions = status.get("conditions", [])
            paused_cond = next(
                (c for c in conditions if c["type"] == "ReconciliationPaused"),
                None,
            )
            assert paused_cond is not None
            assert paused_cond["status"] == "True"

            logger.info("Client correctly received Paused status!")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            if release_name:
                await _cleanup_helm_release(release_name, test_namespace)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.requires_cluster
class TestReconciliationPauseCustomMessage:
    """Test that a custom pause message propagates to CR status."""

    @pytest.mark.timeout(600)
    async def test_custom_pause_message_in_status(
        self,
        shared_operator,
        k8s_core_v1,
        k8s_custom_objects,
        test_namespace,
    ):
        """Custom RECONCILE_PAUSE_MESSAGE should appear in the CR status."""
        release_name = None
        realm_name = f"pause-msg-{uuid.uuid4().hex[:8]}"
        custom_message = "Maintenance: Keycloak 25.0 to 26.0 upgrade in progress"

        try:
            release_name = await _deploy_paused_operator(
                test_namespace=test_namespace,
                shared_operator=shared_operator,
                k8s_core_v1=k8s_core_v1,
                pause_realms=True,
                pause_message=custom_message,
            )

            realm_spec = KeycloakRealmSpec(
                realm_name=realm_name,
                operator_ref=OperatorRef(namespace=test_namespace),
                display_name="Custom Message Test",
                client_authorization_grants=[test_namespace],
            )
            realm_manifest = build_realm_manifest(
                realm_spec, realm_name, test_namespace
            )

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            resource = await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") == "Paused"
                ),
                expected_phases=("Paused",),
                timeout=120,
                operator_namespace=test_namespace,
            )

            status = resource.get("status", {})
            assert custom_message in status.get("message", "")

            # Also verify the condition message
            conditions = status.get("conditions", [])
            paused_cond = next(
                (c for c in conditions if c["type"] == "ReconciliationPaused"),
                None,
            )
            assert paused_cond is not None
            assert custom_message in paused_cond["message"]

            logger.info("Custom pause message correctly propagated to status!")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            if release_name:
                await _cleanup_helm_release(release_name, test_namespace)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.requires_cluster
class TestReconciliationNotPaused:
    """Test that non-paused CR types still reconcile normally."""

    @pytest.mark.timeout(600)
    async def test_realm_reconciles_when_only_clients_paused(
        self,
        shared_operator,
        k8s_core_v1,
        k8s_custom_objects,
        test_namespace,
        keycloak_port_forward,
    ):
        """Realms should reconcile normally when only clients are paused."""
        release_name = None
        realm_name = f"notpaused-{uuid.uuid4().hex[:8]}"
        shared_ns = shared_operator.namespace
        shared_kc_name = shared_operator.name

        try:
            release_name = await _deploy_paused_operator(
                test_namespace=test_namespace,
                shared_operator=shared_operator,
                k8s_core_v1=k8s_core_v1,
                pause_clients=True,  # Only clients paused
                pause_realms=False,  # Realms should still work
                pause_message="Only clients paused",
            )

            realm_spec = KeycloakRealmSpec(
                realm_name=realm_name,
                operator_ref=OperatorRef(namespace=test_namespace),
                display_name="Not Paused Realm",
                client_authorization_grants=[test_namespace],
            )
            realm_manifest = build_realm_manifest(
                realm_spec, realm_name, test_namespace
            )

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Realm should become Ready (not Paused)
            resource = await wait_for_resource_condition(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
                condition_func=lambda r: (
                    (r.get("status") or {}).get("phase") in ("Ready", "Degraded")
                ),
                expected_phases=("Ready", "Degraded"),
                timeout=180,
                operator_namespace=test_namespace,
            )

            status = resource.get("status", {})
            assert status["phase"] in ("Ready", "Degraded")
            assert status["phase"] != "Paused"

            # Verify realm actually exists in Keycloak
            local_port = await keycloak_port_forward(shared_kc_name, shared_ns)
            from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

            # Get credentials
            secret_name = f"{shared_kc_name}-admin-credentials"
            secret = await k8s_core_v1.read_namespaced_secret(secret_name, shared_ns)
            admin_username = base64.b64decode(secret.data["username"]).decode()
            admin_password = base64.b64decode(secret.data["password"]).decode()

            verifier_client = KeycloakAdminClient(
                server_url=f"http://localhost:{local_port}",
                username=admin_username,
                password=admin_password,
            )
            await verifier_client.authenticate()

            fetched_realm = await verifier_client.get_realm(realm_name, shared_ns)
            assert fetched_realm is not None
            assert fetched_realm.realm == realm_name

            logger.info("Realm reconciled normally despite clients being paused!")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            if release_name:
                await _cleanup_helm_release(release_name, test_namespace)
