import asyncio
import base64
import logging
import os
import subprocess
import time

import pytest
from kubernetes import client

from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef
from tests.integration.conftest import build_realm_manifest

logger = logging.getLogger(__name__)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.requires_cluster
async def test_external_keycloak_mode(
    shared_operator,
    k8s_client,
    k8s_core_v1,
    k8s_apps_v1,
    k8s_custom_objects,
    test_namespace,
    cleanup_tracker,
    keycloak_port_forward,
):
    """
    Integration test for External Keycloak Mode (Headless Operator).

    Scenario:
    1. Deploy a SECOND operator in 'test_namespace' configured as External Mode.
    2. Point it to the SHARED Keycloak instance (running in shared_operator.namespace).
    3. Create a KeycloakRealm in 'test_namespace' targeting the second operator.
    4. Verify the realm is created in the shared Keycloak.
    """

    # 1. Setup: Define external operator namespace and credentials
    external_op_ns = test_namespace  # Use the test namespace for the second operator
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

    # Create admin secret in external operator namespace
    external_secret_name = "external-admin-creds"
    external_secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=external_secret_name, namespace=external_op_ns
        ),
        string_data={"username": admin_username, "password": admin_password},
        type="Opaque",
    )
    await k8s_core_v1.create_namespaced_secret(external_op_ns, external_secret)

    # Defensive cleanup: Remove any stale global webhooks from previous failed ext-op runs
    try:
        logger.info("Checking for stale external operator webhooks...")
        # List all validating webhook configurations
        wh_cmd = ["kubectl", "get", "validatingwebhookconfigurations", "-o", "name"]
        result = subprocess.run(wh_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            for wh in result.stdout.strip().split("\n"):
                if "ext-op-" in wh:
                    logger.warning(f"Removing stale webhook: {wh}")
                    subprocess.run(["kubectl", "delete", wh])
    except Exception as e:
        logger.warning(f"Failed to clean up stale webhooks: {e}")

    # 2. Deploy Second Operator (External Mode) using Helm
    chart_path = "charts/keycloak-operator"
    # Use random release name to prevent collisions
    release_name = f"ext-op-{os.urandom(4).hex()}"

    helm_cmd = [
        "helm",
        "install",
        release_name,
        chart_path,
        "--namespace",
        external_op_ns,
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
        f"operator.watchNamespaces={external_op_ns}",  # Watch only own ns
        "--set",
        "namespace.create=false",
        "--set",
        f"namespace.name={external_op_ns}",
        "--set",
        f"operator.namespace={external_op_ns}",
        "--set",
        "operator.replicaCount=1",
        "--set",
        "operator.image.repository=keycloak-operator",
        "--set",
        f"operator.image.tag={os.environ.get('TEST_IMAGE_TAG', 'test')}",
        "--set",
        "webhooks.enabled=true",  # We want to test webhooks in multi-tenant mode too!
        "--set",
        "webhooks.failurePolicy=Ignore",
        "--set",
        f"webhooks.namespaceSelector.matchLabels.tenant={external_op_ns}",  # ISOLATION
        "--set",
        "priorityClass.create=false",
        "--set",
        "crds.install=false",
    ]

    # Label the namespace for the webhook selector
    logger.info(f"Labeling namespace {external_op_ns} for multi-tenancy...")
    label_cmd = [
        "kubectl",
        "label",
        "namespace",
        external_op_ns,
        f"tenant={external_op_ns}",
        "--overwrite",
    ]
    subprocess.run(label_cmd, check=True)

    logger.info(f"Deploying external operator to {external_op_ns}...")
    # Run helm install
    process = await asyncio.create_subprocess_exec(
        *helm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.error(f"Helm install failed: {stderr.decode()}")
        pytest.fail(f"Helm install failed: {stderr.decode()}")

    logger.info("External operator deployed successfully.")

    try:
        # 3. Create KeycloakRealm
        realm_name = f"ext-test-{os.urandom(4).hex()}"
        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(namespace=external_op_ns),
            display_name="External Mode Test Realm",
            client_authorization_grants=[external_op_ns],
        )

        realm_manifest = build_realm_manifest(realm_spec, realm_name, external_op_ns)

        logger.info(f"Creating Realm {realm_name} in {external_op_ns}...")
        await k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=external_op_ns,
            plural="keycloakrealms",
            body=realm_manifest,
        )

        # 4. Wait for Realm to be Ready
        start_time = time.time()
        timeout = 300  # Highly increased timeout for external operator tests

        while time.time() - start_time < timeout:
            try:
                realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=external_op_ns,
                    plural="keycloakrealms",
                    name=realm_name,
                )
                phase = realm_cr.get("status", {}).get("phase")
                if phase == "Ready":
                    logger.info(f"Realm {realm_name} is Ready!")
                    break
                if phase == "Failed":
                    pytest.fail(
                        f"Realm reconciliation failed: {realm_cr.get('status')}"
                    )
            except Exception as e:
                logger.warning(f"Error checking realm status: {e}")

            await asyncio.sleep(2)
        else:
            pytest.fail(f"Timeout waiting for Realm {realm_name} to become Ready")

        # 5. Verify Realm exists in Shared Keycloak
        # Connect to shared keycloak using port-forward
        local_port = await keycloak_port_forward(shared_kc_name, shared_ns)

        from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

        verifier_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username=admin_username,
            password=admin_password,
        )
        await verifier_client.authenticate()

        fetched_realm = await verifier_client.get_realm(realm_name, shared_ns)
        assert fetched_realm is not None
        assert fetched_realm.realm == realm_name
        assert fetched_realm.display_name == "External Mode Test Realm"

        logger.info("Verified realm exists in shared Keycloak instance!")

        # 6. Verify Keycloak CR is blocked in External Mode
        keycloak_cr_name = "managed-kc-attempt"
        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_cr_name, "namespace": external_op_ns},
            "spec": {
                "replicas": 1,
                "image": "quay.io/keycloak/keycloak:latest",
                "operatorRef": {"namespace": external_op_ns},
                "database": {
                    "type": "postgresql",
                    "host": "localhost",
                    "database": "keycloak",
                    "username": "admin",
                    "passwordSecret": {"name": "kc-db-secret", "key": "password"},
                },
            },
        }

        # Create a dummy database secret so connectivity test fails later but Pydantic validation passes
        db_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="kc-db-secret", namespace=external_op_ns),
            string_data={"password": "password"},
        )
        await k8s_core_v1.create_namespaced_secret(external_op_ns, db_secret)

        logger.info("Creating managed Keycloak CR in external operator namespace...")
        await k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=external_op_ns,
            plural="keycloaks",
            body=keycloak_manifest,
        )

        # Wait for it to fail
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                kc_cr = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=external_op_ns,
                    plural="keycloaks",
                    name=keycloak_cr_name,
                )
                phase = kc_cr.get("status", {}).get("phase")
                if phase == "Failed":
                    # Check message instead of phase if we return None in handler
                    message = kc_cr.get("status", {}).get("message", "")
                    # The message is set by our handler even if it returns None (via patch)
                    if "Operator is configured for External Keycloak" in message:
                        logger.info("Verified Keycloak CR is ignored in External Mode.")
                        break
            except Exception as e:
                logger.warning(f"Error checking keycloak status: {e}")

            await asyncio.sleep(2)
        else:
            pytest.fail("Timeout waiting for Keycloak CR to fail in External Mode")

    finally:
        logger.info(f"Cleaning up Helm release: {release_name}")
        subprocess.run(
            ["helm", "uninstall", release_name, "--namespace", external_op_ns],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
