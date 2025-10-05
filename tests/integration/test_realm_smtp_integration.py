"""Integration tests for SMTP configuration in KeycloakRealm."""

import contextlib
import uuid

import pytest
from kubernetes import client

from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_smtp_secret_reference(
    shared_keycloak_instance, keycloak_port_forward
):
    """Test creating realm with SMTP config using secret reference."""
    realm_name = f"test-smtp-{uuid.uuid4().hex[:8]}"
    secret_name = f"smtp-secret-{uuid.uuid4().hex[:8]}"
    namespace = shared_keycloak_instance["namespace"]

    # Create SMTP password secret
    core_api = client.CoreV1Api()
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        string_data={"password": "test-smtp-password"},
    )
    core_api.create_namespaced_secret(namespace=namespace, body=secret)

    try:
        # Create KeycloakRealm with SMTP configuration
        custom_api = client.CustomObjectsApi()
        realm_resource = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": {
                "realm_name": realm_name,
                "keycloak_instance_ref": {
                    "name": shared_keycloak_instance["name"],
                    "namespace": shared_keycloak_instance["namespace"],
                },
                "smtp_server": {
                    "host": "smtp.example.com",
                    "port": 587,
                    "from_address": "noreply@example.com",
                    "from_display_name": "Test Application",
                    "auth": True,
                    "user": "noreply@example.com",
                    "starttls": True,
                    "password_secret": {"name": secret_name, "key": "password"},
                },
            },
        }

        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for realm to be ready
        await wait_for_realm_ready(custom_api, realm_name, namespace, timeout=120)

        # Verify SMTP configuration in Keycloak
        local_port = await keycloak_port_forward(
            shared_keycloak_instance["name"], namespace
        )

        # Get admin credentials from operator-generated secret
        from keycloak_operator.utils.kubernetes import get_admin_credentials

        username, password = get_admin_credentials(
            shared_keycloak_instance["name"], namespace
        )

        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username=username,
            password=password,
        )

        # Fetch realm configuration
        realm_repr = admin_client.get_realm(realm_name)
        assert realm_repr is not None
        realm_config = realm_repr.model_dump(by_alias=True, exclude_none=False)

        # Verify SMTP configuration is present
        assert "smtpServer" in realm_config
        smtp_config = realm_config["smtpServer"]

        assert smtp_config["host"] == "smtp.example.com"
        assert smtp_config["port"] == "587"
        assert smtp_config["from"] == "noreply@example.com"
        assert smtp_config["fromDisplayName"] == "Test Application"
        assert smtp_config["user"] == "noreply@example.com"
        assert smtp_config["starttls"] == "true"  # Keycloak returns strings
        assert smtp_config["auth"] == "true"
        # Password should be present but we can't verify the value
        assert "password" in smtp_config

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)

        with contextlib.suppress(Exception):
            core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_smtp_direct_password(
    shared_keycloak_instance, keycloak_port_forward
):
    """Test creating realm with SMTP config using direct password (deprecated)."""
    realm_name = f"test-smtp-direct-{uuid.uuid4().hex[:8]}"
    namespace = shared_keycloak_instance["namespace"]

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm with direct password
        realm_resource = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": {
                "realm_name": realm_name,
                "keycloak_instance_ref": {
                    "name": shared_keycloak_instance["name"],
                    "namespace": shared_keycloak_instance["namespace"],
                },
                "smtp_server": {
                    "host": "smtp.example.com",
                    "port": 25,
                    "from_address": "test@example.com",
                    "auth": True,
                    "user": "test@example.com",
                    "password": "direct-password",
                },
            },
        }

        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for realm to be ready
        await wait_for_realm_ready(custom_api, realm_name, namespace, timeout=120)

        # Verify realm was created
        local_port = await keycloak_port_forward(
            shared_keycloak_instance["name"], namespace
        )

        # Get admin credentials from operator-generated secret
        from keycloak_operator.utils.kubernetes import get_admin_credentials

        username, password = get_admin_credentials(
            shared_keycloak_instance["name"], namespace
        )

        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username=username,
            password=password,
        )

        realm_repr = admin_client.get_realm(realm_name)
        assert realm_repr is not None
        realm_config = realm_repr.model_dump(by_alias=True, exclude_none=False)

        # Verify SMTP configuration
        assert "smtpServer" in realm_config
        assert realm_config["smtpServer"]["host"] == "smtp.example.com"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_missing_smtp_secret(shared_keycloak_instance):
    """Test realm creation fails gracefully with missing SMTP secret."""
    realm_name = f"test-smtp-missing-{uuid.uuid4().hex[:8]}"
    secret_name = f"nonexistent-secret-{uuid.uuid4().hex[:8]}"
    namespace = shared_keycloak_instance["namespace"]

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm referencing non-existent secret
        realm_resource = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": {
                "realm_name": realm_name,
                "keycloak_instance_ref": {
                    "name": shared_keycloak_instance["name"],
                    "namespace": shared_keycloak_instance["namespace"],
                },
                "smtp_server": {
                    "host": "smtp.example.com",
                    "port": 587,
                    "from_address": "noreply@example.com",
                    "auth": True,
                    "user": "noreply@example.com",
                    "password_secret": {"name": secret_name},
                },
            },
        }

        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait a bit for reconciliation to attempt
        import asyncio

        await asyncio.sleep(5)

        # Check realm status - should show error
        realm = custom_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

        # Realm should not be in Ready phase
        status = realm.get("status", {})
        phase = status.get("phase", "Unknown")
        assert phase in ["Failed", "Degraded", "Pending"]

        # At minimum, it should not be Ready
        assert phase != "Ready"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_missing_secret_key(shared_keycloak_instance):
    """Test realm creation fails gracefully with missing key in secret."""
    realm_name = f"test-smtp-badkey-{uuid.uuid4().hex[:8]}"
    secret_name = f"smtp-secret-badkey-{uuid.uuid4().hex[:8]}"
    namespace = shared_keycloak_instance["namespace"]

    core_api = client.CoreV1Api()

    # Create secret without the expected key
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        string_data={"wrong-key": "some-password"},
    )
    core_api.create_namespaced_secret(namespace=namespace, body=secret)

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm referencing wrong key
        realm_resource = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": {
                "realm_name": realm_name,
                "keycloak_instance_ref": {
                    "name": shared_keycloak_instance["name"],
                    "namespace": shared_keycloak_instance["namespace"],
                },
                "smtp_server": {
                    "host": "smtp.example.com",
                    "port": 587,
                    "from_address": "noreply@example.com",
                    "auth": True,
                    "user": "noreply@example.com",
                    "password_secret": {
                        "name": secret_name,
                        "key": "password",  # Key doesn't exist
                    },
                },
            },
        }

        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for reconciliation
        import asyncio

        await asyncio.sleep(5)

        # Check realm status
        realm = custom_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

        status = realm.get("status", {})
        phase = status.get("phase", "Unknown")
        assert phase in ["Failed", "Degraded", "Pending"]
        assert phase != "Ready"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)

        with contextlib.suppress(Exception):
            core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)


async def wait_for_realm_ready(
    custom_api: client.CustomObjectsApi,
    realm_name: str,
    namespace: str,
    timeout: int = 120,
):
    """Wait for realm to reach Ready phase."""
    import asyncio

    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > timeout:
            raise TimeoutError(
                f"Timeout waiting for realm {realm_name} to be ready after {timeout}s"
            )

        try:
            realm = custom_api.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            status = realm.get("status", {})
            phase = status.get("phase", "Unknown")

            if phase == "Ready":
                return
            elif phase == "Failed":
                message = status.get("message", "Unknown error")
                raise RuntimeError(f"Realm {realm_name} failed: {message}")

        except client.ApiException:
            pass  # Resource might not exist yet

        await asyncio.sleep(2)


async def wait_for_realm_deleted(
    custom_api: client.CustomObjectsApi,
    realm_name: str,
    namespace: str,
    timeout: int = 60,
):
    """Wait for realm to be fully deleted."""
    import asyncio

    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > timeout:
            # Timeout is not an error - just move on
            return

        try:
            custom_api.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Realm still exists, wait
            await asyncio.sleep(1)
        except client.ApiException as e:
            if e.status == 404:
                # Realm is deleted
                return
            # Other errors, just return
            return
