"""Integration tests for SMTP configuration in KeycloakRealm."""

import contextlib
import uuid

import pytest
from kubernetes import client


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_smtp_secret_reference(
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    admission_token_setup,
):
    """Test creating realm with SMTP config using secret reference."""
    # Get admission token from fixture
    admission_secret_name, _ = admission_token_setup

    from keycloak_operator.models.common import AuthorizationSecretRef
    from keycloak_operator.models.realm import (
        KeycloakRealmSpec,
        KeycloakSMTPConfig,
        KeycloakSMTPPasswordSecret,
        OperatorRef,
    )

    realm_name = f"test-smtp-{uuid.uuid4().hex[:8]}"
    secret_name = f"smtp-secret-{uuid.uuid4().hex[:8]}"
    namespace = test_namespace

    # Create SMTP password secret (with required RBAC label)
    core_api = client.CoreV1Api()
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"password": "test-smtp-password"},
    )
    core_api.create_namespaced_secret(namespace=namespace, body=secret)

    try:
        # Create KeycloakRealm with SMTP configuration
        custom_api = client.CustomObjectsApi()

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
            realm_name=realm_name,
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                from_display_name="Test Application",
                auth=True,
                user="noreply@example.com",
                starttls=True,
                password_secret=KeycloakSMTPPasswordSecret(
                    name=secret_name, key="password"
                ),
            ),
        )

        realm_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for realm to be ready
        await wait_for_realm_ready(custom_api, realm_name, namespace, timeout=120)

        # Verify SMTP configuration in Keycloak

        # Fetch realm configuration
        realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
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
                group="vriesdemichael.github.io",
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
    shared_operator,
    keycloak_admin_client,
    operator_namespace,
    test_namespace,
    admission_token_setup,
):
    """Test creating realm with SMTP config using direct password (deprecated)."""
    # Get admission token from fixture
    admission_secret_name, _ = admission_token_setup

    from keycloak_operator.models.common import AuthorizationSecretRef
    from keycloak_operator.models.realm import (
        KeycloakRealmSpec,
        KeycloakSMTPConfig,
        OperatorRef,
    )

    realm_name = f"test-smtp-direct-{uuid.uuid4().hex[:8]}"
    namespace = test_namespace

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm with direct password
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
            realm_name=realm_name,
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=25,
                from_address="test@example.com",
                auth=True,
                user="test@example.com",
                password="direct-password",
            ),
        )

        realm_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for realm to be ready
        await wait_for_realm_ready(custom_api, realm_name, namespace, timeout=120)

        # Verify realm was created

        realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
        assert realm_repr is not None
        realm_config = realm_repr.model_dump(by_alias=True, exclude_none=False)

        # Verify SMTP configuration
        assert "smtpServer" in realm_config
        assert realm_config["smtpServer"]["host"] == "smtp.example.com"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_missing_smtp_secret(
    shared_operator, operator_namespace, test_namespace, admission_token_setup
):
    """Test realm creation fails gracefully with missing SMTP secret."""
    # Get admission token from fixture
    admission_secret_name, _ = admission_token_setup

    from keycloak_operator.models.common import AuthorizationSecretRef
    from keycloak_operator.models.realm import (
        KeycloakRealmSpec,
        KeycloakSMTPConfig,
        KeycloakSMTPPasswordSecret,
        OperatorRef,
    )

    realm_name = f"test-smtp-missing-{uuid.uuid4().hex[:8]}"
    secret_name = f"nonexistent-secret-{uuid.uuid4().hex[:8]}"
    namespace = test_namespace

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm referencing non-existent secret
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
            realm_name=realm_name,
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                user="noreply@example.com",
                password_secret=KeycloakSMTPPasswordSecret(name=secret_name),
            ),
        )

        realm_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for reconciliation to process and fail
        # (reconciliation must start and detect the missing secret)
        await wait_for_realm_not_ready(custom_api, realm_name, namespace, timeout=60)

        # Check realm status - should show error
        realm = custom_api.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

        # Realm should not be in Ready phase
        status = realm.get("status", {})
        phase = status.get("phase", "Unknown")
        # Phase should have transitioned from Unknown to an error state
        assert phase in [
            "Failed",
            "Degraded",
            "Pending",
        ], f"Expected error phase, got: {phase}"

        # At minimum, it should not be Ready
        assert phase != "Ready"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            # Wait for realm to be fully deleted
            await wait_for_realm_deleted(custom_api, realm_name, namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_with_missing_secret_key(
    shared_operator, operator_namespace, test_namespace, admission_token_setup
):
    """Test realm creation fails gracefully with missing key in secret."""
    # Get admission token from fixture
    admission_secret_name, _ = admission_token_setup

    from keycloak_operator.models.common import AuthorizationSecretRef
    from keycloak_operator.models.realm import (
        KeycloakRealmSpec,
        KeycloakSMTPConfig,
        KeycloakSMTPPasswordSecret,
        OperatorRef,
    )

    realm_name = f"test-smtp-badkey-{uuid.uuid4().hex[:8]}"
    secret_name = f"smtp-secret-badkey-{uuid.uuid4().hex[:8]}"
    namespace = test_namespace

    core_api = client.CoreV1Api()

    # Create secret without the expected key (but with required RBAC label)
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=namespace,
            labels={"vriesdemichael.github.io/keycloak-allow-operator-read": "true"},
        ),
        string_data={"wrong-key": "some-password"},
    )
    core_api.create_namespaced_secret(namespace=namespace, body=secret)

    custom_api = client.CustomObjectsApi()

    try:
        # Create KeycloakRealm referencing wrong key
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
            realm_name=realm_name,
            smtp_server=KeycloakSMTPConfig(
                host="smtp.example.com",
                port=587,
                from_address="noreply@example.com",
                auth=True,
                user="noreply@example.com",
                password_secret=KeycloakSMTPPasswordSecret(
                    name=secret_name,
                    key="password",  # Key doesn't exist
                ),
            ),
        )

        realm_resource = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        custom_api.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            body=realm_resource,
        )

        # Wait for reconciliation to process and fail
        # (reconciliation must start and detect the missing secret key)
        await wait_for_realm_not_ready(custom_api, realm_name, namespace, timeout=60)

        # Check realm status
        realm = custom_api.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

        status = realm.get("status", {})
        phase = status.get("phase", "Unknown")
        # Phase should have transitioned from Unknown to an error state
        assert phase in [
            "Failed",
            "Degraded",
            "Pending",
        ], f"Expected error phase, got: {phase}"
        assert phase != "Ready"

    finally:
        # Cleanup - wait for realm to be fully deleted
        with contextlib.suppress(Exception):
            custom_api.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
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
    """
    Wait for realm to reach Ready phase.

    This function tolerates transient Failed states because kopf will retry
    failed reconciliations automatically. Only permanent failures that persist
    for the full timeout will raise an error.
    """
    import asyncio

    start_time = asyncio.get_event_loop().time()
    last_failed_message = None

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > timeout:
            # If we consistently saw Failed state, report it
            if last_failed_message:
                raise RuntimeError(
                    f"Realm {realm_name} failed: {last_failed_message}\n"
                    f"Action required: Wait for automatic retry or check system status"
                )
            raise TimeoutError(
                f"Timeout waiting for realm {realm_name} to be ready after {timeout}s"
            )

        try:
            realm = custom_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
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
                # Store the failure message but continue waiting
                # Kopf will retry failed reconciliations automatically
                message = status.get("message", "Unknown error")
                last_failed_message = message
                # Continue waiting - kopf might retry and succeed

        except client.ApiException:
            pass  # Resource might not exist yet

        await asyncio.sleep(2)


async def wait_for_realm_not_ready(
    custom_api: client.CustomObjectsApi,
    realm_name: str,
    namespace: str,
    timeout: int = 60,
):
    """
    Wait for realm to transition from Unknown phase to any other phase.

    This is useful for error condition tests where we expect the realm
    to fail but need to wait for reconciliation to actually start and process.
    """
    import asyncio

    start_time = asyncio.get_event_loop().time()

    while True:
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > timeout:
            raise TimeoutError(
                f"Timeout waiting for realm {realm_name} to transition from Unknown phase after {timeout}s"
            )

        try:
            realm = custom_api.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            status = realm.get("status", {})
            phase = status.get("phase", "Unknown")

            # Wait until phase is no longer Unknown (reconciliation has started)
            if phase != "Unknown":
                return

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
                group="vriesdemichael.github.io",
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
