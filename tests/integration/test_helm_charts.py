"""
Integration tests for Helm chart-based realm and client deployment.

These tests demonstrate using Helm charts instead of manual YAML to deploy
KeycloakRealm and KeycloakClient resources.
"""

import uuid

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.asyncio
async def _simple_wait(condition_func, timeout=300, interval=3):
    """Simple wait helper for conditions."""
    import asyncio
    import time

    start = time.time()
    while time.time() - start < timeout:
        if await condition_func():
            return True
        await asyncio.sleep(interval)
    return False


class TestHelmRealmDeployment:
    """Test KeycloakRealm deployment via Helm charts."""

    async def test_deploy_realm_via_helm(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
    ):
        """Test deploying a KeycloakRealm using Helm chart."""
        realm_name = f"helm-test-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-realm-{uuid.uuid4().hex[:8]}"

        # Deploy realm via Helm
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            displayName="Helm Test Realm",
        )

        # Verify realm CR was created
        async def realm_exists():
            try:
                realm = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                return realm is not None
            except ApiException:
                return False

        assert await _simple_wait(realm_exists, timeout=30, interval=2)

        # Verify realm reaches Ready phase
        async def realm_ready():
            try:
                realm = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                status = realm.get("status", {})
                phase = status.get("phase")
                message = status.get("message", "")
                # Add debug logging
                print(f"DEBUG: Realm phase={phase}, message={message}")
                return phase == "Ready"
            except ApiException as e:
                print(f"DEBUG: ApiException getting realm: {e.status}")
                return False

        result = await _simple_wait(realm_ready, timeout=120, interval=5)

        # If failed, print final status for debugging
        if not result:
            try:
                realm = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                print(f"DEBUG: Final realm status: {realm.get('status', {})}")
            except Exception as e:
                print(f"DEBUG: Could not get final status: {e}")

        assert result, "Realm did not reach Ready phase"

    async def test_helm_realm_with_smtp_config(
        self,
        helm_realm,
        test_namespace,
        k8s_core_v1,
        k8s_custom_objects,
        operator_namespace,
    ):
        """Test deploying a realm with SMTP configuration via Helm."""
        realm_name = f"helm-smtp-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-smtp-{uuid.uuid4().hex[:8]}"

        # Get admission token from fixture
        smtp_secret_name = f"smtp-secret-{uuid.uuid4().hex[:8]}"
        from kubernetes import client

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=smtp_secret_name,
                namespace=test_namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            string_data={"password": "test-smtp-password"},
        )
        await k8s_core_v1.create_namespaced_secret(test_namespace, secret)

        # Deploy realm with SMTP via Helm
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            smtpServer={
                "enabled": True,
                "host": "smtp.example.com",
                "port": 587,
                "from": "noreply@example.com",
                "user": "smtp-user",
                "passwordSecret": {"name": smtp_secret_name, "key": "password"},
            },
        )

        # Verify realm was created with SMTP config
        async def realm_has_smtp():
            try:
                realm = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                spec = realm.get("spec", {})
                smtp = spec.get("smtpServer", {})
                return smtp.get("host") == "smtp.example.com"
            except ApiException:
                return False

        assert await _simple_wait(realm_has_smtp, timeout=30, interval=2)


@pytest.mark.asyncio
class TestHelmClientDeployment:
    """Test KeycloakClient deployment via Helm charts."""

    async def test_deploy_client_via_helm(
        self,
        helm_realm,
        helm_client,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
    ):
        """Test deploying a KeycloakClient using Helm chart."""
        realm_name = f"client-realm-{uuid.uuid4().hex[:8]}"
        realm_release = f"realm-{uuid.uuid4().hex[:8]}"

        # Get admission token from fixture
        await helm_realm(
            release_name=realm_release,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[test_namespace],  # Grant test namespace access
        )

        # Wait for realm to be ready
        async def realm_ready():
            try:
                realm = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{realm_release}-keycloak-realm",
                )
                status = realm.get("status", {})
                phase = status.get("phase")
                return phase == "Ready"
            except ApiException:
                return False

        assert await _simple_wait(realm_ready, timeout=120, interval=5)

        # Realm is ready - no auth secret needed (grant list authorization)

        # Deploy client via Helm
        client_id = f"test-client-{uuid.uuid4().hex[:8]}"
        client_release = f"client-{uuid.uuid4().hex[:8]}"

        await helm_client(
            release_name=client_release,
            client_id=client_id,
            realm_name=f"{realm_release}-keycloak-realm",
            realm_namespace=test_namespace,
            publicClient=False,
            redirectUris=["https://example.com/callback"],
        )

        # Verify client CR was created
        async def client_exists():
            try:
                client = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=f"{client_release}-keycloak-client",
                )
                return client is not None
            except ApiException:
                return False

        assert await _simple_wait(client_exists, timeout=30, interval=2)

        # Verify client reaches Ready phase
        async def client_ready():
            try:
                client = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=f"{client_release}-keycloak-client",
                )
                status = client.get("status", {})
                phase = status.get("phase")
                print(f"Client status: phase={phase}, full_status={status}")
                return phase == "Ready"
            except ApiException as e:
                print(f"Client check failed: {e}")
                return False

        result = await _simple_wait(client_ready, timeout=120, interval=5)
        if not result:
            # Print final state for debugging
            try:
                client = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=f"{client_release}-keycloak-client",
                )
                print(f"Final client object: {client}")
            except Exception as e:
                print(f"Failed to get final client state: {e}")

        assert result, "Client did not reach Ready phase"


@pytest.mark.asyncio
class TestHelmRealmAdvancedFields:
    """Test Helm chart realm deployment with advanced CRD fields."""

    @pytest.mark.timeout(300)
    async def test_helm_realm_with_roles(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
    ):
        """Test deploying a realm with roles via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"helm-roles-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-roles-{uuid.uuid4().hex[:8]}"

        # Deploy realm with roles
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            roles={
                "realmRoles": [
                    {"name": "admin", "description": "Administrator role"},
                    {"name": "user", "description": "Regular user role"},
                ]
            },
        )

        realm_cr_name = f"{release_name}-keycloak-realm"

        # Wait for realm to be ready using proper wait helper
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify roles are in spec
        realm = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
        )
        spec = realm.get("spec", {})
        roles = spec.get("roles", {})
        realm_roles = roles.get("realmRoles", [])

        assert len(realm_roles) == 2, f"Expected 2 roles, got {len(realm_roles)}"
        role_names = {r.get("name") for r in realm_roles}
        assert "admin" in role_names, "admin role should be present"
        assert "user" in role_names, "user role should be present"

    @pytest.mark.timeout(300)
    async def test_helm_realm_with_events_config(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
    ):
        """Test deploying a realm with events configuration via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"helm-events-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-events-{uuid.uuid4().hex[:8]}"

        # Deploy realm with events config
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            eventsConfig={
                "eventsEnabled": True,
                "adminEventsEnabled": True,
                "eventsListeners": ["jboss-logging"],
            },
        )

        realm_cr_name = f"{release_name}-keycloak-realm"

        # Wait for realm to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify events config is in spec
        realm = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
        )
        spec = realm.get("spec", {})
        events_config = spec.get("eventsConfig", {})

        assert (
            events_config.get("eventsEnabled") is True
        ), "eventsEnabled should be True"
        assert (
            events_config.get("adminEventsEnabled") is True
        ), "adminEventsEnabled should be True"
        assert "jboss-logging" in events_config.get(
            "eventsListeners", []
        ), "jboss-logging should be in eventsListeners"

    @pytest.mark.timeout(300)
    async def test_helm_realm_with_description_and_login_title(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
    ):
        """Test deploying a realm with description and loginPageTitle via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"helm-desc-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-desc-{uuid.uuid4().hex[:8]}"

        description = "Test realm for Helm chart deployment"
        login_title = "Welcome to Test Realm"

        # Deploy realm with description and loginPageTitle
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            description=description,
            loginPageTitle=login_title,
        )

        realm_cr_name = f"{release_name}-keycloak-realm"

        # Wait for realm to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify description and loginPageTitle are in spec
        realm = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
        )
        spec = realm.get("spec", {})

        assert (
            spec.get("description") == description
        ), f"Expected description '{description}', got '{spec.get('description')}'"
        assert (
            spec.get("loginPageTitle") == login_title
        ), f"Expected loginPageTitle '{login_title}', got '{spec.get('loginPageTitle')}'"
