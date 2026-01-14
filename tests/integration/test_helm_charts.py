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

        assert events_config.get("eventsEnabled") is True, (
            "eventsEnabled should be True"
        )
        assert events_config.get("adminEventsEnabled") is True, (
            "adminEventsEnabled should be True"
        )
        assert "jboss-logging" in events_config.get("eventsListeners", []), (
            "jboss-logging should be in eventsListeners"
        )

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

        assert spec.get("description") == description, (
            f"Expected description '{description}', got '{spec.get('description')}'"
        )
        assert spec.get("loginPageTitle") == login_title, (
            f"Expected loginPageTitle '{login_title}', got '{spec.get('loginPageTitle')}'"
        )

    @pytest.mark.timeout(300)
    async def test_helm_realm_with_password_policy(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
    ):
        """Test deploying a realm with password policy via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"helm-policy-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-policy-{uuid.uuid4().hex[:8]}"

        # Deploy realm with password policy
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            passwordPolicy={
                "length": 12,
                "upperCase": 1,
                "lowerCase": 1,
                "digits": 1,
                "specialChars": 1,
                "notUsername": True,
                "hashIterations": 210000,
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

        # Verify password policy is in spec
        realm = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr_name,
        )
        spec = realm.get("spec", {})
        password_policy = spec.get("passwordPolicy", {})

        assert password_policy.get("length") == 12, "length should be 12"
        assert password_policy.get("upperCase") == 1, "upperCase should be 1"
        assert password_policy.get("lowerCase") == 1, "lowerCase should be 1"
        assert password_policy.get("digits") == 1, "digits should be 1"
        assert password_policy.get("specialChars") == 1, "specialChars should be 1"
        assert password_policy.get("notUsername") is True, "notUsername should be True"
        assert password_policy.get("hashIterations") == 210000, (
            "hashIterations should be 210000"
        )


@pytest.mark.asyncio
class TestHelmClientAdvancedSettings:
    """Test Helm chart client deployment with advanced settings fields."""

    @pytest.mark.timeout(300)
    async def test_helm_client_with_authorization_settings(
        self,
        helm_realm,
        helm_client,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
        keycloak_port_forward,
    ):
        """Test deploying a client with authorization and scope settings via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"client-auth-{uuid.uuid4().hex[:8]}"
        realm_release = f"realm-auth-{uuid.uuid4().hex[:8]}"

        # Deploy realm first
        await helm_realm(
            release_name=realm_release,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[test_namespace],
        )

        realm_cr_name = f"{realm_release}-keycloak-realm"

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

        # Deploy client with advanced settings
        client_id = f"auth-client-{uuid.uuid4().hex[:8]}"
        client_release = f"client-auth-{uuid.uuid4().hex[:8]}"

        await helm_client(
            release_name=client_release,
            client_id=client_id,
            realm_name=realm_cr_name,
            realm_namespace=test_namespace,
            publicClient=False,
            redirectUris=["https://example.com/callback"],
            # Advanced settings
            frontchannelLogout=True,
            fullScopeAllowed=False,
            authorizationServicesEnabled=False,
        )

        client_cr_name = f"{client_release}-keycloak-client"

        # Wait for client to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify settings are in spec
        client = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
        )
        spec = client.get("spec", {})
        settings = spec.get("settings", {})

        assert settings.get("frontchannelLogout") is True, (
            "frontchannelLogout should be True"
        )
        assert settings.get("fullScopeAllowed") is False, (
            "fullScopeAllowed should be False"
        )
        assert settings.get("authorizationServicesEnabled") is False, (
            "authorizationServicesEnabled should be False"
        )

        # Verify in Keycloak
        from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

        local_port = await keycloak_port_forward(
            "keycloak", operator_namespace, service_port=8080
        )
        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username="admin",
            password="admin",
        )

        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, test_namespace
        )
        assert kc_client is not None, "Client should exist in Keycloak"
        assert kc_client.frontchannel_logout is True, (
            "Keycloak client frontchannelLogout should be True"
        )
        assert kc_client.full_scope_allowed is False, (
            "Keycloak client fullScopeAllowed should be False"
        )

    @pytest.mark.timeout(300)
    async def test_helm_client_with_session_settings(
        self,
        helm_realm,
        helm_client,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
        keycloak_port_forward,
    ):
        """Test deploying a client with session timeout settings via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"client-sess-{uuid.uuid4().hex[:8]}"
        realm_release = f"realm-sess-{uuid.uuid4().hex[:8]}"

        # Deploy realm first
        await helm_realm(
            release_name=realm_release,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[test_namespace],
        )

        realm_cr_name = f"{realm_release}-keycloak-realm"

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

        # Deploy client with session settings
        client_id = f"sess-client-{uuid.uuid4().hex[:8]}"
        client_release = f"client-sess-{uuid.uuid4().hex[:8]}"

        await helm_client(
            release_name=client_release,
            client_id=client_id,
            realm_name=realm_cr_name,
            realm_namespace=test_namespace,
            publicClient=False,
            redirectUris=["https://example.com/callback"],
            # Session settings (nested in settings)
            settings={
                "accessTokenLifespan": 300,
                "clientSessionIdleTimeout": 1800,
                "clientSessionMaxLifespan": 36000,
            },
        )

        client_cr_name = f"{client_release}-keycloak-client"

        # Wait for client to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify settings are in spec
        client = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
        )
        spec = client.get("spec", {})
        settings = spec.get("settings", {})

        assert settings.get("accessTokenLifespan") == 300, (
            "accessTokenLifespan should be 300"
        )
        assert settings.get("clientSessionIdleTimeout") == 1800, (
            "clientSessionIdleTimeout should be 1800"
        )
        assert settings.get("clientSessionMaxLifespan") == 36000, (
            "clientSessionMaxLifespan should be 36000"
        )

        # Verify in Keycloak (these are stored in attributes)
        from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

        local_port = await keycloak_port_forward(
            "keycloak", operator_namespace, service_port=8080
        )
        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username="admin",
            password="admin",
        )

        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, test_namespace
        )
        assert kc_client is not None, "Client should exist in Keycloak"

        # Session settings are stored in attributes
        attrs = kc_client.attributes or {}
        assert attrs.get("client.session.idle.timeout") == "1800", (
            "Keycloak client session idle timeout should be 1800"
        )
        assert attrs.get("client.session.max.lifespan") == "36000", (
            "Keycloak client session max lifespan should be 36000"
        )

    @pytest.mark.timeout(300)
    async def test_helm_client_with_pkce(
        self,
        helm_realm,
        helm_client,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        shared_operator,
        keycloak_port_forward,
    ):
        """Test deploying a client with PKCE settings via Helm."""
        from .wait_helpers import wait_for_resource_ready

        realm_name = f"client-pkce-{uuid.uuid4().hex[:8]}"
        realm_release = f"realm-pkce-{uuid.uuid4().hex[:8]}"

        # Deploy realm first
        await helm_realm(
            release_name=realm_release,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            clientAuthorizationGrants=[test_namespace],
        )

        realm_cr_name = f"{realm_release}-keycloak-realm"

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

        # Deploy public client with PKCE (common for SPAs)
        client_id = f"pkce-client-{uuid.uuid4().hex[:8]}"
        client_release = f"client-pkce-{uuid.uuid4().hex[:8]}"

        await helm_client(
            release_name=client_release,
            client_id=client_id,
            realm_name=realm_cr_name,
            realm_namespace=test_namespace,
            publicClient=True,
            redirectUris=["https://spa.example.com/callback"],
            # PKCE settings (nested in settings)
            settings={
                "pkceCodeChallengeMethod": "S256",
            },
        )

        client_cr_name = f"{client_release}-keycloak-client"

        # Wait for client to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
            timeout=180,
            operator_namespace=operator_namespace,
        )

        # Verify settings are in spec
        client = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            name=client_cr_name,
        )
        spec = client.get("spec", {})
        settings = spec.get("settings", {})

        assert settings.get("pkceCodeChallengeMethod") == "S256", (
            "pkceCodeChallengeMethod should be S256"
        )

        # Verify in Keycloak (PKCE is stored in attributes)
        from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

        local_port = await keycloak_port_forward(
            "keycloak", operator_namespace, service_port=8080
        )
        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username="admin",
            password="admin",
        )

        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, test_namespace
        )
        assert kc_client is not None, "Client should exist in Keycloak"

        # PKCE is stored in attributes
        attrs = kc_client.attributes or {}
        assert attrs.get("pkce.code.challenge.method") == "S256", (
            "Keycloak client PKCE method should be S256"
        )
