"""
Integration tests for Helm chart-based realm and client deployment.

These tests demonstrate using Helm charts instead of manual YAML to deploy
KeycloakRealm and KeycloakClient resources.
"""

import uuid

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.asyncio
class TestHelmRealmDeployment:
    """Test KeycloakRealm deployment via Helm charts."""

    async def test_deploy_realm_via_helm(
        self,
        helm_realm,
        test_namespace,
        k8s_custom_objects,
        operator_namespace,
        wait_for_condition,
        admission_token_setup,
    ):
        """Test deploying a KeycloakRealm using Helm chart."""
        realm_name = f"helm-test-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-realm-{uuid.uuid4().hex[:8]}"
        
        # Get admission token from fixture
        admission_secret_name, _ = admission_token_setup

        # Deploy realm via Helm with admission token
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            operator_auth_secret=admission_secret_name,
            displayName="Helm Test Realm",
        )

        # Verify realm CR was created
        async def realm_exists():
            try:
                realm = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                return realm is not None
            except ApiException:
                return False

        assert await wait_for_condition(realm_exists, timeout=30, interval=2)

        # Verify realm reaches Ready phase
        async def realm_ready():
            try:
                realm = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{release_name}-keycloak-realm",
                )
                status = realm.get("status", {})
                phase = status.get("phase")
                return phase == "Ready"
            except ApiException:
                return False

        assert await wait_for_condition(realm_ready, timeout=120, interval=5), (
            "Realm did not reach Ready phase"
        )

    async def test_helm_realm_with_smtp_config(
        self,
        helm_realm,
        test_namespace,
        k8s_core_v1,
        k8s_custom_objects,
        operator_namespace,
        wait_for_condition,
        admission_token_setup,
    ):
        """Test deploying a realm with SMTP configuration via Helm."""
        realm_name = f"helm-smtp-{uuid.uuid4().hex[:8]}"
        release_name = f"helm-smtp-{uuid.uuid4().hex[:8]}"
        
        # Get admission token from fixture
        admission_secret_name, _ = admission_token_setup

        # Create SMTP password secret (with required RBAC label)
        smtp_secret_name = f"smtp-secret-{uuid.uuid4().hex[:8]}"
        from kubernetes import client

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=smtp_secret_name,
                namespace=test_namespace,
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            string_data={"password": "test-smtp-password"},
        )
        k8s_core_v1.create_namespaced_secret(test_namespace, secret)

        # Deploy realm with SMTP via Helm
        await helm_realm(
            release_name=release_name,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            operator_auth_secret=admission_secret_name,
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
                realm = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
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

        assert await wait_for_condition(realm_has_smtp, timeout=30, interval=2)


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
        wait_for_condition,
        admission_token_setup,
    ):
        """Test deploying a KeycloakClient using Helm chart."""
        realm_name = f"client-realm-{uuid.uuid4().hex[:8]}"
        realm_release = f"realm-{uuid.uuid4().hex[:8]}"
        
        # Get admission token from fixture
        admission_secret_name, _ = admission_token_setup

        # First deploy a realm
        await helm_realm(
            release_name=realm_release,
            realm_name=realm_name,
            operator_namespace=operator_namespace,
            operator_auth_secret=admission_secret_name,
        )

        # Wait for realm to be ready and get auth secret
        async def realm_ready_with_secret():
            try:
                realm = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=f"{realm_release}-keycloak-realm",
                )
                status = realm.get("status", {})
                phase = status.get("phase")
                auth_secret = status.get("authorizationSecretName")
                return phase == "Ready" and auth_secret is not None
            except ApiException:
                return False

        assert await wait_for_condition(
            realm_ready_with_secret, timeout=120, interval=5
        )

        # Get the realm auth secret name
        realm = k8s_custom_objects.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=f"{realm_release}-keycloak-realm",
        )
        realm_auth_secret = realm["status"]["authorizationSecretName"]

        # Deploy client via Helm with realm auth secret
        client_id = f"test-client-{uuid.uuid4().hex[:8]}"
        client_release = f"client-{uuid.uuid4().hex[:8]}"

        await helm_client(
            release_name=client_release,
            client_id=client_id,
            realm_name=f"{realm_release}-keycloak-realm",
            realm_namespace=test_namespace,
            realm_auth_secret=realm_auth_secret,
            publicClient=False,
            redirectUris=["https://example.com/callback"],
        )

        # Verify client CR was created
        async def client_exists():
            try:
                client = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=f"{client_release}-keycloak-client",
                )
                return client is not None
            except ApiException:
                return False

        assert await wait_for_condition(client_exists, timeout=30, interval=2)

        # Verify client reaches Ready phase
        async def client_ready():
            try:
                client = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
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

        result = await wait_for_condition(client_ready, timeout=120, interval=5)
        if not result:
            # Print final state for debugging
            try:
                client = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=f"{client_release}-keycloak-client",
                )
                print(f"Final client object: {client}")
            except Exception as e:
                print(f"Failed to get final client state: {e}")

        assert result, "Client did not reach Ready phase"
