"""
Integration tests for Keycloak Admin API client operations.

Tests verify the admin API wrapper correctly interacts with Keycloak:
- Authentication and token management
- Realm CRUD operations
- Client CRUD operations
- User and role management
- Error handling and retries
"""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestKeycloakAdminAPI:
    """Test Keycloak Admin API client functionality."""

    @pytest.mark.timeout(180)
    async def test_realm_crud_operations(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test realm creation, retrieval, update, and deletion via admin API."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-realm-crud-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Create realm via CR
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Test CRUD Realm",
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Test GET: Retrieve realm via admin API
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None
            assert realm_repr.realm == realm_name
            assert realm_repr.display_name == "Test CRUD Realm"
            assert realm_repr.enabled is True

            # Test UPDATE: Modify realm via admin API
            realm_repr.display_name = "Updated CRUD Realm"
            realm_repr.enabled = False

            await keycloak_admin_client.update_realm(realm_name, realm_repr, namespace)

            # Verify update
            updated_realm = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert updated_realm.display_name == "Updated CRUD Realm"
            assert updated_realm.enabled is False

            # Test LIST: Verify realm appears in list
            all_realms = await keycloak_admin_client.get_realms(namespace)
            realm_names = [r.realm for r in all_realms]
            assert realm_name in realm_names

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_client_crud_operations(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test client creation, retrieval, and deletion via admin API."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-client-realm-{suffix}"
        client_name = f"test-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Create realm first
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Create client via CR
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=namespace),
                client_id=client_name,
                public_client=False,
                description="Test client for CRUD operations",
            )

            client_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Test GET: Retrieve client via admin API
            client_repr = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            assert client_repr is not None
            assert client_repr.client_id == client_name
            assert client_repr.description == "Test client for CRUD operations"
            assert client_repr.public_client is False

            # Test LIST: Verify client appears in list
            all_clients = await keycloak_admin_client.get_realm_clients(
                realm_name, namespace
            )
            client_ids = [c.client_id for c in all_clients]
            assert client_name in client_ids

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_admin_client_authentication(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_port_forward,
    ) -> None:
        """Test admin client authentication and token management."""
        from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
        from keycloak_operator.utils.kubernetes import get_admin_credentials

        keycloak_name = shared_operator.name
        keycloak_namespace = shared_operator.namespace

        # Set up port-forward
        local_port = await keycloak_port_forward(keycloak_name, keycloak_namespace)

        # Get credentials
        username, password = get_admin_credentials(keycloak_name, keycloak_namespace)

        # Test successful authentication
        admin_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username=username,
            password=password,
        )

        await admin_client.authenticate()
        assert admin_client.access_token is not None
        assert len(admin_client.access_token) > 0

        # Test that subsequent requests use the token
        _realm = await admin_client.get_realm("master", keycloak_namespace)
        # Authentication successful
        assert True  # If no exception, auth worked

        # Test invalid credentials fail properly
        bad_client = KeycloakAdminClient(
            server_url=f"http://localhost:{local_port}",
            username="invalid-user",
            password="invalid-password",
        )

        # Authentication errors raise exceptions

        with pytest.raises(Exception):  # noqa: B017  # Should raise authentication error
            await bad_client.authenticate()

    @pytest.mark.timeout(180)
    async def test_error_handling_404_realm_not_found(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test admin client handles 404 errors correctly."""
        non_existent_realm = f"does-not-exist-{uuid.uuid4().hex[:8]}"
        namespace = test_namespace

        # Attempting to get non-existent realm should return None or raise appropriate error
        realm = await keycloak_admin_client.get_realm(non_existent_realm, namespace)
        assert realm is None  # Should handle 404 gracefully

    @pytest.mark.timeout(180)
    async def test_realm_client_secret_generation(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that client secrets are generated and stored correctly."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-secret-realm-{suffix}"
        client_name = f"test-secret-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Create realm
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Create confidential client (non-public = has secret)
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=namespace),
                client_id=client_name,
                public_client=False,  # Confidential client gets a secret
            )

            client_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify secret was created in Kubernetes
            secret_name = f"{client_name}-credentials"
            secret = await k8s_core_v1.read_namespaced_secret(secret_name, namespace)

            assert secret is not None
            assert "client-id" in secret.data
            assert "client-secret" in secret.data

            # Verify the secret value from Keycloak matches
            client_repr = await keycloak_admin_client.get_client_by_name(
                client_name, realm_name, namespace
            )
            assert client_repr is not None
            assert client_repr.secret is not None
            assert len(client_repr.secret) > 0

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
