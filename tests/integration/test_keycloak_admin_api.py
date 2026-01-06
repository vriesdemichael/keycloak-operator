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

import asyncio
import time
import uuid

import pytest

from .cleanup_utils import delete_custom_resource_with_retry
from .wait_helpers import wait_for_resource_ready


async def _simple_wait(condition_func, timeout=60, interval=2):
    """Simple wait helper for conditions with retry."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            if await condition_func():
                return True
        except Exception:
            pass  # Retry on any error
        await asyncio.sleep(interval)
    return False


async def _cleanup_resource(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 60,
) -> None:
    """Helper to delete a resource and wait for deletion to complete.

    Uses robust cleanup with automatic finalizer removal for stuck resources.
    """
    await delete_custom_resource_with_retry(
        k8s_custom_objects=k8s_custom_objects,
        group=group,
        version=version,
        namespace=namespace,
        plural=plural,
        name=name,
        timeout=timeout,
        force_after=30,
    )


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

            # Test LIST: Verify realm appears in list (with retry for transient API errors)
            async def check_realm_in_list():
                all_realms = await keycloak_admin_client.get_realms(namespace)
                if all_realms is None:
                    return False
                return realm_name in [r.realm for r in all_realms]

            assert await _simple_wait(
                check_realm_in_list, timeout=30, interval=2
            ), f"Realm {realm_name} not found in realm list after retries"

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
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
            # Delete client first (depends on realm), then realm
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            await _cleanup_resource(
                k8s_custom_objects,
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
            # Delete client first (depends on realm), then realm
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.asyncio
    async def test_client_scope_crud_operations(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test client scope CRUD operations directly via admin API."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-scope-api-{suffix}"
        scope_name = f"api-scope-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.keycloak_api import (
            ClientScopeRepresentation,
            ProtocolMapperRepresentation,
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

            # 1. Create client scope
            scope_config = ClientScopeRepresentation(
                name=scope_name,
                description="Test API scope",
                protocol="openid-connect",
            )
            scope_id = await keycloak_admin_client.create_client_scope(
                realm_name, scope_config, namespace
            )
            assert scope_id is not None, "Failed to create client scope"

            # 2. Verify scope exists via get_client_scopes
            scopes = await keycloak_admin_client.get_client_scopes(
                realm_name, namespace
            )
            scope_names = [s.name for s in scopes]
            assert scope_name in scope_names, "Created scope not found in list"

            # 3. Get scope by name
            scope = await keycloak_admin_client.get_client_scope_by_name(
                realm_name, scope_name, namespace
            )
            assert scope is not None
            assert scope.name == scope_name
            assert scope.id == scope_id

            # 4. Get scope by ID
            scope_by_id = await keycloak_admin_client.get_client_scope_by_id(
                realm_name, scope_id, namespace
            )
            assert scope_by_id is not None
            assert scope_by_id.name == scope_name

            # 5. Update scope
            updated_config = ClientScopeRepresentation(
                id=scope_id,
                name=scope_name,
                description="Updated description",
                protocol="openid-connect",
            )
            update_result = await keycloak_admin_client.update_client_scope(
                realm_name, scope_id, updated_config, namespace
            )
            assert update_result is True

            # Verify update
            updated_scope = await keycloak_admin_client.get_client_scope_by_id(
                realm_name, scope_id, namespace
            )
            assert updated_scope is not None
            assert updated_scope.description == "Updated description"

            # 6. Add protocol mapper to scope
            mapper_config = ProtocolMapperRepresentation(
                name="audience-mapper",
                protocol="openid-connect",
                protocol_mapper="oidc-audience-mapper",
                config={
                    "included.custom.audience": "test-api",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            )
            mapper_id = await keycloak_admin_client.create_client_scope_protocol_mapper(
                realm_name, scope_id, mapper_config, namespace
            )
            assert mapper_id is not None, "Failed to create protocol mapper"

            # 7. Get protocol mappers
            mappers = await keycloak_admin_client.get_client_scope_protocol_mappers(
                realm_name, scope_id, namespace
            )
            mapper_names = [m.name for m in mappers]
            assert "audience-mapper" in mapper_names

            # 8. Update protocol mapper
            updated_mapper = ProtocolMapperRepresentation(
                id=mapper_id,
                name="audience-mapper",
                protocol="openid-connect",
                protocol_mapper="oidc-audience-mapper",
                config={
                    "included.custom.audience": "updated-api",
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                },
            )
            mapper_update = (
                await keycloak_admin_client.update_client_scope_protocol_mapper(
                    realm_name, scope_id, mapper_id, updated_mapper, namespace
                )
            )
            assert mapper_update is True

            # 9. Delete protocol mapper
            mapper_delete = (
                await keycloak_admin_client.delete_client_scope_protocol_mapper(
                    realm_name, scope_id, mapper_id, namespace
                )
            )
            assert mapper_delete is True

            # 10. Add scope to realm defaults
            add_default = await keycloak_admin_client.add_realm_default_client_scope(
                realm_name, scope_id, namespace
            )
            assert add_default is True

            # Verify in defaults
            defaults = await keycloak_admin_client.get_realm_default_client_scopes(
                realm_name, namespace
            )
            default_ids = [s.id for s in defaults]
            assert scope_id in default_ids

            # 11. Remove from defaults
            remove_default = (
                await keycloak_admin_client.remove_realm_default_client_scope(
                    realm_name, scope_id, namespace
                )
            )
            assert remove_default is True

            # 12. Add scope to realm optionals
            add_optional = await keycloak_admin_client.add_realm_optional_client_scope(
                realm_name, scope_id, namespace
            )
            assert add_optional is True

            # Verify in optionals
            optionals = await keycloak_admin_client.get_realm_optional_client_scopes(
                realm_name, namespace
            )
            optional_ids = [s.id for s in optionals]
            assert scope_id in optional_ids

            # 13. Remove from optionals
            remove_optional = (
                await keycloak_admin_client.remove_realm_optional_client_scope(
                    realm_name, scope_id, namespace
                )
            )
            assert remove_optional is True

            # 14. Delete client scope
            delete_result = await keycloak_admin_client.delete_client_scope(
                realm_name, scope_id, namespace
            )
            assert delete_result is True

            # Verify deletion
            deleted_scope = await keycloak_admin_client.get_client_scope_by_id(
                realm_name, scope_id, namespace
            )
            assert deleted_scope is None, "Scope should be deleted"

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.asyncio
    async def test_client_scope_idempotency(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test client scope operations are idempotent (double-create, double-delete)."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-scope-idemp-{suffix}"
        scope_name = f"idemp-scope-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.keycloak_api import ClientScopeRepresentation
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

            # Test double-create (409 conflict handling)
            scope_config = ClientScopeRepresentation(
                name=scope_name,
                description="Test scope",
                protocol="openid-connect",
            )

            # First create
            scope_id_1 = await keycloak_admin_client.create_client_scope(
                realm_name, scope_config, namespace
            )
            assert scope_id_1 is not None, "First create should succeed"

            # Second create (same name) - should return existing ID
            scope_id_2 = await keycloak_admin_client.create_client_scope(
                realm_name, scope_config, namespace
            )
            assert scope_id_2 == scope_id_1, "Double-create should return same ID"

            # Test double-delete (404 handling)
            # First delete
            delete_1 = await keycloak_admin_client.delete_client_scope(
                realm_name, scope_id_1, namespace
            )
            assert delete_1 is True, "First delete should succeed"

            # Second delete (already gone) - should still return True
            delete_2 = await keycloak_admin_client.delete_client_scope(
                realm_name, scope_id_1, namespace
            )
            assert delete_2 is True, "Double-delete should succeed (idempotent)"

            # Test double-add to realm defaults
            # Create a new scope for this test
            scope_config_2 = ClientScopeRepresentation(
                name=f"{scope_name}-2",
                protocol="openid-connect",
            )
            scope_id = await keycloak_admin_client.create_client_scope(
                realm_name, scope_config_2, namespace
            )
            assert scope_id is not None

            # Add to defaults twice
            add_1 = await keycloak_admin_client.add_realm_default_client_scope(
                realm_name, scope_id, namespace
            )
            assert add_1 is True

            add_2 = await keycloak_admin_client.add_realm_default_client_scope(
                realm_name, scope_id, namespace
            )
            assert add_2 is True, "Double-add to defaults should succeed"

            # Remove from defaults twice
            remove_1 = await keycloak_admin_client.remove_realm_default_client_scope(
                realm_name, scope_id, namespace
            )
            assert remove_1 is True

            remove_2 = await keycloak_admin_client.remove_realm_default_client_scope(
                realm_name, scope_id, namespace
            )
            assert remove_2 is True, "Double-remove from defaults should succeed"

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
