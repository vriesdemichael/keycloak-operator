"""
Integration tests for Client Scopes management.

Tests verify the operator correctly manages client scopes:
- Client scope creation with protocol mappers
- Client scope update and deletion
- Realm default/optional client scope assignments
- Client-level scope assignments
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_deleted,
    wait_for_resource_ready,
)

logger = logging.getLogger(__name__)


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
    """Helper to delete a resource and wait for deletion to complete."""
    with contextlib.suppress(ApiException):
        await k8s_custom_objects.delete_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
        )
    # Wait for resource to be fully deleted (ignore if already gone)
    with contextlib.suppress(Exception):
        await wait_for_resource_deleted(
            k8s_custom_objects=k8s_custom_objects,
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
            timeout=timeout,
        )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientScopes:
    """Test client scope management via the operator."""

    @pytest.mark.timeout(180)
    async def test_realm_with_client_scopes(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with custom client scopes.

        This test verifies that:
        - A realm can be created with client scope definitions
        - The scopes are created in Keycloak with correct names/descriptions
        - The scopes can be retrieved via the admin API
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"scopes-basic-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Client Scopes Test Realm",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Read access to API",
                    protocol="openid-connect",
                ),
                KeycloakClientScope(
                    name="api.write",
                    description="Write access to API",
                    protocol="openid-connect",
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with scopes
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with 2 client scopes")

            # Wait for realm to become ready
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

            # Verify realm exists
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Verify scopes were created
            scopes = await keycloak_admin_client.get_client_scopes(
                realm_name, namespace
            )
            scope_names = {scope.name for scope in scopes if scope.name}

            assert "api.read" in scope_names, "api.read scope should exist"
            assert "api.write" in scope_names, "api.write scope should exist"

            # Verify scope details
            api_read_scope = await keycloak_admin_client.get_client_scope_by_name(
                realm_name, "api.read", namespace
            )
            assert api_read_scope is not None
            assert api_read_scope.description == "Read access to API"
            assert api_read_scope.protocol == "openid-connect"

            logger.info("✓ Successfully verified client scopes")

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
    async def test_client_scope_with_protocol_mappers(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating client scopes with protocol mappers.

        This test verifies that:
        - Protocol mappers are created inside client scopes
        - Mapper configuration is applied correctly
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"scopes-mappers-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakProtocolMapper,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Scopes with Mappers Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="custom-claims",
                    description="Custom claims scope",
                    protocol="openid-connect",
                    protocol_mappers=[
                        KeycloakProtocolMapper(
                            name="custom-audience",
                            protocol="openid-connect",
                            protocol_mapper="oidc-audience-mapper",
                            config={
                                "included.custom.audience": "my-api",
                                "access.token.claim": "true",
                            },
                        ),
                    ],
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with scopes and mappers
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with scope containing mapper")

            # Wait for realm to become ready
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

            # Verify scope exists
            scope = await keycloak_admin_client.get_client_scope_by_name(
                realm_name, "custom-claims", namespace
            )
            assert scope is not None, "custom-claims scope should exist"
            assert scope.id is not None

            # Verify protocol mapper was created
            mappers = await keycloak_admin_client.get_client_scope_protocol_mappers(
                realm_name, scope.id, namespace
            )
            mapper_names = {m.name for m in mappers if m.name}

            assert "custom-audience" in mapper_names, (
                "custom-audience mapper should exist"
            )

            # Verify mapper configuration
            custom_mapper = next(
                (m for m in mappers if m.name == "custom-audience"), None
            )
            assert custom_mapper is not None
            assert custom_mapper.protocol_mapper == "oidc-audience-mapper"
            assert custom_mapper.config is not None
            assert custom_mapper.config.get("included.custom.audience") == "my-api"

            logger.info("✓ Successfully verified client scope with protocol mappers")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(240)
    async def test_protocol_mapper_update_and_delete(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test updating and deleting protocol mappers within a client scope.

        This test verifies that:
        - Protocol mappers can be updated when config changes
        - Protocol mappers are deleted when removed from spec
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"mapper-update-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakProtocolMapper,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create realm with scope containing two mappers
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Mapper Update Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="update-test-scope",
                    description="Scope for mapper update testing",
                    protocol="openid-connect",
                    protocol_mappers=[
                        KeycloakProtocolMapper(
                            name="audience-mapper",
                            protocol="openid-connect",
                            protocol_mapper="oidc-audience-mapper",
                            config={
                                "included.custom.audience": "initial-audience",
                                "access.token.claim": "true",
                            },
                        ),
                        KeycloakProtocolMapper(
                            name="delete-me-mapper",
                            protocol="openid-connect",
                            protocol_mapper="oidc-audience-mapper",
                            config={
                                "included.custom.audience": "delete-this",
                                "access.token.claim": "true",
                            },
                        ),
                    ],
                ),
            ],
        )

        realm_manifest: dict = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with initial mappers
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

            # Verify both mappers exist
            scope = await keycloak_admin_client.get_client_scope_by_name(
                realm_name, "update-test-scope", namespace
            )
            assert scope is not None and scope.id is not None

            mappers = await keycloak_admin_client.get_client_scope_protocol_mappers(
                realm_name, scope.id, namespace
            )
            mapper_names = {m.name for m in mappers if m.name}
            assert "audience-mapper" in mapper_names
            assert "delete-me-mapper" in mapper_names

            # Get resourceVersion for update
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            current_gen = resource["metadata"].get("generation", 1)
            resource_version = resource["metadata"]["resourceVersion"]

            # Update: change config of one mapper and remove the other
            updated_spec = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Mapper Update Test",
                client_authorization_grants=[namespace],
                client_scopes=[
                    KeycloakClientScope(
                        name="update-test-scope",
                        description="Scope for mapper update testing",
                        protocol="openid-connect",
                        protocol_mappers=[
                            KeycloakProtocolMapper(
                                name="audience-mapper",
                                protocol="openid-connect",
                                protocol_mapper="oidc-audience-mapper",
                                config={
                                    "included.custom.audience": "updated-audience",  # Changed!
                                    "access.token.claim": "true",
                                },
                            ),
                            # delete-me-mapper is removed
                        ],
                    ),
                ],
            )

            realm_manifest["metadata"]["resourceVersion"] = resource_version
            realm_manifest["spec"] = updated_spec.model_dump(
                by_alias=True, exclude_unset=True
            )

            await k8s_custom_objects.replace_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=realm_manifest,
            )

            # Wait for reconciliation to complete
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=current_gen + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify mapper was updated and deleted
            mappers = await keycloak_admin_client.get_client_scope_protocol_mappers(
                realm_name, scope.id, namespace
            )
            mapper_names = {m.name for m in mappers if m.name}

            assert "audience-mapper" in mapper_names, (
                "audience-mapper should still exist"
            )
            assert "delete-me-mapper" not in mapper_names, (
                "delete-me-mapper should be deleted"
            )

            # Verify the updated config
            updated_mapper = next(
                (m for m in mappers if m.name == "audience-mapper"), None
            )
            assert updated_mapper is not None
            assert updated_mapper.config is not None
            assert (
                updated_mapper.config.get("included.custom.audience")
                == "updated-audience"
            )

            logger.info("✓ Successfully verified protocol mapper update and deletion")

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
    async def test_client_scope_deletion(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that removing a scope from spec deletes it from Keycloak.

        This test verifies that:
        - Scopes removed from the CRD spec are deleted from Keycloak
        - Built-in scopes are never deleted
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"scopes-delete-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # First, create realm with two custom scopes
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Scope Deletion Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(name="keep-me", protocol="openid-connect"),
                KeycloakClientScope(name="delete-me", protocol="openid-connect"),
            ],
        )

        realm_manifest: dict = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with both scopes
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

            # Verify both scopes exist
            scopes = await keycloak_admin_client.get_client_scopes(
                realm_name, namespace
            )
            scope_names = {s.name for s in scopes if s.name}
            assert "keep-me" in scope_names
            assert "delete-me" in scope_names

            # Get current resource to get resourceVersion for update
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            current_gen = resource["metadata"].get("generation", 1)
            resource_version = resource["metadata"]["resourceVersion"]

            # Update realm to remove one scope
            updated_spec = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Scope Deletion Test",
                client_authorization_grants=[namespace],
                client_scopes=[
                    KeycloakClientScope(name="keep-me", protocol="openid-connect"),
                    # delete-me is removed
                ],
            )

            # Update manifest with new spec and preserve metadata
            realm_manifest["metadata"]["resourceVersion"] = resource_version
            realm_manifest["spec"] = updated_spec.model_dump(
                by_alias=True, exclude_unset=True
            )

            await k8s_custom_objects.replace_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=realm_manifest,
            )

            # Wait for reconciliation to complete
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=current_gen + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify delete-me scope is gone
            scopes = await keycloak_admin_client.get_client_scopes(
                realm_name, namespace
            )
            scope_names = {s.name for s in scopes if s.name}
            assert "keep-me" in scope_names, "keep-me scope should still exist"
            assert "delete-me" not in scope_names, "delete-me scope should be deleted"

            # Verify built-in scopes are still present
            assert "profile" in scope_names, "built-in profile scope should exist"
            assert "email" in scope_names, "built-in email scope should exist"

            logger.info("✓ Successfully verified client scope deletion")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmDefaultOptionalScopes:
    """Test realm-level default and optional client scope assignments."""

    @pytest.mark.timeout(180)
    async def test_realm_default_client_scopes(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test setting realm default client scopes.

        This test verifies that:
        - Custom scopes can be assigned as realm default scopes
        - Default scopes are reflected in Keycloak configuration
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"default-scopes-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Default Scopes Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Read access",
                    protocol="openid-connect",
                ),
            ],
            default_client_scopes=["api.read", "profile", "email"],
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

            # Verify default scopes
            default_scopes = (
                await keycloak_admin_client.get_realm_default_client_scopes(
                    realm_name, namespace
                )
            )
            default_scope_names = {s.name for s in default_scopes if s.name}

            assert "api.read" in default_scope_names, (
                "api.read should be a default scope"
            )
            assert "profile" in default_scope_names, "profile should be a default scope"
            assert "email" in default_scope_names, "email should be a default scope"

            logger.info("✓ Successfully verified realm default client scopes")

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
    async def test_realm_optional_client_scopes(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test setting realm optional client scopes.

        This test verifies that:
        - Custom scopes can be assigned as realm optional scopes
        - Optional scopes are reflected in Keycloak configuration
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"optional-scopes-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Optional Scopes Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="api.admin",
                    description="Admin access",
                    protocol="openid-connect",
                ),
            ],
            optional_client_scopes=["api.admin", "offline_access"],
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

            # Verify optional scopes
            optional_scopes = (
                await keycloak_admin_client.get_realm_optional_client_scopes(
                    realm_name, namespace
                )
            )
            optional_scope_names = {s.name for s in optional_scopes if s.name}

            assert "api.admin" in optional_scope_names, "api.admin should be optional"
            assert "offline_access" in optional_scope_names, (
                "offline_access should be optional"
            )

            logger.info("✓ Successfully verified realm optional client scopes")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientScopeAssignments:
    """Test client-level scope assignments."""

    @pytest.mark.timeout(240)
    async def test_client_with_custom_scopes(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test assigning custom scopes to a client.

        This test verifies that:
        - A client can specify default and optional client scopes
        - The scope assignments are applied in Keycloak
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"client-scopes-{suffix}"
        client_name = f"scoped-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # First create realm with scopes
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Client Scope Assignment Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="api.read",
                    description="Read access",
                    protocol="openid-connect",
                ),
                KeycloakClientScope(
                    name="api.write",
                    description="Write access",
                    protocol="openid-connect",
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
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

            # Create client with scope assignments
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=namespace),
                client_id=client_name,
                description="Client with custom scopes",
                default_client_scopes=["api.read", "profile"],
                optional_client_scopes=["api.write", "offline_access"],
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

            # Get client UUID
            client_uuid = await keycloak_admin_client.get_client_uuid(
                client_name, realm_name, namespace
            )
            assert client_uuid is not None, "Client should exist"

            # Verify client default scopes
            client_defaults = await keycloak_admin_client.get_client_default_scopes(
                realm_name, client_uuid, namespace
            )
            default_names = {s.name for s in client_defaults if s.name}

            assert "api.read" in default_names, "api.read should be client default"
            assert "profile" in default_names, "profile should be client default"

            # Verify client optional scopes
            client_optionals = await keycloak_admin_client.get_client_optional_scopes(
                realm_name, client_uuid, namespace
            )
            optional_names = {s.name for s in client_optionals if s.name}

            assert "api.write" in optional_names, "api.write should be client optional"
            assert "offline_access" in optional_names, (
                "offline_access should be client optional"
            )

            logger.info("✓ Successfully verified client scope assignments")

        finally:
            # Cleanup client first
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            # Then cleanup realm
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.asyncio
    async def test_client_with_nonexistent_scope_reference(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test client referencing a nonexistent scope gracefully handles the error.

        This test verifies that:
        - A client referencing a nonexistent scope doesn't fail reconciliation
        - The operator logs a warning but continues
        - Other valid scopes are still assigned
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"missing-scope-{suffix}"
        client_name = f"bad-scope-client-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.client import (
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import (
            KeycloakClientScope,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create realm with one scope
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Missing Scope Test",
            client_authorization_grants=[namespace],
            client_scopes=[
                KeycloakClientScope(
                    name="valid-scope",
                    description="This scope exists",
                    protocol="openid-connect",
                ),
            ],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
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

            # Create client referencing both valid and nonexistent scope
            client_spec = KeycloakClientSpec(
                realm_ref=RealmRef(name=realm_name, namespace=namespace),
                client_id=client_name,
                default_client_scopes=[
                    "valid-scope",  # This exists
                    "nonexistent-scope",  # This does NOT exist
                ],
                optional_client_scopes=[
                    "also-nonexistent",  # This does NOT exist
                ],
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

            # Client should still become ready (nonexistent scopes logged as warnings)
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

            # Verify the valid scope was assigned
            client_uuid = await keycloak_admin_client.get_client_uuid(
                client_name, realm_name, namespace
            )
            assert client_uuid is not None, "Client should exist"

            client_defaults = await keycloak_admin_client.get_client_default_scopes(
                realm_name, client_uuid, namespace
            )
            default_names = {s.name for s in client_defaults if s.name}

            # The valid scope should be assigned
            assert "valid-scope" in default_names, "valid-scope should be assigned"

            # The nonexistent scope should NOT cause a crash
            logger.info("✓ Client handles nonexistent scope references gracefully")

        finally:
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
