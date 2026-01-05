"""
Integration tests for Realm Roles and Groups management.

Tests verify the operator correctly manages realm roles and groups:
- Realm role creation, update, and deletion
- Composite role configuration
- Group creation with hierarchical subgroups
- Group role mappings (realm and client roles)
- Default group assignment for new users
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_deleted, wait_for_resource_ready

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
class TestRealmRoles:
    """Test realm role management via the operator."""

    @pytest.mark.timeout(180)
    async def test_realm_with_basic_roles(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with basic realm roles.

        This test verifies that:
        - A realm can be created with realm role definitions
        - The roles are created in Keycloak with correct names/descriptions
        - The roles can be retrieved via the admin API
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"roles-basic-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Roles Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="admin",
                        description="Administrator role",
                    ),
                    KeycloakRealmRole(
                        name="user",
                        description="Standard user role",
                    ),
                    KeycloakRealmRole(
                        name="viewer",
                        description="Read-only viewer role",
                    ),
                ]
            ),
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with roles
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with 3 roles")

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

            # Verify roles were created
            roles = await keycloak_admin_client.get_realm_roles(realm_name, namespace)
            role_names = {role.name for role in roles if role.name}

            assert "admin" in role_names, "admin role should exist"
            assert "user" in role_names, "user role should exist"
            assert "viewer" in role_names, "viewer role should exist"

            # Verify role details
            admin_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "admin", namespace
            )
            assert admin_role is not None
            assert admin_role.description == "Administrator role"

            logger.info("✓ Successfully verified realm roles")

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
    async def test_realm_with_composite_roles(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with composite roles.

        This test verifies that:
        - Composite roles are created correctly
        - Child roles are properly linked to parent composite roles
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"roles-composite-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Composite Roles Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    # Base roles
                    KeycloakRealmRole(
                        name="read",
                        description="Read permission",
                    ),
                    KeycloakRealmRole(
                        name="write",
                        description="Write permission",
                    ),
                    # Composite role that includes read and write
                    KeycloakRealmRole(
                        name="editor",
                        description="Editor role with read and write",
                        composite=True,
                        composite_roles=["read", "write"],
                    ),
                ]
            ),
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

            logger.info(f"Created realm CR: {realm_name} with composite roles")

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

            # Verify composite role exists and is marked as composite
            editor_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "editor", namespace
            )
            assert editor_role is not None
            assert editor_role.composite is True

            # Verify composite role has child roles
            composites = await keycloak_admin_client.get_realm_role_composites(
                realm_name, "editor", namespace
            )
            composite_names = {role.name for role in composites}

            assert "read" in composite_names, "editor should include 'read' role"
            assert "write" in composite_names, "editor should include 'write' role"

            logger.info("✓ Successfully verified composite roles")

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
    async def test_realm_role_with_attributes(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm role with custom attributes.

        This test verifies that:
        - Role attributes are correctly set
        - Attributes can be retrieved via the admin API
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"roles-attrs-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Role Attributes Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="department-head",
                        description="Department head role",
                        attributes={"department": ["Engineering"], "level": ["senior"]},
                    ),
                ]
            ),
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

            # Verify role with attributes
            role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "department-head", namespace
            )
            assert role is not None
            assert role.attributes is not None
            assert "department" in role.attributes
            assert role.attributes["department"] == ["Engineering"]
            assert role.attributes["level"] == ["senior"]

            logger.info("✓ Successfully verified role attributes")

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
class TestGroups:
    """Test group management via the operator."""

    @pytest.mark.timeout(180)
    async def test_realm_with_basic_groups(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with basic groups.

        This test verifies that:
        - Groups are created in Keycloak
        - Group attributes are set correctly
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"groups-basic-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakGroup,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Groups Test Realm",
            client_authorization_grants=[namespace],
            groups=[
                KeycloakGroup(
                    name="engineering",
                    attributes={"department": ["Engineering"]},
                ),
                KeycloakGroup(
                    name="sales",
                    attributes={"department": ["Sales"]},
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
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with 2 groups")

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

            # Verify groups were created
            groups = await keycloak_admin_client.get_groups(realm_name, namespace)
            group_names = {group.name for group in groups}

            assert "engineering" in group_names, "engineering group should exist"
            assert "sales" in group_names, "sales group should exist"

            # Verify group attributes
            eng_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/engineering", namespace
            )
            assert eng_group is not None
            assert eng_group.attributes is not None
            assert "department" in eng_group.attributes
            assert eng_group.attributes["department"] == ["Engineering"]

            logger.info("✓ Successfully verified groups")

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
    async def test_realm_with_nested_subgroups(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with nested subgroups.

        This test verifies that:
        - Nested subgroups are created correctly
        - Group hierarchy is preserved
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"groups-nested-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakGroup,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Nested Groups Test Realm",
            client_authorization_grants=[namespace],
            groups=[
                KeycloakGroup(
                    name="engineering",
                    subgroups=[
                        KeycloakGroup(name="backend"),
                        KeycloakGroup(name="frontend"),
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

            # Verify parent group
            eng_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/engineering", namespace
            )
            assert eng_group is not None

            # Verify subgroups by path
            backend_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/engineering/backend", namespace
            )
            assert backend_group is not None, "backend subgroup should exist"

            frontend_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/engineering/frontend", namespace
            )
            assert frontend_group is not None, "frontend subgroup should exist"

            logger.info("✓ Successfully verified nested subgroups")

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
    async def test_realm_with_group_role_mappings(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with groups that have role mappings.

        This test verifies that:
        - Groups can have realm roles assigned
        - Role mappings are correctly set
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"groups-roles-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakGroup,
            KeycloakRealmRole,
            KeycloakRealmSpec,
            KeycloakRoles,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Group Roles Test Realm",
            client_authorization_grants=[namespace],
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(name="developer"),
                    KeycloakRealmRole(name="admin"),
                ]
            ),
            groups=[
                KeycloakGroup(
                    name="developers",
                    realm_roles=["developer"],
                ),
                KeycloakGroup(
                    name="admins",
                    realm_roles=["admin", "developer"],
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

            # Verify developers group has developer role
            dev_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/developers", namespace
            )
            assert dev_group is not None

            dev_roles = await keycloak_admin_client.get_group_realm_role_mappings(
                realm_name, dev_group.id, namespace
            )
            dev_role_names = {role.name for role in dev_roles}
            assert "developer" in dev_role_names

            # Verify admins group has both admin and developer roles
            admin_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/admins", namespace
            )
            assert admin_group is not None

            admin_roles = await keycloak_admin_client.get_group_realm_role_mappings(
                realm_name, admin_group.id, namespace
            )
            admin_role_names = {role.name for role in admin_roles}
            assert "admin" in admin_role_names
            assert "developer" in admin_role_names

            logger.info("✓ Successfully verified group role mappings")

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
    async def test_realm_with_default_groups(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with default groups.

        This test verifies that:
        - Default groups are configured correctly
        - New users would be assigned to default groups
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"groups-default-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakGroup,
            KeycloakRealmSpec,
            OperatorRef,
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Default Groups Test Realm",
            client_authorization_grants=[namespace],
            groups=[
                KeycloakGroup(name="users"),
                KeycloakGroup(name="guests"),
            ],
            default_groups=["/users"],
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

            # Verify default groups are set
            default_groups = await keycloak_admin_client.get_default_groups(
                realm_name, namespace
            )
            default_group_paths = {
                group.path or f"/{group.name}" for group in default_groups
            }

            assert "/users" in default_group_paths, "users should be a default group"
            assert (
                "/guests" not in default_group_paths
            ), "guests should NOT be a default group"

            logger.info("✓ Successfully verified default groups")

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
class TestRealmRolesAndGroupsAPI:
    """Test direct Keycloak Admin API operations for roles and groups."""

    @pytest.mark.timeout(180)
    async def test_realm_role_crud_operations(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test realm role CRUD operations via admin API."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"api-roles-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.keycloak_api import RoleRepresentation
        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a minimal realm first
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

            # CREATE: Create a role via admin API
            test_role = RoleRepresentation(
                name="test-role",
                description="Test role created via API",
            )
            result = await keycloak_admin_client.create_realm_role(
                realm_name, test_role, namespace
            )
            assert result is True

            # READ: Retrieve the role
            role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "test-role", namespace
            )
            assert role is not None
            assert role.name == "test-role"
            assert role.description == "Test role created via API"

            # UPDATE: Modify the role
            role.description = "Updated description"
            result = await keycloak_admin_client.update_realm_role(
                realm_name, "test-role", role, namespace
            )
            assert result is True

            # Verify update
            updated_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "test-role", namespace
            )
            assert updated_role.description == "Updated description"

            # DELETE: Remove the role
            result = await keycloak_admin_client.delete_realm_role(
                realm_name, "test-role", namespace
            )
            assert result is True

            # Verify deletion
            deleted_role = await keycloak_admin_client.get_realm_role_by_name(
                realm_name, "test-role", namespace
            )
            assert deleted_role is None

            logger.info("✓ Successfully verified role CRUD operations")

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
    async def test_group_crud_operations(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test group CRUD operations via admin API."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"api-groups-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.keycloak_api import GroupRepresentation
        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a minimal realm first
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

            # CREATE: Create a group via admin API
            test_group = GroupRepresentation(
                name="test-group",
                attributes={"test": ["value"]},
            )
            group_id = await keycloak_admin_client.create_group(
                realm_name, test_group, namespace
            )
            assert group_id is not None

            # READ: Retrieve the group
            group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/test-group", namespace
            )
            assert group is not None
            assert group.name == "test-group"
            assert group.attributes == {"test": ["value"]}

            # UPDATE: Modify the group
            group.attributes = {"updated": ["yes"]}
            result = await keycloak_admin_client.update_group(
                realm_name, group.id, group, namespace
            )
            assert result is True

            # Verify update
            updated_group = await keycloak_admin_client.get_group_by_id(
                realm_name, group.id, namespace
            )
            assert updated_group.attributes == {"updated": ["yes"]}

            # DELETE: Remove the group
            result = await keycloak_admin_client.delete_group(
                realm_name, group.id, namespace
            )
            assert result is True

            # Verify deletion
            deleted_group = await keycloak_admin_client.get_group_by_path(
                realm_name, "/test-group", namespace
            )
            assert deleted_group is None

            logger.info("✓ Successfully verified group CRUD operations")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
