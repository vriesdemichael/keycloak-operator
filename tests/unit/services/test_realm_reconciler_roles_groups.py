"""Unit tests for KeycloakRealmReconciler realm roles and groups methods."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.keycloak_api import (
    GroupRepresentation,
    RoleRepresentation,
)
from keycloak_operator.models.realm import (
    KeycloakGroup,
    KeycloakRealmRole,
    KeycloakRealmSpec,
    KeycloakRoles,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client with realm role and group methods."""
    mock = MagicMock()

    # Realm role methods
    mock.get_realm_roles = AsyncMock(return_value=[])
    mock.get_realm_role_by_name = AsyncMock(return_value=None)
    mock.create_realm_role = AsyncMock(return_value=True)
    mock.update_realm_role = AsyncMock(return_value=True)
    mock.delete_realm_role = AsyncMock(return_value=True)

    # Composite role methods
    mock.get_realm_role_composites = AsyncMock(return_value=[])
    mock.add_realm_role_composites = AsyncMock(return_value=True)
    mock.remove_realm_role_composites = AsyncMock(return_value=True)

    # Group methods
    mock.get_groups = AsyncMock(return_value=[])
    mock.get_group_by_id = AsyncMock(return_value=None)
    mock.get_group_by_path = AsyncMock(return_value=None)
    mock.create_group = AsyncMock(return_value="new-group-id")
    mock.create_subgroup = AsyncMock(return_value="new-subgroup-id")
    mock.update_group = AsyncMock(return_value=True)
    mock.delete_group = AsyncMock(return_value=True)

    # Group role mapping methods
    mock.get_group_realm_role_mappings = AsyncMock(return_value=[])
    mock.assign_realm_roles_to_group = AsyncMock(return_value=True)
    mock.remove_realm_roles_from_group = AsyncMock(return_value=True)

    # Default group methods
    mock.get_default_groups = AsyncMock(return_value=[])
    mock.add_default_group = AsyncMock(return_value=True)
    mock.remove_default_group = AsyncMock(return_value=True)

    # Realm update method
    mock.update_realm = AsyncMock(return_value=True)

    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakRealmReconciler:
    """KeycloakRealmReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace, rate_limiter=None):
        return admin_mock

    reconciler_instance = KeycloakRealmReconciler(
        keycloak_admin_factory=mock_factory,
    )
    reconciler_instance.logger = MagicMock()  # type: ignore[assignment]

    return reconciler_instance


# =============================================================================
# Realm Roles Tests
# =============================================================================


class TestConfigureRealmRoles:
    """Tests for configure_realm_roles method."""

    @pytest.mark.asyncio
    async def test_creates_new_realm_role(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New realm role should be created when it doesn't exist."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="admin")]),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.get_realm_roles.assert_called_once()
        admin_mock.create_realm_role.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_realm_role(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing realm role should be updated when it exists."""
        # Mock that role already exists
        existing_role = RoleRepresentation(
            name="admin",
            description="Old description",
        )
        admin_mock.get_realm_roles = AsyncMock(return_value=[existing_role])
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=existing_role)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="admin",
                        description="New description",
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.update_realm_role.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_builtin_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Built-in roles should not be deleted."""
        # Mock existing roles including built-in ones
        existing_roles = [
            RoleRepresentation(name="offline_access"),
            RoleRepresentation(name="uma_authorization"),
            RoleRepresentation(name="default-roles-test-realm"),
            RoleRepresentation(name="custom-role"),
        ]
        admin_mock.get_realm_roles = AsyncMock(return_value=existing_roles)

        # Spec with a new role - should not delete built-in ones
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="new-role")]),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Should only delete custom-role (not built-in roles)
        # Verify delete was called with custom-role
        delete_calls = admin_mock.delete_realm_role.call_args_list
        deleted_roles = {call[0][1] for call in delete_calls}

        # custom-role should be in deleted roles
        assert "custom-role" in deleted_roles
        # Built-in roles should not be in deleted roles
        assert "offline_access" not in deleted_roles
        assert "uma_authorization" not in deleted_roles
        assert "default-roles-test-realm" not in deleted_roles

    @pytest.mark.asyncio
    async def test_creates_role_with_attributes(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Role with attributes should be created correctly."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="admin",
                        description="Administrator role",
                        attributes={"department": ["IT"]},
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.create_realm_role.assert_called_once()
        call_args = admin_mock.create_realm_role.call_args
        role_arg = call_args[0][1]
        assert role_arg.name == "admin"
        assert role_arg.description == "Administrator role"
        assert role_arg.attributes == {"department": ["IT"]}


class TestConfigureCompositeRoles:
    """Tests for composite role configuration."""

    @pytest.mark.asyncio
    async def test_adds_composite_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Composite roles should be added to parent role."""
        # Mock the parent role exists
        parent_role = RoleRepresentation(name="admin", id="admin-id")
        child_role = RoleRepresentation(name="user", id="user-id")
        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role, child_role])
        admin_mock.get_realm_role_by_name = AsyncMock(
            side_effect=lambda realm, name, ns: parent_role
            if name == "admin"
            else child_role
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="admin",
                        composite_roles=["user"],
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.add_realm_role_composites.assert_called()

    @pytest.mark.asyncio
    async def test_removes_unwanted_composite_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Composite roles not in spec should be removed."""
        # Mock existing composites
        parent_role = RoleRepresentation(name="admin", id="admin-id", composite=True)
        existing_composite = RoleRepresentation(name="old-role", id="old-id")
        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role])
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=parent_role)
        admin_mock.get_realm_role_composites = AsyncMock(
            return_value=[existing_composite]
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="admin",
                        composite=True,
                        composite_roles=["new-role"],  # Different from old-role
                    )
                ]
            ),
        )

        # Mock the new role lookup
        new_role = RoleRepresentation(name="new-role", id="new-id")
        admin_mock.get_realm_role_by_name = AsyncMock(
            side_effect=lambda realm, name, ns: parent_role
            if name == "admin"
            else new_role
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Should remove old-role since it's in current but not desired
        admin_mock.remove_realm_role_composites.assert_called()


class TestDeleteRealmRoles:
    """Tests for realm role deletion."""

    @pytest.mark.asyncio
    async def test_deletes_roles_not_in_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Roles not in spec should be deleted."""
        existing_roles = [
            RoleRepresentation(name="to-delete", id="delete-id"),
            RoleRepresentation(name="to-keep", id="keep-id"),
        ]
        admin_mock.get_realm_roles = AsyncMock(return_value=existing_roles)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="to-keep")]),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.delete_realm_role.assert_called_once_with(
            "test-realm", "to-delete", "default"
        )


# =============================================================================
# Groups Tests
# =============================================================================


class TestConfigureGroups:
    """Tests for configure_groups method."""

    @pytest.mark.asyncio
    async def test_creates_new_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New group should be created when it doesn't exist."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="engineering")],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.get_groups.assert_called_once()
        admin_mock.create_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_subgroup(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Subgroups should be created under parent group."""
        # Mock parent group is created and returns ID
        admin_mock.create_group = AsyncMock(return_value="parent-id")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="engineering",
                    subgroups=[KeycloakGroup(name="backend")],
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()
        admin_mock.create_subgroup.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing group should be updated when it exists."""
        existing_group = GroupRepresentation(
            id="group-id",
            name="engineering",
            path="/engineering",
            attributes={"old": ["value"]},
        )
        admin_mock.get_groups = AsyncMock(return_value=[existing_group])
        admin_mock.get_group_by_path = AsyncMock(return_value=existing_group)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="engineering",
                    attributes={"new": ["value"]},
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.update_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_group_with_attributes(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Group with attributes should be created correctly."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="engineering",
                    attributes={"department": ["Engineering"]},
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()
        call_args = admin_mock.create_group.call_args
        group_arg = call_args[0][1]
        assert group_arg.name == "engineering"
        assert group_arg.attributes == {"department": ["Engineering"]}


class TestGroupRoleMappings:
    """Tests for group role mapping configuration."""

    @pytest.mark.asyncio
    async def test_assigns_realm_roles_to_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Realm roles should be assigned to group."""
        # Mock group exists with ID
        existing_group = GroupRepresentation(
            id="group-id",
            name="engineering",
            path="/engineering",
        )
        admin_mock.get_groups = AsyncMock(return_value=[existing_group])
        admin_mock.get_group_by_path = AsyncMock(return_value=existing_group)

        # Mock role exists
        role = RoleRepresentation(name="developer", id="role-id")
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=role)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="engineering",
                    realm_roles=["developer"],
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.assign_realm_roles_to_group.assert_called()

    @pytest.mark.asyncio
    async def test_removes_unassigned_realm_roles_from_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Realm roles not in spec should be removed from group."""
        existing_group = GroupRepresentation(
            id="group-id",
            name="engineering",
            path="/engineering",
        )
        admin_mock.get_groups = AsyncMock(return_value=[existing_group])
        admin_mock.get_group_by_path = AsyncMock(return_value=existing_group)

        # Mock existing role mappings - has old-role and keep-role
        old_role = RoleRepresentation(name="old-role", id="old-role-id")
        keep_role = RoleRepresentation(name="keep-role", id="keep-role-id")
        admin_mock.get_group_realm_role_mappings = AsyncMock(
            return_value=[old_role, keep_role]
        )

        # Mock role lookup
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=keep_role)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="engineering",
                    realm_roles=[
                        "keep-role"
                    ],  # Only keep-role, old-role should be removed
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should remove old-role since it's in current but not desired
        admin_mock.remove_realm_roles_from_group.assert_called()


class TestDeleteGroups:
    """Tests for group deletion."""

    @pytest.mark.asyncio
    async def test_deletes_groups_not_in_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Groups not in spec should be deleted."""
        existing_groups = [
            GroupRepresentation(id="delete-id", name="to-delete", path="/to-delete"),
            GroupRepresentation(id="keep-id", name="to-keep", path="/to-keep"),
        ]
        admin_mock.get_groups = AsyncMock(return_value=existing_groups)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="to-keep")],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.delete_group.assert_called_once_with(
            "test-realm", "delete-id", "default"
        )


class TestConfigureDefaultGroups:
    """Tests for default group configuration."""

    @pytest.mark.asyncio
    async def test_adds_default_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Default groups should be added."""
        # Mock group exists
        group = GroupRepresentation(id="group-id", name="users", path="/users")
        admin_mock.get_group_by_path = AsyncMock(return_value=group)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/users"],
        )

        await reconciler.configure_default_groups(spec, "test-realm", "default")

        admin_mock.add_default_group.assert_called_once_with(
            "test-realm", "group-id", "default"
        )

    @pytest.mark.asyncio
    async def test_removes_default_group_not_in_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Default groups not in spec should be removed."""
        # Mock existing default groups
        old_default = GroupRepresentation(
            id="old-id", name="old-group", path="/old-group"
        )
        new_default = GroupRepresentation(
            id="new-id", name="new-group", path="/new-group"
        )
        admin_mock.get_default_groups = AsyncMock(return_value=[old_default])
        admin_mock.get_group_by_path = AsyncMock(return_value=new_default)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/new-group"],  # Different from old-group
        )

        await reconciler.configure_default_groups(spec, "test-realm", "default")

        # Should remove old-group since it's in current but not desired
        admin_mock.remove_default_group.assert_called_once_with(
            "test-realm", "old-id", "default"
        )

    @pytest.mark.asyncio
    async def test_skips_nonexistent_default_group(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle nonexistent groups gracefully."""
        admin_mock.get_group_by_path = AsyncMock(return_value=None)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/nonexistent"],
        )

        # Should not raise an error
        await reconciler.configure_default_groups(spec, "test-realm", "default")

        # Should not try to add nonexistent group
        admin_mock.add_default_group.assert_not_called()


# =============================================================================
# Deep Nested Groups Tests
# =============================================================================


class TestDeepNestedGroups:
    """Tests for deeply nested group hierarchies."""

    @pytest.mark.asyncio
    async def test_creates_three_level_nested_groups(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Three-level nested groups should be created correctly."""
        # Mock IDs returned for created groups
        admin_mock.create_group = AsyncMock(return_value="level-1-id")
        admin_mock.create_subgroup = AsyncMock(side_effect=["level-2-id", "level-3-id"])

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="level-1",
                    subgroups=[
                        KeycloakGroup(
                            name="level-2",
                            subgroups=[KeycloakGroup(name="level-3")],
                        )
                    ],
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should create top-level group once
        admin_mock.create_group.assert_called_once()

        # Should create subgroups
        assert admin_mock.create_subgroup.call_count == 2


# =============================================================================
# Edge Cases Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_empty_roles_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Empty roles spec should return early without making API calls."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[]),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Implementation returns early when no roles configured
        admin_mock.create_realm_role.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_groups_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Empty groups spec should return early without making API calls."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Implementation returns early when no groups configured
        admin_mock.create_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_none_roles_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """None roles spec should return early without making API calls."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Implementation returns early when roles is None
        admin_mock.create_realm_role.assert_not_called()

    @pytest.mark.asyncio
    async def test_none_groups_spec(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """None groups spec should return early without making API calls."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Implementation returns early when groups is None
        admin_mock.create_group.assert_not_called()

    @pytest.mark.asyncio
    async def test_role_creation_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle role creation failure gracefully."""
        admin_mock.create_realm_role = AsyncMock(return_value=False)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="failing-role")]),
        )

        # Should not raise, just log warning
        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.create_realm_role.assert_called_once()

    @pytest.mark.asyncio
    async def test_group_creation_failure(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Should handle group creation failure gracefully."""
        admin_mock.create_group = AsyncMock(return_value=None)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="failing-group")],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()


# =============================================================================
# Additional Coverage Tests
# =============================================================================


class TestRoleUpdateCoverage:
    """Additional tests to improve coverage for role operations."""

    @pytest.mark.asyncio
    async def test_role_update_when_exists(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test that existing roles are updated."""
        existing_role = RoleRepresentation(
            name="existing-role",
            description="Old description",
            id="role-id",
        )
        admin_mock.get_realm_roles = AsyncMock(return_value=[existing_role])
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=existing_role)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="existing-role",
                        description="New description",
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.update_realm_role.assert_called_once()

    @pytest.mark.asyncio
    async def test_composite_role_child_not_found(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test handling when composite child role doesn't exist."""
        parent_role = RoleRepresentation(name="parent", id="parent-id")
        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role])
        admin_mock.get_realm_role_by_name = AsyncMock(
            side_effect=lambda realm, name, ns: parent_role
            if name == "parent"
            else None  # Child not found
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="parent",
                        composite_roles=["nonexistent-child"],
                    )
                ]
            ),
        )

        # Should not raise, just log warning about missing child
        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Should still attempt to get the child role
        assert admin_mock.get_realm_role_by_name.call_count >= 1


class TestGroupUpdateCoverage:
    """Additional tests to improve coverage for group operations."""

    @pytest.mark.asyncio
    async def test_group_update_path(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test that existing groups trigger update path."""
        existing_group = GroupRepresentation(
            id="group-id",
            name="existing-group",
            path="/existing-group",
        )
        admin_mock.get_groups = AsyncMock(return_value=[existing_group])
        admin_mock.get_group_by_path = AsyncMock(return_value=existing_group)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="existing-group",
                    attributes={"updated": ["yes"]},
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.update_group.assert_called()

    @pytest.mark.asyncio
    async def test_group_role_not_found(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test handling when group's realm role doesn't exist."""
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="new-group-id")
        admin_mock.get_realm_role_by_name = AsyncMock(
            return_value=None
        )  # Role not found

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="new-group",
                    realm_roles=["nonexistent-role"],
                )
            ],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_group_creation_conflict_recovery(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test that conflict (409) on group creation is handled."""
        # First call returns None (simulating 409 conflict handling)
        admin_mock.get_group_by_path = AsyncMock(
            side_effect=[
                None,  # First check - doesn't exist
                GroupRepresentation(
                    id="recovered-id", name="conflict-group", path="/conflict-group"
                ),  # Recovery lookup
            ]
        )
        admin_mock.create_group = AsyncMock(return_value=None)  # Conflict returns None

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="conflict-group")],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should attempt recovery lookup
        assert admin_mock.get_group_by_path.call_count >= 1


class TestDefaultGroupCoverage:
    """Additional tests for default group operations."""

    @pytest.mark.asyncio
    async def test_default_group_add_and_remove(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test adding and removing default groups in same operation."""
        old_default = GroupRepresentation(
            id="old-id", name="old-default", path="/old-default"
        )
        new_group = GroupRepresentation(
            id="new-id", name="new-default", path="/new-default"
        )

        admin_mock.get_default_groups = AsyncMock(return_value=[old_default])
        admin_mock.get_group_by_path = AsyncMock(return_value=new_group)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/new-default"],
        )

        await reconciler.configure_default_groups(spec, "test-realm", "default")

        admin_mock.add_default_group.assert_called_once()
        admin_mock.remove_default_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_default_group_without_leading_slash(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test default group path normalization (adds leading slash)."""
        group = GroupRepresentation(id="group-id", name="users", path="/users")
        admin_mock.get_default_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=group)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["users"],  # Without leading slash
        )

        await reconciler.configure_default_groups(spec, "test-realm", "default")

        # Should normalize to /users
        admin_mock.get_group_by_path.assert_called_with(
            "test-realm", "/users", "default"
        )


class TestClientRoleMappings:
    """Tests for client role mappings on groups."""

    @pytest.mark.asyncio
    async def test_group_with_client_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test group with client role mappings."""
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="group-id")
        admin_mock.get_client_by_name = AsyncMock(
            return_value=MagicMock(id="client-uuid")
        )
        admin_mock.get_client_role = AsyncMock(
            return_value=RoleRepresentation(name="client-role", id="role-id")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="test-group",
                    client_roles={"my-client": ["client-role"]},
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()


# =============================================================================
# Exception Path Coverage Tests
# =============================================================================


class TestExceptionCoverage:
    """Tests to cover exception handling paths."""

    @pytest.mark.asyncio
    async def test_delete_realm_role_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when deleting a realm role fails."""
        existing_roles = [
            RoleRepresentation(name="custom-role-to-delete", id="role-id"),
        ]
        admin_mock.get_realm_roles = AsyncMock(return_value=existing_roles)
        admin_mock.delete_realm_role = AsyncMock(side_effect=Exception("Delete failed"))

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="other-role")]),
        )

        # Should not raise, just log warning
        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.delete_realm_role.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_role_configuration_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when role configuration fails."""
        admin_mock.get_realm_roles = AsyncMock(return_value=[])
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=None)
        admin_mock.create_realm_role = AsyncMock(side_effect=Exception("Create failed"))

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(realm_roles=[KeycloakRealmRole(name="new-role")]),
        )

        # Should not raise, just log warning
        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        admin_mock.create_realm_role.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_composite_role_configuration_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when composite role configuration fails."""
        parent_role = RoleRepresentation(name="parent", id="parent-id")
        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role])
        admin_mock.get_realm_role_by_name = AsyncMock(return_value=parent_role)
        admin_mock.get_realm_role_composites = AsyncMock(
            side_effect=Exception("Failed to get composites")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="parent",
                        composite_roles=["child"],
                    )
                ]
            ),
        )

        # Should not raise, just log warning
        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_group_configuration_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when group configuration fails."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(
            side_effect=Exception("Create group failed")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="new-group")],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.create_group.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_delete_group_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when deleting a group fails."""
        existing_groups = [
            GroupRepresentation(id="group-id", name="old-group", path="/old-group"),
        ]
        admin_mock.get_groups = AsyncMock(return_value=existing_groups)
        admin_mock.delete_group = AsyncMock(side_effect=Exception("Delete failed"))

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[KeycloakGroup(name="other-group")],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.delete_group.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_group_realm_roles_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when configuring group realm roles fails."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="group-id")
        admin_mock.get_group_realm_role_mappings = AsyncMock(
            side_effect=Exception("Failed to get role mappings")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="test-group",
                    realm_roles=["admin"],
                )
            ],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_client_not_found_for_group_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test handling when client is not found for group client roles."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="group-id")
        admin_mock.get_client_uuid = AsyncMock(return_value=None)  # Client not found

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="test-group",
                    client_roles={"nonexistent-client": ["role"]},
                )
            ],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        admin_mock.get_client_uuid.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_client_role_assignment_with_existing_roles(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test client role assignment when some roles already exist."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="group-id")
        admin_mock.get_client_uuid = AsyncMock(return_value="client-uuid")
        admin_mock.get_group_client_role_mappings = AsyncMock(
            return_value=[RoleRepresentation(name="existing-role", id="existing-id")]
        )
        admin_mock.get_client_role = AsyncMock(
            return_value=RoleRepresentation(name="new-role", id="new-id")
        )
        admin_mock.assign_client_roles_to_group = AsyncMock(return_value=True)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="test-group",
                    client_roles={"my-client": ["existing-role", "new-role"]},
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should only add new-role, not existing-role
        admin_mock.assign_client_roles_to_group.assert_called_once()

    @pytest.mark.asyncio
    async def test_client_role_configuration_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when client role configuration fails."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="group-id")
        admin_mock.get_client_uuid = AsyncMock(return_value="client-uuid")
        admin_mock.get_group_client_role_mappings = AsyncMock(
            side_effect=Exception("Failed to get client role mappings")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="test-group",
                    client_roles={"my-client": ["role"]},
                )
            ],
        )

        # Should not raise, just log warning
        await reconciler.configure_groups(spec, "test-realm", "default")

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_default_group_add_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when adding default group fails."""
        admin_mock.get_default_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(
            return_value=GroupRepresentation(id="group-id", name="users", path="/users")
        )
        admin_mock.add_default_group = AsyncMock(
            side_effect=Exception("Add default failed")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/users"],
        )

        # Should not raise, just log warning
        await reconciler.configure_default_groups(spec, "test-realm", "default")

        admin_mock.add_default_group.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_default_group_remove_exception(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test exception handling when removing default group fails."""
        admin_mock.get_default_groups = AsyncMock(
            return_value=[
                GroupRepresentation(id="old-id", name="old-group", path="/old-group")
            ]
        )
        admin_mock.remove_default_group = AsyncMock(
            side_effect=Exception("Remove default failed")
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/new-group"],  # Different group, so old is removed
        )

        # Need to mock get_group_by_path for the new group
        admin_mock.get_group_by_path = AsyncMock(
            return_value=GroupRepresentation(
                id="new-id", name="new-group", path="/new-group"
            )
        )
        admin_mock.add_default_group = AsyncMock(return_value=True)

        # Should not raise, just log warning
        await reconciler.configure_default_groups(spec, "test-realm", "default")

        admin_mock.remove_default_group.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_default_group_not_found(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test handling when default group to add is not found."""
        admin_mock.get_default_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)  # Group not found

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            default_groups=["/nonexistent-group"],
        )

        # Should not raise, just log warning
        await reconciler.configure_default_groups(spec, "test-realm", "default")

        admin_mock.get_group_by_path.assert_called_once()
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_no_default_groups_early_return(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test early return when no default groups specified."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            # Don't specify default_groups at all - it will use default empty list
        )

        await reconciler.configure_default_groups(spec, "test-realm", "default")

        # Should return early without calling admin client (empty list)
        admin_mock.get_default_groups.assert_not_called()


class TestGroupPathCollectionCoverage:
    """Tests for group path collection helper methods."""

    @pytest.mark.asyncio
    async def test_collect_group_paths_with_nested_groups(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test that nested group paths are collected correctly."""
        admin_mock.get_groups = AsyncMock(return_value=[])
        admin_mock.get_group_by_path = AsyncMock(return_value=None)
        admin_mock.create_group = AsyncMock(return_value="parent-id")
        admin_mock.create_subgroup = AsyncMock(return_value="child-id")

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="parent",
                    subgroups=[
                        KeycloakGroup(
                            name="child",
                            subgroups=[KeycloakGroup(name="grandchild")],
                        )
                    ],
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should create parent, child, and grandchild
        admin_mock.create_group.assert_called_once()
        assert admin_mock.create_subgroup.call_count == 2


class TestGroupMapBuildingCoverage:
    """Tests for group map building helper methods."""

    @pytest.mark.asyncio
    async def test_build_group_map_with_nested_existing_groups(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test that existing nested groups are mapped correctly."""
        child_group = GroupRepresentation(
            id="child-id", name="child", path="/parent/child"
        )
        parent_group = GroupRepresentation(
            id="parent-id",
            name="parent",
            path="/parent",
            sub_groups=[child_group],
        )
        admin_mock.get_groups = AsyncMock(return_value=[parent_group])
        # Mock get_group_by_path to return existing groups
        admin_mock.get_group_by_path = AsyncMock(
            side_effect=lambda realm, path, ns: parent_group
            if path == "/parent"
            else child_group
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            groups=[
                KeycloakGroup(
                    name="parent",
                    subgroups=[KeycloakGroup(name="child")],
                )
            ],
        )

        await reconciler.configure_groups(spec, "test-realm", "default")

        # Should update existing groups, not create new ones
        admin_mock.update_group.assert_called()


class TestCompositeRoleCoverage:
    """Additional tests for composite role edge cases."""

    @pytest.mark.asyncio
    async def test_remove_composite_roles_none_to_remove(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test when there are no composite roles to remove."""
        parent_role = RoleRepresentation(name="parent", id="parent-id", composite=True)
        child_role = RoleRepresentation(name="child", id="child-id")

        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role, child_role])
        admin_mock.get_realm_role_by_name = AsyncMock(
            side_effect=lambda realm, name, ns: parent_role
            if name == "parent"
            else child_role
        )
        admin_mock.get_realm_role_composites = AsyncMock(
            return_value=[child_role]  # Current composites match desired
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="parent",
                        composite_roles=["child"],  # Same as current
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Should not try to remove any composites
        admin_mock.remove_realm_role_composites.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_composite_roles_none_to_add(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Test when there are no composite roles to add (all exist)."""
        parent_role = RoleRepresentation(name="parent", id="parent-id", composite=True)
        child_role = RoleRepresentation(name="child", id="child-id")

        admin_mock.get_realm_roles = AsyncMock(return_value=[parent_role, child_role])
        admin_mock.get_realm_role_by_name = AsyncMock(
            side_effect=lambda realm, name, ns: parent_role
            if name == "parent"
            else child_role
        )
        admin_mock.get_realm_role_composites = AsyncMock(
            return_value=[child_role]  # Already has child
        )

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            roles=KeycloakRoles(
                realm_roles=[
                    KeycloakRealmRole(
                        name="parent",
                        composite_roles=["child"],
                    )
                ]
            ),
        )

        await reconciler.configure_realm_roles(spec, "test-realm", "default")

        # Should not try to add any composites (already there)
        admin_mock.add_realm_role_composites.assert_not_called()


# =============================================================================
# do_update Method Tests for Roles/Groups Changes
# =============================================================================


class TestDoUpdateRolesGroups:
    """Tests for do_update method handling role and group changes."""

    @pytest.fixture
    def mock_status(self) -> MagicMock:
        """Create a mock status object."""
        status = MagicMock()
        status.phase = "Ready"
        status.message = ""
        return status

    @pytest.mark.asyncio
    async def test_do_update_handles_roles_change(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles roles changes."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "roles": {"realmRoles": []},
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "roles": {"realmRoles": [{"name": "new-role"}]},
        }
        diff = [("change", ("spec", "roles", "realmRoles"), [], [{"name": "new-role"}])]

        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        assert result is not None
        assert result["phase"] == "Ready"
        admin_mock.get_realm_roles.assert_called()

    @pytest.mark.asyncio
    async def test_do_update_handles_groups_change(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles groups changes."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "groups": [],
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "groups": [{"name": "new-group"}],
        }
        diff = [("change", ("spec", "groups"), [], [{"name": "new-group"}])]

        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        assert result is not None
        assert result["phase"] == "Ready"
        admin_mock.get_groups.assert_called()

    @pytest.mark.asyncio
    async def test_do_update_handles_default_groups_change(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles default groups changes."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "defaultGroups": [],
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "defaultGroups": ["/users"],
        }
        diff = [("change", ("spec", "defaultGroups"), [], ["/users"])]

        admin_mock.get_group_by_path = AsyncMock(
            return_value=GroupRepresentation(id="group-id", name="users", path="/users")
        )

        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        assert result is not None
        assert result["phase"] == "Ready"
        admin_mock.get_default_groups.assert_called()

    @pytest.mark.asyncio
    async def test_do_update_roles_exception_handled(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles exceptions in roles configuration."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "roles": {"realmRoles": []},
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "roles": {"realmRoles": [{"name": "new-role"}]},
        }
        diff = [
            ("change", ("spec", "roles"), [], {"realmRoles": [{"name": "new-role"}]})
        ]

        admin_mock.get_realm_roles = AsyncMock(side_effect=Exception("API error"))

        # Should not raise, just log warning
        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        # Exception caught, no changes made, returns None
        assert result is None
        # Verify warning was logged
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_do_update_groups_exception_handled(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles exceptions in groups configuration."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "groups": [],
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "groups": [{"name": "new-group"}],
        }
        diff = [("change", ("spec", "groups"), [], [{"name": "new-group"}])]

        admin_mock.get_groups = AsyncMock(side_effect=Exception("API error"))

        # Should not raise, just log warning
        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        # Exception caught, no changes made, returns None
        assert result is None
        # Verify warning was logged
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_do_update_default_groups_exception_handled(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update handles exceptions in default groups configuration."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "defaultGroups": [],
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
            "defaultGroups": ["/users"],
        }
        diff = [("change", ("spec", "defaultGroups"), [], ["/users"])]

        admin_mock.get_default_groups = AsyncMock(side_effect=Exception("API error"))

        # Should not raise, just log warning
        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        # Exception caught, no changes made, returns None
        assert result is None
        # Verify warning was logged
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_do_update_no_changes(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
        mock_status: MagicMock,
    ) -> None:
        """Test do_update returns None when no relevant changes."""
        old_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
        }
        new_spec = {
            "operatorRef": {"namespace": "keycloak-system"},
            "realmName": "test-realm",
        }
        # Empty diff - no changes
        diff = []

        result = await reconciler.do_update(
            old_spec, new_spec, diff, "test-realm", "default", mock_status
        )

        # No changes, returns None
        assert result is None
