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
    reconciler_instance.logger = MagicMock()

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
