"""Unit tests for KeycloakClientReconciler authorization methods."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.models.client import (
    AggregatePolicy,
    AuthorizationPermissions,
    AuthorizationPolicies,
    AuthorizationResource,
    AuthorizationScope,
    ClientPolicy,
    GroupPolicy,
    JavaScriptPolicy,
    RegexPolicy,
    ResourcePermission,
    RolePolicy,
    RolePolicyRole,
    ScopePermission,
    TimePolicy,
    UserPolicy,
)
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client with authorization methods."""
    mock = MagicMock()

    # Authorization scope methods
    mock.get_authorization_scopes = AsyncMock(return_value=[])
    mock.create_authorization_scope = AsyncMock(return_value={"id": "scope-1"})
    mock.update_authorization_scope = AsyncMock(return_value=True)
    mock.delete_authorization_scope = AsyncMock(return_value=True)

    # Authorization resource methods
    mock.get_authorization_resources = AsyncMock(return_value=[])
    mock.create_authorization_resource = AsyncMock(return_value={"_id": "resource-1"})
    mock.update_authorization_resource = AsyncMock(return_value=True)
    mock.delete_authorization_resource = AsyncMock(return_value=True)

    # Authorization policy methods
    mock.get_authorization_policies = AsyncMock(return_value=[])
    mock.create_authorization_policy = AsyncMock(return_value={"id": "policy-1"})
    mock.update_authorization_policy = AsyncMock(return_value=True)
    mock.delete_authorization_policy = AsyncMock(return_value=True)

    # Authorization permission methods
    mock.get_authorization_permissions = AsyncMock(return_value=[])
    mock.create_authorization_permission = AsyncMock(return_value={"id": "perm-1"})
    mock.update_authorization_permission = AsyncMock(return_value=True)
    mock.delete_authorization_permission = AsyncMock(return_value=True)

    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakClientReconciler:
    """KeycloakClientReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace):
        return admin_mock

    reconciler_instance = KeycloakClientReconciler(
        keycloak_admin_factory=mock_factory,
    )
    reconciler_instance.logger = MagicMock()

    return reconciler_instance


class TestReconcileAuthorizationScopes:
    """Tests for _reconcile_authorization_scopes method."""

    @pytest.mark.asyncio
    async def test_creates_new_scope(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New scope should be created when it doesn't exist."""
        desired_scopes = [
            AuthorizationScope(name="read", display_name="Read Access"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        admin_mock.get_authorization_scopes.assert_called_once()
        admin_mock.create_authorization_scope.assert_called_once()
        call_args = admin_mock.create_authorization_scope.call_args
        assert call_args[0][2]["name"] == "read"
        assert call_args[0][2]["displayName"] == "Read Access"

    @pytest.mark.asyncio
    async def test_updates_existing_scope_when_changed(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing scope should be updated when display name changes."""
        admin_mock.get_authorization_scopes.return_value = [
            {"id": "scope-1", "name": "read", "displayName": "Old Name"}
        ]

        desired_scopes = [
            AuthorizationScope(name="read", display_name="New Name"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        admin_mock.update_authorization_scope.assert_called_once()
        admin_mock.create_authorization_scope.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_update_when_scope_unchanged(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing scope should not be updated when unchanged."""
        admin_mock.get_authorization_scopes.return_value = [
            {
                "id": "scope-1",
                "name": "read",
                "displayName": "Read Access",
                "iconUri": None,
            }
        ]

        desired_scopes = [
            AuthorizationScope(name="read", display_name="Read Access"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        admin_mock.update_authorization_scope.assert_not_called()
        admin_mock.create_authorization_scope.assert_not_called()

    @pytest.mark.asyncio
    async def test_deletes_removed_scope(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Scopes not in desired state should be deleted."""
        admin_mock.get_authorization_scopes.return_value = [
            {"id": "scope-1", "name": "read"},
            {"id": "scope-2", "name": "write"},
        ]

        # Only want "read", "write" should be deleted
        desired_scopes = [
            AuthorizationScope(name="read"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        admin_mock.delete_authorization_scope.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_scope_failure_logs_warning(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Failed scope creation should log a warning."""
        admin_mock.create_authorization_scope.return_value = None

        desired_scopes = [
            AuthorizationScope(name="read"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_multiple_scopes_created(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Multiple scopes should all be created."""
        desired_scopes = [
            AuthorizationScope(name="read"),
            AuthorizationScope(name="write"),
            AuthorizationScope(name="delete"),
        ]

        await reconciler._reconcile_authorization_scopes(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_scopes,
            "default",
            "my-client",
        )

        assert admin_mock.create_authorization_scope.call_count == 3


class TestReconcileAuthorizationResources:
    """Tests for _reconcile_authorization_resources method."""

    @pytest.mark.asyncio
    async def test_creates_new_resource(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """New resource should be created when it doesn't exist."""
        admin_mock.get_authorization_scopes.return_value = [
            {"id": "scope-1", "name": "read"}
        ]

        desired_resources = [
            AuthorizationResource(
                name="Document",
                display_name="Document Resource",
                type="urn:my-app:document",
                uris=["/documents/*"],
                scopes=["read"],
            ),
        ]

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        admin_mock.create_authorization_resource.assert_called_once()
        call_args = admin_mock.create_authorization_resource.call_args
        assert call_args[0][2]["name"] == "Document"
        assert call_args[0][2]["scopes"] == [{"id": "scope-1", "name": "read"}]

    @pytest.mark.asyncio
    async def test_updates_existing_resource(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing resource should be updated."""
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"}
        ]
        admin_mock.get_authorization_scopes.return_value = []

        desired_resources = [
            AuthorizationResource(name="Document", display_name="Updated Name"),
        ]

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        admin_mock.update_authorization_resource.assert_called_once()
        admin_mock.create_authorization_resource.assert_not_called()

    @pytest.mark.asyncio
    async def test_deletes_removed_resource(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Resources not in desired state should be deleted."""
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"},
            {"_id": "resource-2", "name": "Image"},
        ]
        admin_mock.get_authorization_scopes.return_value = []

        # Only want "Document", "Image" should be deleted
        desired_resources = [
            AuthorizationResource(name="Document"),
        ]

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        admin_mock.delete_authorization_resource.assert_called_once()

    @pytest.mark.asyncio
    async def test_preserves_default_resource(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Default Resource should not be deleted."""
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Default Resource"},
        ]
        admin_mock.get_authorization_scopes.return_value = []

        # Empty desired resources - but Default Resource should be kept
        desired_resources = []

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        admin_mock.delete_authorization_resource.assert_not_called()

    @pytest.mark.asyncio
    async def test_warns_on_missing_scope(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Warning should be logged when referenced scope doesn't exist."""
        admin_mock.get_authorization_scopes.return_value = []  # No scopes exist

        desired_resources = [
            AuthorizationResource(name="Document", scopes=["nonexistent-scope"]),
        ]

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_create_resource_failure_logs_warning(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Failed resource creation should log a warning."""
        admin_mock.create_authorization_resource.return_value = None
        admin_mock.get_authorization_scopes.return_value = []

        desired_resources = [
            AuthorizationResource(name="Document"),
        ]

        await reconciler._reconcile_authorization_resources(
            admin_mock,
            "test-realm",
            "client-uuid",
            desired_resources,
            "default",
            "my-client",
        )

        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]


class TestReconcileAuthorizationPolicies:
    """Tests for _reconcile_authorization_policies method."""

    @pytest.mark.asyncio
    async def test_creates_role_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Role policy should be created."""
        policies = AuthorizationPolicies(
            role_policies=[
                RolePolicy(
                    name="admin-policy",
                    description="Requires admin role",
                    roles=[RolePolicyRole(name="admin")],
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        call_args = admin_mock.create_authorization_policy.call_args
        assert call_args[0][2] == "role"  # policy type

    @pytest.mark.asyncio
    async def test_creates_user_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """User policy should be created."""
        policies = AuthorizationPolicies(
            user_policies=[
                UserPolicy(
                    name="specific-users",
                    users=["alice", "bob"],
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        call_args = admin_mock.create_authorization_policy.call_args
        assert call_args[0][2] == "user"

    @pytest.mark.asyncio
    async def test_creates_group_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Group policy should be created."""
        policies = AuthorizationPolicies(
            group_policies=[
                GroupPolicy(
                    name="admin-group-policy",
                    groups=["/admins", "/superusers"],
                    groups_claim="groups",
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()

    @pytest.mark.asyncio
    async def test_creates_client_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Client policy should be created."""
        policies = AuthorizationPolicies(
            client_policies=[
                ClientPolicy(
                    name="trusted-clients",
                    clients=["client-a", "client-b"],
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        call_args = admin_mock.create_authorization_policy.call_args
        assert call_args[0][2] == "client"

    @pytest.mark.asyncio
    async def test_creates_time_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Time policy should be created with all time fields."""
        policies = AuthorizationPolicies(
            time_policies=[
                TimePolicy(
                    name="business-hours",
                    not_before="2024-01-01T00:00:00Z",
                    not_on_or_after="2025-12-31T23:59:59Z",
                    day_month=1,
                    day_month_end=31,
                    month=1,
                    month_end=12,
                    year=2024,
                    year_end=2025,
                    hour=9,
                    hour_end=17,
                    minute=0,
                    minute_end=59,
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        call_args = admin_mock.create_authorization_policy.call_args
        assert call_args[0][2] == "time"

    @pytest.mark.asyncio
    async def test_creates_regex_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Regex policy should be created."""
        policies = AuthorizationPolicies(
            regex_policies=[
                RegexPolicy(
                    name="email-pattern",
                    target_claim="email",
                    pattern=".*@example\\.com$",
                )
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        call_args = admin_mock.create_authorization_policy.call_args
        assert call_args[0][2] == "regex"

    @pytest.mark.asyncio
    async def test_creates_aggregate_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Aggregate policy should be created after other policies."""
        # First, the existing policies (after creating role policy)
        admin_mock.get_authorization_policies.side_effect = [
            [],  # First call - no existing policies
            [{"id": "policy-1", "name": "admin-policy"}],  # After role policy created
        ]

        policies = AuthorizationPolicies(
            role_policies=[
                RolePolicy(name="admin-policy", roles=[RolePolicyRole(name="admin")])
            ],
            aggregate_policies=[
                AggregatePolicy(
                    name="combined-policy",
                    decision_strategy="UNANIMOUS",
                    policies=["admin-policy"],  # Reference the role policy
                )
            ],
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        # Should have created 2 policies: role and aggregate
        assert admin_mock.create_authorization_policy.call_count == 2

    @pytest.mark.asyncio
    async def test_javascript_policy_blocked_by_default(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """JavaScript policies should be blocked when not explicitly allowed."""
        policies = AuthorizationPolicies(
            allow_javascript_policies=False,  # Default
            javascript_policies=[
                JavaScriptPolicy(name="js-policy", code="return true;")
            ],
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        # Policy should NOT be created
        admin_mock.create_authorization_policy.assert_not_called()
        # Should log a warning
        reconciler.logger.warning.assert_called()  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_javascript_policy_created_when_allowed(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """JavaScript policies should be created when explicitly allowed."""
        policies = AuthorizationPolicies(
            allow_javascript_policies=True,
            javascript_policies=[
                JavaScriptPolicy(name="js-policy", code="return true;")
            ],
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.create_authorization_policy.assert_called()
        # Should log a security warning
        assert any(
            "SECURITY WARNING" in str(call)
            for call in reconciler.logger.warning.call_args_list  # type: ignore[union-attr]
        )

    @pytest.mark.asyncio
    async def test_updates_existing_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing policy should be updated."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "admin-policy", "type": "role"}
        ]

        policies = AuthorizationPolicies(
            role_policies=[
                RolePolicy(name="admin-policy", description="Updated", roles=[])
            ]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.update_authorization_policy.assert_called()
        admin_mock.create_authorization_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_deletes_removed_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Policies not in desired state should be deleted."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "keep-policy", "type": "role"},
            {"id": "policy-2", "name": "delete-policy", "type": "user"},
        ]

        policies = AuthorizationPolicies(
            role_policies=[RolePolicy(name="keep-policy", roles=[])]
        )

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.delete_authorization_policy.assert_called()

    @pytest.mark.asyncio
    async def test_preserves_default_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Default Policy should not be deleted."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "Default Policy", "type": "role"},
        ]

        policies = AuthorizationPolicies()  # Empty - but Default Policy should stay

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        admin_mock.delete_authorization_policy.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_permission_types_in_delete(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Permission types (resource, scope) should not be deleted as policies."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "perm-1", "name": "my-resource-perm", "type": "resource"},
            {"id": "perm-2", "name": "my-scope-perm", "type": "scope"},
        ]

        policies = AuthorizationPolicies()

        await reconciler._reconcile_authorization_policies(
            admin_mock, "test-realm", "client-uuid", policies, "default", "my-client"
        )

        # Permissions should not be deleted via policy deletion
        admin_mock.delete_authorization_policy.assert_not_called()


class TestReconcileAuthorizationPermissions:
    """Tests for _reconcile_authorization_permissions method."""

    @pytest.mark.asyncio
    async def test_creates_resource_permission(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Resource permission should be created."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "admin-policy"}
        ]
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"}
        ]
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions(
            resource_permissions=[
                ResourcePermission(
                    name="document-access",
                    resources=["Document"],
                    policies=["admin-policy"],
                )
            ]
        )

        await reconciler._reconcile_authorization_permissions(
            admin_mock, "test-realm", "client-uuid", permissions, "default", "my-client"
        )

        admin_mock.create_authorization_permission.assert_called()

    @pytest.mark.asyncio
    async def test_creates_scope_permission(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Scope permission should be created."""
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "admin-policy"}
        ]
        admin_mock.get_authorization_resources.return_value = []
        admin_mock.get_authorization_scopes.return_value = [
            {"id": "scope-1", "name": "read"}
        ]

        permissions = AuthorizationPermissions(
            scope_permissions=[
                ScopePermission(
                    name="read-permission",
                    scopes=["read"],
                    policies=["admin-policy"],
                )
            ]
        )

        await reconciler._reconcile_authorization_permissions(
            admin_mock, "test-realm", "client-uuid", permissions, "default", "my-client"
        )

        admin_mock.create_authorization_permission.assert_called()

    @pytest.mark.asyncio
    async def test_updates_existing_permission(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Existing permission should be updated."""
        admin_mock.get_authorization_permissions.return_value = [
            {"id": "perm-1", "name": "document-access", "type": "resource"}
        ]
        admin_mock.get_authorization_policies.return_value = [
            {"id": "policy-1", "name": "admin-policy"}
        ]
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"}
        ]
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions(
            resource_permissions=[
                ResourcePermission(
                    name="document-access",
                    resources=["Document"],
                    policies=["admin-policy"],
                )
            ]
        )

        await reconciler._reconcile_authorization_permissions(
            admin_mock, "test-realm", "client-uuid", permissions, "default", "my-client"
        )

        admin_mock.update_authorization_permission.assert_called()
        admin_mock.create_authorization_permission.assert_not_called()

    @pytest.mark.asyncio
    async def test_deletes_removed_permission(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Permissions not in desired state should be deleted."""
        admin_mock.get_authorization_permissions.return_value = [
            {"id": "perm-1", "name": "keep-perm", "type": "resource"},
            {"id": "perm-2", "name": "delete-perm", "type": "resource"},
        ]
        admin_mock.get_authorization_policies.return_value = []
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"}
        ]
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions(
            resource_permissions=[
                ResourcePermission(name="keep-perm", resources=["Document"])
            ]
        )

        await reconciler._reconcile_authorization_permissions(
            admin_mock, "test-realm", "client-uuid", permissions, "default", "my-client"
        )

        admin_mock.delete_authorization_permission.assert_called()

    @pytest.mark.asyncio
    async def test_preserves_default_permission(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Default Permission should not be deleted."""
        admin_mock.get_authorization_permissions.return_value = [
            {"id": "perm-1", "name": "Default Permission", "type": "resource"},
        ]
        admin_mock.get_authorization_policies.return_value = []
        admin_mock.get_authorization_resources.return_value = []
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions()

        await reconciler._reconcile_authorization_permissions(
            admin_mock, "test-realm", "client-uuid", permissions, "default", "my-client"
        )

        admin_mock.delete_authorization_permission.assert_not_called()

    @pytest.mark.asyncio
    async def test_raises_error_on_missing_policy(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Error should be raised when referenced policy doesn't exist."""
        from keycloak_operator.errors import ReconciliationError

        admin_mock.get_authorization_policies.return_value = []  # No policies
        admin_mock.get_authorization_resources.return_value = [
            {"_id": "resource-1", "name": "Document"}
        ]
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions(
            resource_permissions=[
                ResourcePermission(
                    name="document-access",
                    resources=["Document"],
                    policies=["nonexistent-policy"],
                )
            ]
        )

        with pytest.raises(ReconciliationError) as exc_info:
            await reconciler._reconcile_authorization_permissions(
                admin_mock,
                "test-realm",
                "client-uuid",
                permissions,
                "default",
                "my-client",
            )

        assert "nonexistent-policy" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_error_on_missing_resource(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Error should be raised when referenced resource doesn't exist."""
        from keycloak_operator.errors import ReconciliationError

        admin_mock.get_authorization_policies.return_value = []
        admin_mock.get_authorization_resources.return_value = []  # No resources
        admin_mock.get_authorization_scopes.return_value = []

        permissions = AuthorizationPermissions(
            resource_permissions=[
                ResourcePermission(
                    name="document-access",
                    resources=["NonexistentResource"],
                )
            ]
        )

        with pytest.raises(ReconciliationError) as exc_info:
            await reconciler._reconcile_authorization_permissions(
                admin_mock,
                "test-realm",
                "client-uuid",
                permissions,
                "default",
                "my-client",
            )

        assert "NonexistentResource" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_error_on_missing_scope(
        self,
        reconciler: KeycloakClientReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """Error should be raised when referenced scope doesn't exist."""
        from keycloak_operator.errors import ReconciliationError

        admin_mock.get_authorization_policies.return_value = []
        admin_mock.get_authorization_resources.return_value = []
        admin_mock.get_authorization_scopes.return_value = []  # No scopes

        permissions = AuthorizationPermissions(
            scope_permissions=[
                ScopePermission(
                    name="read-permission",
                    scopes=["nonexistent-scope"],
                )
            ]
        )

        with pytest.raises(ReconciliationError) as exc_info:
            await reconciler._reconcile_authorization_permissions(
                admin_mock,
                "test-realm",
                "client-uuid",
                permissions,
                "default",
                "my-client",
            )

        assert "nonexistent-scope" in str(exc_info.value)
