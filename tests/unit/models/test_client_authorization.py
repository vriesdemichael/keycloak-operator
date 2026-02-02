"""Unit tests for client authorization models."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.client import (
    AggregatePolicy,
    AuthorizationPermissions,
    AuthorizationResource,
    AuthorizationScope,
    AuthorizationSettings,
    ClientPolicy,
    GroupPolicy,
    RegexPolicy,
    ResourcePermission,
    RolePolicy,
    RolePolicyRole,
    ScopePermission,
    TimePolicy,
    UserPolicy,
)


class TestAuthorizationScope:
    """Tests for AuthorizationScope model."""

    def test_valid_scope(self):
        """Should create scope with valid name."""
        scope = AuthorizationScope(name="read")
        assert scope.name == "read"

    def test_scope_with_display_name(self):
        """Should create scope with display name and icon."""
        scope = AuthorizationScope(
            name="read",
            displayName="Read Access",
            iconUri="https://example.com/icon.png",
        )
        assert scope.name == "read"
        assert scope.display_name == "Read Access"
        assert scope.icon_uri == "https://example.com/icon.png"

    def test_empty_name_allowed(self):
        """AuthorizationScope does not validate empty names (Keycloak handles this)."""
        # AuthorizationScope doesn't validate names - Keycloak server will reject invalid ones
        scope = AuthorizationScope(name="")
        assert scope.name == ""


class TestAuthorizationResource:
    """Tests for AuthorizationResource model."""

    def test_valid_resource(self):
        """Should create resource with valid name."""
        resource = AuthorizationResource(name="documents")
        assert resource.name == "documents"

    def test_resource_with_all_fields(self):
        """Should create resource with all optional fields."""
        resource = AuthorizationResource(
            name="documents",
            displayName="Documents API",
            type="urn:resource:documents",
            uris=["/api/documents/*"],
            icon_uri="https://example.com/doc.png",
            scopes=["read", "write"],
            owner_managed_access=True,
            attributes={"category": ["api"]},
        )
        assert resource.name == "documents"
        assert resource.display_name == "Documents API"
        assert resource.type == "urn:resource:documents"
        assert resource.uris == ["/api/documents/*"]
        assert resource.scopes == ["read", "write"]
        assert resource.owner_managed_access is True
        assert resource.attributes == {"category": ["api"]}

    def test_empty_name_raises_error(self):
        """Should raise error for empty name."""
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationResource(name="")
        assert "cannot be empty" in str(exc_info.value)

    def test_whitespace_name_raises_error(self):
        """Should raise error for whitespace-only name."""
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationResource(name="   ")
        assert "cannot be empty" in str(exc_info.value)


class TestAuthorizationSettings:
    """Tests for AuthorizationSettings model."""

    def test_default_values(self):
        """Should have correct default values."""
        settings = AuthorizationSettings()
        assert settings.policy_enforcement_mode == "ENFORCING"
        assert settings.decision_strategy == "UNANIMOUS"
        assert settings.allow_remote_resource_management is True
        assert settings.scopes == []
        assert settings.resources == []
        assert settings.policies is None
        assert settings.permissions is None

    def test_valid_enforcement_modes(self):
        """Should accept all valid enforcement modes."""
        for mode in ["ENFORCING", "PERMISSIVE", "DISABLED"]:
            settings = AuthorizationSettings(policyEnforcementMode=mode)
            assert settings.policy_enforcement_mode == mode

    def test_enforcement_mode_case_insensitive(self):
        """Should normalize enforcement mode to uppercase."""
        settings = AuthorizationSettings(policyEnforcementMode="enforcing")
        assert settings.policy_enforcement_mode == "ENFORCING"

    def test_invalid_enforcement_mode_raises_error(self):
        """Should raise error for invalid enforcement mode."""
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationSettings(policyEnforcementMode="INVALID")
        assert "Policy enforcement mode must be one of" in str(exc_info.value)

    def test_valid_decision_strategies(self):
        """Should accept all valid decision strategies."""
        for strategy in ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]:
            settings = AuthorizationSettings(decisionStrategy=strategy)
            assert settings.decision_strategy == strategy

    def test_decision_strategy_case_insensitive(self):
        """Should normalize decision strategy to uppercase."""
        settings = AuthorizationSettings(decisionStrategy="unanimous")
        assert settings.decision_strategy == "UNANIMOUS"

    def test_invalid_decision_strategy_raises_error(self):
        """Should raise error for invalid decision strategy."""
        with pytest.raises(ValidationError) as exc_info:
            AuthorizationSettings(decisionStrategy="INVALID")
        assert "Decision strategy must be one of" in str(exc_info.value)


class TestRolePolicy:
    """Tests for RolePolicy model."""

    def test_valid_role_policy(self):
        """Should create valid role policy."""
        policy = RolePolicy(
            name="admin-policy",
            roles=[RolePolicyRole(name="admin", required=True)],
        )
        assert policy.name == "admin-policy"
        assert len(policy.roles) == 1
        assert policy.roles[0].name == "admin"
        assert policy.roles[0].required is True

    def test_default_logic(self):
        """Should default to POSITIVE logic."""
        policy = RolePolicy(name="test", roles=[])
        assert policy.logic == "POSITIVE"

    def test_valid_logic_values(self):
        """Should accept valid logic values."""
        for logic in ["POSITIVE", "NEGATIVE"]:
            policy = RolePolicy(name="test", logic=logic, roles=[])
            assert policy.logic == logic

    def test_logic_case_insensitive(self):
        """Should normalize logic to uppercase."""
        policy = RolePolicy(name="test", logic="positive", roles=[])
        assert policy.logic == "POSITIVE"

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            RolePolicy(name="test", logic="INVALID", roles=[])
        assert "Logic must be one of" in str(exc_info.value)

    def test_role_policy_role_with_required(self):
        """Should support required flag on roles."""
        role = RolePolicyRole(name="manager", required=True)
        assert role.name == "manager"
        assert role.required is True

    def test_role_policy_role_default_required(self):
        """Should default required to False."""
        role = RolePolicyRole(name="viewer")
        assert role.name == "viewer"
        assert role.required is False


class TestClientPolicy:
    """Tests for ClientPolicy model."""

    def test_valid_client_policy(self):
        """Should create valid client policy."""
        policy = ClientPolicy(name="client-policy", clients=["client-a", "client-b"])
        assert policy.name == "client-policy"
        assert policy.clients == ["client-a", "client-b"]

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            ClientPolicy(name="test", logic="INVALID", clients=[])
        assert "Logic must be one of" in str(exc_info.value)


class TestUserPolicy:
    """Tests for UserPolicy model."""

    def test_valid_user_policy(self):
        """Should create valid user policy."""
        policy = UserPolicy(name="user-policy", users=["user1", "user2"])
        assert policy.name == "user-policy"
        assert policy.users == ["user1", "user2"]

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            UserPolicy(name="test", logic="INVALID", users=[])
        assert "Logic must be one of" in str(exc_info.value)


class TestGroupPolicy:
    """Tests for GroupPolicy model."""

    def test_valid_group_policy(self):
        """Should create valid group policy."""
        policy = GroupPolicy(name="group-policy", groups=["admins", "users"])
        assert policy.name == "group-policy"
        assert policy.groups == ["admins", "users"]

    def test_groups_claim(self):
        """Should support groups claim configuration."""
        policy = GroupPolicy(
            name="group-policy", groups=["admins"], groups_claim="groups"
        )
        assert policy.groups_claim == "groups"

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            GroupPolicy(name="test", logic="INVALID", groups=[])
        assert "Logic must be one of" in str(exc_info.value)


class TestTimePolicy:
    """Tests for TimePolicy model."""

    def test_valid_time_policy(self):
        """Should create valid time policy with time range."""
        policy = TimePolicy(
            name="business-hours",
            not_before="09:00",
            not_on_or_after="17:00",
        )
        assert policy.name == "business-hours"
        assert policy.not_before == "09:00"
        assert policy.not_on_or_after == "17:00"

    def test_time_policy_with_dates(self):
        """Should support date-based restrictions."""
        policy = TimePolicy(
            name="date-range",
            day_month=1,
            day_month_end=31,
            month=1,
            month_end=12,
            year=2024,
            year_end=2025,
        )
        assert policy.day_month == 1
        assert policy.year == 2024

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            TimePolicy(name="test", logic="INVALID")
        assert "Logic must be one of" in str(exc_info.value)


class TestRegexPolicy:
    """Tests for RegexPolicy model."""

    def test_valid_regex_policy(self):
        """Should create valid regex policy."""
        policy = RegexPolicy(
            name="email-domain",
            target_claim="email",
            pattern=".*@example\\.com$",
        )
        assert policy.name == "email-domain"
        assert policy.target_claim == "email"
        assert policy.pattern == ".*@example\\.com$"

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            RegexPolicy(name="test", target_claim="x", pattern="x", logic="INVALID")
        assert "Logic must be one of" in str(exc_info.value)


class TestAggregatePolicy:
    """Tests for AggregatePolicy model."""

    def test_valid_aggregate_policy(self):
        """Should create valid aggregate policy."""
        policy = AggregatePolicy(
            name="combined-policy",
            policies=["policy-a", "policy-b"],
        )
        assert policy.name == "combined-policy"
        assert policy.policies == ["policy-a", "policy-b"]

    def test_valid_decision_strategies(self):
        """Should accept valid decision strategies."""
        for strategy in ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]:
            policy = AggregatePolicy(
                name="test", policies=[], decisionStrategy=strategy
            )
            assert policy.decision_strategy == strategy

    def test_decision_strategy_case_insensitive(self):
        """Should normalize decision strategy to uppercase."""
        policy = AggregatePolicy(
            name="test", policies=[], decisionStrategy="affirmative"
        )
        assert policy.decision_strategy == "AFFIRMATIVE"

    def test_invalid_decision_strategy_raises_error(self):
        """Should raise error for invalid decision strategy."""
        with pytest.raises(ValidationError) as exc_info:
            AggregatePolicy(name="test", policies=[], decisionStrategy="INVALID")
        assert "Decision strategy must be one of" in str(exc_info.value)

    def test_invalid_logic_raises_error(self):
        """Should raise error for invalid logic."""
        with pytest.raises(ValidationError) as exc_info:
            AggregatePolicy(name="test", policies=[], logic="INVALID")
        assert "Logic must be one of" in str(exc_info.value)


class TestResourcePermission:
    """Tests for ResourcePermission model."""

    def test_valid_resource_permission(self):
        """Should create valid resource permission."""
        permission = ResourcePermission(
            name="doc-access",
            resources=["documents"],
            policies=["admin-policy"],
        )
        assert permission.name == "doc-access"
        assert permission.resources == ["documents"]
        assert permission.policies == ["admin-policy"]

    def test_permission_with_resource_type(self):
        """Should support resource type filtering."""
        permission = ResourcePermission(
            name="doc-read",
            resource_type="urn:documents",
            policies=["reader-policy"],
        )
        assert permission.resource_type == "urn:documents"

    def test_valid_decision_strategies(self):
        """Should accept valid decision strategies."""
        for strategy in ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]:
            permission = ResourcePermission(
                name="test",
                resources=[],
                policies=[],
                decisionStrategy=strategy,
            )
            assert permission.decision_strategy == strategy

    def test_invalid_decision_strategy_raises_error(self):
        """Should raise error for invalid decision strategy."""
        with pytest.raises(ValidationError) as exc_info:
            ResourcePermission(
                name="test",
                resources=[],
                policies=[],
                decisionStrategy="INVALID",
            )
        assert "Decision strategy must be one of" in str(exc_info.value)


class TestScopePermission:
    """Tests for ScopePermission model."""

    def test_valid_scope_permission(self):
        """Should create valid scope permission."""
        permission = ScopePermission(
            name="read-access",
            scopes=["read"],
            policies=["reader-policy"],
        )
        assert permission.name == "read-access"
        assert permission.scopes == ["read"]
        assert permission.policies == ["reader-policy"]

    def test_permission_with_resources(self):
        """Should support resources."""
        permission = ScopePermission(
            name="doc-read",
            scopes=["read"],
            policies=["reader-policy"],
            resources=["documents"],
        )
        assert permission.resources == ["documents"]

    def test_invalid_decision_strategy_raises_error(self):
        """Should raise error for invalid decision strategy."""
        with pytest.raises(ValidationError) as exc_info:
            ScopePermission(
                name="test",
                scopes=[],
                policies=[],
                decisionStrategy="INVALID",
            )
        assert "Decision strategy must be one of" in str(exc_info.value)


class TestAuthorizationPermissions:
    """Tests for AuthorizationPermissions model."""

    def test_empty_permissions(self):
        """Should create empty permissions container."""
        permissions = AuthorizationPermissions()
        assert permissions.resource_permissions == []
        assert permissions.scope_permissions == []

    def test_with_resource_permissions(self):
        """Should hold resource permissions."""
        permissions = AuthorizationPermissions(
            resourcePermissions=[
                ResourcePermission(name="test", resources=["r1"], policies=["p1"])
            ]
        )
        assert len(permissions.resource_permissions) == 1

    def test_with_scope_permissions(self):
        """Should hold scope permissions."""
        permissions = AuthorizationPermissions(
            scopePermissions=[
                ScopePermission(name="test", scopes=["s1"], policies=["p1"])
            ]
        )
        assert len(permissions.scope_permissions) == 1
