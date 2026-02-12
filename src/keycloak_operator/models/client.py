"""
Pydantic models for KeycloakClient resources.

This module defines type-safe data models for Keycloak client specifications
and status. These models enable dynamic client provisioning across namespaces
with proper validation and GitOps compatibility.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from keycloak_operator.models.types import (
    KeycloakConfigMap,
    KubernetesMetadata,
)


class RealmRef(BaseModel):
    """Reference to a parent KeycloakRealm."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Name of the KeycloakRealm CR")
    namespace: str = Field(..., description="Namespace of the KeycloakRealm CR")


class KeycloakClientSecretRef(BaseModel):
    """
    Reference to an existing Kubernetes secret containing the client secret.

    Used when manually managing the client secret instead of letting the operator
    generate one.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Secret name")
    key: str = Field(..., description="Key in secret data containing the client secret")


class KeycloakClientScope(BaseModel):
    """Configuration for client scopes."""

    name: str = Field(..., description="Scope name")
    default: bool = Field(True, description="Whether this is a default scope")
    optional: bool = Field(False, description="Whether this is an optional scope")


class KeycloakClientProtocolMapper(BaseModel):
    """Configuration for protocol mappers."""

    name: str = Field(..., description="Mapper name")
    protocol: str = Field("openid-connect", description="Protocol type")
    protocol_mapper: str = Field(..., alias="protocolMapper", description="Mapper type")
    config: KeycloakConfigMap = Field(
        default_factory=dict, description="Mapper configuration"
    )

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        valid_protocols = ["openid-connect", "saml", "docker-v2"]
        if v not in valid_protocols:
            raise ValueError(f"Protocol must be one of {valid_protocols}")
        return v


class KeycloakClientAuthenticationFlow(BaseModel):
    """Configuration for client authentication flows."""

    model_config = {"populate_by_name": True}

    browser_flow: str | None = Field(
        None, alias="browserFlow", description="Browser authentication flow"
    )
    direct_grant_flow: str | None = Field(
        None, alias="directGrantFlow", description="Direct grant authentication flow"
    )
    client_authentication_flow: str | None = Field(
        None, alias="clientAuthenticationFlow", description="Client authentication flow"
    )


class KeycloakClientSettings(BaseModel):
    """Advanced client settings."""

    model_config = {"populate_by_name": True}

    # Basic settings
    always_display_in_console: bool = Field(
        False,
        alias="alwaysDisplayInConsole",
        description="Always display in admin console",
    )
    client_authenticator_type: str = Field(
        "client-secret",
        alias="clientAuthenticatorType",
        description="Client authenticator type",
    )

    # Access settings
    standard_flow_enabled: bool = Field(
        True,
        alias="standardFlowEnabled",
        description="Enable standard flow (authorization code flow)",
    )
    implicit_flow_enabled: bool = Field(
        False, alias="implicitFlowEnabled", description="Enable implicit flow"
    )
    direct_access_grants_enabled: bool = Field(
        True,
        alias="directAccessGrantsEnabled",
        description="Enable direct access grants (password flow)",
    )
    service_accounts_enabled: bool = Field(
        False, alias="serviceAccountsEnabled", description="Enable service accounts"
    )

    # Advanced settings
    consent_required: bool = Field(
        False, alias="consentRequired", description="Require user consent"
    )
    display_on_consent_screen: bool = Field(
        True, alias="displayOnConsentScreen", description="Display on consent screen"
    )
    include_in_token_scope: bool = Field(
        True, alias="includeInTokenScope", description="Include in token scope"
    )
    frontchannel_logout: bool = Field(
        True, alias="frontchannelLogout", description="Enable front-channel logout"
    )
    full_scope_allowed: bool = Field(
        True,
        alias="fullScopeAllowed",
        description="Allow full scope for role mappings",
    )
    authorization_services_enabled: bool = Field(
        False,
        alias="authorizationServicesEnabled",
        description="Enable fine-grained authorization support",
    )

    # Token settings
    access_token_lifespan: int | None = Field(
        None,
        alias="accessTokenLifespan",
        description="Access token lifespan in seconds",
    )
    refresh_token_lifespan: int | None = Field(
        None,
        alias="refreshTokenLifespan",
        description="Refresh token lifespan in seconds",
    )

    # Session settings
    client_session_idle_timeout: int | None = Field(
        None,
        alias="clientSessionIdleTimeout",
        description="Client session idle timeout in seconds",
    )
    client_session_max_lifespan: int | None = Field(
        None,
        alias="clientSessionMaxLifespan",
        description="Client session max lifespan in seconds",
    )

    # PKCE settings
    pkce_code_challenge_method: str | None = Field(
        None,
        alias="pkceCodeChallengeMethod",
        description="PKCE code challenge method (S256 or plain)",
    )

    @field_validator("pkce_code_challenge_method")
    @classmethod
    def validate_pkce_method(cls, v):
        if v and v not in ["S256", "plain"]:
            raise ValueError(
                "PKCE code challenge method must be 'S256', 'plain', or empty"
            )
        return v or None

    @field_validator("client_authenticator_type")
    @classmethod
    def validate_authenticator_type(cls, v):
        valid_types = [
            "client-secret",
            "client-jwt",
            "client-secret-jwt",
            "client-x509",
        ]
        if v not in valid_types:
            raise ValueError(f"Client authenticator type must be one of {valid_types}")
        return v


class ServiceAccountRoles(BaseModel):
    """Role mappings for service account users."""

    model_config = {"populate_by_name": True}

    realm_roles: list[str] = Field(
        default_factory=list,
        alias="realmRoles",
        description="Realm-level roles to assign to the service account",
    )
    client_roles: dict[str, list[str]] = Field(
        default_factory=dict,
        alias="clientRoles",
        description=(
            "Client-level roles to assign to the service account (client_id -> role names)"
        ),
    )


class SecretMetadata(BaseModel):
    """Metadata to be added to the managed secret."""

    model_config = {"populate_by_name": True}

    labels: dict[str, str] = Field(
        default_factory=dict, description="Labels to add to the secret."
    )
    annotations: dict[str, str] = Field(
        default_factory=dict, description="Annotations to add to the secret."
    )


class SecretRotationConfig(BaseModel):
    """Configuration for automated client secret rotation."""

    model_config = {"populate_by_name": True}

    enabled: bool = Field(False, description="Enable automated secret rotation")
    rotation_period: str = Field(
        "90d",
        alias="rotationPeriod",
        description="Rotation period (e.g., '90d', '24h', '10s'). Supported units: s, m, h, d.",
    )
    rotation_time: str | None = Field(
        None,
        alias="rotationTime",
        description="Target time for rotation in 'HH:MM' format. If set, rotation waits for this time.",
    )
    timezone: str = Field(
        "UTC",
        description="IANA Timezone for rotation scheduling (e.g., 'America/New_York', 'UTC').",
    )

    @field_validator("rotation_time", mode="before")
    @classmethod
    def validate_rotation_time(cls, v: str | None) -> str | None:
        """Validate rotation_time is in HH:MM format with valid hour/minute values."""
        if v is None:
            return v

        if not isinstance(v, str):
            raise ValueError("rotation_time must be a string in 'HH:MM' format")

        parts = v.split(":")
        if len(parts) != 2:
            raise ValueError(
                f"Invalid rotation_time format '{v}'. Expected 'HH:MM' format."
            )

        try:
            hour = int(parts[0])
            minute = int(parts[1])
        except ValueError as e:
            raise ValueError(
                f"Invalid rotation_time format '{v}'. Hour and minute must be integers."
            ) from e

        if not (0 <= hour <= 23):
            raise ValueError(
                f"Invalid hour '{hour}' in rotation_time '{v}'. Hour must be 0-23."
            )
        if not (0 <= minute <= 59):
            raise ValueError(
                f"Invalid minute '{minute}' in rotation_time '{v}'. Minute must be 0-59."
            )

        return v


# =============================================================================
# Authorization Settings Models
# =============================================================================


class AuthorizationScope(BaseModel):
    """
    Authorization scope definition.

    Scopes define the actions that can be performed on resources
    (e.g., 'read', 'write', 'delete').
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Scope name (e.g., 'read', 'write')")
    display_name: str | None = Field(
        None, alias="displayName", description="Human-readable display name"
    )
    icon_uri: str | None = Field(
        None, alias="iconUri", description="Icon URI for UI display"
    )


class AuthorizationResource(BaseModel):
    """
    Protected resource definition.

    Resources represent the objects being protected by authorization policies
    (e.g., APIs, documents, users).
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Resource name (unique identifier)")
    display_name: str | None = Field(
        None, alias="displayName", description="Human-readable display name"
    )
    type: str | None = Field(
        None,
        description="Resource type for grouping (e.g., 'urn:my-api:resources:documents')",
    )
    uris: list[str] = Field(
        default_factory=list, description="URIs associated with this resource"
    )
    scopes: list[str] = Field(
        default_factory=list, description="Scope names that apply to this resource"
    )
    owner_managed_access: bool = Field(
        False,
        alias="ownerManagedAccess",
        description="Enable owner-managed access for this resource",
    )
    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Resource attributes"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Resource name cannot be empty")
        return v


class AuthorizationSettings(BaseModel):
    """
    Authorization services settings for a client.

    Contains the resource server configuration including enforcement mode,
    decision strategy, scopes, and resources.
    """

    model_config = {"populate_by_name": True}

    policy_enforcement_mode: str = Field(
        "ENFORCING",
        alias="policyEnforcementMode",
        description="Policy enforcement mode: ENFORCING, PERMISSIVE, or DISABLED",
    )
    decision_strategy: str = Field(
        "UNANIMOUS",
        alias="decisionStrategy",
        description="Decision strategy: UNANIMOUS, AFFIRMATIVE, or CONSENSUS",
    )
    allow_remote_resource_management: bool = Field(
        True,
        alias="allowRemoteResourceManagement",
        description="Allow remote resource management via Protection API",
    )
    scopes: list[AuthorizationScope] = Field(
        default_factory=list, description="Authorization scopes"
    )
    resources: list[AuthorizationResource] = Field(
        default_factory=list, description="Protected resources"
    )
    policies: "AuthorizationPolicies | None" = Field(
        None, description="Authorization policies"
    )
    permissions: "AuthorizationPermissions | None" = Field(
        None, description="Authorization permissions (tie policies to resources/scopes)"
    )

    @field_validator("policy_enforcement_mode")
    @classmethod
    def validate_enforcement_mode(cls, v: str) -> str:
        valid_modes = ["ENFORCING", "PERMISSIVE", "DISABLED"]
        if v.upper() not in valid_modes:
            raise ValueError(f"Policy enforcement mode must be one of {valid_modes}")
        return v.upper()

    @field_validator("decision_strategy")
    @classmethod
    def validate_decision_strategy(cls, v: str) -> str:
        valid_strategies = ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]
        if v.upper() not in valid_strategies:
            raise ValueError(f"Decision strategy must be one of {valid_strategies}")
        return v.upper()


# =============================================================================
# Authorization Policy Models
# =============================================================================


class RolePolicyRole(BaseModel):
    """A role reference for role-based policies."""

    model_config = {"populate_by_name": True}

    id: str | None = Field(
        None, description="Role ID (resolved at reconciliation time)"
    )
    name: str = Field(..., description="Role name")
    required: bool = Field(False, description="Whether this role is required")


class RolePolicy(BaseModel):
    """
    Role-based authorization policy.

    Grants access based on realm or client role assignments.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    roles: list[RolePolicyRole] = Field(
        default_factory=list, description="List of roles that grant access"
    )
    fetch_roles: bool = Field(
        True,
        alias="fetchRoles",
        description="Whether to fetch roles from userinfo endpoint",
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class UserPolicy(BaseModel):
    """
    User-based authorization policy.

    Grants access to specific users by username.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    users: list[str] = Field(
        default_factory=list, description="List of usernames that are granted access"
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class GroupPolicy(BaseModel):
    """
    Group-based authorization policy.

    Grants access based on group membership.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    groups: list[str] = Field(
        default_factory=list,
        description="List of group paths (e.g., '/admin', '/org/team')",
    )
    groups_claim: str = Field(
        "groups",
        alias="groupsClaim",
        description="Name of the claim containing group information",
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class ClientPolicy(BaseModel):
    """
    Client-based authorization policy.

    Grants access to specific OAuth2 clients.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    clients: list[str] = Field(
        default_factory=list, description="List of client IDs that are granted access"
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class TimePolicy(BaseModel):
    """
    Time-based authorization policy.

    Grants access based on time constraints.
    All time fields are optional - only specified constraints are enforced.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )

    # Date range constraints (ISO 8601 format: yyyy-MM-dd HH:mm:ss)
    not_before: str | None = Field(
        None, alias="notBefore", description="Policy is not valid before this date/time"
    )
    not_on_or_after: str | None = Field(
        None,
        alias="notOnOrAfter",
        description="Policy is not valid on or after this date/time",
    )

    # Day of month range (1-31)
    day_month: int | None = Field(
        None, alias="dayMonth", ge=1, le=31, description="Start day of month (1-31)"
    )
    day_month_end: int | None = Field(
        None, alias="dayMonthEnd", ge=1, le=31, description="End day of month (1-31)"
    )

    # Month range (1-12)
    month: int | None = Field(
        None, ge=1, le=12, description="Start month (1=January, 12=December)"
    )
    month_end: int | None = Field(
        None, alias="monthEnd", ge=1, le=12, description="End month (1-12)"
    )

    # Year range
    year: int | None = Field(None, ge=1900, le=2100, description="Start year")
    year_end: int | None = Field(
        None, alias="yearEnd", ge=1900, le=2100, description="End year"
    )

    # Hour range (0-23)
    hour: int | None = Field(None, ge=0, le=23, description="Start hour (0-23)")
    hour_end: int | None = Field(
        None, alias="hourEnd", ge=0, le=23, description="End hour (0-23)"
    )

    # Minute range (0-59)
    minute: int | None = Field(None, ge=0, le=59, description="Start minute (0-59)")
    minute_end: int | None = Field(
        None, alias="minuteEnd", ge=0, le=59, description="End minute (0-59)"
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class RegexPolicy(BaseModel):
    """
    Regex-based authorization policy.

    Grants access based on regex matching against a token claim.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    target_claim: str = Field(
        ..., alias="targetClaim", description="Name of the claim to match against"
    )
    pattern: str = Field(..., description="Regex pattern to match")

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class AggregatePolicy(BaseModel):
    """
    Aggregate authorization policy.

    Combines multiple policies using a decision strategy.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    decision_strategy: str = Field(
        "UNANIMOUS",
        alias="decisionStrategy",
        description="How to combine policy results: UNANIMOUS, AFFIRMATIVE, or CONSENSUS",
    )
    policies: list[str] = Field(
        default_factory=list,
        description="Names of policies to aggregate (must be defined in the same CR)",
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()

    @field_validator("decision_strategy")
    @classmethod
    def validate_decision_strategy(cls, v: str) -> str:
        valid = ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]
        if v.upper() not in valid:
            raise ValueError(f"Decision strategy must be one of {valid}")
        return v.upper()


class JavaScriptPolicy(BaseModel):
    """
    JavaScript-based authorization policy.

    WARNING: JavaScript policies require the 'upload-scripts' feature to be enabled
    in Keycloak, which is disabled by default for security reasons. Use with caution.

    The policy code has access to evaluation context with user, client, and resource info.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Policy name (unique identifier)")
    description: str | None = Field(None, description="Policy description")
    logic: str = Field(
        "POSITIVE",
        description="Policy logic: POSITIVE (grant if match) or NEGATIVE (deny if match)",
    )
    code: str = Field(
        ...,
        description="JavaScript code for the policy. Must set result via 'context.grant()' or 'context.deny()'",
    )

    @field_validator("logic")
    @classmethod
    def validate_logic(cls, v: str) -> str:
        valid = ["POSITIVE", "NEGATIVE"]
        if v.upper() not in valid:
            raise ValueError(f"Logic must be one of {valid}")
        return v.upper()


class AuthorizationPolicies(BaseModel):
    """
    Container for all authorization policy types.

    Policies define WHO can access resources. They are referenced by permissions
    to create the complete authorization model.
    """

    model_config = {"populate_by_name": True}

    # Security setting for JavaScript policies
    allow_javascript_policies: bool = Field(
        False,
        alias="allowJavaScriptPolicies",
        description=(
            "SECURITY: Enable JavaScript policies. Disabled by default. "
            "Requires 'upload-scripts' feature in Keycloak server."
        ),
    )

    # Policy types
    role_policies: list[RolePolicy] = Field(
        default_factory=list,
        alias="rolePolicies",
        description="Role-based policies",
    )
    user_policies: list[UserPolicy] = Field(
        default_factory=list,
        alias="userPolicies",
        description="User-based policies",
    )
    group_policies: list[GroupPolicy] = Field(
        default_factory=list,
        alias="groupPolicies",
        description="Group-based policies",
    )
    client_policies: list[ClientPolicy] = Field(
        default_factory=list,
        alias="clientPolicies",
        description="Client-based policies",
    )
    time_policies: list[TimePolicy] = Field(
        default_factory=list,
        alias="timePolicies",
        description="Time-based policies",
    )
    regex_policies: list[RegexPolicy] = Field(
        default_factory=list,
        alias="regexPolicies",
        description="Regex-based policies",
    )
    aggregate_policies: list[AggregatePolicy] = Field(
        default_factory=list,
        alias="aggregatePolicies",
        description="Aggregate policies (combine other policies)",
    )
    javascript_policies: list[JavaScriptPolicy] = Field(
        default_factory=list,
        alias="javascriptPolicies",
        description="JavaScript policies (requires allowJavaScriptPolicies=true)",
    )


# =============================================================================
# Authorization Permission Models
# =============================================================================


class ResourcePermission(BaseModel):
    """
    Resource-based authorization permission.

    Defines access rights for specific resources with associated policies.
    This permission type grants access to entire resources (all scopes).
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Permission name (unique identifier)")
    description: str | None = Field(None, description="Permission description")
    decision_strategy: str = Field(
        "UNANIMOUS",
        alias="decisionStrategy",
        description="How to combine policy results: UNANIMOUS, AFFIRMATIVE, or CONSENSUS",
    )
    resources: list[str] = Field(
        default_factory=list,
        description="Resource names this permission applies to",
    )
    resource_type: str | None = Field(
        None,
        alias="resourceType",
        description="Apply to all resources of this type (alternative to listing resources)",
    )
    policies: list[str] = Field(
        default_factory=list,
        description="Policy names that control access to these resources",
    )

    @field_validator("decision_strategy")
    @classmethod
    def validate_decision_strategy(cls, v: str) -> str:
        valid = ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]
        if v.upper() not in valid:
            raise ValueError(f"Decision strategy must be one of {valid}")
        return v.upper()


class ScopePermission(BaseModel):
    """
    Scope-based authorization permission.

    Defines access rights for specific scopes, optionally on specific resources.
    This permission type provides finer-grained control than resource permissions.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Permission name (unique identifier)")
    description: str | None = Field(None, description="Permission description")
    decision_strategy: str = Field(
        "UNANIMOUS",
        alias="decisionStrategy",
        description="How to combine policy results: UNANIMOUS, AFFIRMATIVE, or CONSENSUS",
    )
    resources: list[str] = Field(
        default_factory=list,
        description="Resource names to scope this permission to (optional)",
    )
    resource_type: str | None = Field(
        None,
        alias="resourceType",
        description="Apply to all resources of this type (alternative to listing resources)",
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="Scope names this permission applies to",
    )
    policies: list[str] = Field(
        default_factory=list,
        description="Policy names that control access to these scopes",
    )

    @field_validator("decision_strategy")
    @classmethod
    def validate_decision_strategy(cls, v: str) -> str:
        valid = ["UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"]
        if v.upper() not in valid:
            raise ValueError(f"Decision strategy must be one of {valid}")
        return v.upper()

    @field_validator("scopes")
    @classmethod
    def validate_scopes_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Scope permission must have at least one scope")
        return v


class AuthorizationPermissions(BaseModel):
    """
    Container for all authorization permission types.

    Permissions tie policies to resources/scopes to create the complete
    authorization model. They define WHAT can be accessed and link to
    policies that define WHO can access.
    """

    model_config = {"populate_by_name": True}

    resource_permissions: list[ResourcePermission] = Field(
        default_factory=list,
        alias="resourcePermissions",
        description="Resource-based permissions (grant access to entire resources)",
    )
    scope_permissions: list[ScopePermission] = Field(
        default_factory=list,
        alias="scopePermissions",
        description="Scope-based permissions (grant access to specific scopes)",
    )


class KeycloakClientSpec(BaseModel):
    """
    Specification for a KeycloakClient resource.

    This model defines all configurable aspects of a Keycloak client
    including authentication, authorization, and protocol settings.
    """

    model_config = {"populate_by_name": True}

    # Core client configuration
    client_id: str = Field(
        ..., alias="clientId", description="Unique client identifier"
    )
    client_name: str | None = Field(
        None, alias="clientName", description="Human-readable client name"
    )
    description: str | None = Field(None, description="Client description")

    # Realm reference and authorization
    realm_ref: RealmRef = Field(
        ..., alias="realmRef", description="Reference to the parent KeycloakRealm"
    )

    # Client type configuration
    public_client: bool = Field(
        False, alias="publicClient", description="Whether this is a public client"
    )
    bearer_only: bool = Field(
        False, alias="bearerOnly", description="Bearer-only client"
    )
    protocol: str = Field("openid-connect", description="Client protocol")

    # OAuth2/OIDC configuration
    redirect_uris: list[str] = Field(
        default_factory=list, alias="redirectUris", description="Valid redirect URIs"
    )
    web_origins: list[str] = Field(
        default_factory=list,
        alias="webOrigins",
        description="Valid web origins for CORS",
    )
    post_logout_redirect_uris: list[str] = Field(
        default_factory=list,
        alias="postLogoutRedirectUris",
        description="Valid post-logout redirect URIs",
    )

    # Client settings
    settings: KeycloakClientSettings = Field(
        default_factory=KeycloakClientSettings, description="Advanced client settings"
    )

    # Service account configuration
    service_account_roles: ServiceAccountRoles = Field(
        default_factory=ServiceAccountRoles,
        alias="serviceAccountRoles",
        description="Role mappings for the client's service account user",
    )

    # Authentication flows
    authentication_flows: KeycloakClientAuthenticationFlow = Field(
        default_factory=KeycloakClientAuthenticationFlow,
        alias="authenticationFlows",
        description="Client authentication flow overrides",
    )

    # Scopes and mappers
    default_client_scopes: list[str] = Field(
        default_factory=list,
        alias="defaultClientScopes",
        description="Default client scopes",
    )
    optional_client_scopes: list[str] = Field(
        default_factory=list,
        alias="optionalClientScopes",
        description="Optional client scopes",
    )
    protocol_mappers: list[KeycloakClientProtocolMapper] = Field(
        default_factory=list, alias="protocolMappers", description="Protocol mappers"
    )

    # Roles and permissions
    client_roles: list[str] = Field(
        default_factory=list,
        alias="clientRoles",
        description="Client-specific roles to create",
    )

    # Authorization services configuration
    authorization_settings: AuthorizationSettings | None = Field(
        None,
        alias="authorizationSettings",
        description="Fine-grained authorization settings (requires authorizationServicesEnabled in settings)",
    )

    # Advanced configuration
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Additional client attributes"
    )

    # Secret management
    regenerate_secret: bool = Field(
        False,
        alias="regenerateSecret",
        description="Regenerate client secret on update",
    )
    secret_name: str | None = Field(
        None,
        alias="secretName",
        description="Name of Kubernetes secret for client credentials",
    )
    secret_metadata: SecretMetadata | None = Field(
        default=None,
        alias="secretMetadata",
        description="Metadata to attach to the managed secret.",
    )
    client_secret: KeycloakClientSecretRef | None = Field(
        None,
        alias="clientSecret",
        description=(
            "Reference to an existing secret containing the client secret. "
            "If set, this secret is used instead of generating one. "
            "Cannot be used with secret rotation."
        ),
    )

    # Secret rotation settings
    secret_rotation: SecretRotationConfig = Field(
        default_factory=SecretRotationConfig,
        alias="secretRotation",
        description="Automated secret rotation configuration",
    )

    # GitOps settings
    manage_secret: bool = Field(
        True,
        alias="manageSecret",
        description="Create and manage Kubernetes secret for credentials",
    )

    @model_validator(mode="after")
    def validate_secret_configuration(self) -> "KeycloakClientSpec":
        """Validate secret configuration constraints."""
        # Check client_secret vs secret_rotation
        if self.client_secret and self.secret_rotation.enabled:
            raise ValueError(
                "Manual client secret (clientSecret) cannot be used with automated "
                "secret rotation (secretRotation.enabled=true). Disable rotation "
                "to use a manual secret."
            )

        # Check client_secret vs public_client
        if self.client_secret and self.public_client:
            raise ValueError(
                "Manual client secret (clientSecret) cannot be used with public clients. "
                "Public clients do not use client secrets."
            )

        return self

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Client ID must be a non-empty string")
        if len(v) > 255:
            raise ValueError("Client ID must be 255 characters or less")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v):
        valid_protocols = ["openid-connect", "saml", "docker-v2"]
        if v not in valid_protocols:
            raise ValueError(f"Protocol must be one of {valid_protocols}")
        return v

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v: list[str]) -> list[str]:
        """Validate redirect URIs follow Keycloak wildcard rules.

        Keycloak allows wildcards (*) in specific locations:
        - ✓ In path: http://localhost:3000/* or https://example.com/app/*
        - ✓ Custom schemes: custom:* or mycustomscheme:*
        - ✗ In domain: https://*.example.com or http://example*.com
        - ✗ Bare wildcard: * (too permissive, blocked since Keycloak 22.x)

        Wildcards can only appear at the END of the URI.
        """
        for uri in v:
            if not uri:
                continue

            # Check for bare wildcard (no longer valid in Keycloak 22+)
            if uri.strip() == "*":
                raise ValueError(
                    "Bare wildcard '*' is not allowed as redirect URI. "
                    "Use a specific pattern like 'http://localhost:3000/*' or 'https://example.com/app/*'"
                )

            # Check if wildcard exists
            if "*" not in uri:
                continue  # No wildcard, no further validation needed

            # Parse scheme - custom schemes may use : or ://
            if ":" not in uri:
                raise ValueError(
                    f"Invalid redirect URI format: '{uri}'. "
                    f"Must include scheme (e.g., 'http://', 'https://', or 'custom:')"
                )

            # Determine if using :// (http/https) or : (custom schemes)
            if "://" in uri:
                scheme, rest = uri.split("://", 1)
            else:
                scheme, rest = uri.split(":", 1)

            # For custom schemes (not http/https), wildcard is allowed
            # Examples: custom:*, myapp:callback/*, electron://app/*
            if scheme.lower() not in ["http", "https"]:
                # Custom schemes can use wildcard after colon
                # Pattern: custom:* or custom:path/* or custom://something/*
                # Still validate wildcard is at the end
                if not uri.endswith("*"):
                    raise ValueError(
                        f"Wildcard must be at the end of redirect URI: '{uri}'. "
                        f"Example: 'myapp:callback/*' not 'myapp:call*back'"
                    )
                continue

            # For http(s) schemes, wildcard must be in PATH, not DOMAIN
            # At this point, rest is everything after ://
            if "/" in rest:
                # Split into domain and path portions
                domain_part, path_part = rest.split("/", 1)

                # Check if wildcard appears in domain portion
                if "*" in domain_part:
                    raise ValueError(
                        f"Wildcard not allowed in domain portion of redirect URI: '{uri}'. "
                        f"❌ Invalid: 'https://*.example.com' or 'http://example*.com'. "
                        f"✓ Valid: 'https://example.com/*' or 'https://example.com/app/*'"
                    )

                # Wildcard in path is valid, but must be at the end
                if not uri.endswith("*"):
                    raise ValueError(
                        f"Wildcard must be at the end of redirect URI: '{uri}'. "
                        f"Example: 'http://example.com/path/*' not 'http://example.com/pa*th/more'"
                    )
            else:
                # No path separator, so everything after :// is domain
                # Example: http://example.com*
                if "*" in rest:
                    raise ValueError(
                        f"Wildcard not allowed in domain-only redirect URI: '{uri}'. "
                        f"❌ Invalid: 'http://example.com*' or 'https://*.example.com'. "
                        f"✓ Valid: 'http://example.com/*' (add trailing slash and wildcard)"
                    )

        return v

    def to_keycloak_config(self) -> dict[str, Any]:
        """
        Convert the client specification to Keycloak API format.

        Returns:
            Dictionary in Keycloak Admin API format
        """
        config: dict[str, Any] = {
            "clientId": self.client_id,
            "name": self.client_name or self.client_id,
            "description": self.description,
            "protocol": self.protocol,
            "publicClient": self.public_client,
            "bearerOnly": self.bearer_only,
            "enabled": True,  # Client is enabled when CR exists
            "redirectUris": self.redirect_uris,
            "webOrigins": self.web_origins,
            "attributes": self.attributes.copy(),
        }

        # Add client settings
        config.update(
            {
                "alwaysDisplayInConsole": self.settings.always_display_in_console,
                "clientAuthenticatorType": self.settings.client_authenticator_type,
                "standardFlowEnabled": self.settings.standard_flow_enabled,
                "implicitFlowEnabled": self.settings.implicit_flow_enabled,
                "directAccessGrantsEnabled": self.settings.direct_access_grants_enabled,
                "serviceAccountsEnabled": self.settings.service_accounts_enabled,
                "consentRequired": self.settings.consent_required,
                "displayOnConsentScreen": self.settings.display_on_consent_screen,
                "includeInTokenScope": self.settings.include_in_token_scope,
                "frontchannelLogout": self.settings.frontchannel_logout,
                "fullScopeAllowed": self.settings.full_scope_allowed,
                "authorizationServicesEnabled": self.settings.authorization_services_enabled,
            }
        )

        # Add token lifespan settings if specified
        if self.settings.access_token_lifespan is not None:
            config["attributes"]["access.token.lifespan"] = str(
                self.settings.access_token_lifespan
            )

        if self.settings.refresh_token_lifespan is not None:
            config["attributes"]["refresh.token.lifespan"] = str(
                self.settings.refresh_token_lifespan
            )

        # Add session timeout settings if specified
        if self.settings.client_session_idle_timeout is not None:
            config["attributes"]["client.session.idle.timeout"] = str(
                self.settings.client_session_idle_timeout
            )

        if self.settings.client_session_max_lifespan is not None:
            config["attributes"]["client.session.max.lifespan"] = str(
                self.settings.client_session_max_lifespan
            )

        # Add PKCE settings if specified
        if self.settings.pkce_code_challenge_method:
            config["attributes"]["pkce.code.challenge.method"] = (
                self.settings.pkce_code_challenge_method
            )

        # Add authentication flow overrides
        if self.authentication_flows.browser_flow:
            config["browserFlow"] = self.authentication_flows.browser_flow

        if self.authentication_flows.direct_grant_flow:
            config["directGrantFlow"] = self.authentication_flows.direct_grant_flow

        if self.authentication_flows.client_authentication_flow:
            config["clientAuthenticationFlow"] = (
                self.authentication_flows.client_authentication_flow
            )

        # Add post-logout redirect URIs (Keycloak 18+)
        if self.post_logout_redirect_uris:
            config["attributes"]["post.logout.redirect.uris"] = "||".join(
                self.post_logout_redirect_uris
            )

        return config


class KeycloakClientCondition(BaseModel):
    """Status condition for KeycloakClient resource."""

    model_config = {"populate_by_name": True}

    type: str = Field(..., description="Condition type")
    status: str = Field(..., description="Condition status (True/False/Unknown)")
    reason: str | None = Field(None, description="Reason for the condition")
    message: str | None = Field(None, description="Human-readable message")
    last_transition_time: str | None = Field(
        None,
        alias="lastTransitionTime",
        description="Last time the condition transitioned",
    )


class KeycloakClientEndpoints(BaseModel):
    """Endpoints for the KeycloakClient."""

    model_config = {"populate_by_name": True}

    auth: str | None = Field(None, description="Authorization endpoint")
    token: str | None = Field(None, description="Token endpoint")
    userinfo: str | None = Field(None, description="UserInfo endpoint")
    jwks: str | None = Field(None, description="JWKS endpoint")
    issuer: str | None = Field(None, description="Issuer URL")
    end_session: str | None = Field(
        None, alias="endSession", description="End session (logout) endpoint"
    )


class KeycloakClientStatus(BaseModel):
    """
    Status of a KeycloakClient resource.

    This model represents the current state of a client as managed
    by the operator.
    """

    model_config = {"populate_by_name": True}

    # Overall status
    phase: str = Field("Pending", description="Current phase of the client")
    message: str | None = Field(None, description="Human-readable status message")
    reason: str | None = Field(None, description="Reason for current phase")

    # Detailed status
    conditions: list[KeycloakClientCondition] = Field(
        default_factory=list, description="Detailed status conditions"
    )
    observed_generation: int | None = Field(
        None,
        alias="observedGeneration",
        description="Generation of the spec that was last processed",
    )

    # Client information
    client_id: str | None = Field(
        None, alias="clientId", description="Keycloak client ID"
    )
    internal_id: str | None = Field(
        None, alias="internalId", description="Internal Keycloak client UUID"
    )
    realm: str | None = Field(None, description="Target realm")
    public_client: bool | None = Field(
        None, alias="publicClient", description="Whether this is a public client"
    )

    # Connection information
    keycloak_instance: str | None = Field(
        None,
        alias="keycloakInstance",
        description="Keycloak instance reference (namespace/name)",
    )
    credentials_secret: str | None = Field(
        None, alias="credentialsSecret", description="Name of the credentials secret"
    )

    # Endpoints
    endpoints: KeycloakClientEndpoints = Field(
        default_factory=KeycloakClientEndpoints, description="Client endpoints"
    )

    # Authorization status
    authorization_granted: bool = Field(
        False,
        alias="authorizationGranted",
        description="Whether this client's namespace is authorized by the realm",
    )
    authorization_message: str | None = Field(
        None,
        alias="authorizationMessage",
        description="Human-readable authorization status message",
    )

    # Health and monitoring
    last_health_check: str | None = Field(
        None, alias="lastHealthCheck", description="Timestamp of last health check"
    )
    last_updated: str | None = Field(
        None, alias="lastUpdated", description="Timestamp of last successful update"
    )

    # Statistics
    created_roles: list[str] = Field(
        default_factory=list,
        alias="createdRoles",
        description="Client roles that were created",
    )
    applied_mappers: list[str] = Field(
        default_factory=list,
        alias="appliedMappers",
        description="Protocol mappers that were applied",
    )

    # Drift detection
    last_reconcile_event_time: int | None = Field(
        None,
        alias="lastReconcileEventTime",
        description="Timestamp (Unix ms) of latest Keycloak admin event after last reconciliation",
    )


class KeycloakClient(BaseModel):
    """
    Complete KeycloakClient custom resource model.

    This represents the full Kubernetes custom resource for dynamic
    client provisioning with cross-namespace support.
    """

    api_version: str = Field("vriesdemichael.github.io/v1", alias="apiVersion")
    kind: str = Field("KeycloakClient")
    metadata: KubernetesMetadata = Field(..., description="Kubernetes metadata")
    spec: KeycloakClientSpec = Field(..., description="Client specification")
    status: KeycloakClientStatus | None = Field(
        None, description="Client status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"


# Resolve forward references for AuthorizationSettings -> AuthorizationPolicies/AuthorizationPermissions
AuthorizationSettings.model_rebuild()
