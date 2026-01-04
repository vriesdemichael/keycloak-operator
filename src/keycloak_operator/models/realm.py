"""
Pydantic models for KeycloakRealm resources.

This module defines type-safe data models for Keycloak realm specifications
and status. These models enable comprehensive realm management including
authentication flows, identity providers, and user federation.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from keycloak_operator.models.types import (
    KeycloakConfigMap,
    KubernetesMetadata,
)


class OperatorRef(BaseModel):
    """Reference to the operator managing this realm."""

    model_config = {"populate_by_name": True}

    namespace: str = Field(..., description="Namespace where the operator is running")


class KeycloakRealmTheme(BaseModel):
    """Theme configuration for a realm."""

    login: str | None = Field(None, description="Login theme")
    admin: str | None = Field(None, description="Admin theme")
    account: str | None = Field(None, description="Account theme")
    email: str | None = Field(None, description="Email theme")


class KeycloakRealmLocalization(BaseModel):
    """Localization configuration for a realm."""

    model_config = {"populate_by_name": True}

    enabled: bool = Field(True, description="Enable internationalization")
    default_locale: str = Field(
        "en", alias="defaultLocale", description="Default locale"
    )
    supported_locales: list[str] = Field(
        default_factory=lambda: ["en"],
        alias="supportedLocales",
        description="Supported locales",
    )


class KeycloakRealmTokenSettings(BaseModel):
    """Token settings for a realm."""

    model_config = {"populate_by_name": True}

    # Access token settings
    access_token_lifespan: int = Field(
        300, alias="accessTokenLifespan", description="Access token lifespan in seconds"
    )
    access_token_lifespan_for_implicit_flow: int = Field(
        900,
        alias="accessTokenLifespanForImplicitFlow",
        description="Access token lifespan for implicit flow in seconds",
    )

    # SSO session settings
    sso_session_idle_timeout: int = Field(
        1800,
        alias="ssoSessionIdleTimeout",
        description="SSO session idle timeout in seconds",
    )
    sso_session_max_lifespan: int = Field(
        36000,
        alias="ssoSessionMaxLifespan",
        description="SSO session max lifespan in seconds",
    )

    # Offline session settings
    offline_session_idle_timeout: int = Field(
        2592000,
        alias="offlineSessionIdleTimeout",
        description="Offline session idle timeout in seconds",  # 30 days
    )
    offline_session_max_lifespan_enabled: bool = Field(
        False,
        alias="offlineSessionMaxLifespanEnabled",
        description="Enable offline session max lifespan",
    )
    offline_session_max_lifespan: int = Field(
        5184000,
        alias="offlineSessionMaxLifespan",
        description="Offline session max lifespan in seconds",  # 60 days
    )

    # Client session settings
    client_session_idle_timeout: int = Field(
        0,
        alias="clientSessionIdleTimeout",
        description="Client session idle timeout in seconds",
    )
    client_session_max_lifespan: int = Field(
        0,
        alias="clientSessionMaxLifespan",
        description="Client session max lifespan in seconds",
    )

    # Client offline session settings
    client_offline_session_idle_timeout: int = Field(
        0,
        alias="clientOfflineSessionIdleTimeout",
        description="Client offline session idle timeout in seconds",
    )
    client_offline_session_max_lifespan: int = Field(
        0,
        alias="clientOfflineSessionMaxLifespan",
        description="Client offline session max lifespan in seconds",
    )

    @field_validator(
        "access_token_lifespan", "sso_session_idle_timeout", "sso_session_max_lifespan"
    )
    @classmethod
    def validate_positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("Timeout values must be positive")
        return v


class KeycloakIdentityProviderSecretRef(BaseModel):
    """
    Reference to Kubernetes secret containing identity provider secrets.

    The secret must be in the same namespace as the KeycloakRealm.
    Cross-namespace secret references are not supported for security reasons.
    """

    name: str = Field(..., description="Secret name")
    key: str = Field(..., description="Key in secret data")


class KeycloakIdentityProviderMapper(BaseModel):
    """
    Identity provider mapper configuration.

    Mappers transform claims/attributes from the identity provider
    into Keycloak user attributes, roles, or session attributes.
    """

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Mapper name (unique within IDP)")
    identity_provider_mapper: str = Field(
        ...,
        alias="identityProviderMapper",
        description="Mapper type (e.g., 'oidc-user-attribute-idp-mapper')",
    )
    config: dict[str, str] = Field(
        default_factory=dict,
        description="Mapper-specific configuration",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Mapper name must be a non-empty string")
        return v

    @field_validator("identity_provider_mapper")
    @classmethod
    def validate_mapper_type(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Mapper type must be a non-empty string")
        return v


class KeycloakIdentityProvider(BaseModel):
    """Identity provider configuration."""

    model_config = {"populate_by_name": True}

    alias: str = Field(..., description="Identity provider alias")
    provider_id: str = Field(..., alias="providerId", description="Provider type ID")
    display_name: str | None = Field(
        None, alias="displayName", description="Display name"
    )
    enabled: bool = Field(True, description="Whether the provider is enabled")

    # Provider-specific configuration
    config: KeycloakConfigMap = Field(
        default_factory=dict, description="Provider-specific configuration"
    )

    # Secret references for sensitive configuration values
    config_secrets: dict[str, KeycloakIdentityProviderSecretRef] = Field(
        default_factory=dict,
        alias="configSecrets",
        description="Secret references for sensitive config values (e.g., clientSecret)",
    )

    # UI settings
    first_broker_login_flow_alias: str | None = Field(
        None, alias="firstBrokerLoginFlowAlias", description="First broker login flow"
    )
    post_broker_login_flow_alias: str | None = Field(
        None, alias="postBrokerLoginFlowAlias", description="Post broker login flow"
    )
    link_only: bool = Field(
        False, alias="linkOnly", description="Link existing users only"
    )
    store_token: bool = Field(
        False, alias="storeToken", description="Store identity provider tokens"
    )
    trust_email: bool = Field(
        False, alias="trustEmail", description="Trust email from identity provider"
    )

    # IDP Mappers for claim/attribute transformation
    mappers: list[KeycloakIdentityProviderMapper] = Field(
        default_factory=list,
        description="Identity provider mappers for claim/attribute transformation",
    )

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Alias must be a non-empty string")
        return v

    def model_post_init(self, __context):
        """Validate that sensitive keys are only in configSecrets, not plaintext in config."""
        # Define known sensitive keys that must use configSecrets
        sensitive_keys = {
            "clientSecret",
            "secret",
            "password",
            "privateKey",
            "signingKey",
        }

        # Check if any sensitive keys are in config (plaintext)
        for key in self.config:
            if key in sensitive_keys:
                raise ValueError(
                    f"Sensitive config key '{key}' must not be in 'config'. "
                    f"Use 'configSecrets' to reference a Kubernetes secret instead."
                )

        # Also check for duplicates between config and configSecrets
        if self.config_secrets:
            for key in self.config_secrets:
                if key in self.config:
                    raise ValueError(
                        f"Config key '{key}' cannot be specified in both 'config' and 'configSecrets'. "
                        f"Use 'configSecrets' for sensitive values."
                    )


class KeycloakUserFederation(BaseModel):
    """User federation configuration."""

    name: str = Field(..., description="Federation provider name")
    provider_id: str = Field(..., description="Federation provider type")
    priority: int = Field(0, description="Federation priority")
    enabled: bool = Field(True, description="Whether federation is enabled")

    # Provider-specific configuration
    config: KeycloakConfigMap = Field(
        default_factory=dict, description="Federation-specific configuration"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Name must be a non-empty string")
        return v

    @field_validator("provider_id")
    @classmethod
    def validate_provider_id(cls, v):
        valid_providers = ["ldap", "kerberos", "sssd"]
        if v not in valid_providers:
            raise ValueError(f"Provider ID must be one of {valid_providers}")
        return v


# =============================================================================
# Authentication Flow Types
# =============================================================================
# These types match the Keycloak Admin API representations for authentication
# management. Field names use camelCase aliases to match API conventions.

# Valid requirement values for authentication executions
AuthenticationExecutionRequirement = Literal[
    "REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL"
]


class AuthenticatorConfigInfo(BaseModel):
    """
    Configuration for a configurable authenticator execution.

    Maps to AuthenticatorConfigRepresentation in Keycloak API.
    Used for authenticators that have configuration options (e.g., OTP settings).
    """

    model_config = {"populate_by_name": True}

    alias: str | None = Field(None, description="Configuration alias for reference")
    config: dict[str, str] = Field(
        default_factory=dict,
        description="Authenticator-specific configuration key-value pairs",
    )


class AuthenticationExecutionExport(BaseModel):
    """
    Authentication execution step configuration.

    Maps to AuthenticationExecutionExportRepresentation in Keycloak API.
    Represents a single step in an authentication flow.
    """

    model_config = {"populate_by_name": True}

    # For authenticator executions (e.g., auth-cookie, auth-otp-form)
    authenticator: str | None = Field(
        None,
        description="Authenticator provider ID (e.g., 'auth-cookie', 'auth-otp-form')",
    )

    # For sub-flow references
    flow_alias: str | None = Field(
        None,
        alias="flowAlias",
        description="Alias of sub-flow (when authenticatorFlow=true)",
    )
    authenticator_flow: bool = Field(
        False,
        alias="authenticatorFlow",
        description="True if this execution references a sub-flow",
    )

    # Execution requirement level
    requirement: AuthenticationExecutionRequirement = Field(
        "DISABLED",
        description="Execution requirement: REQUIRED, ALTERNATIVE, DISABLED, CONDITIONAL",
    )

    # Execution order
    priority: int = Field(
        0,
        description="Execution priority (lower = earlier in flow)",
    )

    # Configuration for configurable authenticators
    authenticator_config: str | None = Field(
        None,
        alias="authenticatorConfig",
        description="Reference to authenticator configuration alias",
    )

    # Whether user can set up this authenticator during login
    user_setup_allowed: bool | None = Field(
        None,
        alias="userSetupAllowed",
        description="Allow user to set up authenticator during login",
    )

    def model_post_init(self, __context):
        """Validate that execution has either authenticator or flow reference."""
        if not self.authenticator and not self.flow_alias:
            raise ValueError(
                "Execution must specify either 'authenticator' or 'flowAlias'"
            )
        if self.authenticator and self.flow_alias:
            raise ValueError(
                "Execution cannot specify both 'authenticator' and 'flowAlias'"
            )
        # Auto-set authenticator_flow based on flow_alias
        if self.flow_alias and not self.authenticator_flow:
            object.__setattr__(self, "authenticator_flow", True)


class KeycloakAuthenticationFlow(BaseModel):
    """
    Authentication flow configuration.

    Maps to AuthenticationFlowRepresentation in Keycloak API.
    Defines a complete authentication flow with its executions.
    """

    model_config = {"populate_by_name": True}

    alias: str = Field(..., description="Unique flow alias/name")
    description: str | None = Field(None, description="Flow description")
    provider_id: str = Field(
        "basic-flow",
        alias="providerId",
        description="Flow provider: 'basic-flow' or 'client-flow'",
    )
    top_level: bool = Field(
        True,
        alias="topLevel",
        description="True for top-level flows, false for sub-flows",
    )
    built_in: bool = Field(
        False,
        alias="builtIn",
        description="Whether this is a built-in flow (read-only)",
    )

    # Flow executions (steps)
    authentication_executions: list[AuthenticationExecutionExport] = Field(
        default_factory=list,
        alias="authenticationExecutions",
        description="Ordered list of authentication executions",
    )

    # Authenticator configurations referenced by executions
    authenticator_config: list[AuthenticatorConfigInfo] = Field(
        default_factory=list,
        alias="authenticatorConfig",
        description="Configurations for configurable authenticators",
    )

    # Operator-specific: copy from existing built-in flow
    copy_from: str | None = Field(
        None,
        alias="copyFrom",
        description="Copy from existing flow alias before applying modifications",
    )

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Alias must be a non-empty string")
        return v

    @field_validator("provider_id")
    @classmethod
    def validate_provider_id(cls, v):
        valid_providers = ["basic-flow", "client-flow"]
        if v not in valid_providers:
            raise ValueError(f"provider_id must be one of {valid_providers}")
        return v


class RequiredActionProvider(BaseModel):
    """
    Required action configuration.

    Maps to RequiredActionProviderRepresentation in Keycloak API.
    Required actions are actions users must perform (e.g., verify email, configure OTP).
    """

    model_config = {"populate_by_name": True}

    alias: str = Field(
        ...,
        description="Required action alias (e.g., 'CONFIGURE_TOTP', 'VERIFY_EMAIL')",
    )
    name: str | None = Field(None, description="Display name for the action")
    provider_id: str | None = Field(
        None,
        alias="providerId",
        description="Provider ID (usually same as alias)",
    )
    enabled: bool = Field(True, description="Whether this action is enabled")
    default_action: bool = Field(
        False,
        alias="defaultAction",
        description="Add to new users by default",
    )
    priority: int = Field(
        0,
        description="Order priority (lower = earlier)",
    )
    config: dict[str, str] = Field(
        default_factory=dict,
        description="Action-specific configuration",
    )

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Alias must be a non-empty string")
        return v


class KeycloakRealmSecurity(BaseModel):
    """Security settings for a realm."""

    model_config = {"populate_by_name": True}

    # SSL settings
    ssl_required: str = Field(
        "external",
        alias="sslRequired",
        description="SSL requirement (all, external, none)",
    )

    # Brute force protection
    brute_force_protected: bool = Field(
        False, alias="bruteForceProtected", description="Enable brute force protection"
    )
    permanent_lockout: bool = Field(
        False,
        alias="permanentLockout",
        description="Permanent lockout after max failures",
    )
    failure_factor: int = Field(
        30, alias="failureFactor", description="Number of failures before lockout"
    )
    max_failure_wait: int = Field(
        900,
        alias="maxFailureWait",
        description="Max wait time after failures in seconds",
    )
    minimum_quick_login_wait: int = Field(
        60,
        alias="minimumQuickLoginWait",
        description="Minimum quick login wait in seconds",
    )
    wait_increment: int = Field(
        60, alias="waitIncrement", description="Wait increment per failure in seconds"
    )
    quick_login_check_millis: int = Field(
        1000,
        alias="quickLoginCheckMillis",
        description="Quick login check interval in milliseconds",
    )
    max_delta_time: int = Field(
        43200,
        alias="maxDeltaTime",
        description="Max delta time for failures in seconds",  # 12 hours
    )

    # Token revocation
    revoke_refresh_token: bool = Field(
        False, alias="revokeRefreshToken", description="Revoke refresh tokens on use"
    )
    refresh_token_max_reuse: int = Field(
        0, alias="refreshTokenMaxReuse", description="Maximum refresh token reuse count"
    )

    # Registration settings
    registration_allowed: bool = Field(
        False, alias="registrationAllowed", description="Allow user registration"
    )
    registration_email_as_username: bool = Field(
        False,
        alias="registrationEmailAsUsername",
        description="Use email as username for registration",
    )
    edit_username_allowed: bool = Field(
        False,
        alias="editUsernameAllowed",
        description="Allow users to edit their username",
    )
    reset_password_allowed: bool = Field(
        True, alias="resetPasswordAllowed", description="Allow password reset"
    )
    remember_me: bool = Field(
        False, alias="rememberMe", description="Enable remember me"
    )
    verify_email: bool = Field(
        False, alias="verifyEmail", description="Require email verification"
    )
    login_with_email_allowed: bool = Field(
        True, alias="loginWithEmailAllowed", description="Allow login with email"
    )
    duplicate_emails_allowed: bool = Field(
        False,
        alias="duplicateEmailsAllowed",
        description="Allow duplicate email addresses",
    )

    @field_validator("max_failure_wait", "minimum_quick_login_wait")
    @classmethod
    def validate_positive_seconds(cls, v):
        if v < 0:
            raise ValueError("Time values must be non-negative")
        return v


class KeycloakProtocolMapper(BaseModel):
    """Protocol mapper for client scopes."""

    name: str = Field(..., description="Mapper name")
    protocol: str = Field(..., description="Protocol (openid-connect, saml)")
    protocol_mapper: str = Field(..., description="Mapper type")
    config: dict[str, str] = Field(
        default_factory=dict, description="Mapper configuration"
    )


class KeycloakClientScope(BaseModel):
    """Client scope definition."""

    name: str = Field(..., description="Scope name")
    description: str | None = Field(None, description="Scope description")
    protocol: str = Field("openid-connect", description="Protocol")
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Scope attributes"
    )
    protocol_mappers: list[KeycloakProtocolMapper] = Field(
        default_factory=list, description="Protocol mappers"
    )


class KeycloakRealmRole(BaseModel):
    """Realm role definition."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Role name")
    description: str | None = Field(None, description="Role description")
    composite: bool = Field(False, description="Is composite role")
    client_role: bool = Field(False, alias="clientRole", description="Is client role")
    container_id: str | None = Field(
        None, alias="containerId", description="Container ID"
    )
    attributes: dict[str, list[str]] | None = Field(None, description="Role attributes")
    # Composite role children - list of role names to include
    composite_roles: list[str] = Field(
        default_factory=list,
        alias="compositeRoles",
        description="Names of roles to include in this composite role",
    )


class KeycloakRoles(BaseModel):
    """Realm and client role definitions."""

    model_config = {"populate_by_name": True}

    realm_roles: list[KeycloakRealmRole] = Field(
        default_factory=list, alias="realmRoles", description="Realm roles"
    )


class KeycloakGroup(BaseModel):
    """Group definition."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Group name")
    path: str | None = Field(None, description="Group path")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Group attributes"
    )
    realm_roles: list[str] = Field(
        default_factory=list, alias="realmRoles", description="Assigned realm roles"
    )
    client_roles: dict[str, list[str]] = Field(
        default_factory=dict,
        alias="clientRoles",
        description="Assigned client roles by client ID",
    )
    # Support for nested groups
    subgroups: list["KeycloakGroup"] = Field(
        default_factory=list,
        alias="subGroups",
        description="Subgroups of this group",
    )


class KeycloakEventsConfig(BaseModel):
    """Event logging configuration."""

    model_config = {"populate_by_name": True}

    events_enabled: bool = Field(
        False, alias="eventsEnabled", description="Enable event logging"
    )
    events_listeners: list[str] = Field(
        default_factory=list, alias="eventsListeners", description="Event listeners"
    )
    enabled_event_types: list[str] = Field(
        default_factory=list,
        alias="enabledEventTypes",
        description="Enabled event types",
    )
    events_expiration: int | None = Field(
        None, alias="eventsExpiration", description="Event expiration in seconds", ge=1
    )
    admin_events_enabled: bool = Field(
        False, alias="adminEventsEnabled", description="Enable admin event logging"
    )
    admin_events_details_enabled: bool = Field(
        False,
        alias="adminEventsDetailsEnabled",
        description="Include details in admin events",
    )


class KeycloakPasswordPolicy(BaseModel):
    """
    Password policy configuration for a realm.

    Enforces password requirements for users. The policy is converted to
    Keycloak's "and"-separated policy string format.
    """

    model_config = {"populate_by_name": True}

    length: int | None = Field(None, ge=1, description="Minimum password length")
    upper_case: int | None = Field(
        None, alias="upperCase", ge=0, description="Minimum uppercase characters"
    )
    lower_case: int | None = Field(
        None, alias="lowerCase", ge=0, description="Minimum lowercase characters"
    )
    digits: int | None = Field(None, ge=0, description="Minimum digit characters")
    special_chars: int | None = Field(
        None, alias="specialChars", ge=0, description="Minimum special characters"
    )
    not_username: bool = Field(
        False, alias="notUsername", description="Password cannot equal username"
    )
    not_email: bool = Field(
        False, alias="notEmail", description="Password cannot equal email"
    )
    hash_iterations: int | None = Field(
        None, alias="hashIterations", ge=1, description="PBKDF2 hash iterations"
    )
    password_history: int | None = Field(
        None,
        alias="passwordHistory",
        ge=0,
        description="Number of previous passwords to check",
    )
    force_expired_password_change: int | None = Field(
        None,
        alias="forceExpiredPasswordChange",
        ge=0,
        description="Days until password expires and must be changed (0 = expires immediately; unset = never expires)",
    )
    max_length: int | None = Field(
        None, alias="maxLength", ge=1, description="Maximum password length"
    )
    regex_pattern: str | None = Field(
        None, alias="regexPattern", description="Custom regex pattern"
    )

    def to_policy_string(self) -> str:
        """
        Convert to Keycloak password policy string format.

        Returns:
            Policy string with " and " separator (e.g., "length(12) and upperCase(1) and notUsername")
        """
        policies = []
        if self.length is not None:
            policies.append(f"length({self.length})")
        if self.upper_case is not None:
            policies.append(f"upperCase({self.upper_case})")
        if self.lower_case is not None:
            policies.append(f"lowerCase({self.lower_case})")
        if self.digits is not None:
            policies.append(f"digits({self.digits})")
        if self.special_chars is not None:
            policies.append(f"specialChars({self.special_chars})")
        if self.not_username:
            policies.append("notUsername")
        if self.not_email:
            policies.append("notEmail")
        if self.hash_iterations is not None:
            policies.append(f"hashIterations({self.hash_iterations})")
        if self.password_history is not None:
            policies.append(f"passwordHistory({self.password_history})")
        if self.force_expired_password_change is not None:
            policies.append(
                f"forceExpiredPasswordChange({self.force_expired_password_change})"
            )
        if self.max_length is not None:
            policies.append(f"maxLength({self.max_length})")
        if self.regex_pattern is not None:
            policies.append(f"regexPattern({self.regex_pattern})")
        return " and ".join(policies)


class KeycloakSMTPPasswordSecret(BaseModel):
    """
    Reference to Kubernetes secret containing SMTP password.

    The secret must be in the same namespace as the KeycloakRealm.
    Cross-namespace secret references are not supported for security reasons.
    """

    name: str = Field(..., description="Secret name")
    key: str = Field(default="password", description="Key in secret data")


class KeycloakSMTPConfig(BaseModel):
    """SMTP server configuration with validation."""

    model_config = {"populate_by_name": True}

    host: str = Field(..., description="SMTP server host")
    port: int = Field(..., description="SMTP server port", ge=1, le=65535)
    from_address: str = Field(..., alias="from", description="From email address")
    from_display_name: str | None = Field(
        None, alias="fromDisplayName", description="From display name"
    )
    reply_to: str | None = Field(None, alias="replyTo", description="Reply-to address")
    envelope_from: str | None = Field(
        None, alias="envelopeFrom", description="Envelope from address"
    )
    ssl: bool = Field(False, description="Use SSL")
    starttls: bool = Field(False, description="Use STARTTLS")
    auth: bool = Field(False, description="Require authentication")
    user: str | None = Field(None, description="SMTP username")
    password: str | None = Field(
        None, description="SMTP password (use password_secret instead)"
    )
    password_secret: KeycloakSMTPPasswordSecret | None = Field(
        None, alias="passwordSecret", description="Secret reference for password"
    )

    @field_validator("auth")
    @classmethod
    def validate_auth_requirements(cls, v, info):
        """Ensure auth settings are consistent."""
        # Note: This validator runs before model is fully constructed,
        # so we validate in model_validator instead
        return v

    def model_post_init(self, __context):
        """Validate auth requirements after model construction."""
        if self.auth and not self.user:
            raise ValueError("SMTP user required when auth=true")
        if self.auth and not self.password and not self.password_secret:
            raise ValueError("SMTP password or password_secret required when auth=true")
        if self.password and self.password_secret:
            raise ValueError("Cannot specify both password and password_secret")


class KeycloakRealmSpec(BaseModel):
    """
    Specification for a KeycloakRealm resource.

    This model defines all configurable aspects of a Keycloak realm
    including security, authentication, and user management settings.
    """

    model_config = {"populate_by_name": True}

    # Core realm configuration
    realm_name: str = Field(..., alias="realmName", description="Name of the realm")
    display_name: str | None = Field(
        None, alias="displayName", description="Human-readable display name"
    )
    description: str | None = Field(None, description="Realm description")
    login_page_title: str | None = Field(
        None, alias="loginPageTitle", description="HTML title for login pages"
    )

    # Operator reference and authorization
    operator_ref: OperatorRef = Field(
        ...,
        alias="operatorRef",
        description="Reference to the operator managing this realm",
    )

    # Client authorization grants
    client_authorization_grants: list[str] = Field(
        default_factory=list,
        alias="clientAuthorizationGrants",
        description="List of namespaces authorized to create clients in this realm",
    )

    # Themes and localization
    themes: KeycloakRealmTheme | None = Field(None, description="Theme configuration")
    localization: KeycloakRealmLocalization | None = Field(
        None, description="Localization settings"
    )

    # Token and session settings
    token_settings: KeycloakRealmTokenSettings = Field(
        default_factory=KeycloakRealmTokenSettings,
        alias="tokenSettings",
        description="Token and session configuration",
    )

    # Security settings
    security: KeycloakRealmSecurity = Field(
        default_factory=KeycloakRealmSecurity, description="Security configuration"
    )

    # Authentication flows
    authentication_flows: list[KeycloakAuthenticationFlow] = Field(
        default_factory=list,
        alias="authenticationFlows",
        description="Custom authentication flows",
    )

    # Authentication flow bindings (assign flows to realm authentication types)
    browser_flow: str | None = Field(
        None,
        alias="browserFlow",
        description="Flow alias for browser authentication",
    )
    registration_flow: str | None = Field(
        None,
        alias="registrationFlow",
        description="Flow alias for user registration",
    )
    direct_grant_flow: str | None = Field(
        None,
        alias="directGrantFlow",
        description="Flow alias for direct access grants (Resource Owner Password)",
    )
    reset_credentials_flow: str | None = Field(
        None,
        alias="resetCredentialsFlow",
        description="Flow alias for password reset",
    )
    client_authentication_flow: str | None = Field(
        None,
        alias="clientAuthenticationFlow",
        description="Flow alias for client authentication",
    )
    docker_authentication_flow: str | None = Field(
        None,
        alias="dockerAuthenticationFlow",
        description="Flow alias for Docker registry authentication",
    )
    first_broker_login_flow: str | None = Field(
        None,
        alias="firstBrokerLoginFlow",
        description="Flow alias for first login via identity provider",
    )

    # Required actions
    required_actions: list[RequiredActionProvider] = Field(
        default_factory=list,
        alias="requiredActions",
        description="Required action configurations (e.g., CONFIGURE_TOTP, VERIFY_EMAIL)",
    )

    # Identity providers
    identity_providers: list[KeycloakIdentityProvider] = Field(
        default_factory=list,
        alias="identityProviders",
        description="Identity provider configurations",
    )

    # User federation
    user_federation: list[KeycloakUserFederation] = Field(
        default_factory=list,
        alias="userFederation",
        description="User federation configurations",
    )

    # Client scopes
    client_scopes: list[KeycloakClientScope] = Field(
        default_factory=list,
        alias="clientScopes",
        description="Client scope definitions",
    )

    # Roles
    roles: KeycloakRoles | None = Field(None, description="Role definitions")

    # Groups
    groups: list[KeycloakGroup] = Field(
        default_factory=list, description="Group definitions"
    )

    # Default groups - group names that are automatically assigned to new users
    default_groups: list[str] = Field(
        default_factory=list,
        alias="defaultGroups",
        description="Group names (or paths) to automatically assign to new users",
    )

    # SMTP configuration
    smtp_server: KeycloakSMTPConfig | None = Field(
        None, alias="smtpServer", description="SMTP server configuration"
    )

    # Advanced settings
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Additional realm attributes"
    )

    # Password policy
    password_policy: KeycloakPasswordPolicy | None = Field(
        None,
        alias="passwordPolicy",
        description="Password policy configuration",
    )

    # Events and logging
    events_config: KeycloakEventsConfig = Field(
        default_factory=KeycloakEventsConfig,
        alias="eventsConfig",
        description="Event logging configuration",
    )

    @field_validator("realm_name")
    @classmethod
    def validate_realm_name(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Realm name must be a non-empty string")
        if len(v) > 255:
            raise ValueError("Realm name must be 255 characters or less")
        # Check for invalid characters
        invalid_chars = ["/", "\\", "?", "#", "%", "&", "=", "+", " "]
        for char in invalid_chars:
            if char in v:
                raise ValueError(f"Realm name contains invalid character: {char}")
        return v

    @field_validator("client_authorization_grants")
    @classmethod
    def validate_namespace_grants(cls, v):
        """Validate namespace names in authorization grants."""
        if not isinstance(v, list):
            raise ValueError("client_authorization_grants must be a list")

        for namespace in v:
            if not isinstance(namespace, str):
                raise ValueError("All namespace grants must be strings")
            if not namespace:
                raise ValueError("Namespace grants cannot be empty strings")
            # Validate DNS-1123 subdomain (Kubernetes namespace naming rules)
            if len(namespace) > 63:
                raise ValueError(f"Namespace '{namespace}' exceeds 63 characters")
            if not namespace.replace("-", "").replace("_", "").isalnum():
                raise ValueError(f"Namespace '{namespace}' contains invalid characters")
            if namespace.startswith("-") or namespace.endswith("-"):
                raise ValueError(
                    f"Namespace '{namespace}' cannot start or end with hyphen"
                )

        return v

    def to_keycloak_config(self, include_flow_bindings: bool = True) -> dict[str, Any]:
        """
        Convert the realm specification to Keycloak API format.

        Args:
            include_flow_bindings: Whether to include flow binding fields.
                                   Set to False when creating realm initially
                                   (flows don't exist yet).

        Returns:
            Dictionary in Keycloak Admin API format
        """
        config = {
            "realm": self.realm_name,
            "displayName": self.display_name,
            "description": self.description,
            "displayNameHtml": self.login_page_title,
            "enabled": True,  # Realms are always enabled (K8s-native: resource exists = enabled)
            "attributes": self.attributes.copy(),
        }

        # Add theme configuration
        if self.themes:
            config.update(
                {
                    "loginTheme": self.themes.login,
                    "adminTheme": self.themes.admin,
                    "accountTheme": self.themes.account,
                    "emailTheme": self.themes.email,
                }
            )

        # Add localization settings
        if self.localization:
            config.update(
                {
                    "defaultLocale": self.localization.default_locale,
                    "supportedLocales": self.localization.supported_locales,
                    "internationalizationEnabled": self.localization.enabled,
                }
            )

        # Add token settings
        config.update(
            {
                "accessTokenLifespan": self.token_settings.access_token_lifespan,
                "accessTokenLifespanForImplicitFlow": self.token_settings.access_token_lifespan_for_implicit_flow,
                "ssoSessionIdleTimeout": self.token_settings.sso_session_idle_timeout,
                "ssoSessionMaxLifespan": self.token_settings.sso_session_max_lifespan,
                "offlineSessionIdleTimeout": self.token_settings.offline_session_idle_timeout,
                "offlineSessionMaxLifespanEnabled": self.token_settings.offline_session_max_lifespan_enabled,
                "offlineSessionMaxLifespan": self.token_settings.offline_session_max_lifespan,
                "clientSessionIdleTimeout": self.token_settings.client_session_idle_timeout,
                "clientSessionMaxLifespan": self.token_settings.client_session_max_lifespan,
            }
        )

        # Add security settings
        security = self.security
        config.update(
            {
                "sslRequired": security.ssl_required,
                "bruteForceProtected": security.brute_force_protected,
                "permanentLockout": security.permanent_lockout,
                "failureFactor": security.failure_factor,
                "maxFailureWaitSeconds": security.max_failure_wait,
                "minimumQuickLoginWaitSeconds": security.minimum_quick_login_wait,
                "waitIncrementSeconds": security.wait_increment,
                "quickLoginCheckMilliSeconds": security.quick_login_check_millis,
                "maxDeltaTimeSeconds": security.max_delta_time,
                "revokeRefreshToken": security.revoke_refresh_token,
                "refreshTokenMaxReuse": security.refresh_token_max_reuse,
                "registrationAllowed": security.registration_allowed,
                "registrationEmailAsUsername": security.registration_email_as_username,
                "editUsernameAllowed": security.edit_username_allowed,
                "resetPasswordAllowed": security.reset_password_allowed,
                "rememberMe": security.remember_me,
                "verifyEmail": security.verify_email,
                "loginWithEmailAllowed": security.login_with_email_allowed,
                "duplicateEmailsAllowed": security.duplicate_emails_allowed,
            }
        )

        # Add SMTP configuration
        if self.smtp_server:
            # Map Python field names to Keycloak API field names
            smtp = self.smtp_server
            smtp_config = {
                "host": smtp.host,
                "port": str(smtp.port),
                "from": smtp.from_address,
                "auth": str(smtp.auth).lower(),
                "ssl": str(smtp.ssl).lower(),
                "starttls": str(smtp.starttls).lower(),
            }
            # Add optional fields if present
            if smtp.from_display_name:
                smtp_config["fromDisplayName"] = smtp.from_display_name
            if smtp.reply_to:
                smtp_config["replyTo"] = smtp.reply_to
            if smtp.envelope_from:
                smtp_config["envelopeFrom"] = smtp.envelope_from
            if smtp.user:
                smtp_config["user"] = smtp.user
            # Password is injected by reconciler, not included here

            config["smtpServer"] = smtp_config

        # Add password policy
        if self.password_policy:
            policy_string = self.password_policy.to_policy_string()
            if policy_string:
                config["passwordPolicy"] = policy_string

        # Add events configuration
        events = self.events_config
        config.update(
            {
                "eventsEnabled": events.events_enabled,
                "eventsListeners": events.events_listeners,
                "enabledEventTypes": events.enabled_event_types,
                "eventsExpiration": events.events_expiration,
                "adminEventsEnabled": events.admin_events_enabled,
                "adminEventsDetailsEnabled": events.admin_events_details_enabled,
            }
        )

        # Add authentication flow bindings (only if specified and requested)
        if include_flow_bindings:
            if self.browser_flow:
                config["browserFlow"] = self.browser_flow
            if self.registration_flow:
                config["registrationFlow"] = self.registration_flow
            if self.direct_grant_flow:
                config["directGrantFlow"] = self.direct_grant_flow
            if self.reset_credentials_flow:
                config["resetCredentialsFlow"] = self.reset_credentials_flow
            if self.client_authentication_flow:
                config["clientAuthenticationFlow"] = self.client_authentication_flow
            if self.docker_authentication_flow:
                config["dockerAuthenticationFlow"] = self.docker_authentication_flow
            if self.first_broker_login_flow:
                config["firstBrokerLoginFlow"] = self.first_broker_login_flow

        return config


class KeycloakRealmCondition(BaseModel):
    """Status condition for KeycloakRealm resource."""

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


class KeycloakRealmEndpoints(BaseModel):
    """Endpoints for the KeycloakRealm."""

    model_config = {"populate_by_name": True}

    issuer: str | None = Field(None, description="Issuer endpoint")
    auth: str | None = Field(None, description="Authorization endpoint")
    token: str | None = Field(None, description="Token endpoint")
    userinfo: str | None = Field(None, description="Userinfo endpoint")
    jwks: str | None = Field(None, description="JWKS endpoint")
    end_session: str | None = Field(
        None, alias="endSession", description="End session endpoint"
    )
    registration: str | None = Field(None, description="Registration endpoint")


class KeycloakRealmFeatures(BaseModel):
    """Features configured for the realm."""

    model_config = {"populate_by_name": True}

    user_registration: bool = Field(
        False, alias="userRegistration", description="User registration enabled"
    )
    password_reset: bool = Field(
        False, alias="passwordReset", description="Password reset enabled"
    )
    identity_providers: int = Field(
        0, alias="identityProviders", description="Number of identity providers"
    )
    user_federation_providers: int = Field(
        0,
        alias="userFederationProviders",
        description="Number of user federation providers",
    )
    custom_themes: bool = Field(
        False, alias="customThemes", description="Custom themes configured"
    )


class KeycloakRealmStatus(BaseModel):
    """
    Status of a KeycloakRealm resource.

    This model represents the current state of a realm as managed
    by the operator.
    """

    model_config = {"populate_by_name": True}

    # Overall status
    phase: str = Field("Pending", description="Current phase of the realm")
    message: str | None = Field(None, description="Human-readable status message")
    reason: str | None = Field(None, description="Reason for current phase")

    # Detailed status
    conditions: list[KeycloakRealmCondition] = Field(
        default_factory=list, description="Detailed status conditions"
    )
    observed_generation: int | None = Field(
        None,
        alias="observedGeneration",
        description="Generation of the spec that was last processed",
    )

    # Realm information
    realm_name: str | None = Field(
        None, alias="realmName", description="Keycloak realm name"
    )
    internal_id: str | None = Field(
        None, alias="internalId", description="Internal Keycloak realm ID"
    )
    keycloak_instance: str | None = Field(
        None,
        alias="keycloakInstance",
        description="Keycloak instance reference (namespace/name)",
    )

    # Authorization status
    authorized_client_namespaces: list[str] = Field(
        default_factory=list,
        alias="authorizedClientNamespaces",
        description="Current list of namespaces authorized to create clients",
    )

    # Endpoints
    endpoints: KeycloakRealmEndpoints = Field(
        default_factory=KeycloakRealmEndpoints, description="Realm endpoints"
    )

    # Feature status
    features: KeycloakRealmFeatures = Field(
        default_factory=KeycloakRealmFeatures, description="Configured features"
    )

    # Health and monitoring
    last_health_check: str | None = Field(
        None, alias="lastHealthCheck", description="Timestamp of last health check"
    )
    last_updated: str | None = Field(
        None, alias="lastUpdated", description="Timestamp of last successful update"
    )

    # Statistics
    active_users: int | None = Field(
        None, alias="activeUsers", description="Number of active users in realm"
    )
    total_clients: int | None = Field(
        None, alias="totalClients", description="Total number of clients"
    )
    realm_roles_count: int | None = Field(
        None, alias="realmRolesCount", description="Number of realm roles"
    )


class KeycloakRealm(BaseModel):
    """
    Complete KeycloakRealm custom resource model.

    This represents the full Kubernetes custom resource for comprehensive
    realm management with authentication flows and identity providers.
    """

    api_version: str = Field("vriesdemichael.github.io/v1", alias="apiVersion")
    kind: str = Field("KeycloakRealm")
    metadata: KubernetesMetadata = Field(..., description="Kubernetes metadata")
    spec: KeycloakRealmSpec = Field(..., description="Realm specification")
    status: KeycloakRealmStatus | None = Field(
        None, description="Realm status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"
