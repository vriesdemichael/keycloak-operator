"""
Pydantic models for KeycloakRealm resources.

This module defines type-safe data models for Keycloak realm specifications
and status. These models enable comprehensive realm management including
authentication flows, identity providers, and user federation.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from .common import AuthorizationSecretRef


class OperatorRef(BaseModel):
    """Reference to the operator managing this realm."""

    model_config = {"populate_by_name": True}

    namespace: str = Field(..., description="Namespace where the operator is running")
    authorization_secret_ref: AuthorizationSecretRef = Field(
        ...,
        alias="authorizationSecretRef",
        description="Secret containing the token to authorize with the operator",
    )


class KeycloakRealmTheme(BaseModel):
    """Theme configuration for a realm."""

    login: str | None = Field(None, description="Login theme")
    admin: str | None = Field(None, description="Admin theme")
    account: str | None = Field(None, description="Account theme")
    email: str | None = Field(None, description="Email theme")


class KeycloakRealmLocalization(BaseModel):
    """Localization configuration for a realm."""

    default_locale: str = Field("en", description="Default locale")
    supported_locales: list[str] = Field(
        default_factory=lambda: ["en"], description="Supported locales"
    )
    internationalization_enabled: bool = Field(
        True, description="Enable internationalization"
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

    @field_validator(
        "access_token_lifespan", "sso_session_idle_timeout", "sso_session_max_lifespan"
    )
    @classmethod
    def validate_positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("Timeout values must be positive")
        return v


class KeycloakIdentityProvider(BaseModel):
    """Identity provider configuration."""

    alias: str = Field(..., description="Identity provider alias")
    provider_id: str = Field(..., description="Provider type ID")
    display_name: str | None = Field(None, description="Display name")
    enabled: bool = Field(True, description="Whether the provider is enabled")

    # Provider-specific configuration
    config: dict[str, Any] = Field(
        default_factory=dict, description="Provider-specific configuration"
    )

    # UI settings
    first_broker_login_flow_alias: str | None = Field(
        None, description="First broker login flow"
    )
    post_broker_login_flow_alias: str | None = Field(
        None, description="Post broker login flow"
    )
    link_only: bool = Field(False, description="Link existing users only")
    store_token: bool = Field(False, description="Store identity provider tokens")
    trust_email: bool = Field(False, description="Trust email from identity provider")

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Alias must be a non-empty string")
        return v


class KeycloakUserFederation(BaseModel):
    """User federation configuration."""

    name: str = Field(..., description="Federation provider name")
    provider_id: str = Field(..., description="Federation provider type")
    priority: int = Field(0, description="Federation priority")
    enabled: bool = Field(True, description="Whether federation is enabled")

    # Provider-specific configuration
    config: dict[str, Any] = Field(
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


class KeycloakAuthenticationFlow(BaseModel):
    """Authentication flow configuration."""

    alias: str = Field(..., description="Flow alias")
    description: str | None = Field(None, description="Flow description")
    provider_id: str = Field("basic-flow", description="Flow provider ID")
    top_level: bool = Field(True, description="Whether this is a top-level flow")
    built_in: bool = Field(False, description="Whether this is a built-in flow")

    # Flow executions
    authentication_executions: list[dict[str, Any]] = Field(
        default_factory=list, description="Authentication executions"
    )

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("Alias must be a non-empty string")
        return v


class KeycloakRealmSecurity(BaseModel):
    """Security settings for a realm."""

    # Password policy
    password_policy: str | None = Field(None, description="Password policy string")

    # Brute force protection
    brute_force_protected: bool = Field(
        False, description="Enable brute force protection"
    )
    permanent_lockout: bool = Field(
        False, description="Permanent lockout after max failures"
    )
    max_failure_wait_seconds: int = Field(
        900, description="Max wait time after failures in seconds"
    )
    minimum_quick_login_wait_seconds: int = Field(
        60, description="Minimum quick login wait in seconds"
    )
    wait_increment_seconds: int = Field(
        60, description="Wait increment per failure in seconds"
    )
    quick_login_check_milli_seconds: int = Field(
        1000, description="Quick login check interval in milliseconds"
    )
    max_delta_time_seconds: int = Field(
        43200,
        description="Max delta time for failures in seconds",  # 12 hours
    )
    failure_reset_time_seconds: int = Field(
        43200,
        description="Failure reset time in seconds",  # 12 hours
    )

    # Registration settings
    registration_allowed: bool = Field(False, description="Allow user registration")
    registration_email_as_username: bool = Field(
        False, description="Use email as username for registration"
    )
    edit_username_allowed: bool = Field(
        False, description="Allow users to edit their username"
    )
    reset_password_allowed: bool = Field(True, description="Allow password reset")
    remember_me: bool = Field(False, description="Enable remember me")
    verify_email: bool = Field(False, description="Require email verification")
    login_with_email_allowed: bool = Field(True, description="Allow login with email")
    duplicate_emails_allowed: bool = Field(
        False, description="Allow duplicate email addresses"
    )

    @field_validator("max_failure_wait_seconds", "minimum_quick_login_wait_seconds")
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

    name: str = Field(..., description="Role name")
    description: str | None = Field(None, description="Role description")
    composite: bool = Field(False, description="Is composite role")
    client_role: bool = Field(False, description="Is client role")
    container_id: str | None = Field(None, description="Container ID")


class KeycloakRoles(BaseModel):
    """Realm and client role definitions."""

    realm_roles: list[KeycloakRealmRole] = Field(
        default_factory=list, description="Realm roles"
    )


class KeycloakGroup(BaseModel):
    """Group definition."""

    name: str = Field(..., description="Group name")
    path: str | None = Field(None, description="Group path")
    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Group attributes"
    )
    realm_roles: list[str] = Field(
        default_factory=list, description="Assigned realm roles"
    )
    client_roles: dict[str, list[str]] = Field(
        default_factory=dict, description="Assigned client roles by client ID"
    )


class KeycloakEventsConfig(BaseModel):
    """Event logging configuration."""

    events_enabled: bool = Field(False, description="Enable event logging")
    events_listeners: list[str] = Field(
        default_factory=list, description="Event listeners"
    )
    enabled_event_types: list[str] = Field(
        default_factory=list, description="Enabled event types"
    )
    events_expiration: int | None = Field(
        None, description="Event expiration in seconds", ge=1
    )
    admin_events_enabled: bool = Field(False, description="Enable admin event logging")
    admin_events_details_enabled: bool = Field(
        False, description="Include details in admin events"
    )


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

    # SMTP configuration
    smtp_server: KeycloakSMTPConfig | None = Field(
        None, alias="smtpServer", description="SMTP server configuration"
    )

    # Advanced settings
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Additional realm attributes"
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

    def to_keycloak_config(self) -> dict[str, Any]:
        """
        Convert the realm specification to Keycloak API format.

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
                    "internationalizationEnabled": self.localization.internationalization_enabled,
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
                "passwordPolicy": security.password_policy,
                "bruteForceProtected": security.brute_force_protected,
                "permanentLockout": security.permanent_lockout,
                "maxFailureWaitSeconds": security.max_failure_wait_seconds,
                "minimumQuickLoginWaitSeconds": security.minimum_quick_login_wait_seconds,
                "waitIncrementSeconds": security.wait_increment_seconds,
                "quickLoginCheckMilliSeconds": security.quick_login_check_milli_seconds,
                "maxDeltaTimeSeconds": security.max_delta_time_seconds,
                "failureResetTimeSeconds": security.failure_reset_time_seconds,
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

    # Authorization
    authorization_secret_name: str | None = Field(
        None,
        alias="authorizationSecretName",
        description="Name of the secret containing the realm's authorization token",
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

    api_version: str = Field("keycloak.mdvr.nl/v1", alias="apiVersion")
    kind: str = Field("KeycloakRealm")
    metadata: dict[str, Any] = Field(..., description="Kubernetes metadata")
    spec: KeycloakRealmSpec = Field(..., description="Realm specification")
    status: KeycloakRealmStatus | None = Field(
        None, description="Realm status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"
