"""
Pydantic models for KeycloakClient resources.

This module defines type-safe data models for Keycloak client specifications
and status. These models enable dynamic client provisioning across namespaces
with proper validation and GitOps compatibility.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from .keycloak import KeycloakInstanceRef


class KeycloakClientScope(BaseModel):
    """Configuration for client scopes."""

    name: str = Field(..., description="Scope name")
    default: bool = Field(True, description="Whether this is a default scope")
    optional: bool = Field(False, description="Whether this is an optional scope")


class KeycloakClientProtocolMapper(BaseModel):
    """Configuration for protocol mappers."""

    name: str = Field(..., description="Mapper name")
    protocol: str = Field("openid-connect", description="Protocol type")
    protocol_mapper: str = Field(..., description="Mapper type")
    config: dict[str, Any] = Field(
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

    browser_flow: str | None = Field(None, description="Browser authentication flow")
    direct_grant_flow: str | None = Field(
        None, description="Direct grant authentication flow"
    )
    client_authentication_flow: str | None = Field(
        None, description="Client authentication flow"
    )


class KeycloakClientSettings(BaseModel):
    """Advanced client settings."""

    # Basic settings
    enabled: bool = Field(True, description="Whether the client is enabled")
    always_display_in_console: bool = Field(
        False, description="Always display in admin console"
    )
    client_authenticator_type: str = Field(
        "client-secret", description="Client authenticator type"
    )

    # Access settings
    standard_flow_enabled: bool = Field(
        True, description="Enable standard flow (authorization code flow)"
    )
    implicit_flow_enabled: bool = Field(False, description="Enable implicit flow")
    direct_access_grants_enabled: bool = Field(
        True, description="Enable direct access grants (password flow)"
    )
    service_accounts_enabled: bool = Field(False, description="Enable service accounts")

    # Advanced settings
    consent_required: bool = Field(False, description="Require user consent")
    display_on_consent_screen: bool = Field(
        True, description="Display on consent screen"
    )
    include_in_token_scope: bool = Field(True, description="Include in token scope")

    # Token settings
    access_token_lifespan: int | None = Field(
        None, description="Access token lifespan in seconds"
    )
    refresh_token_lifespan: int | None = Field(
        None, description="Refresh token lifespan in seconds"
    )

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


class KeycloakClientSpec(BaseModel):
    """
    Specification for a KeycloakClient resource.

    This model defines all configurable aspects of a Keycloak client
    including authentication, authorization, and protocol settings.
    """

    # Core client configuration
    client_id: str = Field(..., description="Unique client identifier")
    client_name: str | None = Field(None, description="Human-readable client name")
    description: str | None = Field(None, description="Client description")

    # Target configuration
    keycloak_instance_ref: KeycloakInstanceRef = Field(
        ..., description="Reference to the target Keycloak instance"
    )
    realm: str = Field("master", description="Target realm name")

    # Client type configuration
    public_client: bool = Field(False, description="Whether this is a public client")
    bearer_only: bool = Field(False, description="Bearer-only client")
    protocol: str = Field("openid-connect", description="Client protocol")

    # OAuth2/OIDC configuration
    redirect_uris: list[str] = Field(
        default_factory=list, description="Valid redirect URIs"
    )
    web_origins: list[str] = Field(
        default_factory=list, description="Valid web origins for CORS"
    )
    post_logout_redirect_uris: list[str] = Field(
        default_factory=list, description="Valid post-logout redirect URIs"
    )

    # Client settings
    settings: KeycloakClientSettings = Field(
        default_factory=KeycloakClientSettings, description="Advanced client settings"
    )

    # Authentication flows
    authentication_flows: KeycloakClientAuthenticationFlow = Field(
        default_factory=KeycloakClientAuthenticationFlow,
        description="Client authentication flow overrides",
    )

    # Scopes and mappers
    default_client_scopes: list[str] = Field(
        default_factory=list, description="Default client scopes"
    )
    optional_client_scopes: list[str] = Field(
        default_factory=list, description="Optional client scopes"
    )
    protocol_mappers: list[KeycloakClientProtocolMapper] = Field(
        default_factory=list, description="Protocol mappers"
    )

    # Roles and permissions
    client_roles: list[str] = Field(
        default_factory=list, description="Client-specific roles to create"
    )

    # Advanced configuration
    attributes: dict[str, str] = Field(
        default_factory=dict, description="Additional client attributes"
    )

    # Secret management
    regenerate_secret: bool = Field(
        False, description="Regenerate client secret on update"
    )
    secret_name: str | None = Field(
        None, description="Name of Kubernetes secret for client credentials"
    )

    # GitOps settings
    manage_secret: bool = Field(
        True, description="Create and manage Kubernetes secret for credentials"
    )

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
    def validate_redirect_uris(cls, v):
        for uri in v:
            if "*" in uri:
                raise ValueError("Wildcard characters not allowed in redirect URIs")
        return v

    def to_keycloak_config(self) -> dict[str, Any]:
        """
        Convert the client specification to Keycloak API format.

        Returns:
            Dictionary in Keycloak Admin API format
        """
        config = {
            "clientId": self.client_id,
            "name": self.client_name or self.client_id,
            "description": self.description,
            "protocol": self.protocol,
            "publicClient": self.public_client,
            "bearerOnly": self.bearer_only,
            "enabled": self.settings.enabled,
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

    type: str = Field(..., description="Condition type")
    status: str = Field(..., description="Condition status (True/False/Unknown)")
    reason: str | None = Field(None, description="Reason for the condition")
    message: str | None = Field(None, description="Human-readable message")
    last_transition_time: str | None = Field(
        None, description="Last time the condition transitioned"
    )


class KeycloakClientEndpoints(BaseModel):
    """Endpoints for the KeycloakClient."""

    auth: str | None = Field(None, description="Authorization endpoint")
    token: str | None = Field(None, description="Token endpoint")
    userinfo: str | None = Field(None, description="UserInfo endpoint")
    jwks: str | None = Field(None, description="JWKS endpoint")
    issuer: str | None = Field(None, description="Issuer URL")
    end_session: str | None = Field(None, description="End session (logout) endpoint")


class KeycloakClientStatus(BaseModel):
    """
    Status of a KeycloakClient resource.

    This model represents the current state of a client as managed
    by the operator.
    """

    # Overall status
    phase: str = Field("Pending", description="Current phase of the client")
    message: str | None = Field(None, description="Human-readable status message")
    reason: str | None = Field(None, description="Reason for current phase")

    # Detailed status
    conditions: list[KeycloakClientCondition] = Field(
        default_factory=list, description="Detailed status conditions"
    )
    observed_generation: int | None = Field(
        None, description="Generation of the spec that was last processed"
    )

    # Client information
    client_id: str | None = Field(None, description="Keycloak client ID")
    internal_id: str | None = Field(None, description="Internal Keycloak client UUID")
    realm: str | None = Field(None, description="Target realm")
    public_client: bool | None = Field(
        None, description="Whether this is a public client"
    )

    # Connection information
    keycloak_instance: str | None = Field(
        None, description="Keycloak instance reference (namespace/name)"
    )
    credentials_secret: str | None = Field(
        None, description="Name of the credentials secret"
    )

    # Endpoints
    endpoints: KeycloakClientEndpoints = Field(
        default_factory=KeycloakClientEndpoints, description="Client endpoints"
    )

    # Health and monitoring
    last_health_check: str | None = Field(
        None, description="Timestamp of last health check"
    )
    last_updated: str | None = Field(
        None, description="Timestamp of last successful update"
    )

    # Statistics
    created_roles: list[str] = Field(
        default_factory=list, description="Client roles that were created"
    )
    applied_mappers: list[str] = Field(
        default_factory=list, description="Protocol mappers that were applied"
    )


class KeycloakClient(BaseModel):
    """
    Complete KeycloakClient custom resource model.

    This represents the full Kubernetes custom resource for dynamic
    client provisioning with cross-namespace support.
    """

    api_version: str = Field("keycloak.mdvr.nl/v1", alias="apiVersion")
    kind: str = Field("KeycloakClient")
    metadata: dict[str, Any] = Field(..., description="Kubernetes metadata")
    spec: KeycloakClientSpec = Field(..., description="Client specification")
    status: KeycloakClientStatus | None = Field(
        None, description="Client status (managed by operator)"
    )

    class Config:
        populate_by_name = True
        extra = "forbid"
