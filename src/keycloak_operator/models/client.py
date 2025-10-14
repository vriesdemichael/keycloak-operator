"""
Pydantic models for KeycloakClient resources.

This module defines type-safe data models for Keycloak client specifications
and status. These models enable dynamic client provisioning across namespaces
with proper validation and GitOps compatibility.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from .common import AuthorizationSecretRef


class RealmRef(BaseModel):
    """Reference to a parent KeycloakRealm."""

    model_config = {"populate_by_name": True}

    name: str = Field(..., description="Name of the KeycloakRealm CR")
    namespace: str = Field(..., description="Namespace of the KeycloakRealm CR")
    authorization_secret_ref: AuthorizationSecretRef = Field(
        ..., alias="authorizationSecretRef"
    )


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
    enabled: bool = Field(True, description="Whether the client is enabled")
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

    # GitOps settings
    manage_secret: bool = Field(
        True,
        alias="manageSecret",
        description="Create and manage Kubernetes secret for credentials",
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
