# KeycloakClient CRD Reference

Complete reference for the `KeycloakClient` Custom Resource Definition.

## Overview

The `KeycloakClient` CRD defines a Keycloak client - an OAuth2/OIDC application that uses Keycloak for authentication and authorization. Clients can be web applications, mobile apps, APIs, or service-to-service integrations.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `KeycloakClient`
**Plural:** `keycloakclients`
**Singular:** `keycloakclient`
**Short Names:** `kcc`

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: my-app
  namespace: my-team
spec:
  clientId: my-app
  realmRef:
    name: my-realm
    namespace: my-team
    authorizationSecretRef:
      name: my-realm-auth-token
```

## Spec Fields

### Core Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `clientId` | `string` | **Yes** | - | Unique client identifier (1-255 characters) |
| `clientName` | `string` | No | - | Human-readable client name |
| `description` | `string` | No | - | Client description |

**Example:**
```yaml
spec:
  clientId: webapp-production
  clientName: "Production Web Application"
  description: "Customer-facing web application"
```

### Realm Reference (Required)

Reference to the parent KeycloakRealm and authorization token.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `realmRef.name` | `string` | **Yes** | - | Name of the KeycloakRealm CR |
| `realmRef.namespace` | `string` | **Yes** | - | Namespace of the KeycloakRealm CR |
| `realmRef.authorizationSecretRef.name` | `string` | **Yes** | - | Name of the realm's authorization secret |
| `realmRef.authorizationSecretRef.key` | `string` | No | `token` | Key within the secret containing the token |

**Example:**
```yaml
spec:
  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth-token
```

### Client Type Configuration

Configure the basic client type and protocol.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `publicClient` | boolean | No | `false` | Whether this is a public client (no client secret). Use `true` for SPAs and mobile apps. |
| `bearerOnly` | boolean | No | `false` | Bearer-only client (for APIs that only verify tokens, don't initiate login) |
| `protocol` | `string` | No | `openid-connect` | Client protocol. Options: `openid-connect`, `saml`, `docker-v2` |

**Client Types:**

- **Confidential Client** (`publicClient: false`): Server-side applications that can securely store client secrets (traditional web apps, backend services)
- **Public Client** (`publicClient: true`): Applications that cannot securely store secrets (SPAs, mobile apps, CLIs)
- **Bearer-Only** (`bearerOnly: true`): APIs that only validate tokens, don't initiate login flows

**Example - Confidential:**
```yaml
spec:
  publicClient: false  # Server-side web app
```

**Example - Public:**
```yaml
spec:
  publicClient: true  # Single Page Application
```

**Example - Bearer-Only:**
```yaml
spec:
  bearerOnly: true  # Resource server / API
  publicClient: false
```

### OAuth2/OIDC Configuration

Configure redirect URIs and web origins for OAuth2/OIDC flows.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `redirectUris` | []`string` | No | `[]` | Valid redirect URIs (callback URLs). Use `*` for local development only. |
| `webOrigins` | []`string` | No | `[]` | Valid web origins for CORS. Use `*` for local development only. |
| `postLogoutRedirectUris` | []`string` | No | `[]` | Valid post-logout redirect URIs |

**Example - Web Application:**
```yaml
spec:
  redirectUris:
    - "https://app.example.com/callback"
    - "https://app.example.com/silent-renew"
  webOrigins:
    - "https://app.example.com"
  postLogoutRedirectUris:
    - "https://app.example.com"
```

**Example - Development (⚠️ Do not use in production):**
```yaml
spec:
  redirectUris:
    - "http://localhost:3000/*"
  webOrigins:
    - "*"  # Allow all origins
```

### Client Settings

Advanced client configuration options.

#### Basic Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `settings.enabled` | boolean | No | `true` | Enable/disable the client |
| `settings.alwaysDisplayInConsole` | boolean | No | `false` | Always display in admin console |
| `settings.clientAuthenticatorType` | `string` | No | `client-secret` | Client authentication type. Options: `client-secret`, `client-jwt`, `client-secret-jwt`, `client-x509` |

#### OAuth2 Flow Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `settings.standardFlowEnabled` | boolean | No | `true` | Enable standard flow (authorization code flow) - recommended for web apps |
| `settings.implicitFlowEnabled` | boolean | No | `false` | Enable implicit flow (deprecated, use PKCE instead) |
| `settings.directAccessGrantsEnabled` | boolean | No | `true` | Enable direct access grants (resource owner password credentials flow) |
| `settings.serviceAccountsEnabled` | boolean | No | `false` | Enable service accounts (client credentials flow) for M2M |

**OAuth2 Flow Guide:**

- **Authorization Code Flow** (`standardFlowEnabled: true`): Best for traditional web apps with backend
- **Authorization Code + PKCE** (`standardFlowEnabled: true`, `publicClient: true`): Best for SPAs and mobile apps
- **Client Credentials** (`serviceAccountsEnabled: true`): Best for machine-to-machine (service accounts)
- **Resource Owner Password** (`directAccessGrantsEnabled: true`): Only use when other flows are not possible

**Example - Web App:**
```yaml
spec:
  publicClient: false
  settings:
    standardFlowEnabled: true
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: false
```

**Example - SPA with PKCE:**
```yaml
spec:
  publicClient: true
  settings:
    standardFlowEnabled: true
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false
```

**Example - Service Account (M2M):**
```yaml
spec:
  publicClient: false
  settings:
    standardFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: true
```

#### Consent and Token Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `settings.consentRequired` | boolean | No | `false` | Require user consent |
| `settings.displayOnConsentScreen` | boolean | No | `true` | Display on consent screen |
| `settings.includeInTokenScope` | boolean | No | `true` | Include in token scope |
| `settings.accessTokenLifespan` | integer | No | - | Access token lifespan in seconds (overrides realm default) |
| `settings.refreshTokenLifespan` | integer | No | - | Refresh token lifespan in seconds (overrides realm default) |

**Example:**
```yaml
spec:
  settings:
    consentRequired: true  # Require user consent
    accessTokenLifespan: 600  # 10 minutes
    refreshTokenLifespan: 86400  # 24 hours
```

### Authentication Flows

Override default authentication flows for this client.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `authenticationFlows.browserFlow` | `string` | No | - | Browser authentication flow override |
| `authenticationFlows.directGrantFlow` | `string` | No | - | Direct grant authentication flow override |
| `authenticationFlows.clientAuthenticationFlow` | `string` | No | - | Client authentication flow override |

**Example:**
```yaml
spec:
  authenticationFlows:
    browserFlow: browser-with-mfa
    directGrantFlow: direct-grant-with-otp
```

### Scopes and Mappers

Configure client scopes and protocol mappers for claims customization.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `defaultClientScopes` | []`string` | No | `[]` | Default client scopes (always included) |
| `optionalClientScopes` | []`string` | No | `[]` | Optional client scopes (user can opt-in) |
| `protocolMappers` | []object | No | `[]` | Protocol mappers for custom claims |
| `protocolMappers[].name` | `string` | **Yes** | - | Mapper name |
| `protocolMappers[].protocol` | `string` | No | `openid-connect` | Protocol (e.g., `openid-connect`, `saml`) |
| `protocolMappers[].protocolMapper` | `string` | **Yes** | - | Mapper type |
| `protocolMappers[].config` | map[`string`]`string` | No | `{}` | Mapper configuration |

**Common Protocol Mappers:**

- `oidc-usermodel-attribute-mapper`: Map user attribute to claim
- `oidc-usermodel-property-mapper`: Map user property to claim
- `oidc-group-membership-mapper`: Map group memberships to claim
- `oidc-audience-mapper`: Add audience to token
- `oidc-hardcoded-claim-mapper`: Add static claim

**Example - User Attribute Mapper:**
```yaml
spec:
  protocolMappers:
    - name: department-mapper
      protocol: openid-connect
      protocolMapper: oidc-usermodel-attribute-mapper
      config:
        user.attribute: department
        claim.name: department
        jsonType.label: String
        id.token.claim: "true"
        access.token.claim: "true"
        userinfo.token.claim: "true"
```

**Example - Audience Mapper:**
```yaml
spec:
  protocolMappers:
    - name: api-audience
      protocol: openid-connect
      protocolMapper: oidc-audience-mapper
      config:
        included.client.audience: api-server
        access.token.claim: "true"
```

**Example - Hardcoded Claim:**
```yaml
spec:
  protocolMappers:
    - name: environment-claim
      protocol: openid-connect
      protocolMapper: oidc-hardcoded-claim-mapper
      config:
        claim.name: environment
        claim.value: production
        access.token.claim: "true"
```

### Roles and Permissions

Configure client-specific roles and service account permissions.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `clientRoles` | []`string` | No | `[]` | Client-specific roles to create |
| `serviceAccountRoles.realmRoles` | []`string` | No | `[]` | Realm roles to assign to service account |
| `serviceAccountRoles.clientRoles` | map[`string`][]`string` | No | `{}` | Client roles to assign to service account (by client ID) |

**Example - Client Roles:**
```yaml
spec:
  clientRoles:
    - admin
    - editor
    - viewer
```

**Example - Service Account with Permissions:**
```yaml
spec:
  settings:
    serviceAccountsEnabled: true
  serviceAccountRoles:
    realmRoles:
      - offline_access
      - uma_authorization
    clientRoles:
      api-server:
        - read:data
        - write:data
      admin-console:
        - view-users
```

### Advanced Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `attributes` | map[`string`]`string` | No | `{}` | Additional client attributes |

**Example:**
```yaml
spec:
  attributes:
    pkce.code.challenge.method: S256  # Require PKCE with SHA-256
    post.logout.redirect.uris: "+"  # Allow any registered redirect URI
```

### Secret Management

Configure how client credentials are managed.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `regenerateSecret` | boolean | No | `false` | Regenerate client secret on update |
| `secretName` | `string` | No | `<client-name>-client-secret` | Name of Kubernetes secret for client credentials |
| `manageSecret` | boolean | No | `true` | Create and manage Kubernetes secret for credentials |

**Example:**
```yaml
spec:
  manageSecret: true
  secretName: webapp-credentials
  regenerateSecret: false  # Only regenerate manually
```

The operator creates a secret with the following keys:
- `client-id`: Client ID
- `client-secret`: Client secret (confidential clients only)
- `issuer`: OIDC issuer URL
- `token-endpoint`: Token endpoint URL
- `auth-endpoint`: Authorization endpoint URL

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | `string` | Current phase: `Pending`, `Provisioning`, `Ready`, `Failed`, `Updating`, `Degraded` |
| `message` | `string` | Human-readable status message |
| `reason` | `string` | Reason for current phase |
| `observedGeneration` | integer | Generation of spec that was last processed |
| `clientId` | `string` | Client ID in Keycloak |
| `internalId` | `string` | Internal Keycloak client ID (UUID) |
| `realm` | `string` | Realm name |
| `publicClient` | boolean | Whether this is a public client |
| `keycloakInstance` | `string` | Keycloak instance managing this client |
| `credentialsSecret` | `string` | Name of secret containing client credentials |
| `endpoints.auth` | `string` | OIDC authorization endpoint |
| `endpoints.token` | `string` | OIDC token endpoint |
| `endpoints.userinfo` | `string` | OIDC userinfo endpoint |
| `endpoints.jwks` | `string` | OIDC JWKS endpoint |
| `endpoints.issuer` | `string` | OIDC issuer |
| `endpoints.endSession` | `string` | OIDC end session endpoint |
| `createdRoles` | []`string` | List of created client roles |
| `appliedMappers` | []`string` | List of applied protocol mappers |
| `lastHealthCheck` | `string` (datetime) | Last health check timestamp |
| `lastUpdated` | `string` (datetime) | Last update timestamp |

## Complete Examples

### Web Application (Confidential)

Traditional server-side web application with backend.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: webapp
  namespace: production
spec:
  clientId: webapp-production
  clientName: "Production Web App"

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  publicClient: false  # Confidential client

  redirectUris:
    - "https://app.example.com/callback"
    - "https://app.example.com/silent-renew"
  webOrigins:
    - "https://app.example.com"
  postLogoutRedirectUris:
    - "https://app.example.com"

  settings:
    standardFlowEnabled: true  # Authorization code flow
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: false
    consentRequired: false

  defaultClientScopes:
    - profile
    - email
    - roles
```

### Single Page Application (Public with PKCE)

Modern SPA using authorization code flow with PKCE.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: spa
  namespace: production
spec:
  clientId: spa-production

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  publicClient: true  # Public client (no secret)

  redirectUris:
    - "https://app.example.com/callback"
    - "https://app.example.com/silent-renew.html"
  webOrigins:
    - "https://app.example.com"

  settings:
    standardFlowEnabled: true  # Auth code + PKCE
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false

  attributes:
    pkce.code.challenge.method: S256  # Require PKCE with SHA-256
```

### Mobile Application (Public with PKCE)

Mobile app using custom URI schemes.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: mobile-app
  namespace: production
spec:
  clientId: mobile-app

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  publicClient: true

  redirectUris:
    - "myapp://callback"  # Custom URI scheme
    - "com.example.myapp://callback"  # Reverse domain notation

  settings:
    standardFlowEnabled: true  # Auth code + PKCE
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false

  attributes:
    pkce.code.challenge.method: S256
```

### API / Resource Server (Bearer-Only)

Backend API that only validates tokens.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: api-server
  namespace: production
spec:
  clientId: api-server

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  bearerOnly: true  # Only validates tokens, doesn't initiate login
  publicClient: false
```

### Service Account (Machine-to-Machine)

Backend service using client credentials flow.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: backend-service
  namespace: production
spec:
  clientId: backend-service

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  publicClient: false

  settings:
    standardFlowEnabled: false  # No interactive flows
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: true  # Client credentials flow

  serviceAccountRoles:
    realmRoles:
      - offline_access
    clientRoles:
      api-server:
        - read:data
        - write:data
```

### Client with Custom Claims

Client with custom protocol mappers for additional claims.

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: webapp-with-claims
  namespace: production
spec:
  clientId: webapp

  realmRef:
    name: production-realm
    namespace: production
    authorizationSecretRef:
      name: production-realm-auth

  redirectUris:
    - "https://app.example.com/callback"

  protocolMappers:
    # Map user department to claim
    - name: department
      protocolMapper: oidc-usermodel-attribute-mapper
      config:
        user.attribute: department
        claim.name: department
        jsonType.label: String
        id.token.claim: "true"
        access.token.claim: "true"
        userinfo.token.claim: "true"

    # Map groups to claim
    - name: groups
      protocolMapper: oidc-group-membership-mapper
      config:
        claim.name: groups
        full.path: "false"
        id.token.claim: "true"
        access.token.claim: "true"
        userinfo.token.claim: "true"

    # Add static environment claim
    - name: environment
      protocolMapper: oidc-hardcoded-claim-mapper
      config:
        claim.name: env
        claim.value: production
        access.token.claim: "true"

    # Add audience
    - name: api-audience
      protocolMapper: oidc-audience-mapper
      config:
        included.client.audience: api-server
        access.token.claim: "true"
```

## Retrieving Client Credentials

For confidential clients, credentials are stored in a Kubernetes secret:

```bash
# Get client secret
kubectl get secret webapp-client-secret \
  -n production \
  -o jsonpath='{.data.client-secret}' | base64 -d

# Get all credentials
kubectl get secret webapp-client-secret \
  -n production \
  -o json | jq '.data | map_values(@base64d)'
```

## See Also

- [Keycloak CRD Reference](keycloak-crd.md)
- [KeycloakRealm CRD Reference](keycloak-realm-crd.md)
- See charts/keycloak-client/README.md in the repository root
- [Quick Start Guide](../quickstart/README.md)
