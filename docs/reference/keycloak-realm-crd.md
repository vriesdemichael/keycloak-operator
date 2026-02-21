# KeycloakRealm CRD Reference

Complete reference for the `KeycloakRealm` Custom Resource Definition.

## Overview

The `KeycloakRealm` CRD defines a Keycloak realm - an identity domain with users, authentication settings, and access control. Realms are isolated from each other and provide complete separation of users, clients, roles, and configuration.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `KeycloakRealm`
**Plural:** `keycloakrealms`
**Singular:** `keycloakrealm`
**Short Names:** `kcr`

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-team
spec:
  realmName: my-team
  displayName: "My Team"
  operatorRef:
    namespace: keycloak-system
```

## Spec Fields

### Core Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `realmName` | `string` | **Yes** | - | Realm name (must be unique in Keycloak, 1-255 characters) |
| `displayName` | `string` | No | - | Human-readable realm name |
| `description` | `string` | No | - | Realm description |
| `loginPageTitle` | `string` | No | - | HTML title for login pages |

**Example:**
```yaml
spec:
  realmName: production
  displayName: "Production Environment"
  description: "Production realm for customer-facing applications"
  loginPageTitle: "Production Login"
```

### Operator Reference (Required)

Reference to the Keycloak operator.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `operatorRef.namespace` | `string` | **Yes** | - | Namespace where the operator is running (e.g., `keycloak-system`) |

**Example:**
```yaml
spec:
  operatorRef:
    namespace: keycloak-system
```

**Example - Additional realms (auto-discovery):**
```yaml
spec:
  operatorRef:
    namespace: keycloak-system
```

### Security Settings

Comprehensive security and authentication configuration.

#### Registration and Email

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `security.registrationAllowed` | boolean | No | `false` | Allow user self-registration |
| `security.registrationEmailAsUsername` | boolean | No | `false` | Use email as username for registration |
| `security.editUsernameAllowed` | boolean | No | `false` | Allow users to edit their username |
| `security.resetPasswordAllowed` | boolean | No | `true` | Allow password reset |
| `security.rememberMe` | boolean | No | `false` | Show "Remember Me" checkbox on login |
| `security.verifyEmail` | boolean | No | `false` | Require email verification |
| `security.loginWithEmailAllowed` | boolean | No | `true` | Allow login with email address |
| `security.duplicateEmailsAllowed` | boolean | No | `false` | Allow multiple users with same email |

**Example:**
```yaml
spec:
  security:
    registrationAllowed: true
    registrationEmailAsUsername: true
    verifyEmail: true
    resetPasswordAllowed: true
    loginWithEmailAllowed: true
```

#### SSL/TLS Requirements

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `security.sslRequired` | `string` | No | `external` | SSL requirement level. Options: `all`, `external`, `none` |

- `all`: HTTPS required for all connections
- `external`: HTTPS required for external connections only
- `none`: HTTPS not required

#### Brute Force Protection

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `security.bruteForceProtected` | boolean | No | `false` | Enable brute force attack protection |
| `security.permanentLockout` | boolean | No | `false` | Permanently lock out users after max failures |
| `security.maxFailureWait` | integer | No | - | Max wait time after login failures (seconds) |
| `security.minimumQuickLoginWait` | integer | No | - | Minimum wait for quick login attempts (seconds) |
| `security.waitIncrement` | integer | No | - | Incremental wait time (seconds) |
| `security.quickLoginCheckMillis` | integer | No | - | Time window for quick login detection (milliseconds) |
| `security.maxDeltaTime` | integer | No | - | Maximum time delta between login attempts (seconds) |
| `security.failureFactor` | integer | No | - | Multiplier for wait time after failures |

**Example:**
```yaml
spec:
  security:
    bruteForceProtected: true
    permanentLockout: false
    maxFailureWait: 900  # 15 minutes
    minimumQuickLoginWait: 60
    waitIncrement: 60
    quickLoginCheckMillis: 1000
    maxDeltaTime: 43200  # 12 hours
    failureFactor: 30
```

#### Token and Session Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `security.revokeRefreshToken` | boolean | No | `false` | Revoke refresh tokens after use |
| `security.refreshTokenMaxReuse` | integer | No | - | Max times a refresh token can be reused (min: 0) |

### Token Settings

Configure token lifespans and session timeouts.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tokenSettings.accessTokenLifespan` | integer | No | - | Access token lifespan in seconds |
| `tokenSettings.accessTokenLifespanForImplicitFlow` | integer | No | - | Access token lifespan for implicit flow in seconds |
| `tokenSettings.ssoSessionIdleTimeout` | integer | No | - | SSO session idle timeout in seconds |
| `tokenSettings.ssoSessionMaxLifespan` | integer | No | - | SSO session max lifespan in seconds |
| `tokenSettings.offlineSessionIdleTimeout` | integer | No | - | Offline session idle timeout in seconds |
| `tokenSettings.offlineSessionMaxLifespanEnabled` | boolean | No | `false` | Enable offline session max lifespan |
| `tokenSettings.offlineSessionMaxLifespan` | integer | No | - | Offline session max lifespan in seconds |
| `tokenSettings.clientSessionIdleTimeout` | integer | No | - | Client session idle timeout in seconds |
| `tokenSettings.clientSessionMaxLifespan` | integer | No | - | Client session max lifespan in seconds |
| `tokenSettings.clientOfflineSessionIdleTimeout` | integer | No | - | Client offline session idle timeout in seconds |
| `tokenSettings.clientOfflineSessionMaxLifespan` | integer | No | - | Client offline session max lifespan in seconds |

**Example:**
```yaml
spec:
  tokenSettings:
    accessTokenLifespan: 300  # 5 minutes
    ssoSessionIdleTimeout: 1800  # 30 minutes
    ssoSessionMaxLifespan: 36000  # 10 hours
    offlineSessionIdleTimeout: 2592000  # 30 days
```

### Theme Configuration

Customize the appearance of Keycloak pages.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `themes.login` | `string` | No | - | Login page theme |
| `themes.admin` | `string` | No | - | Admin console theme |
| `themes.account` | `string` | No | - | Account management theme |
| `themes.email` | `string` | No | - | Email template theme |

**Example:**
```yaml
spec:
  themes:
    login: keycloak
    admin: keycloak
    account: keycloak
    email: keycloak
```

### SMTP Server Configuration

Configure email sending for registration, password reset, and notifications.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `smtpServer.host` | `string` | No | - | SMTP server hostname |
| `smtpServer.port` | integer | No | - | SMTP server port (1-65535) |
| `smtpServer.from` | `string` | No | - | From email address |
| `smtpServer.fromDisplayName` | `string` | No | - | From display name |
| `smtpServer.replyTo` | `string` | No | - | Reply-to email address |
| `smtpServer.envelopeFrom` | `string` | No | - | Envelope from address |
| `smtpServer.ssl` | boolean | No | `false` | Use SSL |
| `smtpServer.starttls` | boolean | No | `false` | Use STARTTLS |
| `smtpServer.auth` | boolean | No | `false` | Require authentication |
| `smtpServer.user` | `string` | No | - | SMTP username |
| `smtpServer.password` | `string` | No | - | SMTP password (use `passwordSecret` instead) |
| `smtpServer.passwordSecret.name` | `string` | No | - | Secret name containing SMTP password (recommended) |
| `smtpServer.passwordSecret.key` | `string` | No | `password` | Key in secret data |

**Example - Gmail:**
```yaml
spec:
  smtpServer:
    host: smtp.gmail.com
    port: 587
    from: noreply@example.com
    fromDisplayName: "My App"
    starttls: true
    auth: true
    user: noreply@example.com
    passwordSecret:
      name: smtp-credentials
      key: password
```

**Example - SendGrid:**
```yaml
spec:
  smtpServer:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    fromDisplayName: "My Team"
    starttls: true
    auth: true
    user: apikey
    passwordSecret:
      name: sendgrid-credentials
      key: api-key
```

### Localization

Configure internationalization (i18n) support.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `localization.enabled` | boolean | No | `false` | Enable internationalization |
| `localization.supportedLocales` | []`string` | No | - | List of supported locales (e.g., `en`, `de`, `fr`) |
| `localization.defaultLocale` | `string` | No | - | Default locale |

**Example:**
```yaml
spec:
  localization:
    enabled: true
    supportedLocales:
      - en
      - de
      - fr
      - es
    defaultLocale: en
```

### Authentication Flows

Define custom authentication flows with executions.

#### Flow Configuration

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `authenticationFlows[].alias` | `string` | **Yes** | - | Flow alias (unique identifier) |
| `authenticationFlows[].description` | `string` | No | - | Flow description |
| `authenticationFlows[].providerId` | `string` | No | `basic-flow` | Provider ID for the flow |
| `authenticationFlows[].topLevel` | boolean | No | `true` | Whether this is a top-level flow |
| `authenticationFlows[].builtIn` | boolean | No | `false` | Whether this is a built-in flow |
| `authenticationFlows[].executions` | []object | No | - | List of executions in this flow |

#### Execution Configuration

Executions define the individual steps within an authentication flow. Each execution must specify either an `authenticator` (for built-in authenticators) or a `flowAlias` (to reference a sub-flow).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `executions[].authenticator` | `string` | No* | - | Authenticator provider ID (e.g., `auth-username-password-form`) |
| `executions[].flowAlias` | `string` | No* | - | Reference to a sub-flow by its alias |
| `executions[].requirement` | `string` | No | `DISABLED` | Execution requirement: `REQUIRED`, `ALTERNATIVE`, `CONDITIONAL`, `DISABLED` |
| `executions[].priority` | integer | No | `0` | Order of execution (lower = first) |
| `executions[].authenticatorFlow` | boolean | No | `false` | True if this execution references a sub-flow |
| `executions[].authenticatorConfig` | object | No | - | Configuration for the authenticator |

\* Either `authenticator` or `flowAlias` must be specified, but not both.

#### Authenticator Config

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `authenticatorConfig.alias` | `string` | **Yes** | - | Configuration alias (unique identifier) |
| `authenticatorConfig.config` | map[`string`]`string` | No | `{}` | Key-value configuration parameters |

#### Common Authenticators

| Authenticator ID | Description |
|------------------|-------------|
| `auth-cookie` | Cookie-based authentication |
| `auth-username-password-form` | Username/password form |
| `auth-otp-form` | One-time password (OTP) form |
| `identity-provider-redirector` | Redirect to identity provider |
| `reset-credentials-choose-user` | Password reset: choose user |
| `reset-credential-email` | Password reset: send email |
| `reset-password` | Password reset: set new password |
| `conditional-user-configured` | Conditional: check if user has authenticator configured |
| `auth-conditional-otp-form` | Conditional OTP form |

**Example - Simple Flow:**
```yaml
spec:
  authenticationFlows:
    - alias: my-browser-flow
      description: "Custom browser flow"
      providerId: basic-flow
      topLevel: true
      builtIn: false
      executions:
        - authenticator: auth-cookie
          requirement: ALTERNATIVE
          priority: 10
        - authenticator: auth-username-password-form
          requirement: REQUIRED
          priority: 20
```

**Example - Flow with OTP:**
```yaml
spec:
  authenticationFlows:
    - alias: browser-with-otp
      description: "Browser flow with mandatory OTP"
      providerId: basic-flow
      topLevel: true
      executions:
        - authenticator: auth-cookie
          requirement: ALTERNATIVE
          priority: 10
        - authenticator: auth-username-password-form
          requirement: REQUIRED
          priority: 20
        - authenticator: auth-otp-form
          requirement: REQUIRED
          priority: 30
```

**Example - Flow with Sub-flow:**
```yaml
spec:
  authenticationFlows:
    # Main browser flow
    - alias: custom-browser
      description: "Custom browser flow with conditional OTP"
      providerId: basic-flow
      topLevel: true
      executions:
        - authenticator: auth-cookie
          requirement: ALTERNATIVE
          priority: 10
        - authenticator: auth-username-password-form
          requirement: REQUIRED
          priority: 20
        - flowAlias: conditional-otp-subflow
          requirement: CONDITIONAL
          priority: 30
          authenticatorFlow: true

    # Sub-flow for conditional OTP
    - alias: conditional-otp-subflow
      description: "Conditional OTP sub-flow"
      providerId: basic-flow
      topLevel: false
      executions:
        - authenticator: conditional-user-configured
          requirement: REQUIRED
          priority: 10
        - authenticator: auth-otp-form
          requirement: REQUIRED
          priority: 20
```

**Example - Identity Provider Redirector with Config:**
```yaml
spec:
  authenticationFlows:
    - alias: idp-redirector-flow
      description: "Auto-redirect to Azure AD"
      providerId: basic-flow
      topLevel: true
      executions:
        - authenticator: identity-provider-redirector
          requirement: REQUIRED
          priority: 10
          authenticatorConfig:
            alias: azure-redirector-config
            config:
              defaultProvider: azure-ad
```

### Identity Providers

Configure external identity providers (social login, SAML, OIDC).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `identityProviders[].alias` | `string` | **Yes** | - | Provider alias (unique identifier) |
| `identityProviders[].providerId` | `string` | **Yes** | - | Provider ID (e.g., `google`, `github`, `oidc`, `saml`) |
| `identityProviders[].enabled` | boolean | No | `true` | Enable this provider |
| `identityProviders[].trustEmail` | boolean | No | `false` | Trust email from provider |
| `identityProviders[].storeToken` | boolean | No | `false` | Store provider tokens |
| `identityProviders[].addReadTokenRoleOnCreate` | boolean | No | `false` | Add read token role on create |
| `identityProviders[].authenticateByDefault` | boolean | No | `false` | Authenticate by default |
| `identityProviders[].linkOnly` | boolean | No | `false` | Only allow linking |
| `identityProviders[].firstBrokerLoginFlowAlias` | `string` | No | - | First broker login flow |
| `identityProviders[].postBrokerLoginFlowAlias` | `string` | No | - | Post broker login flow |
| `identityProviders[].config` | map[`string`]`string` | No | `{}` | Provider-specific configuration |

**Example - Google:**
```yaml
spec:
  identityProviders:
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      config:
        clientId: "your-client-id.apps.googleusercontent.com"
        clientSecret: "your-client-secret"
        hostedDomain: "example.com"
```

**Example - Azure AD:**
```yaml
spec:
  identityProviders:
    - alias: azure-ad
      providerId: oidc
      enabled: true
      trustEmail: true
      config:
        clientId: "azure-client-id"
        clientSecret: "azure-client-secret"
        authorizationUrl: "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize"
        tokenUrl: "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token"
        jwksUrl: "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys"
        issuer: "https://login.microsoftonline.com/tenant-id/v2.0"
```

See [examples/](../../examples/) directory for complete identity provider configurations.

### User Federation

Configure user federation providers (LDAP, Active Directory).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `userFederation[].displayName` | `string` | **Yes** | - | Display name for the provider |
| `userFederation[].providerName` | `string` | **Yes** | - | Provider name (e.g., `ldap`, `kerberos`) |
| `userFederation[].priority` | integer | No | - | Provider priority (min: 0) |
| `userFederation[].config` | map[`string`]`string` | No | `{}` | Provider-specific configuration |

**Example - LDAP:**
```yaml
spec:
  userFederation:
    - displayName: "Corporate LDAP"
      providerName: ldap
      priority: 0
      config:
        connectionUrl: "ldap://ldap.example.com:389"
        usersDn: "ou=users,dc=example,dc=com"
        bindDn: "cn=admin,dc=example,dc=com"
        bindCredential: "admin-password"
```

### Client Scopes

Define reusable protocol mappers and claims.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `clientScopes[].name` | `string` | **Yes** | - | Scope name |
| `clientScopes[].description` | `string` | No | - | Scope description |
| `clientScopes[].protocol` | `string` | No | `openid-connect` | Protocol (e.g., `openid-connect`, `saml`) |
| `clientScopes[].attributes` | map[`string`]`string` | No | `{}` | Scope attributes |
| `clientScopes[].protocolMappers` | []object | No | - | Protocol mappers for this scope |

**Example:**
```yaml
spec:
  clientScopes:
    - name: department
      description: "Department information"
      protocol: openid-connect
      protocolMappers:
        - name: department-mapper
          protocol: openid-connect
          protocolMapper: oidc-usermodel-attribute-mapper
          config:
            user.attribute: department
            claim.name: department
            jsonType.label: String
```

### Roles

Define realm-level roles.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `roles.realmRoles[].name` | `string` | **Yes** | - | Role name |
| `roles.realmRoles[].description` | `string` | No | - | Role description |
| `roles.realmRoles[].composite` | boolean | No | `false` | Whether this is a composite role |
| `roles.realmRoles[].compositeRoles` | []`string` | No | - | Names of roles to include in this composite role |
| `roles.realmRoles[].clientRole` | boolean | No | `false` | Whether this is a client role |
| `roles.realmRoles[].containerId` | `string` | No | - | Container ID (for composite roles) |
| `roles.realmRoles[].attributes` | map[string][]string | No | - | Role attributes as key-value pairs where values are arrays |

**Example - Basic Roles:**
```yaml
spec:
  roles:
    realmRoles:
      - name: admin
        description: "Administrator role"
        attributes:
          department: ["IT"]
          level: ["senior"]
      - name: user
        description: "Standard user role"
      - name: viewer
        description: "Read-only viewer role"
```

**Example - Composite Roles:**
```yaml
spec:
  roles:
    realmRoles:
      # Base roles
      - name: user
        description: "Standard user role"
      - name: developer
        description: "Developer role with code access"
      - name: reviewer
        description: "Code reviewer role"
      # Composite role that includes other roles
      - name: senior-developer
        description: "Senior developer with all developer permissions"
        composite: true
        compositeRoles:
          - developer
          - reviewer
      # Manager composite role
      - name: engineering-manager
        description: "Engineering manager with full access"
        composite: true
        compositeRoles:
          - user
          - senior-developer
```

### Groups

Define user groups with role assignments and hierarchical subgroups.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `groups[].name` | `string` | **Yes** | - | Group name |
| `groups[].path` | `string` | No | - | Group path (auto-generated if not specified) |
| `groups[].attributes` | map[`string`][]`string` | No | `{}` | Group attributes |
| `groups[].realmRoles` | []`string` | No | - | Realm roles assigned to group members |
| `groups[].clientRoles` | map[`string`][]`string` | No | `{}` | Client roles assigned to group members |
| `groups[].subGroups` | []group | No | - | Nested subgroups |

**Example - Basic Groups:**
```yaml
spec:
  groups:
    - name: engineering
      attributes:
        department: ["Engineering"]
      realmRoles:
        - user
    - name: admins
      realmRoles:
        - admin
```

**Example - Nested Groups:**
```yaml
spec:
  groups:
    - name: engineering
      attributes:
        department: ["Engineering"]
      realmRoles:
        - user
      subGroups:
        - name: backend
          attributes:
            team: ["Backend"]
          realmRoles:
            - developer
        - name: frontend
          attributes:
            team: ["Frontend"]
          realmRoles:
            - developer
        - name: platform
          attributes:
            team: ["Platform"]
          realmRoles:
            - developer
            - admin  # Platform team has admin access
    - name: product
      attributes:
        department: ["Product"]
      realmRoles:
        - user
      subGroups:
        - name: managers
          realmRoles:
            - reviewer
```

**Example - Groups with Client Roles:**
```yaml
spec:
  groups:
    - name: api-consumers
      clientRoles:
        my-api-client:
          - api-read
          - api-write
        admin-portal:
          - view-dashboard
```

### Default Groups

Specify groups that are automatically assigned to new users when they register or are created.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `defaultGroups` | []`string` | No | `[]` | Group names or paths to automatically assign to new users |

**Example:**
```yaml
spec:
  # Define groups first
  groups:
    - name: users
      realmRoles:
        - user
    - name: engineering
      subGroups:
        - name: new-hires
          realmRoles:
            - trainee

  # Assign default groups
  defaultGroups:
    - /users                    # All new users get the 'users' group
    - /engineering/new-hires    # New engineering users start in new-hires
```

### Custom Attributes

Add custom realm attributes.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `attributes` | map[`string`]`string` | No | `{}` | Custom attributes as key-value pairs |

**Example:**
```yaml
spec:
  attributes:
    organization: "ACME Corp"
    environment: "production"
```

### Events Configuration

Configure event logging and auditing.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `eventsConfig.eventsEnabled` | boolean | No | `false` | Enable user event logging |
| `eventsConfig.eventsListeners` | []`string` | No | - | Event listener implementations |
| `eventsConfig.enabledEventTypes` | []`string` | No | - | Enabled event types |
| `eventsConfig.eventsExpiration` | integer | No | - | Event expiration time in seconds |
| `eventsConfig.adminEventsEnabled` | boolean | No | `false` | Enable admin event logging |
| `eventsConfig.adminEventsDetailsEnabled` | boolean | No | `false` | Include details in admin events |

**Example:**
```yaml
spec:
  eventsConfig:
    eventsEnabled: true
    eventsListeners:
      - jboss-logging
    enabledEventTypes:
      - LOGIN
      - LOGOUT
      - REGISTER
      - UPDATE_PASSWORD
    eventsExpiration: 2592000  # 30 days
    adminEventsEnabled: true
    adminEventsDetailsEnabled: true
```

## Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `phase` | `string` | Current phase: `Pending`, `Provisioning`, `Ready`, `Failed`, `Updating`, `Degraded` |
| `message` | `string` | Human-readable status message |
| `reason` | `string` | Reason for current phase |
| `observedGeneration` | integer | Generation of spec that was last processed |
| `realmName` | `string` | Name of the realm in Keycloak |
| `internalId` | `string` | Internal Keycloak realm ID |
| `keycloakInstance` | `string` | Keycloak instance managing this realm |

### OIDC Endpoints (Automatically Populated)

The operator automatically discovers and populates all standard OIDC/OAuth2 endpoints based on the Keycloak instance URL and realm name:

| Field | Type | Description |
|-------|------|-------------|
| `endpoints.issuer` | `string` | OIDC issuer endpoint |
| `endpoints.auth` | `string` | OIDC authorization endpoint |
| `endpoints.token` | `string` | OIDC token endpoint |
| `endpoints.userinfo` | `string` | OIDC userinfo endpoint |
| `endpoints.jwks` | `string` | OIDC JWKS endpoint |
| `endpoints.endSession` | `string` | OIDC end session endpoint |
| `endpoints.registration` | `string` | OIDC dynamic client registration endpoint |

These endpoints are automatically constructed using the Keycloak instance's base URL (from public/internal endpoints or service DNS) and follow the standard OIDC discovery specification.

### Additional Status Fields

| Field | Type | Description |
|-------|------|-------------|
| `features.userRegistration` | boolean | Whether user registration is enabled |
| `features.passwordReset` | boolean | Whether password reset is enabled |
| `features.identityProviders` | integer | Number of configured identity providers |
| `features.userFederationProviders` | integer | Number of user federation providers |
| `features.customThemes` | boolean | Whether custom themes are configured |
| `activeUsers` | integer | Number of active users |
| `totalClients` | integer | Number of clients in realm |
| `realmRolesCount` | integer | Number of realm roles |
| `lastHealthCheck` | `string` (datetime) | Last health check timestamp |
| `lastUpdated` | `string` (datetime) | Last update timestamp |

## Complete Examples

### Basic Realm

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: basic-realm
  namespace: my-team
spec:
  realmName: basic
  displayName: "Basic Realm"
  operatorRef:
    namespace: keycloak-system
```

### Production Realm with Security

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: production
  namespace: production
spec:
  realmName: production
  displayName: "Production Environment"

  operatorRef:
    namespace: keycloak-system

  security:
    registrationAllowed: false
    verifyEmail: true
    resetPasswordAllowed: true
    loginWithEmailAllowed: true
    sslRequired: all
    bruteForceProtected: true
    permanentLockout: false
    maxFailureWait: 900
    minimumQuickLoginWait: 60

  tokenSettings:
    accessTokenLifespan: 300
    ssoSessionIdleTimeout: 1800
    ssoSessionMaxLifespan: 36000

  smtpServer:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    fromDisplayName: "Production System"
    starttls: true
    auth: true
    user: apikey
    passwordSecret:
      name: smtp-credentials

  eventsConfig:
    eventsEnabled: true
    eventsListeners:
      - jboss-logging
    adminEventsEnabled: true
```

### Realm with Google SSO

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: realm-with-google
  namespace: my-team
spec:
  realmName: myteam
  displayName: "My Team"

  operatorRef:
    namespace: keycloak-system

  security:
    registrationAllowed: true
    verifyEmail: true

  identityProviders:
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      config:
        clientId: "your-client-id.apps.googleusercontent.com"
        clientSecret: "your-client-secret"
        hostedDomain: "example.com"
```

## See Also

**Related CRD References:**

- [Keycloak CRD Reference](keycloak-crd.md) - Configure Keycloak instances
- [KeycloakClient CRD Reference](keycloak-client-crd.md) - Configure OAuth2/OIDC clients

**Configuration Guides:**

- [End-to-End Setup](../how-to/end-to-end-setup.md) - Complete realm deployment example
- [SMTP Configuration](../how-to/smtp-configuration.md) - Email server setup for realms
- [Multi-Tenant Setup](../how-to/multi-tenant.md) - Configuring multiple realms with authorization grants
- [Identity Providers](../guides/identity-providers.md) - Integrate Google, GitHub, Azure AD, and other SSO

**Examples:**

- [Realm Examples](../../examples/realms/) - Production-ready realm configurations
- [Identity Provider Examples](../../examples/identity-providers/) - SSO integration examples

**Architecture & Security:**

- [Architecture](../concepts/architecture.md) - Operator architecture
- [Security Model](../concepts/security.md) - Authorization and security model
- [Security Model](../concepts/security.md) - Authorization model
