# KeycloakRealm CRD Reference

Reference for the `KeycloakRealm` custom resource.

A realm is the main tenant boundary in this operator. It contains authentication settings, identity providers, federation, roles, groups, client scopes, and the namespace authorization list that decides which namespaces may create clients against it.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `KeycloakRealm`
**Short Name:** `kcr`

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: team-a
  namespace: team-a
spec:
  realmName: team-a
  operatorRef:
    namespace: keycloak-system
```

## Core Fields

| Field | Type | Notes |
| --- | --- | --- |
| `realmName` | string | required; becomes the Keycloak realm identifier |
| `displayName` | string | optional human-readable name |
| `description` | string | optional description |
| `loginPageTitle` | string | optional HTML title |
| `operatorRef.namespace` | string | namespace where the managing operator runs |
| `clientAuthorizationGrants` | list | namespaces allowed to create `KeycloakClient` resources against this realm |

Example:

```yaml
spec:
  realmName: customer-portal
  displayName: Customer Portal
  operatorRef:
    namespace: keycloak-system
  clientAuthorizationGrants:
    - customer-portal
    - customer-portal-staging
```

`clientAuthorizationGrants` is an authorization boundary, not a documentation hint. If a namespace is not granted there, client creation for that realm is rejected.

## Security And Session Settings

### `security`

`security` covers login, registration, brute-force protection, and refresh-token behavior.

Notable fields:

| Field | Type | Notes |
| --- | --- | --- |
| `security.sslRequired` | string | `all`, `external`, or `none` |
| `security.registrationAllowed` | boolean | self-registration |
| `security.registrationEmailAsUsername` | boolean | email-as-username registration mode |
| `security.editUsernameAllowed` | boolean | user can rename login |
| `security.resetPasswordAllowed` | boolean | enable reset flow |
| `security.rememberMe` | boolean | show remember-me login option |
| `security.verifyEmail` | boolean | require email verification |
| `security.loginWithEmailAllowed` | boolean | allow login by email |
| `security.duplicateEmailsAllowed` | boolean | disable unique-email enforcement |
| `security.bruteForceProtected` | boolean | enable lockout controls |
| `security.permanentLockout` | boolean | permanent lockout behavior |
| `security.failureFactor` | integer | failures before penalties start |
| `security.maxFailureWait` | integer | upper wait bound |
| `security.minimumQuickLoginWait` | integer | minimum quick-login penalty |
| `security.waitIncrement` | integer | incremental penalty |
| `security.quickLoginCheckMillis` | integer | short-window detection interval |
| `security.maxDeltaTime` | integer | lookback window for failures |
| `security.revokeRefreshToken` | boolean | revoke refresh tokens after use |
| `security.refreshTokenMaxReuse` | integer | allowed reuse count |

### `tokenSettings`

`tokenSettings` controls access-token, SSO, offline-session, and client-session lifetimes.

Representative fields:

- `accessTokenLifespan`
- `accessTokenLifespanForImplicitFlow`
- `ssoSessionIdleTimeout`
- `ssoSessionMaxLifespan`
- `offlineSessionIdleTimeout`
- `offlineSessionMaxLifespanEnabled`
- `offlineSessionMaxLifespan`
- `clientSessionIdleTimeout`
- `clientSessionMaxLifespan`
- `clientOfflineSessionIdleTimeout`
- `clientOfflineSessionMaxLifespan`

### Browser security headers

Use `browserSecurityHeaders` to manage CSP, HSTS, frame options, referrer policy, and related headers served by Keycloak login pages.

### Password, OTP, and WebAuthn policies

These sections were missing from the older docs but are supported directly by the model.

| Field | Notes |
| --- | --- |
| `passwordPolicy` | structured password policy converted to Keycloak's policy string |
| `otpPolicy` | TOTP or HOTP policy |
| `webAuthnPolicy` | regular WebAuthn registration and verification policy |
| `webAuthnPasswordlessPolicy` | passwordless WebAuthn configuration, including `passkeysEnabled` |

Example:

```yaml
spec:
  passwordPolicy:
    length: 14
    upperCase: 1
    lowerCase: 1
    digits: 1
    specialChars: 1
    notUsername: true
    passwordHistory: 5
  otpPolicy:
    type: totp
    algorithm: HmacSHA256
    digits: 6
    period: 30
  webAuthnPasswordlessPolicy:
    rpEntityName: Customer Portal
    userVerificationRequirement: required
    passkeysEnabled: true
```

## UX, Email, And Localization

| Field | Notes |
| --- | --- |
| `themes` | login, admin, account, and email theme names |
| `localization.enabled` | enable i18n support |
| `localization.defaultLocale` | default locale |
| `localization.supportedLocales` | locale allow-list |
| `smtpServer` | outbound email settings |

For `smtpServer`, prefer `passwordSecret` over inline `password`. The secret must be in the same namespace as the realm and must carry the operator allow label when the operator reads it cross-resource.

## Authentication Flows And Required Actions

### `authenticationFlows`

The canonical field names match the model, not the older prose examples.

Each flow uses:

- `alias`
- `providerId`
- `topLevel`
- `builtIn`
- `authenticationExecutions`
- optional `authenticatorConfig`
- optional `copyFrom`

Each execution uses either:

- `authenticator`, or
- `flowAlias`

and may also set:

- `requirement`
- `priority`
- `authenticatorFlow`
- `authenticatorConfig`
- `userSetupAllowed`

Example:

```yaml
spec:
  authenticationFlows:
    - alias: browser-with-otp
      providerId: basic-flow
      topLevel: true
      authenticationExecutions:
        - authenticator: auth-cookie
          requirement: ALTERNATIVE
          priority: 10
        - authenticator: auth-username-password-form
          requirement: REQUIRED
          priority: 20
        - authenticator: auth-otp-form
          requirement: REQUIRED
          priority: 30
  browserFlow: browser-with-otp
```

### Flow bindings

Realm-level binding fields:

- `browserFlow`
- `registrationFlow`
- `directGrantFlow`
- `resetCredentialsFlow`
- `clientAuthenticationFlow`
- `dockerAuthenticationFlow`
- `firstBrokerLoginFlow`

### `requiredActions`

Use this to manage actions such as `VERIFY_EMAIL` or `CONFIGURE_TOTP` declaratively, including priority and default enrollment behavior.

## Identity Providers And Federation

### `identityProviders`

Each identity provider supports:

- `alias`
- `providerId`
- `displayName`
- `enabled`
- `config`
- `configSecrets`
- broker-flow bindings
- `linkOnly`, `storeToken`, `trustEmail`
- `mappers`

Sensitive values such as `clientSecret`, `password`, or signing keys must not be placed in plaintext `config`. Use `configSecrets` instead.

### `userFederation`

The model supports LDAP and Kerberos federation with:

- connection and bind settings
- search settings
- edit mode
- sync schedules
- mappers
- secret-backed bind credentials and keytabs

This is also surfaced back in `status.userFederationStatus` for observability.

## Roles, Groups, Scopes, And Client Behavior

### Roles and groups

Supported sections include:

- `roles.realmRoles`
- `groups`
- `defaultGroups`
- `defaultRoles`
- `defaultRole`

### Client scopes and scope mappings

Supported sections include:

- `clientScopes`
- `defaultClientScopes`
- `optionalClientScopes`
- `scopeMappings`
- `clientScopeMappings`

### Client profiles and client policies

These are advanced OAuth and compliance controls for matching clients.

- `clientProfiles` define executor bundles
- `clientPolicies` define conditions and which profiles apply when those conditions match

That is how the operator models policy-driven client hardening such as PKCE enforcement or confidential-client constraints.

## Organizations

Organizations are supported for Keycloak `26+`.

To use them:

- set `organizationsEnabled: true`
- define one or more `organizations`

Each organization can declare:

- `name`
- `alias`
- `description`
- `enabled`
- `domains`
- `attributes`
- linked `identityProviders`

If you omit `organizationsEnabled: true`, the operator will not treat the organization list as active realm configuration.

## Events And Attributes

| Field | Notes |
| --- | --- |
| `eventsConfig` | user and admin event logging, listeners, expiration |
| `attributes` | additional raw realm attributes forwarded to Keycloak |

## Status Fields

Important status fields:

| Field | Meaning |
| --- | --- |
| `phase`, `message`, `reason` | overall reconciliation state |
| `observedGeneration` | last processed generation |
| `realmName`, `internalId` | resolved realm identifiers |
| `keycloakInstance` | controlling Keycloak instance reference |
| `authorizedClientNamespaces` | current namespace grant list |
| `endpoints.*` | issuer, auth, token, userinfo, JWKS, logout, registration URLs |
| `features.*` | summary of enabled realm capabilities |
| `userFederationStatus` | per-provider connectivity and sync state |
| `lastHealthCheck`, `lastUpdated` | reconciliation timing |
| `activeUsers`, `totalClients`, `realmRolesCount`, `clientScopesCount` | summary statistics |
| `lastReconcileEventTime` | drift-detection watermark |

Common phases are `Pending`, `Provisioning`, `Reconciling`, `Ready`, `Updating`, `Degraded`, and `Failed`.

## Examples

### Production realm with delegated client namespaces

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: customer-portal
  namespace: customer-portal
spec:
  realmName: customer-portal
  displayName: Customer Portal
  operatorRef:
    namespace: keycloak-system
  clientAuthorizationGrants:
    - customer-portal
    - customer-portal-jobs
  security:
    sslRequired: external
    verifyEmail: true
    bruteForceProtected: true
    rememberMe: true
  passwordPolicy:
    length: 14
    upperCase: 1
    lowerCase: 1
    digits: 1
    specialChars: 1
    notUsername: true
  smtpServer:
    host: smtp.example.com
    port: 587
    from: noreply@example.com
    auth: true
    starttls: true
    user: noreply@example.com
    passwordSecret:
      name: smtp-password
```

### Realm with custom browser flow and required action

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: secure-login
  namespace: security
spec:
  realmName: secure-login
  operatorRef:
    namespace: keycloak-system
  authenticationFlows:
    - alias: browser-with-otp
      providerId: basic-flow
      topLevel: true
      authenticationExecutions:
        - authenticator: auth-cookie
          requirement: ALTERNATIVE
          priority: 10
        - authenticator: auth-username-password-form
          requirement: REQUIRED
          priority: 20
        - authenticator: auth-otp-form
          requirement: REQUIRED
          priority: 30
  browserFlow: browser-with-otp
  requiredActions:
    - alias: CONFIGURE_TOTP
      enabled: true
      defaultAction: true
      priority: 10
```

### Realm with organizations

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: b2b
  namespace: b2b
spec:
  realmName: b2b
  operatorRef:
    namespace: keycloak-system
  organizationsEnabled: true
  organizations:
    - name: acme-corp
      alias: acme
      description: ACME Corporation
      domains:
        - name: acme.example
          verified: true
      attributes:
        tier:
          - enterprise
```

## See Also

- [KeycloakClient CRD Reference](./keycloak-client-crd.md)
- [RBAC Implementation](../rbac-implementation.md)
- [Multi-Tenant Setup](../how-to/multi-tenant.md)
- [SMTP Configuration](../how-to/smtp-configuration.md)
- [ADR 017: Kubernetes RBAC Over Keycloak Security](../decisions/generated-markdown/017-kubernetes-rbac-over-keycloak-security.md)
