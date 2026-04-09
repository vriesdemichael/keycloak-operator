# KeycloakClient CRD Reference

Reference for the `KeycloakClient` custom resource.

A client represents an OAuth2, OIDC, SAML, or Docker registry integration managed inside a realm. The operator supports ordinary login clients, public SPA/mobile clients, bearer-only APIs, service-account clients, and resource-server authorization models.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `KeycloakClient`
**Short Name:** `kcc`

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: webapp
  namespace: team-a
spec:
  clientId: webapp
  realmRef:
    name: team-a
    namespace: team-a
```

## Core Fields

| Field | Type | Notes |
| --- | --- | --- |
| `clientId` | string | required unique client identifier |
| `clientName` | string | optional display name |
| `description` | string | optional description |
| `realmRef.name` | string | referenced realm resource |
| `realmRef.namespace` | string | namespace of that realm resource |
| `protocol` | string | `openid-connect`, `saml`, or `docker-v2` |
| `publicClient` | boolean | public clients do not use client secrets |
| `bearerOnly` | boolean | API-style client that validates tokens but does not initiate login |

## URL Fields And Redirect Validation

Relevant fields:

- `redirectUris`
- `webOrigins`
- `postLogoutRedirectUris`
- `rootUrl`
- `adminUrl`
- `baseUrl`

The operator validates redirect URI wildcard use more strictly than the older docs described:

- bare `*` is rejected
- wildcard use is valid at the end of a path, like `https://example.com/*`
- wildcard use in the hostname is rejected
- custom URI schemes are supported, such as `myapp://callback` or `myapp:*`

Example:

```yaml
spec:
  redirectUris:
    - https://app.example.com/callback
    - https://app.example.com/*
  webOrigins:
    - https://app.example.com
  postLogoutRedirectUris:
    - https://app.example.com
```

## Client Settings

The `settings` block holds the bulk of client behavior.

### Authentication and flow controls

| Field | Notes |
| --- | --- |
| `settings.clientAuthenticatorType` | `client-secret`, `client-jwt`, `client-secret-jwt`, or `client-x509` |
| `settings.standardFlowEnabled` | authorization code flow |
| `settings.implicitFlowEnabled` | implicit flow, usually avoid for modern apps |
| `settings.directAccessGrantsEnabled` | password grant |
| `settings.serviceAccountsEnabled` | client credentials flow |
| `settings.authorizationServicesEnabled` | required for fine-grained authorization |

### Consent and token shaping

| Field | Notes |
| --- | --- |
| `settings.consentRequired` | require user consent |
| `settings.displayOnConsentScreen` | visibility in consent UI |
| `settings.includeInTokenScope` | include in scope calculations |
| `settings.frontchannelLogout` | enable front-channel logout |
| `settings.fullScopeAllowed` | allow full-scope role mapping |
| `settings.accessTokenLifespan` | client override for access token lifespan |
| `settings.refreshTokenLifespan` | client override for refresh token lifespan |
| `settings.clientSessionIdleTimeout` | client session idle timeout |
| `settings.clientSessionMaxLifespan` | client session max lifespan |
| `settings.pkceCodeChallengeMethod` | `S256` or `plain` |

## Authentication Flow Overrides

The `authenticationFlows` section can point the client at realm-defined flow aliases:

- `browserFlow`
- `directGrantFlow`
- `clientAuthenticationFlow`

Example:

```yaml
spec:
  authenticationFlows:
    browserFlow: browser-with-otp
    clientAuthenticationFlow: hardened-confidential-client
```

## Scopes, Mappers, Roles, And Service Accounts

Supported sections include:

- `defaultClientScopes`
- `optionalClientScopes`
- `protocolMappers`
- `clientRoles`
- `serviceAccountRoles.realmRoles`
- `serviceAccountRoles.clientRoles`

That covers the common cases of:

- mapping custom claims
- attaching audiences
- creating client roles
- granting realm or client roles to the service-account user

## Fine-Grained Authorization

This is the largest feature gap in the old page and is fully modeled now.

To use it:

- set `settings.authorizationServicesEnabled: true`
- define `authorizationSettings`

### Top-level authorization settings

| Field | Notes |
| --- | --- |
| `authorizationSettings.policyEnforcementMode` | `ENFORCING`, `PERMISSIVE`, or `DISABLED` |
| `authorizationSettings.decisionStrategy` | `UNANIMOUS`, `AFFIRMATIVE`, or `CONSENSUS` |
| `authorizationSettings.allowRemoteResourceManagement` | enable protection API management |
| `authorizationSettings.scopes` | named actions such as `read` or `write` |
| `authorizationSettings.resources` | protected resources and associated scopes |
| `authorizationSettings.policies` | who is allowed |
| `authorizationSettings.permissions` | what those policies apply to |

### Supported policy types

The model supports these policy containers:

- `rolePolicies`
- `userPolicies`
- `groupPolicies`
- `clientPolicies`
- `timePolicies`
- `regexPolicies`
- `aggregatePolicies`
- `javascriptPolicies`

### Supported permission types

The model supports:

- `resourcePermissions`
- `scopePermissions`

### Security note on JavaScript policies

`javascriptPolicies` are disabled by default at the model level unless `allowJavaScriptPolicies: true` is set.

That is deliberate. JavaScript policies require Keycloak script-upload support and carry a real security review burden. Treat them as an exception, not a normal authorization tool.

Example:

```yaml
spec:
  settings:
    authorizationServicesEnabled: true
  authorizationSettings:
    policyEnforcementMode: ENFORCING
    decisionStrategy: UNANIMOUS
    scopes:
      - name: read
      - name: write
    resources:
      - name: documents
        uris:
          - /api/documents/*
        scopes:
          - read
          - write
    policies:
      rolePolicies:
        - name: document-editors
          roles:
            - name: editor
      groupPolicies:
        - name: finance-team
          groups:
            - /finance
    permissions:
      scopePermissions:
        - name: documents-read
          resources:
            - documents
          scopes:
            - read
          policies:
            - finance-team
        - name: documents-write
          resources:
            - documents
          scopes:
            - write
          policies:
            - document-editors
```

## Secret Management

The operator supports both managed and externally supplied secrets.

### Managed secret options

| Field | Notes |
| --- | --- |
| `manageSecret` | create and maintain a Kubernetes secret for client credentials |
| `secretName` | override the managed secret name |
| `secretMetadata.labels` / `annotations` | decorate the managed secret |
| `regenerateSecret` | force a new client secret on update |

### Existing secret option

Use `clientSecret` when the secret value already exists and should not be generated by the operator.

```yaml
spec:
  clientSecret:
    name: legacy-client-secret
    key: client-secret
```

Constraints enforced by validation:

- `clientSecret` cannot be used with `publicClient: true`
- `clientSecret` cannot be combined with `secretRotation.enabled: true`

### Secret rotation

The `secretRotation` block documents actual operator behavior:

| Field | Type | Notes |
| --- | --- | --- |
| `secretRotation.enabled` | boolean | enable automatic secret rotation |
| `secretRotation.rotationPeriod` | string | interval such as `90d`, `24h`, or `10s` |
| `secretRotation.rotationTime` | string | optional `HH:MM` target time |
| `secretRotation.timezone` | string | IANA timezone such as `UTC` or `Europe/Amsterdam` |

Scheduling semantics:

- the rotation period determines how often the secret becomes eligible
- if `rotationTime` is set, the operator waits for the next matching wall-clock time in the configured timezone
- if no `rotationTime` is set, rotation occurs as soon as the period is reached on the reconcile path

The managed secret contains these keys when applicable:

- `client-id`
- `client-secret`
- `issuer`
- `token-endpoint`
- `auth-endpoint`

## Status Fields

Important status fields:

| Field | Meaning |
| --- | --- |
| `phase`, `message`, `reason` | current reconciliation state |
| `observedGeneration` | last processed generation |
| `clientId`, `internalId` | logical and internal Keycloak identifiers |
| `realm` | target realm name |
| `publicClient` | whether the current client is public |
| `keycloakInstance` | managing Keycloak instance reference |
| `credentialsSecret` | secret name used for generated credentials |
| `endpoints.*` | issuer, auth, token, userinfo, JWKS, and logout endpoints |
| `authorizationGranted` | whether the realm currently authorizes this namespace |
| `authorizationMessage` | authorization summary |
| `createdRoles`, `appliedMappers` | reconciliation outputs |
| `lastHealthCheck`, `lastUpdated` | timing metadata |
| `lastReconcileEventTime` | drift-detection watermark |

Common phases are `Pending`, `Provisioning`, `Reconciling`, `Ready`, `Updating`, `Degraded`, and `Failed`.

## Examples

### Confidential web app with managed secret rotation

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: webapp
  namespace: team-a
spec:
  clientId: webapp
  clientName: Team A Web App
  realmRef:
    name: team-a
    namespace: team-a
  redirectUris:
    - https://app.example.com/callback
  webOrigins:
    - https://app.example.com
  postLogoutRedirectUris:
    - https://app.example.com
  settings:
    standardFlowEnabled: true
    directAccessGrantsEnabled: false
  secretRotation:
    enabled: true
    rotationPeriod: 30d
    rotationTime: "02:00"
    timezone: UTC
```

### SPA with PKCE

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: spa
  namespace: team-a
spec:
  clientId: spa
  realmRef:
    name: team-a
    namespace: team-a
  publicClient: true
  redirectUris:
    - https://spa.example.com/*
  webOrigins:
    - https://spa.example.com
  settings:
    standardFlowEnabled: true
    implicitFlowEnabled: false
    directAccessGrantsEnabled: false
    pkceCodeChallengeMethod: S256
```

### Resource server with authorization services

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: documents-api
  namespace: team-a
spec:
  clientId: documents-api
  realmRef:
    name: team-a
    namespace: team-a
  bearerOnly: true
  settings:
    standardFlowEnabled: false
    directAccessGrantsEnabled: false
    serviceAccountsEnabled: false
    authorizationServicesEnabled: true
  authorizationSettings:
    policyEnforcementMode: ENFORCING
    decisionStrategy: UNANIMOUS
    scopes:
      - name: read
      - name: write
    resources:
      - name: documents
        uris:
          - /api/documents/*
        scopes:
          - read
          - write
    policies:
      rolePolicies:
        - name: editors
          roles:
            - name: editor
    permissions:
      scopePermissions:
        - name: edit-documents
          resources:
            - documents
          scopes:
            - write
          policies:
            - editors
```

## See Also

- [KeycloakRealm CRD Reference](./keycloak-realm-crd.md)
- [End-to-End Setup](../how-to/end-to-end-setup.md)
- [RBAC Implementation](../rbac-implementation.md)
- [ADR 017: Kubernetes RBAC Over Keycloak Security](../decisions/generated-markdown/017-kubernetes-rbac-over-keycloak-security.md)
