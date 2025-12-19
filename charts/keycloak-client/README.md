# Keycloak Client Helm Chart

Helm chart for deploying Keycloak Clients - OAuth2/OIDC applications that authenticate users through Keycloak.

## Overview

A Keycloak client represents an application that can request authentication and authorization from Keycloak. This includes:
- **Web Applications** - Server-side applications with confidential client secrets
- **Single Page Applications (SPAs)** - Public clients without secrets (React, Angular, Vue)
- **Mobile Applications** - Public clients for iOS/Android apps
- **APIs/Services** - Bearer-only clients that validate tokens
- **Service Accounts** - Machine-to-machine authentication without user interaction

This chart creates a `KeycloakClient` custom resource that is reconciled by the Keycloak Operator.

**Target Users:** Application developers who need OAuth2/OIDC authentication for their applications.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.8+
- **Keycloak Operator** installed ([keycloak-operator chart](../keycloak-operator/README.md))
- **Keycloak Realm** created ([keycloak-realm chart](../keycloak-realm/README.md))
- **Realm Authorization Token** from the realm resource

## Installation

### Quick Start

```bash
# Get realm authorization secret name
REALM_SECRET=$(kubectl get keycloakrealm my-realm \
  -n my-team \
  -o jsonpath='{.status.authorizationSecretName}')

# Install client chart
helm install my-client keycloak-operator/keycloak-client \
  --set clientId=my-app \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --set redirectUris[0]="https://myapp.example.com/callback" \
  --set webOrigins[0]="https://myapp.example.com" \
  --namespace my-team
```

### Install with Custom Values

```yaml
# values-custom.yaml
clientId: my-app
description: "My Application OAuth2 Client"

realmRef:
  name: my-realm
  namespace: my-team

# Confidential client (server-side app)
publicClient: false

redirectUris:
  - "https://myapp.example.com/callback"
  - "https://myapp.example.com/auth/callback"
  - "http://localhost:3000/callback"  # For local dev

webOrigins:
  - "https://myapp.example.com"
  - "http://localhost:3000"

# OAuth2 flows
standardFlowEnabled: true       # Authorization Code flow
directAccessGrantsEnabled: true # Resource Owner Password Credentials
serviceAccountsEnabled: false   # Machine-to-machine

# Service account roles (if enabled)
serviceAccountRoles:
  realmRoles:
    - view-users
  clientRoles:
    account:
      - view-profile
```

```bash
helm install my-client keycloak-operator/keycloak-client \
  -f values-custom.yaml \
  --namespace my-team
```

### Verify Installation

```bash
# Check client status
kubectl get keycloakclient my-client -n my-team

# Wait for client to be ready
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakclient/my-client \
  -n my-team --timeout=300s

# View client details
kubectl describe keycloakclient my-client -n my-team
```

## Configuration

### Values Reference

#### Required Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `clientId` | **REQUIRED** Unique client identifier | `""` |
| `realmRef.name` | **REQUIRED** Name of KeycloakRealm CR | `""` |
| `realmRef.namespace` | **REQUIRED** Namespace of KeycloakRealm CR | `""` |

#### Client Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `description` | Human-readable client description | `""` |
| `publicClient` | Public client (no secret) vs confidential (has secret) | `false` |
| `bearerOnly` | Bearer-only client (for APIs that only validate tokens) | `false` |
| `protocol` | Authentication protocol | `openid-connect` |

#### Realm Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `realmRef.name` | Name of KeycloakRealm custom resource | `""` |
| `realmRef.namespace` | Namespace of KeycloakRealm resource | `""` |

#### RBAC Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rbac.create` | Create RoleBinding for operator access | `true` |
| `rbac.operatorNamespace` | Namespace where operator is running | `keycloak-system` |
| `rbac.operatorClusterRoleName` | Name of operator's ClusterRole | `keycloak-operator-namespace-access` |
| `rbac.operatorServiceAccountName` | Name of operator's ServiceAccount (auto-detected if empty) | `""` |

#### OAuth2/OIDC Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redirectUris` | OAuth2 redirect URIs (where users return after login) | `[]` |
| `webOrigins` | CORS allowed origins | `[]` |
| `postLogoutRedirectUris` | Where to redirect after logout | `[]` |
| `baseUrl` | Base URL of the client application | `""` |
| `rootUrl` | Root URL for relative redirect URIs | `""` |
| `adminUrl` | Admin URL for backchannel logout | `""` |

**Example:**
```yaml
redirectUris:
  - "https://myapp.example.com/callback"
  - "https://myapp.example.com/auth/callback"
  - "http://localhost:3000/callback"  # Development

webOrigins:
  - "https://myapp.example.com"
  - "http://localhost:3000"

postLogoutRedirectUris:
  - "https://myapp.example.com/goodbye"

baseUrl: "https://myapp.example.com"
```

#### Client Authentication

| Parameter | Description | Default |
|-----------|-------------|---------|
| `clientAuthenticatorType` | Authentication method | `client-secret` |

Options: `client-secret`, `client-jwt`, `client-x509`, `secret-jwt`

#### OAuth2 Flows

| Parameter | Description | Default |
|-----------|-------------|---------|
| `standardFlowEnabled` | Authorization Code flow (recommended) | `true` |
| `implicitFlowEnabled` | Implicit flow (deprecated, not recommended) | `false` |
| `directAccessGrantsEnabled` | Resource Owner Password Credentials flow | `true` |
| `serviceAccountsEnabled` | Enable service account for machine-to-machine | `false` |

**Flow Recommendations:**
- **Web Apps:** `standardFlowEnabled: true` (Authorization Code)
- **SPAs:** `standardFlowEnabled: true` + `publicClient: true` + PKCE
- **Mobile Apps:** `standardFlowEnabled: true` + `publicClient: true` + PKCE
- **APIs:** `bearerOnly: true`
- **M2M:** `serviceAccountsEnabled: true`

#### Consent Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `consentRequired` | Require user consent before sharing data | `false` |
| `displayOnConsentScreen` | Display this client on consent screen | `true` |

#### Advanced Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `frontchannelLogout` | Enable front-channel logout | `true` |
| `authorizationServicesEnabled` | Enable fine-grained authorization | `false` |
| `alwaysDisplayInConsole` | Always show in account console | `false` |
| `fullScopeAllowed` | Allow all realm roles | `true` |

#### Client Settings (Advanced)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `settings.enabled` | Enable the client | `true` |
| `settings.pkceCodeChallengeMethod` | PKCE challenge method (`S256`, `plain`, or empty) | `""` |
| `settings.accessTokenLifespan` | Access token TTL (0 = use realm default) | `0` |
| `settings.clientSessionIdleTimeout` | Client session idle timeout (0 = use realm default) | `0` |
| `settings.clientSessionMaxLifespan` | Client session max lifespan (0 = use realm default) | `0` |

**Example:** Enable PKCE for SPA

```yaml
settings:
  pkceCodeChallengeMethod: "S256"  # Require PKCE with SHA-256
```

#### Client Scopes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `defaultClientScopes` | Default OAuth2 scopes always included | `[]` |
| `optionalClientScopes` | Optional scopes user can grant | `[]` |

**Example:**
```yaml
defaultClientScopes:
  - profile
  - email
  - roles

optionalClientScopes:
  - address
  - phone
  - offline_access
```

#### Service Account Roles

Only applicable when `serviceAccountsEnabled: true`:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccountRoles.realmRoles` | Realm roles assigned to service account | `[]` |
| `serviceAccountRoles.clientRoles` | Client roles assigned to service account | `{}` |

**Example:**
```yaml
serviceAccountsEnabled: true

serviceAccountRoles:
  realmRoles:
    - view-users
    - view-clients

  clientRoles:
    account:
      - view-profile
      - manage-account
    other-client:
      - read
      - write
```

#### Protocol Mappers

| Parameter | Description | Default |
|-----------|-------------|---------|
| `protocolMappers` | Custom OIDC token mappers | `[]` |

**Example:** Add audience mapper

```yaml
protocolMappers:
  - name: audience-mapper
    protocol: openid-connect
    protocolMapper: oidc-audience-mapper
    config:
      included.client.audience: "my-api"
      id.token.claim: "false"
      access.token.claim: "true"

  - name: custom-claim
    protocol: openid-connect
    protocolMapper: oidc-hardcoded-claim-mapper
    config:
      claim.name: "app_version"
      claim.value: "1.0.0"
      id.token.claim: "true"
      access.token.claim: "true"
      userinfo.token.claim: "true"
```

#### Authentication Flow Overrides

| Parameter | Description | Default |
|-----------|-------------|---------|
| `authenticationFlow.browserFlow` | Custom browser authentication flow | `""` |
| `authenticationFlow.directGrantFlow` | Custom direct grant flow | `""` |
| `authenticationFlow.clientAuthenticationFlow` | Custom client authentication flow | `""` |

#### Secret Management

| Parameter | Description | Default |
|-----------|-------------|---------|
| `manageSecret` | Automatically create Kubernetes secret with client credentials | `true` |
| `secretName` | Name of the secret (auto-generated if empty) | `""` |
| `regenerateSecret` | Regenerate client secret on update | `false` |

When `manageSecret: true` and `publicClient: false`, the operator creates a secret containing:
- `client-id` - The OAuth2 client ID
- `client-secret` - The client secret
- `issuer-url` - The OIDC issuer URL
- `token-url` - The token endpoint
- `auth-url` - The authorization endpoint
- `userinfo-url` - The userinfo endpoint

#### Extra Manifests

| Parameter | Description | Default |
|-----------|-------------|---------|
| `extraManifests` | Additional Kubernetes manifests to deploy | `[]` |

#### Common Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `commonLabels` | Labels applied to all resources | `{}` |
| `commonAnnotations` | Annotations applied to all resources | `{}` |

## Usage Examples

### Web Application (Confidential Client)

Server-side application with client secret:

```yaml
clientId: webapp
description: "My Web Application"

realmRef:
  name: my-realm
  namespace: my-team

# Confidential client (has secret)
publicClient: false

redirectUris:
  - "https://webapp.example.com/callback"

webOrigins:
  - "https://webapp.example.com"

# Standard authorization code flow
standardFlowEnabled: true
implicitFlowEnabled: false
directAccessGrantsEnabled: false
serviceAccountsEnabled: false
```

### Single Page Application (Public Client with PKCE)

React/Angular/Vue application without server-side secret:

```yaml
clientId: my-spa
description: "My Single Page Application"

realmRef:
  name: my-realm
  namespace: my-team

# Public client (no secret)
publicClient: true

redirectUris:
  - "https://spa.example.com/callback"
  - "http://localhost:3000/callback"

webOrigins:
  - "https://spa.example.com"
  - "http://localhost:3000"

postLogoutRedirectUris:
  - "https://spa.example.com/"

# Use authorization code flow with PKCE
standardFlowEnabled: true
implicitFlowEnabled: false  # Don't use implicit flow

settings:
  pkceCodeChallengeMethod: "S256"  # Require PKCE
```

### Mobile Application (Public Client)

iOS/Android application:

```yaml
clientId: mobile-app
description: "My Mobile Application"

realmRef:
  name: my-realm
  namespace: my-team

publicClient: true

redirectUris:
  - "com.example.myapp://callback"  # Custom URL scheme

# Authorization code flow with PKCE
standardFlowEnabled: true

settings:
  pkceCodeChallengeMethod: "S256"

# Optional: Support offline access
optionalClientScopes:
  - offline_access
```

### API/Resource Server (Bearer-Only)

API that only validates access tokens:

```yaml
clientId: my-api
description: "My REST API"

realmRef:
  name: my-realm
  namespace: my-team

# Bearer-only (no login flows)
bearerOnly: true
publicClient: false

# No redirect URIs needed for bearer-only
redirectUris: []
webOrigins: []

# Disable all flows
standardFlowEnabled: false
implicitFlowEnabled: false
directAccessGrantsEnabled: false
serviceAccountsEnabled: false
```

### Service Account (Machine-to-Machine)

Background service or microservice:

```yaml
clientId: background-service
description: "Background Processing Service"

realmRef:
  name: my-realm
  namespace: my-team

publicClient: false

# No redirect URIs for service accounts
redirectUris: []
webOrigins: []

# Only service account enabled
standardFlowEnabled: false
implicitFlowEnabled: false
directAccessGrantsEnabled: false
serviceAccountsEnabled: true

# Assign roles to service account
serviceAccountRoles:
  realmRoles:
    - view-users
    - manage-clients

  clientRoles:
    my-api:
      - read
      - write
      - admin
```

### Client with Protocol Mappers

Add custom claims to tokens:

```yaml
clientId: custom-claims-client
description: "Client with Custom Token Claims"

realmRef:
  name: my-realm
  namespace: my-team

publicClient: false

redirectUris:
  - "https://app.example.com/callback"

# Add custom protocol mappers
protocolMappers:
  # Add audience claim
  - name: api-audience
    protocol: openid-connect
    protocolMapper: oidc-audience-mapper
    config:
      included.client.audience: "my-api"
      access.token.claim: "true"

  # Add hardcoded claim
  - name: app-environment
    protocol: openid-connect
    protocolMapper: oidc-hardcoded-claim-mapper
    config:
      claim.name: "environment"
      claim.value: "production"
      access.token.claim: "true"
      id.token.claim: "true"

  # Add user attribute
  - name: department-claim
    protocol: openid-connect
    protocolMapper: oidc-usermodel-attribute-mapper
    config:
      user.attribute: "department"
      claim.name: "department"
      access.token.claim: "true"
      id.token.claim: "true"
```

## Post-Installation

### 1. Wait for Client to be Ready

```bash
# Monitor client status
kubectl get keycloakclient my-client -n my-team -w

# Wait for Ready phase
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakclient/my-client \
  -n my-team --timeout=300s
```

### 2. Retrieve Client Credentials

For confidential clients (non-public):

```bash
# Get secret name (default: {client-name}-credentials)
SECRET_NAME="my-client-credentials"

# Get client ID
kubectl get secret $SECRET_NAME -n my-team \
  -o jsonpath='{.data.client-id}' | base64 -d

# Get client secret
kubectl get secret $SECRET_NAME -n my-team \
  -o jsonpath='{.data.client-secret}' | base64 -d

# Get all endpoints
kubectl get secret $SECRET_NAME -n my-team -o yaml
```

### 3. Configure Your Application

#### Node.js (Passport.js)

```javascript
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const issuerUrl = process.env.ISSUER_URL;

passport.use('keycloak', new Strategy({
  issuer: issuerUrl,
  clientID: clientId,
  clientSecret: clientSecret,
  callbackURL: 'https://myapp.example.com/callback',
}, (issuer, profile, done) => {
  return done(null, profile);
}));
```

#### Python (Flask)

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url=f"{os.getenv('ISSUER_URL')}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid profile email'}
)
```

#### React (SPA with PKCE)

```javascript
import { UserManager } from 'oidc-client';

const userManager = new UserManager({
  authority: process.env.REACT_APP_ISSUER_URL,
  client_id: process.env.REACT_APP_CLIENT_ID,
  redirect_uri: 'http://localhost:3000/callback',
  response_type: 'code',
  scope: 'openid profile email',
});
```

## Upgrading

```bash
# Upgrade to latest version
helm upgrade my-client \
  oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  --namespace my-team \
  --reuse-values
```

### Regenerate Client Secret

```bash
helm upgrade my-client keycloak-operator/keycloak-client \
  --namespace my-team \
  --reuse-values \
  --set regenerateSecret=true
```

## Uninstalling

```bash
# Uninstall the chart
helm uninstall my-client -n my-team
```

**⚠️ Warning:** This will delete the client from Keycloak. Applications using this client will stop working!

## Troubleshooting

### Client Stuck in Pending/Failed

**Symptom:** Client resource shows `Pending` or `Failed` phase

```bash
# Check client status
kubectl describe keycloakclient my-client -n my-team

# Check operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep my-client
```

**Common causes:**
1. **Invalid realm token** - Verify `realmRef.authorizationSecretRef.name`
2. **Realm not ready** - Check `kubectl get keycloakrealm -n my-team`
3. **Invalid redirect URIs** - Check URI format
4. **RBAC issues** - Verify RoleBinding exists

### No Client Secret Created

**Symptom:** Secret `{client-name}-credentials` doesn't exist

```bash
# Check if secret should be created
helm get values my-client -n my-team | grep manageSecret

# Check if client is public
helm get values my-client -n my-team | grep publicClient
```

**Solution:** Secrets are only created for confidential clients (`publicClient: false` and `manageSecret: true`)

### OAuth2 Redirect URI Mismatch

**Symptom:** OAuth2 error "redirect_uri_mismatch"

```bash
# Check configured redirect URIs
kubectl get keycloakclient my-client -n my-team -o jsonpath='{.spec.redirectUris}'
```

**Solution:** Ensure redirect URI in your app exactly matches one in the client configuration (including trailing slashes):

```yaml
redirectUris:
  - "https://myapp.example.com/callback"  # Must match exactly
```

### CORS Issues

**Symptom:** Browser console shows CORS errors

```bash
# Check web origins
kubectl get keycloakclient my-client -n my-team -o jsonpath='{.spec.webOrigins}'
```

**Solution:** Add your frontend URL to `webOrigins`:

```yaml
webOrigins:
  - "https://myapp.example.com"
  - "http://localhost:3000"  # For development
```

### Service Account Roles Not Assigned

**Symptom:** Service account doesn't have expected permissions

```bash
# Verify service account is enabled
kubectl get keycloakclient my-client -n my-team -o jsonpath='{.spec.serviceAccountsEnabled}'

# Check configured roles
kubectl get keycloakclient my-client -n my-team -o yaml | grep -A10 serviceAccountRoles
```

**Solution:** Ensure `serviceAccountsEnabled: true` and roles are correctly specified

## Documentation

- **Main Documentation:** https://github.com/vriesdemichael/keycloak-operator
- **Quick Start Guide:** [docs/quickstart/README.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/quickstart/README.md)
- **OAuth2/OIDC Flows:** https://www.keycloak.org/docs/latest/securing_apps/
- **Protocol Mappers:** https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers

## Related Charts

- **[keycloak-operator](../keycloak-operator/README.md)** - Deploy the Keycloak Operator (required)
- **[keycloak-realm](../keycloak-realm/README.md)** - Deploy Keycloak realms (required)

## Support

- **Issues:** https://github.com/vriesdemichael/keycloak-operator/issues
- **Discussions:** https://github.com/vriesdemichael/keycloak-operator/discussions

## License

MIT License - see [LICENSE](https://github.com/vriesdemichael/keycloak-operator/blob/main/LICENSE) for details.
