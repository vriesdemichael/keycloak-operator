# Identity Providers (IDPs)

Identity Providers allow Keycloak to delegate authentication to external systems, enabling Single Sign-On (SSO) and user federation from providers like GitHub, Google, Azure AD, or custom OIDC/SAML providers.

## Table of Contents

- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [Configuration](#configuration)
  - [GitHub OAuth](#github-oauth)
  - [Google OAuth](#google-oauth)
  - [Azure AD (Microsoft Entra ID)](#azure-ad-microsoft-entra-id)
  - [Custom OIDC Provider](#custom-oidc-provider)
  - [SAML Provider](#saml-provider)
- [IDP Mappers](#idp-mappers)
- [Complete Examples](#complete-examples)

## Overview

The operator supports configuring identity providers through the `KeycloakRealm` custom resource. Identity providers are configured in the `identityProviders` field of the realm spec.

When a user tries to log in to your Keycloak realm, they'll see buttons for each enabled identity provider on the login page, allowing them to authenticate through external systems.

## Supported Providers

The operator supports all Keycloak built-in identity providers:

- **Social Providers**: GitHub, Google, Facebook, LinkedIn, Stack Overflow, Microsoft, etc.
- **Enterprise Providers**: OIDC (OpenID Connect), SAML 2.0
- **Keycloak-to-Keycloak**: Federation between Keycloak instances

## Configuration

### GitHub OAuth

GitHub OAuth allows users to sign in with their GitHub accounts.

**Prerequisites:**
1. Create a GitHub OAuth App:
   - Go to Settings → Developer settings → OAuth Apps → New OAuth App
   - Set Authorization callback URL to: `https://your-keycloak-domain/realms/your-realm/broker/github/endpoint`
   - Note your Client ID and Client Secret

**Example:**

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  identityProviders:
    - alias: github
      providerId: github
      enabled: true
      trustEmail: false
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-github-oauth-app-client-id
        clientSecret: your-github-oauth-app-client-secret
        defaultScope: "user:email"
        syncMode: IMPORT
```

**Important Configuration Options:**

- `alias`: Unique identifier for this IDP (will be part of the callback URL)
- `trustEmail`: Whether to trust email addresses from GitHub (set to `false` for security)
- `syncMode`: How to sync users (`IMPORT`, `FORCE`, or `LEGACY`)
  - `IMPORT`: Create new users, update on first login only
  - `FORCE`: Update user data on every login
  - `LEGACY`: Don't update existing users

### Google OAuth

Google OAuth allows users to sign in with their Google accounts.

**Prerequisites:**
1. Create a Google Cloud Project and OAuth 2.0 Client:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a project → APIs & Services → Credentials → Create OAuth Client ID
   - Application type: Web application
   - Authorized redirect URIs: `https://your-keycloak-domain/realms/your-realm/broker/google/endpoint`
   - Note your Client ID and Client Secret

**Example:**

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  identityProviders:
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-google-oauth-client-id.apps.googleusercontent.com
        clientSecret: your-google-oauth-client-secret
        hostedDomain: ""  # Optional: restrict to specific domain (e.g., "company.com")
        defaultScope: "openid profile email"
        syncMode: IMPORT
```

**Domain Restriction:**

To restrict logins to a specific Google Workspace domain:

```yaml
config:
  hostedDomain: "company.com"
```

### Azure AD (Microsoft Entra ID)

Azure AD integration allows users to sign in with their Microsoft work or school accounts.

**Prerequisites:**
1. Register an application in Azure AD:
   - Go to [Azure Portal](https://portal.azure.com/) → Azure Active Directory → App registrations → New registration
   - Set Redirect URI: `https://your-keycloak-domain/realms/your-realm/broker/azure-ad/endpoint`
   - Create a client secret in Certificates & secrets
   - Note your Application (client) ID, Directory (tenant) ID, and client secret

**Example:**

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  identityProviders:
    - alias: azure-ad
      providerId: oidc
      enabled: true
      trustEmail: true
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-azure-app-client-id
        clientSecret: your-azure-app-client-secret
        authorizationUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/authorize
        tokenUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token
        userInfoUrl: https://graph.microsoft.com/oidc/userinfo
        jwksUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/discovery/v2.0/keys
        issuer: https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
        defaultScope: "openid profile email"
        syncMode: IMPORT
        validateSignature: "true"
        useJwksUrl: "true"
```

Replace `YOUR_TENANT_ID` with your Azure AD tenant ID.

### Custom OIDC Provider

For any OpenID Connect-compliant identity provider.

**Example:**

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  identityProviders:
    - alias: custom-oidc
      providerId: oidc
      enabled: true
      trustEmail: false
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-client-id
        clientSecret: your-client-secret
        authorizationUrl: https://idp.example.com/oauth2/authorize
        tokenUrl: https://idp.example.com/oauth2/token
        userInfoUrl: https://idp.example.com/oauth2/userinfo
        jwksUrl: https://idp.example.com/oauth2/keys
        issuer: https://idp.example.com
        defaultScope: "openid profile email"
        syncMode: IMPORT
        validateSignature: "true"
        useJwksUrl: "true"
```

**Discovery Endpoint:**

Most OIDC providers support auto-discovery. You can find URLs at:
```
https://idp.example.com/.well-known/openid-configuration
```

### SAML Provider

For SAML 2.0 identity providers.

**Example:**

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  identityProviders:
    - alias: saml-idp
      providerId: saml
      enabled: true
      trustEmail: false
      firstBrokerLoginFlowAlias: first broker login
      config:
        singleSignOnServiceUrl: https://idp.example.com/saml/sso
        singleLogoutServiceUrl: https://idp.example.com/saml/logout
        backchannelSupported: "true"
        nameIDPolicyFormat: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
        principalType: SUBJECT
        signatureAlgorithm: RSA_SHA256
        xmlSigKeyInfoKeyNameTransformer: NONE
        syncMode: IMPORT
```

## IDP Mappers

**Note:** Currently, protocol mappers are supported for client scopes, but IDP-specific mappers (attribute importers) will be added in a future release.

Protocol mappers allow you to customize the claims/attributes in tokens. Here's an example of protocol mappers on a client scope:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
spec:
  realmName: my-realm
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: my-realm-token

  clientScopes:
    - name: custom-claims
      protocol: openid-connect
      protocolMappers:
        - name: groups-mapper
          protocol: openid-connect
          protocolMapper: oidc-group-membership-mapper
          config:
            claim.name: groups
            full.path: "false"
            id.token.claim: "true"
            access.token.claim: "true"
            userinfo.token.claim: "true"
```

For IDP attribute mappers (to import user attributes from the IDP), this functionality is planned for a future release. Meanwhile, you can configure them manually in the Keycloak admin console.

## Complete Examples

### Multi-IDP Setup

A realm with multiple identity providers:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: multi-idp-realm
  namespace: my-app
spec:
  realmName: multi-idp
  operatorRef:
    name: keycloak-operator
    namespace: keycloak-operator
  authorizationSecretRef: multi-idp-token

  identityProviders:
    # GitHub for developers
    - alias: github
      providerId: github
      enabled: true
      trustEmail: false
      config:
        clientId: github-client-id
        clientSecret: github-client-secret
        defaultScope: "user:email"
        syncMode: IMPORT

    # Google Workspace for employees
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      config:
        clientId: google-client-id.apps.googleusercontent.com
        clientSecret: google-client-secret
        hostedDomain: "company.com"
        defaultScope: "openid profile email"
        syncMode: FORCE

    # Azure AD for enterprise SSO
    - alias: azure-ad
      providerId: oidc
      enabled: true
      trustEmail: true
      config:
        clientId: azure-client-id
        clientSecret: azure-client-secret
        authorizationUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize
        tokenUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token
        userInfoUrl: https://graph.microsoft.com/oidc/userinfo
        jwksUrl: https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys
        issuer: https://login.microsoftonline.com/TENANT_ID/v2.0
        defaultScope: "openid profile email"
        syncMode: FORCE
        validateSignature: "true"
        useJwksUrl: "true"
```

### Using Secrets for Credentials

**Best Practice:** Store IDP client secrets in Kubernetes Secrets instead of hardcoding them in the CR.

**Note:** This feature is planned for a future release. Currently, secrets must be included in the `config` directly.

Planned syntax (coming soon):

```yaml
identityProviders:
  - alias: github
    providerId: github
    enabled: true
    trustEmail: false
    config:
      clientId: my-github-client-id
      clientSecretRef:  # Reference to Kubernetes Secret
        name: github-oauth-secret
        key: client-secret
      defaultScope: "user:email"
      syncMode: IMPORT
```

## Troubleshooting

### Common Issues

**1. "Invalid redirect URI" error:**
- Verify your redirect URI in the IDP matches exactly: `https://your-keycloak-domain/realms/your-realm/broker/{alias}/endpoint`
- Check for trailing slashes and protocol (http vs https)

**2. Users can't log in:**
- Check that `enabled: true` is set
- Verify client ID and secret are correct
- Check IDP logs for authentication failures

**3. User attributes not syncing:**
- Set `syncMode: FORCE` to update on every login
- Verify the requested scopes include the attributes you need
- Check IDP mapper configuration

**4. Email not trusted:**
- Set `trustEmail: true` only for trusted providers
- If false, users must verify their email after first login

### Checking IDP Status

You can verify IDP configuration in Keycloak:

```bash
# Port-forward to Keycloak
kubectl port-forward -n keycloak-operator svc/keycloak 8080:8080

# Access admin console at http://localhost:8080
# Navigate to: Realm Settings → Identity Providers
```

## See Also

- [Keycloak Realm Configuration](realms.md)
- [Client Scopes](client-scopes.md)
- [Authentication Flows](authentication-flows.md)
- [Examples](../examples/)
