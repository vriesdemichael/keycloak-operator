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

Sensitive identity provider values such as `clientSecret` must not be placed in `identityProviders[].config`. The realm model rejects known sensitive keys in `config`; provide them through `identityProviders[].configSecrets` instead.

Secrets referenced from `configSecrets` must:
- live in the same namespace as the `KeycloakRealm`
- include the label `vriesdemichael.github.io/keycloak-allow-operator-read: "true"`

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
    namespace: keycloak-operator

  identityProviders:
    - alias: github
      providerId: github
      enabled: true
      trustEmail: false
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-github-oauth-app-client-id
        defaultScope: "user:email"
        syncMode: IMPORT
      configSecrets:
        clientSecret:
          name: github-idp-secret
          key: clientSecret

# Secret must be in the same namespace as the realm and labeled for operator read access
---
apiVersion: v1
kind: Secret
metadata:
  name: github-idp-secret
  namespace: my-app
  labels:
    vriesdemichael.github.io/keycloak-allow-operator-read: "true"
stringData:
  clientSecret: your-github-oauth-app-client-secret
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
    namespace: keycloak-operator

  identityProviders:
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-google-oauth-client-id.apps.googleusercontent.com
        hostedDomain: ""  # Optional: restrict to specific domain (e.g., "company.com")
        defaultScope: "openid profile email"
        syncMode: IMPORT
      configSecrets:
        clientSecret:
          name: google-idp-secret
          key: clientSecret
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
    namespace: keycloak-operator

  identityProviders:
    - alias: azure-ad
      providerId: oidc
      enabled: true
      trustEmail: true
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-azure-app-client-id
        authorizationUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/authorize
        tokenUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/token
        userInfoUrl: https://graph.microsoft.com/oidc/userinfo
        jwksUrl: https://login.microsoftonline.com/YOUR_TENANT_ID/discovery/v2.0/keys
        issuer: https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
        defaultScope: "openid profile email"
        syncMode: IMPORT
        validateSignature: "true"
        useJwksUrl: "true"
      configSecrets:
        clientSecret:
          name: azure-ad-idp-secret
          key: clientSecret
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
    namespace: keycloak-operator

  identityProviders:
    - alias: custom-oidc
      providerId: oidc
      enabled: true
      trustEmail: false
      firstBrokerLoginFlowAlias: first broker login
      config:
        clientId: your-client-id
        authorizationUrl: https://idp.example.com/oauth2/authorize
        tokenUrl: https://idp.example.com/oauth2/token
        userInfoUrl: https://idp.example.com/oauth2/userinfo
        jwksUrl: https://idp.example.com/oauth2/keys
        issuer: https://idp.example.com
        defaultScope: "openid profile email"
        syncMode: IMPORT
        validateSignature: "true"
        useJwksUrl: "true"
      configSecrets:
        clientSecret:
          name: custom-oidc-idp-secret
          key: clientSecret
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
    namespace: keycloak-operator

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

Identity provider mappers are supported through the `identityProviders[].mappers` field. Use them to import claims from the external provider into Keycloak user attributes, roles, or session notes.

Example:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
spec:
  realmName: my-realm
  operatorRef:
    namespace: keycloak-operator

  identityProviders:
    - alias: dex
      providerId: oidc
      config:
        clientId: my-client-id
        authorizationUrl: https://dex.example.com/auth
        tokenUrl: https://dex.example.com/token
        userInfoUrl: https://dex.example.com/userinfo
        jwksUrl: https://dex.example.com/keys
        issuer: https://dex.example.com
      configSecrets:
        clientSecret:
          name: dex-idp-secret
          key: clientSecret
      mappers:
        - name: email-mapper
          identityProviderMapper: oidc-user-attribute-idp-mapper
          config:
            claim: email
            user.attribute: email
            syncMode: INHERIT
```

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
    namespace: keycloak-operator

  identityProviders:
    # GitHub for developers
    - alias: github
      providerId: github
      enabled: true
      trustEmail: false
      config:
        clientId: github-client-id
        defaultScope: "user:email"
        syncMode: IMPORT
      configSecrets:
        clientSecret:
          name: github-idp-secret
          key: clientSecret

    # Google Workspace for employees
    - alias: google
      providerId: google
      enabled: true
      trustEmail: true
      config:
        clientId: google-client-id.apps.googleusercontent.com
        hostedDomain: "company.com"
        defaultScope: "openid profile email"
        syncMode: FORCE
      configSecrets:
        clientSecret:
          name: google-idp-secret
          key: clientSecret

    # Azure AD for enterprise SSO
    - alias: azure-ad
      providerId: oidc
      enabled: true
      trustEmail: true
      config:
        clientId: azure-client-id
        authorizationUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/authorize
        tokenUrl: https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token
        userInfoUrl: https://graph.microsoft.com/oidc/userinfo
        jwksUrl: https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys
        issuer: https://login.microsoftonline.com/TENANT_ID/v2.0
        defaultScope: "openid profile email"
        syncMode: FORCE
        validateSignature: "true"
        useJwksUrl: "true"
      configSecrets:
        clientSecret:
          name: azure-ad-idp-secret
          key: clientSecret
```

### Using Secrets for Credentials

Store IDP client secrets in Kubernetes Secrets and reference them with `configSecrets`.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-oauth-secret
  namespace: my-app
  labels:
    vriesdemichael.github.io/keycloak-allow-operator-read: "true"
stringData:
  client-secret: your-github-oauth-app-client-secret
---
identityProviders:
  - alias: github
    providerId: github
    enabled: true
    trustEmail: false
    config:
      clientId: my-github-client-id
      defaultScope: "user:email"
      syncMode: IMPORT
    configSecrets:
      clientSecret:
        name: github-oauth-secret
        key: client-secret
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

Verify IDP configuration through the CRD status:

```bash
# Check realm status includes IDP configuration
kubectl get keycloakrealm <name> -n <namespace> -o yaml

# Check operator logs for IDP reconciliation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator \
  | grep "identity.*provider"
```

## See Also

- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md)
- [Quick Start Guide](../quickstart/README.md)
