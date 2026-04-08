# Identity Providers

Identity providers let a realm delegate authentication to external systems such as GitHub, Google, Microsoft Entra ID, or another OIDC or SAML provider.

The recommended deployment path is the `keycloak-realm` Helm chart. Raw `KeycloakRealm` manifests are still supported, but they are the advanced path when you want to manage the CR directly.

## Overview

The realm chart maps identity provider configuration directly from `values.yaml` into `spec.identityProviders` on the generated `KeycloakRealm`.

```yaml
# values.yaml for charts/keycloak-realm
identityProviders:
  - alias: github
    providerId: github
    enabled: true
    trustEmail: false
    firstBrokerLoginFlowAlias: first broker login
    config:
      clientId: your-github-client-id
      defaultScope: "user:email"
      syncMode: IMPORT
    configSecrets:
      clientSecret:
        name: github-idp-secret
        key: clientSecret
```

The underlying CR field is `spec.identityProviders`.

## Secret Handling

Sensitive values must go in `configSecrets`, not in `config`.

The realm model rejects plaintext values for known sensitive keys such as:

- `clientSecret`
- `secret`
- `password`
- `privateKey`
- `signingKey`

Referenced secrets must:

- live in the same namespace as the `KeycloakRealm`
- include the label `vriesdemichael.github.io/keycloak-allow-operator-read: "true"`

Example:

```yaml
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

To label an existing secret:

```bash
kubectl label secret github-idp-secret -n my-app \
  vriesdemichael.github.io/keycloak-allow-operator-read=true
```

## Flow Aliases

Two optional fields control the user journey around brokered login:

- `firstBrokerLoginFlowAlias`: runs when a user signs in through the provider for the first time and Keycloak needs to create or link the local account.
- `postBrokerLoginFlowAlias`: runs after successful brokered login for follow-up steps you want on normal brokered authentication.

If you do not need custom flows, leave them unset or use the standard Keycloak defaults.

## Using Helm

### GitHub OAuth

```yaml
identityProviders:
  - alias: github
    providerId: github
    displayName: GitHub
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
```

### Google OAuth

```yaml
identityProviders:
  - alias: google
    providerId: google
    displayName: Google
    enabled: true
    trustEmail: true
    firstBrokerLoginFlowAlias: first broker login
    config:
      clientId: your-google-client-id.apps.googleusercontent.com
      hostedDomain: company.com
      defaultScope: "openid profile email"
      syncMode: IMPORT
    configSecrets:
      clientSecret:
        name: google-idp-secret
        key: clientSecret
```

### Azure AD / Microsoft Entra ID

Use the OIDC provider with explicit Microsoft endpoints.

```yaml
identityProviders:
  - alias: azure-ad
    providerId: oidc
    displayName: Microsoft Entra ID
    enabled: true
    trustEmail: true
    firstBrokerLoginFlowAlias: first broker login
    postBrokerLoginFlowAlias: post broker login
    config:
      clientId: 00000000-0000-0000-0000-000000000000
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

Replace:

- `YOUR_TENANT_ID` with the Microsoft tenant ID
- `clientId` with the application registration client ID

### Custom OIDC Provider

```yaml
identityProviders:
  - alias: custom-oidc
    providerId: oidc
    enabled: true
    trustEmail: false
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

### SAML Provider

```yaml
identityProviders:
  - alias: saml-idp
    providerId: saml
    enabled: true
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

## OIDC Endpoint Discovery

The operator does not expose a dedicated `discoveryUrl` field for identity providers. For OIDC providers, fetch the provider's discovery document and copy the resolved endpoints into `config`.

Example:

```bash
curl -s https://idp.example.com/.well-known/openid-configuration | jq '{issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri}'
```

Then map those values into:

- `issuer`
- `authorizationUrl`
- `tokenUrl`
- `userInfoUrl`
- `jwksUrl`

## Raw CR Example

If you are managing the CR directly, the same structure lives under `spec.identityProviders`.

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-realm
  operatorRef:
    namespace: keycloak-system
  identityProviders:
    - alias: github
      providerId: github
      enabled: true
      config:
        clientId: your-github-client-id
        defaultScope: "user:email"
        syncMode: IMPORT
      configSecrets:
        clientSecret:
          name: github-idp-secret
          key: clientSecret
```

## Common Mappers

Identity provider mappers use the `identityProviders[].mappers` field.

```yaml
identityProviders:
  - alias: custom-oidc
    providerId: oidc
    config:
      clientId: my-client-id
      authorizationUrl: https://idp.example.com/auth
      tokenUrl: https://idp.example.com/token
      userInfoUrl: https://idp.example.com/userinfo
      jwksUrl: https://idp.example.com/keys
      issuer: https://idp.example.com
    configSecrets:
      clientSecret:
        name: custom-oidc-secret
        key: clientSecret
    mappers:
      - name: email-mapper
        identityProviderMapper: oidc-user-attribute-idp-mapper
        config:
          claim: email
          user.attribute: email
          syncMode: INHERIT
      - name: team-mapper
        identityProviderMapper: oidc-user-attribute-idp-mapper
        config:
          claim: team
          user.attribute: team
          syncMode: INHERIT
```

Use mappers when you need to:

- copy claims into user attributes
- map upstream attributes into roles or groups
- preserve brokered attributes in the local Keycloak user model

## Troubleshooting

### Sensitive value rejected in `config`

Move the value to `configSecrets`. Sensitive keys are intentionally blocked from plaintext config.

### Login button does not appear

- verify `enabled: true`
- verify the provider `alias` is unique in the realm
- verify the upstream client ID and secret are correct

### Redirect URI mismatch

The broker endpoint format is:

```text
https://your-keycloak-domain/realms/your-realm/broker/<alias>/endpoint
```

### Claims are missing

- request the necessary scopes from the upstream provider
- add or correct the mapper configuration
- switch `syncMode` if you expect attributes to refresh on later logins

## See Also

- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md)
- [Multi-Tenant Guide](../how-to/multi-tenant.md)
- `charts/keycloak-realm/README.md` for chart-specific values context
- `examples/realm-with-azure-ad-idp.yaml`, `examples/realm-with-github-idp.yaml`, and `examples/realm-with-google-idp.yaml` for full manifest examples
