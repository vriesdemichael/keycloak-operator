# Keycloak Realm Helm Chart

Helm chart for deploying Keycloak Realms - identity domains that contain users, roles, clients, and authentication settings.

## Overview

A Keycloak realm is an isolated identity domain where you manage:
- **Users and Groups** - User accounts and organizational structures
- **Roles** - Authorization roles and permissions
- **Authentication** - Login settings, password policies, brute force protection
- **Clients** - OAuth2/OIDC applications that authenticate users
- **Themes** - Custom branding for login pages and emails
- **Identity Providers** - Social login (Google, GitHub) and SAML/OIDC federation

This chart creates a `KeycloakRealm` custom resource that is reconciled by the Keycloak Operator.

**Target Users:** Development teams who need isolated identity domains for their applications.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.8+
- **Keycloak Operator** installed ([keycloak-operator chart](../keycloak-operator/README.md))
- **Operator Authorization Token** from the operator installation

## Installation

### Quick Start

```bash
# Get operator token first
OPERATOR_TOKEN=$(kubectl get secret keycloak-operator-auth-token \
  -n keycloak-system \
  -o jsonpath='{.data.token}' | base64 -d)

# Install realm chart
helm install my-realm keycloak-operator/keycloak-realm \
  --set realmName=my-app \
  --set operatorRef.namespace=keycloak-system \
  --namespace my-team \
  --create-namespace
```

### Install with Custom Values

```yaml
# values-custom.yaml
realmName: my-app-realm
displayName: "My Application"

instanceRef:
  name: keycloak
  namespace: keycloak-system

# Grant these namespaces permission to create clients
clientAuthorizationGrants:
  - my-namespace
  - partner-namespace

security:
  registrationAllowed: false
  resetPasswordAllowed: true
  rememberMe: true
  bruteForceProtected: true

themes:
  loginTheme: my-custom-theme
  accountTheme: my-custom-theme

smtpServer:
  enabled: true
  host: smtp.gmail.com
  port: 587
  from: noreply@example.com
  fromDisplayName: "My App"
  auth: true
  user: noreply@example.com
  passwordSecret:
    name: smtp-password
    key: password
```

```bash
helm install my-realm keycloak-operator/keycloak-realm \
  -f values-custom.yaml \
  --namespace my-team \
  --create-namespace
```

### Verify Installation

```bash
# Check realm status
kubectl get keycloakrealm my-realm -n my-team

# Wait for realm to be ready
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakrealm/my-realm \
  -n my-team --timeout=300s

# View realm details
kubectl describe keycloakrealm my-realm -n my-team
```

## Configuration

### Values Reference

#### Required Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `realmName` | **REQUIRED** Keycloak realm identifier | `""` |
| `operatorRef.namespace` | **REQUIRED** Namespace where operator is running | `keycloak-system` |

#### Realm Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `displayName` | Human-readable realm name shown in UI | `""` |

#### Operator Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `instanceRef.name` | Name of the Keycloak instance | `keycloak` |
| `instanceRef.namespace` | Namespace where Keycloak instance is running | `keycloak-system` |
| `clientAuthorizationGrants` | List of namespaces that can create clients in this realm | `[]` |

**Authorization:**
- **Realm Creation:** Controlled by Kubernetes RBAC
- **Client Creation:** Only namespaces in `clientAuthorizationGrants` can create clients
- No tokens required - fully declarative authorization


#### RBAC Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rbac.create` | Create RoleBinding for operator access | `true` |
| `rbac.operatorClusterRoleName` | Name of operator's ClusterRole | `keycloak-operator-namespace-access` |
| `rbac.operatorServiceAccountName` | Name of operator's ServiceAccount (auto-detected if empty) | `""` |

**Important:** The operator needs RBAC permissions to read secrets in your namespace. The chart automatically creates the necessary RoleBinding when `rbac.create: true`.

#### Security Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.registrationAllowed` | Allow users to self-register | `false` |
| `security.registrationEmailAsUsername` | Use email as username for registration | `false` |
| `security.editUsernameAllowed` | Allow users to edit their username | `false` |
| `security.resetPasswordAllowed` | Allow password reset via email | `true` |
| `security.rememberMe` | Enable "Remember Me" functionality | `false` |
| `security.verifyEmail` | Require email verification | `false` |
| `security.loginWithEmailAllowed` | Allow login with email address | `true` |
| `security.duplicateEmailsAllowed` | Allow duplicate email addresses | `false` |

##### Brute Force Protection

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.bruteForceProtected` | Enable brute force attack protection | `true` |
| `security.permanentLockout` | Permanently lockout after max failures | `false` |
| `security.maxFailureWait` | Max time user is locked out (seconds) | `900` (15 min) |
| `security.minimumQuickLoginWait` | Min wait between login attempts (seconds) | `60` |
| `security.waitIncrement` | Time added after each failure (seconds) | `60` |
| `security.quickLoginCheckMillis` | Quick login check interval (milliseconds) | `1000` |
| `security.maxDeltaTime` | Max time window for failures (seconds) | `43200` (12 hours) |
| `security.failureFactor` | Number of failures before lockout | `30` |

#### Theme Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `themes.login` | Login page theme | `""` (Keycloak default) |
| `themes.admin` | Admin console theme | `""` (Keycloak default) |
| `themes.account` | Account management theme | `""` (Keycloak default) |
| `themes.email` | Email template theme | `""` (Keycloak default) |

**Note:** Custom themes must be deployed to your Keycloak instance before referencing them here.

#### Localization Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `localization.enabled` | Enable internationalization | `true` |
| `localization.defaultLocale` | Default locale | `en` |
| `localization.supportedLocales` | List of supported locales | `["en"]` |

**Example:** Multi-language support

```yaml
localization:
  enabled: true
  defaultLocale: en
  supportedLocales:
    - en
    - nl
    - de
    - fr
    - es
```

#### Token Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tokenSettings.accessTokenLifespan` | Access token TTL (seconds) | `300` (5 min) |
| `tokenSettings.accessTokenLifespanForImplicitFlow` | Implicit flow token TTL (seconds) | `900` (15 min) |
| `tokenSettings.ssoSessionIdleTimeout` | SSO session idle timeout (seconds) | `1800` (30 min) |
| `tokenSettings.ssoSessionMaxLifespan` | SSO session max lifespan (seconds) | `36000` (10 hours) |
| `tokenSettings.offlineSessionIdleTimeout` | Offline session idle timeout (seconds) | `2592000` (30 days) |
| `tokenSettings.offlineSessionMaxLifespanEnabled` | Enable offline session max lifespan | `false` |
| `tokenSettings.offlineSessionMaxLifespan` | Offline session max lifespan (seconds) | `5184000` (60 days) |

**Example:** Shorter token lifespans for high-security applications

```yaml
tokenSettings:
  accessTokenLifespan: 60        # 1 minute
  ssoSessionIdleTimeout: 300     # 5 minutes
  ssoSessionMaxLifespan: 7200    # 2 hours
```

#### SMTP Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `smtpServer.enabled` | Enable SMTP email sending | `false` |
| `smtpServer.host` | SMTP server hostname | `""` |
| `smtpServer.port` | SMTP server port | `587` |
| `smtpServer.from` | From email address | `""` |
| `smtpServer.fromDisplayName` | From display name | `""` |
| `smtpServer.replyTo` | Reply-to email address | `""` |
| `smtpServer.envelopeFrom` | Envelope from address | `""` |
| `smtpServer.ssl` | Enable SSL/TLS | `false` |
| `smtpServer.starttls` | Enable STARTTLS | `true` |
| `smtpServer.auth` | Enable authentication | `true` |
| `smtpServer.user` | SMTP username | `""` |
| `smtpServer.passwordSecret.name` | Secret containing SMTP password | `""` |
| `smtpServer.passwordSecret.key` | Key in secret | `password` |

**Example:** Gmail SMTP

```yaml
smtpServer:
  enabled: true
  host: smtp.gmail.com
  port: 587
  from: noreply@example.com
  fromDisplayName: "My Application"
  replyTo: support@example.com
  starttls: true
  auth: true
  user: noreply@example.com
  passwordSecret:
    name: gmail-smtp-password
    key: password
```

**Important:** SMTP password secret must have the label:
```bash
kubectl label secret gmail-smtp-password \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n my-team
```

#### Custom Attributes

| Parameter | Description | Default |
|-----------|-------------|---------|
| `attributes` | Free-form key-value pairs for custom realm attributes | `{}` |

**Example:** Custom branding

```yaml
attributes:
  _browser_header.contentSecurityPolicy: "frame-src 'self'; frame-ancestors 'self';"
  _browser_header.xFrameOptions: "SAMEORIGIN"
  frontendUrl: "https://auth.example.com"
```

#### Extra Manifests

| Parameter | Description | Default |
|-----------|-------------|---------|
| `extraManifests` | Additional Kubernetes manifests to deploy | `[]` |

Use this for deploying secrets, ExternalSecrets, SealedSecrets, etc.

**Example:** Deploy SMTP secret

```yaml
extraManifests:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: smtp-password
      labels:
        vriesdemichael.github.io/keycloak-allow-operator-read: "true"
    stringData:
      password: "my-smtp-password"
```

#### Common Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `commonLabels` | Labels applied to all resources | `{}` |
| `commonAnnotations` | Annotations applied to all resources | `{}` |

## Usage Examples

### Basic Realm

Minimal configuration with default security settings:

```yaml
realmName: basic-app
displayName: "Basic Application"

operatorRef:
  namespace: keycloak-system
```

### Realm with Email Verification

Enable email verification for new users:

```yaml
realmName: verified-app
displayName: "Verified Application"

operatorRef:
  namespace: keycloak-system

security:
  verifyEmail: true
  loginWithEmailAllowed: true

smtpServer:
  enabled: true
  host: smtp.sendgrid.net
  port: 587
  from: verify@example.com
  fromDisplayName: "Verification Service"
  auth: true
  user: apikey
  passwordSecret:
    name: sendgrid-api-key
    key: password
```

### Realm with Self-Service Registration

Allow users to register accounts:

```yaml
realmName: public-app
displayName: "Public Application"

operatorRef:
  namespace: keycloak-system

security:
  registrationAllowed: true
  registrationEmailAsUsername: true
  verifyEmail: true
  resetPasswordAllowed: true
  rememberMe: true

smtpServer:
  enabled: true
  host: smtp.gmail.com
  port: 587
  from: noreply@example.com
  fromDisplayName: "Public App"
  auth: true
  user: noreply@example.com
  passwordSecret:
    name: gmail-password
    key: password
```

### Realm with Custom Themes

Use custom branding for login pages:

```yaml
realmName: branded-app
displayName: "Branded Application"

operatorRef:
  namespace: keycloak-system

themes:
  loginTheme: my-company-theme
  accountTheme: my-company-theme
  emailTheme: my-company-theme

attributes:
  frontendUrl: "https://auth.example.com"
```

### Multi-Language Realm

Support multiple languages:

```yaml
realmName: international-app
displayName: "International Application"

operatorRef:
  namespace: keycloak-system

localization:
  enabled: true
  defaultLocale: en
  supportedLocales:
    - en
    - nl
    - de
    - fr
    - es
    - ja
    - zh-CN
```

### High-Security Realm

Short-lived tokens and strict brute force protection:

```yaml
realmName: secure-app
displayName: "High Security Application"

operatorRef:
  namespace: keycloak-system

security:
  resetPasswordAllowed: false  # Require admin intervention
  rememberMe: false
  duplicateEmailsAllowed: false
  bruteForceProtected: true
  permanentLockout: false
  maxFailureWait: 1800  # 30 minutes
  failureFactor: 5      # Only 5 attempts

tokenSettings:
  accessTokenLifespan: 60       # 1 minute
  ssoSessionIdleTimeout: 300    # 5 minutes
  ssoSessionMaxLifespan: 3600   # 1 hour
```

## Post-Installation

### 1. Wait for Realm to be Ready

```bash
# Monitor realm status
kubectl get keycloakrealm my-realm -n my-team -w

# Wait for Ready phase
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakrealm/my-realm \
  -n my-team --timeout=300s
```

### 2. Retrieve Realm Authorization Token

The realm automatically generates a token for creating clients:

```bash
# Get the realm authorization secret name
REALM_SECRET=$(kubectl get keycloakrealm my-realm \
  -n my-team \
  -o jsonpath='{.status.authorizationSecretName}')

# Retrieve the token
kubectl get secret $REALM_SECRET \
  -n my-team \
  -o jsonpath='{.data.token}' | base64 -d
```

### 3. Create Clients

Now you can create OAuth2/OIDC clients in this realm:

```bash
helm install my-client keycloak-operator/keycloak-client \
  --set clientId=my-app \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --namespace my-team
```

## Upgrading

```bash
# Upgrade to latest version
helm upgrade my-realm \
  oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace my-team \
  --reuse-values
```

### Upgrade with New Values

```bash
helm upgrade my-realm keycloak-operator/keycloak-realm \
  --namespace my-team \
  --reuse-values \
  --set security.resetPasswordAllowed=false
```

## Uninstalling

```bash
# Uninstall the chart
helm uninstall my-realm -n my-team
```

**⚠️ Warning:** This will delete the realm from Keycloak, including all users, roles, and clients!

## Troubleshooting

### Realm Stuck in Pending/Failed

**Symptom:** Realm resource shows `Pending` or `Failed` phase

```bash
# Check realm status
kubectl describe keycloakrealm my-realm -n my-team

# Check operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep my-realm
```

**Common causes:**
1. **Invalid operator token** - Verify token is correct
2. **Operator not running** - Check operator pods
3. **Network issues** - Verify operator can reach Keycloak
4. **Keycloak instance not ready** - Check Keycloak resource

### RBAC Permission Denied

**Symptom:** `Operator does not have access to namespace`

```bash
# Check if RoleBinding exists
kubectl get rolebinding -n my-team | grep keycloak-operator

# Manually create RoleBinding if needed
kubectl create rolebinding keycloak-operator-access \
  --clusterrole=keycloak-operator-namespace-access \
  --serviceaccount=keycloak-system:keycloak-operator-keycloak-system \
  -n my-team
```

### Secret Not Found

**Symptom:** `Required secret 'smtp-password' not found`

```bash
# Check if secret exists
kubectl get secret smtp-password -n my-team

# Check if secret has required label
kubectl get secret smtp-password -n my-team -o yaml | grep keycloak-allow-operator-read
```

**Solution:** Add the required label:

```bash
kubectl label secret smtp-password \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n my-team
```

### SMTP Not Working

**Symptom:** Password reset emails not sent

```bash
# Verify SMTP configuration in realm
kubectl get keycloakrealm my-realm -n my-team -o yaml | grep -A10 smtpServer

# Test SMTP credentials manually
kubectl run smtp-test --rm -i --tty --image=python:3.9 -- python3 -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('user@example.com', 'password')
server.quit()
print('SMTP connection successful!')
"
```

**Common issues:**
- Wrong password in secret
- Missing `vriesdemichael.github.io/keycloak-allow-operator-read` label
- SMTP server requires app-specific password (Gmail, Outlook)
- Firewall blocking port 587

### Token Rotation Issues


See the [Token Rotation Troubleshooting](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/security.md#troubleshooting) section in the security documentation.

## Documentation

- **Main Documentation:** https://github.com/vriesdemichael/keycloak-operator
- **Quick Start Guide:** [docs/quickstart/README.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/quickstart/README.md)
- **Security Model:** [docs/security.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/security.md)
- **Token Management:** [docs/operations/token-management.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/operations/token-management.md)

## Related Charts

- **[keycloak-operator](../keycloak-operator/README.md)** - Deploy the Keycloak Operator (required)
- **[keycloak-client](../keycloak-client/README.md)** - Deploy OAuth2/OIDC clients in this realm

## Support

- **Issues:** https://github.com/vriesdemichael/keycloak-operator/issues
- **Discussions:** https://github.com/vriesdemichael/keycloak-operator/discussions

## License

MIT License - see [LICENSE](https://github.com/vriesdemichael/keycloak-operator/blob/main/LICENSE) for details.
