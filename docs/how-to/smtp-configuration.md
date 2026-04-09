# SMTP Configuration Guide

Configure SMTP for Keycloak email features such as verification mail, password reset, and administrative notifications.

For most users, the `keycloak-realm` chart values are the primary interface. Raw `KeycloakRealm` manifests are still useful when you need direct CR control, but they are the advanced path.

## Read This First

- the realm field is `spec.smtpServer`, not `spec.smtp`
- the password reference is `passwordSecret.name` plus `passwordSecret.key`, not `credentialsSecret`
- the SMTP password secret must live in the same namespace as the `KeycloakRealm`
- the operator only reads the secret when it is labeled `vriesdemichael.github.io/keycloak-allow-operator-read=true`

## TLS and Port Choice

Pick the transport mode first so the rest of the config does not fight you.

| Port | Typical mode | Set |
| --- | --- | --- |
| `587` | STARTTLS | `starttls: true`, `ssl: false` |
| `465` | Implicit TLS | `ssl: true`, `starttls: false` |
| `25` | Plain SMTP or opportunistic STARTTLS | only use when your provider explicitly requires it |

## Helm Values (Recommended)

The realm chart exposes SMTP through `smtpServer.*` values and renders the corresponding `KeycloakRealm.spec.smtpServer` block.

```yaml
smtpServer:
  enabled: true
  host: smtp.sendgrid.net
  port: 587
  from: noreply@example.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  user: apikey
  passwordSecret:
    name: my-realm-smtp
    key: password
```

Create and label the password secret in the same namespace as the chart release:

```bash
kubectl create secret generic my-realm-smtp \
  --from-literal=password='smtp-password' \
  -n my-app

kubectl label secret my-realm-smtp \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n my-app
```

If your provider requires a username separate from the password secret, set it directly in values:

```yaml
smtpServer:
  user: noreply@example.com
```

## Raw `KeycloakRealm` Example

Use the raw CRD only when you are intentionally managing manifests directly.

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
  smtpServer:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    fromDisplayName: My Application
    auth: true
    starttls: true
    user: apikey
    passwordSecret:
      name: my-realm-smtp
      key: password
```

The field mapping is direct:

| Helm value | Raw CR field |
| --- | --- |
| `smtpServer.host` | `spec.smtpServer.host` |
| `smtpServer.user` | `spec.smtpServer.user` |
| `smtpServer.passwordSecret.name` | `spec.smtpServer.passwordSecret.name` |
| `smtpServer.passwordSecret.key` | `spec.smtpServer.passwordSecret.key` |

## Provider Examples

### SendGrid

```yaml
smtpServer:
  enabled: true
  host: smtp.sendgrid.net
  port: 587
  from: noreply@example.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  user: apikey
  passwordSecret:
    name: smtp-sendgrid
    key: password
```

### Gmail

Enable 2FA first and create an App Password, then use port `587` with STARTTLS:

```yaml
smtpServer:
  enabled: true
  host: smtp.gmail.com
  port: 587
  from: your-email@gmail.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  user: your-email@gmail.com
  passwordSecret:
    name: smtp-gmail
    key: password
```

### AWS SES

```yaml
smtpServer:
  enabled: true
  host: email-smtp.us-east-1.amazonaws.com
  port: 587
  from: verified-sender@example.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  user: YOUR_SMTP_USERNAME
  passwordSecret:
    name: smtp-ses
    key: password
```

## Testing the Configuration

Enable a mail-triggering feature such as email verification or password reset and then test against a real mailbox.

```yaml
spec:
  security:
    verifyEmail: true
    registrationAllowed: true
  smtpServer:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    auth: true
    starttls: true
    user: apikey
    passwordSecret:
      name: my-realm-smtp
      key: password
```

Recommended smoke test flow:

1. apply the realm change
2. create or register a test user with a mailbox you control
3. trigger verification mail or password reset
4. confirm the mail is received and the link completes successfully

## Troubleshooting

### Secret Not Found Or Not Authorized

Check both namespace placement and the required label:

```bash
kubectl get secret my-realm-smtp -n my-app -o yaml
```

You should see:

- the secret in the same namespace as the `KeycloakRealm`
- the `vriesdemichael.github.io/keycloak-allow-operator-read=true` label
- the expected key under `data` or `stringData`

### SMTP Authentication Fails

Typical causes:

- provider-specific username rules such as SendGrid using `apikey`
- stale password or app password rotation
- account lockout or sender-verification requirements

### Connection Or TLS Errors

Validate that the port and TLS mode match the provider expectation.

- `587` should normally mean STARTTLS
- `465` should normally mean implicit TLS

If Keycloak is operator-managed, inspect the Keycloak pod logs in the Keycloak namespace. If only the realm reconciliation failed, inspect the realm status and operator logs first.

## Production Notes

- use a dedicated SMTP credential or API key for Keycloak instead of reusing a human mailbox password
- store the password through your normal secret-management path such as Sealed Secrets or External Secrets
- treat SMTP failures as part of your authentication SLO, because password reset and verification flows depend on them

## Related Documentation

- The `charts/keycloak-realm/README.md` file in the repository contains additional chart-specific examples.
- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md)
- [Troubleshooting Guide](../operations/troubleshooting.md)
