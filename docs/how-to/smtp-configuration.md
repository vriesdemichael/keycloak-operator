# SMTP Configuration Guide

Configure SMTP for Keycloak email features (verification, password reset, notifications).

## Quick Setup

### 1. Create SMTP Credentials Secret

```bash
kubectl create secret generic my-realm-smtp \
  --from-literal=username=smtp-user \
  --from-literal=password=smtp-password \
  --namespace=my-app
```

### 2. Configure Realm with SMTP

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
    authorizationSecretRef:
      name: my-app-operator-token

  smtp:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    fromDisplayName: My Application
    auth: true
    starttls: true
    credentialsSecret: my-realm-smtp
```

---

## Provider Examples

### SendGrid

```bash
# Create secret
kubectl create secret generic smtp-sendgrid \
  --from-literal=username=apikey \
  --from-literal=password=SG.your-api-key \
  --namespace=my-app
```

```yaml
smtp:
  host: smtp.sendgrid.net
  port: 587
  from: noreply@example.com
  fromDisplayName: My App
  auth: true
  starttls: true
  credentialsSecret: smtp-sendgrid
```

### Gmail

**Setup**: Enable 2FA and create App Password at https://myaccount.google.com/apppasswords

```bash
kubectl create secret generic smtp-gmail \
  --from-literal=username=your-email@gmail.com \
  --from-literal=password=your-app-password \
  --namespace=my-app
```

```yaml
smtp:
  host: smtp.gmail.com
  port: 587
  from: your-email@gmail.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  credentialsSecret: smtp-gmail
```

### AWS SES

```bash
# Get SMTP credentials from AWS SES Console
kubectl create secret generic smtp-ses \
  --from-literal=username=YOUR_SMTP_USERNAME \
  --from-literal=password=YOUR_SMTP_PASSWORD \
  --namespace=my-app
```

```yaml
smtp:
  host: email-smtp.us-east-1.amazonaws.com
  port: 587
  from: verified-sender@example.com  # Must be verified in SES
  fromDisplayName: My Application
  auth: true
  starttls: true
  credentialsSecret: smtp-ses
```

### Mailgun

```bash
kubectl create secret generic smtp-mailgun \
  --from-literal=username=postmaster@mg.example.com \
  --from-literal=password=your-smtp-password \
  --namespace=my-app
```

```yaml
smtp:
  host: smtp.mailgun.org
  port: 587
  from: noreply@mg.example.com
  fromDisplayName: My Application
  auth: true
  starttls: true
  credentialsSecret: smtp-mailgun
```

### Office 365

```bash
kubectl create secret generic smtp-o365 \
  --from-literal=username=your-email@company.com \
  --from-literal=password=your-password \
  --namespace=my-app
```

```yaml
smtp:
  host: smtp.office365.com
  port: 587
  from: your-email@company.com
  fromDisplayName: Company Name
  auth: true
  starttls: true
  credentialsSecret: smtp-o365
```

---

## Testing SMTP Configuration

### 1. Enable Email Verification

Update your realm to enable email verification:

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
    authorizationSecretRef:
      name: my-app-operator-token
      key: token

  security:
    verifyEmail: true
    registrationAllowed: true  # For testing only

  smtp:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@example.com
    fromDisplayName: My Application
    auth: true
    starttls: true
    credentialsSecret: my-realm-smtp
```

Apply the changes:
```bash
kubectl apply -f realm-with-smtp.yaml
```

### 2. Test Email Delivery

**Option A: Self-Registration Flow** (recommended for testing)
1. Navigate to your realm's account registration page:
   ```
   https://keycloak.example.com/realms/my-realm/protocol/openid-connect/registrations?client_id=account&response_type=code
   ```
2. Fill out registration form with valid email
3. Check email for verification link
4. Click link to verify account

**Option B: Password Reset Flow**
1. Create a test user via Keycloak admin console or realm import
2. Navigate to password reset page:
   ```
   https://keycloak.example.com/realms/my-realm/login-actions/reset-credentials
   ```
3. Enter test user's email
4. Check email for password reset link

### 3. Check Keycloak Logs

```bash
kubectl logs -n keycloak-system -l app=keycloak --tail=50 | grep -i smtp
```

---

## Troubleshooting

### SMTP Connection Refused

```bash
# Test SMTP connectivity from Keycloak pod
KEYCLOAK_POD=$(kubectl get pods -n keycloak-system -l app=keycloak -o name | head -1)

kubectl exec -it -n keycloak-system ${KEYCLOAK_POD} -- \
  curl -v telnet://smtp.sendgrid.net:587
```

**Solutions**:
- Verify host/port correct
- Check firewall/network policies
- Ensure SMTP service allows connections

### Authentication Failed

**Check**:
- Username/password correct in secret
- API key format (some providers use "apikey" as username)
- Account not locked/suspended

```bash
# Verify secret contents
kubectl get secret smtp-credentials -n my-app -o yaml
```

### Emails Not Received

**Check**:
1. **Spam folder**
2. **Sender verification** (AWS SES requires verified senders)
3. **Rate limits** (provider may throttle)
4. **DKIM/SPF records** if using custom domain

### SSL/TLS Issues

**Port Configuration**:
- Port 587: Use `starttls: true`, `ssl: false`
- Port 465: Use `ssl: true`, `starttls: false`
- Port 25: Use `starttls: false`, `ssl: false` (not recommended)

```yaml
# For port 465 (SSL)
smtp:
  port: 465
  ssl: true
  starttls: false
```

---

## Production Best Practices

### 1. Use SealedSecrets

```bash
# Encrypt SMTP credentials
kubeseal -o yaml < smtp-secret.yaml > smtp-secret-sealed.yaml
kubectl apply -f smtp-secret-sealed.yaml
```

### 2. Dedicated SMTP Service Account

Create dedicated account/API key for Keycloak:
- Limit permissions (send-only)
- Easier to rotate credentials
- Better audit trail

### 3. Monitor Email Delivery

Track metrics:
- Emails sent (Keycloak events)
- Bounce rate (provider dashboard)
- Delivery time

### 4. Configure Rate Limits

Avoid provider throttling:
- SendGrid: 100 emails/day (free), higher for paid
- Gmail: 500 emails/day
- AWS SES: 200 emails/day (sandbox), higher after verification

---

## Related Documentation

- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md)
- [Troubleshooting Guide](../operations/troubleshooting.md)
