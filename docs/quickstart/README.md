# Quick Start Guide

Get started with the Keycloak Operator in under 10 minutes! This guide walks you through deploying a complete Keycloak setup with a realm and OAuth2 client.

## Prerequisites

Before you begin, ensure you have:

- ✅ Kubernetes cluster (v1.26+)
- ✅ `kubectl` configured to access your cluster
- ✅ [Helm 3](https://helm.sh/docs/intro/install/) installed
- ✅ Cluster admin permissions (for CRD and operator installation)
- ✅ [CloudNativePG operator](https://cloudnative-pg.io/documentation/current/installation_upgrade/) installed (for PostgreSQL database)

**Optional but recommended:**
- Ingress controller (nginx, traefik, etc.) for external access
- cert-manager for automatic TLS certificates

## Step 1: Install the Operator

Install the Keycloak operator using Helm:

```bash
# Add the Helm repository (if published)
# helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator

# Or install directly from local chart
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace
```

Verify the operator is running:

```bash
kubectl get pods -n keycloak-system
# Expected output:
# NAME                                 READY   STATUS    RESTARTS   AGE
# keycloak-operator-xxxxx-xxxxx        1/1     Running   0          30s
# keycloak-operator-xxxxx-xxxxx        1/1     Running   0          30s
```

**Troubleshooting:** If pods are not running, check logs:
```bash
kubectl logs -n keycloak-system -l app=keycloak-operator --tail=50
```

## Step 2: Deploy Keycloak Instance

Create a Keycloak instance with an integrated PostgreSQL database:

```bash
kubectl apply -f examples/01-keycloak-instance.yaml
```

This creates:
- **Keycloak deployment** with 3 replicas for high availability
- **PostgreSQL cluster** managed by CloudNativePG
- **Kubernetes Service** for internal access
- **Admin credentials secret** for console access

Wait for Keycloak to become ready (this takes 2-3 minutes):

```bash
kubectl wait --for=condition=Ready keycloak/keycloak \
  -n keycloak-system \
  --timeout=5m
```

Check the status:

```bash
kubectl get keycloak -n keycloak-system
# Expected output:
# NAME       PHASE   AGE
# keycloak   Ready   3m
```

View endpoints and credentials:

```bash
# Get Keycloak admin credentials
kubectl get secret keycloak-admin-credentials \
  -n keycloak-system \
  -o jsonpath='{.data.username}' | base64 -d && echo
kubectl get secret keycloak-admin-credentials \
  -n keycloak-system \
  -o jsonpath='{.data.password}' | base64 -d && echo

# Get Keycloak URL (if using port-forward)
kubectl port-forward svc/keycloak-keycloak -n keycloak-system 8080:8080
# Access: http://localhost:8080
```

## Step 3: Create Application Namespace and Bootstrap Token

Create a namespace for your application:

```bash
kubectl create namespace my-app
```

### Understanding Token Types

The operator uses a **two-phase token system** for enhanced security:

1. **Admission Token** (one-time, platform team creates)
   - Used to bootstrap a namespace
   - Creates the first realm
   - Triggers automatic generation of operational token

2. **Operational Token** (auto-rotating, operator manages)
   - Generated automatically after first realm
   - Used by all subsequent realms
   - Rotates every 90 days with zero downtime

### Create Admission Token

Platform teams create admission tokens for application teams:

```bash
# Generate a cryptographically secure token
ADMISSION_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Create admission token secret
kubectl create secret generic admission-token-my-app \
  --from-literal=token="$ADMISSION_TOKEN" \
  --namespace=my-app

# Add required labels
kubectl label secret admission-token-my-app \
  keycloak.mdvr.nl/token-type=admission \
  keycloak.mdvr.nl/allow-operator-read=true \
  --namespace=my-app

# Store token metadata in operator ConfigMap
TOKEN_HASH=$(echo -n "$ADMISSION_TOKEN" | sha256sum | cut -d' ' -f1)
kubectl patch configmap keycloak-operator-token-metadata \
  --namespace=keycloak-operator-system \
  --type=merge \
  --patch "{
    \"data\": {
      \"$TOKEN_HASH\": \"{\\\"namespace\\\": \\\"my-app\\\", \\\"token_type\\\": \\\"admission\\\", \\\"token_hash\\\": \\\"$TOKEN_HASH\\\", \\\"issued_at\\\": \\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"valid_until\\\": \\\"$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"version\\\": 1, \\\"created_by_realm\\\": null, \\\"revoked\\\": false}\"
    }
  }"
```

Verify the admission token was created:

```bash
kubectl get secret admission-token-my-app -n my-app
```

**📝 Note**: In production, platform teams typically:
- Use sealed secrets or external secret managers
- Distribute via GitOps repositories
- Include token setup in namespace provisioning automation

## Step 4: Create Your First Realm (Bootstrap)

A realm is an identity domain that contains users, roles, and clients.

**The first realm in a namespace is special** - it triggers the bootstrap process:
1. Validates the admission token
2. Generates an operational token (auto-rotating)
3. Stores operational token in `my-app-operator-token` secret
4. Future realms automatically use the operational token

Create your first realm:

```bash
kubectl apply -f - <<EOF
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-app-realm
  namespace: my-app
spec:
  realmName: my-app
  operatorRef:
    namespace: keycloak-operator-system
    authorizationSecretRef:
      name: admission-token-my-app  # ← Uses admission token (one-time)
      key: token
  security:
    registrationAllowed: false
    resetPasswordAllowed: true
  themes:
    loginTheme: keycloak
    accountTheme: keycloak
EOF
```

Wait for the realm to become ready (takes 10-30 seconds):

```bash
kubectl wait --for=condition=Ready keycloakrealm/my-app-realm \
  -n my-app \
  --timeout=2m
```

Check the realm status:

```bash
kubectl get keycloakrealm -n my-app
# Expected output:
# NAME            PHASE   AGE
# my-app-realm    Ready   45s

# View detailed status
kubectl get keycloakrealm my-app-realm -n my-app -o yaml | grep -A 10 status:
```

**Verify operational token was created**:

```bash
# After first realm creation, operational token should exist
kubectl get secret my-app-operator-token -n my-app

# Check token metadata
kubectl get secret my-app-operator-token -n my-app -o yaml | grep -A5 annotations:
# You should see:
#   keycloak.mdvr.nl/version: "1"
#   keycloak.mdvr.nl/valid-until: "<90 days from now>"
#   keycloak.mdvr.nl/created-by-realm: "my-app-realm"
```

The realm is now available at: `http://localhost:8080/realms/my-app` (via port-forward)

**🎉 Bootstrap Complete!**
- ✅ Admission token used (one-time)
- ✅ Operational token generated
- ✅ Automatic rotation enabled (90-day cycle)
- ✅ Future realms will use operational token

### Optional: Create Additional Realms

After bootstrap, create additional realms using the operational token:

```bash
kubectl apply -f - <<EOF
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-second-realm
  namespace: my-app
spec:
  realmName: my-second-app
  operatorRef:
    namespace: keycloak-operator-system
    authorizationSecretRef:
      name: my-app-operator-token  # ← Uses operational token (auto-rotating)
      key: token
  security:
    registrationAllowed: false
    resetPasswordAllowed: true
EOF
```

**Notice the difference:**
- First realm: Uses `admission-token-my-app` (one-time)
- Additional realms: Use `my-app-operator-token` (auto-rotating)

## Step 5: Create an OAuth2 Client

Create an OAuth2/OIDC client for your application:

```bash
kubectl apply -f examples/03-client-example.yaml
```

Wait for the client to become ready:

```bash
kubectl wait --for=condition=Ready keycloakclient/my-app-client \
  -n my-app \
  --timeout=2m
```

Check the client status:

```bash
kubectl get keycloakclient -n my-app
# Expected output:
# NAME             PHASE   AGE
# my-app-client    Ready   30s
```

## Step 6: Retrieve Client Credentials

The operator automatically creates a Kubernetes secret with OAuth2 credentials:

```bash
kubectl get secret my-app-client-credentials -n my-app -o yaml
```

Extract the credentials for use in your application:

```bash
# Client ID
kubectl get secret my-app-client-credentials -n my-app \
  -o jsonpath='{.data.client_id}' | base64 -d && echo

# Client Secret (for confidential clients)
kubectl get secret my-app-client-credentials -n my-app \
  -o jsonpath='{.data.client_secret}' | base64 -d && echo

# OIDC Discovery URL
kubectl get secret my-app-client-credentials -n my-app \
  -o jsonpath='{.data.issuer_url}' | base64 -d && echo

# Token Endpoint
kubectl get secret my-app-client-credentials -n my-app \
  -o jsonpath='{.data.token_url}' | base64 -d && echo
```

Create a convenient environment file:

```bash
kubectl get secret my-app-client-credentials -n my-app -o json | \
  jq -r '.data | to_entries[] | "\(.key | ascii_upcase)=\(.value | @base64d)"' > .env
cat .env
```

## Step 7: Test OAuth2 Flow

Access the Keycloak admin console:

```bash
# If using port-forward
kubectl port-forward svc/keycloak-keycloak -n keycloak-system 8080:8080

# Open in browser: http://localhost:8080
# Login with admin credentials from Step 2
```

Navigate to your realm:
1. Click **"my-app"** in the realm dropdown (top-left)
2. Go to **Clients** → **my-app**
3. Verify the client configuration

Test the OAuth2 authorization flow:
```bash
# Authorization endpoint
AUTH_URL="http://localhost:8080/realms/my-app/protocol/openid-connect/auth"
CLIENT_ID="my-app"
REDIRECT_URI="http://localhost:3000/callback"

# Open in browser (replace localhost:3000 with your app URL):
echo "${AUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid"
```

## Step 8: Integrate with Your Application

### Example: Node.js Application

```javascript
const { Issuer } = require('openid-client');

// Load credentials from the secret
const KEYCLOAK_URL = process.env.ISSUER_URL;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// Discover OpenID configuration
const issuer = await Issuer.discover(KEYCLOAK_URL);

const client = new issuer.Client({
  client_id: CLIENT_ID,
  client_secret: CLIENT_SECRET,
  redirect_uris: ['http://localhost:3000/callback'],
  response_types: ['code'],
});

// Use client for authentication
```

### Example: Python Application

```python
from authlib.integrations.flask_client import OAuth
import os

oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url=os.getenv('ISSUER_URL') + '/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

# Use oauth.keycloak for authentication
```

### Example: Spring Boot Application

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: ${CLIENT_ID}
            client-secret: ${CLIENT_SECRET}
            scope: openid,profile,email
        provider:
          keycloak:
            issuer-uri: ${ISSUER_URL}
```

## Verify Installation

Check that all resources are healthy:

```bash
# Check operator
kubectl get pods -n keycloak-system -l app=keycloak-operator

# Check Keycloak instance
kubectl get keycloak -n keycloak-system

# Check realm
kubectl get keycloakrealm -n my-app

# Check client
kubectl get keycloakclient -n my-app

# View operator logs
kubectl logs -n keycloak-system -l app=keycloak-operator --tail=100
```

All resources should show `PHASE=Ready`.

## Clean Up

To remove everything created in this guide:

```bash
# Delete client (will remove from Keycloak)
kubectl delete keycloakclient my-app-client -n my-app

# Delete realm (will remove from Keycloak)
kubectl delete keycloakrealm my-app-realm -n my-app

# Delete Keycloak instance (will remove database)
kubectl delete keycloak keycloak -n keycloak-system

# Delete namespace
kubectl delete namespace my-app

# Uninstall operator (optional)
helm uninstall keycloak-operator -n keycloak-system
```

**⚠️ Warning:** Deleting a Keycloak instance will delete the database and all stored users, sessions, and runtime data.

## Next Steps

- 📖 Read the [Security Model](../security.md) documentation
- 📊 Learn about [Observability](../observability.md) features
- 🏗️ Understand the [Architecture](../architecture.md)
- 🔧 Explore [Development Guide](../development.md)

## Troubleshooting

### Operator pods not starting

```bash
# Check operator logs
kubectl logs -n keycloak-system -l app=keycloak-operator

# Check for RBAC issues
kubectl describe clusterrolebinding keycloak-operator
```

### Keycloak instance stuck in Pending

```bash
# Check Keycloak resource status
kubectl describe keycloak keycloak -n keycloak-system

# Check PostgreSQL cluster status
kubectl get cluster -n keycloak-system

# Check pod events
kubectl get events -n keycloak-system --sort-by='.lastTimestamp'
```

### Realm reconciliation fails

```bash
# Check realm status
kubectl describe keycloakrealm my-app-realm -n my-app

# Verify authorization token exists (admission or operational)
kubectl get secret admission-token-my-app -n my-app  # For first realm
kubectl get secret my-app-operator-token -n my-app    # For subsequent realms

# Check operator can reach Keycloak
kubectl logs -n keycloak-operator-system -l app=keycloak-operator | grep "my-app-realm"
```

### Bootstrap not working (no operational token created)

**Symptoms**: First realm created but no `my-app-operator-token` secret generated

```bash
# Check if admission token exists
kubectl get secret admission-token-my-app -n my-app

# Check if admission token has correct labels
kubectl get secret admission-token-my-app -n my-app -o yaml | grep -A3 labels:
# Should include:
#   keycloak.mdvr.nl/token-type: admission
#   keycloak.mdvr.nl/allow-operator-read: "true"

# Check if token is in metadata ConfigMap
TOKEN_HASH=$(kubectl get secret admission-token-my-app -n my-app -o jsonpath='{.data.token}' | base64 -d | sha256sum | cut -d' ' -f1)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | jq --arg hash "$TOKEN_HASH" '.data[$hash]'

# Check operator logs for bootstrap
kubectl logs -n keycloak-operator-system -l app=keycloak-operator | grep -i "bootstrap\|admission"
```

### Token rotation issues

**Symptoms**: Token expired, rotation not happening automatically

```bash
# Check token status
kubectl get secret my-app-operator-token -n my-app -o yaml | grep -A10 annotations:

# Check if token is past expiry
VALID_UNTIL=$(kubectl get secret my-app-operator-token -n my-app \
  -o jsonpath='{.metadata.annotations.keycloak\.mdvr\.nl/valid-until}')
echo "Token expires: $VALID_UNTIL"
echo "Current time:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Check operator logs for rotation
kubectl logs -n keycloak-operator-system -l app=keycloak-operator | grep -i "rotation"

# Check for rotation metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep token_rotation
```

### Authorization failed after token rotation

**Symptoms**: Realms fail with "Authorization failed" after automatic rotation

```bash
# Check if realm is using admission token (should use operational)
kubectl get keycloakrealm my-app-realm -n my-app -o yaml | grep -A3 authorizationSecretRef:
# First realm can use admission token OR operational token
# Subsequent realms MUST use operational token

# Check if grace period has ended
kubectl get secret my-app-operator-token -n my-app -o jsonpath='{.data}' | jq 'keys'
# During grace period: ["token", "token-previous"]
# After grace period: ["token"]

# Update realm to use operational token
kubectl patch keycloakrealm my-app-realm -n my-app --type=merge -p '
spec:
  operatorRef:
    authorizationSecretRef:
      name: my-app-operator-token
      key: token
'
```

### Client creation fails

```bash
# Check client status
kubectl describe keycloakclient my-app-client -n my-app

# Verify realm is Ready
kubectl get keycloakrealm -n my-app

# Check realm authorization secret exists
kubectl get secret my-app-realm-realm-auth -n my-app
```

## Support

- 📚 [Full Documentation](../index.md)
- 🐛 [Report Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
- 💬 [Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)
