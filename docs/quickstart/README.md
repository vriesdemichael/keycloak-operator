# Quick Start Guide

Get started with the Keycloak Operator in under 10 minutes! This guide walks you through deploying a complete Keycloak setup with a realm and OAuth2 client.

## Prerequisites

Before you begin, ensure you have:

- ✅ Kubernetes cluster (v1.26+)
- ✅ `kubectl` configured to access your cluster
- ✅ [Helm 3](https://helm.sh/docs/intro/install/) installed
- ✅ Cluster admin permissions (for CRD and operator installation)
- ✅ [CloudNativePG operator](https://cloudnative-pg.io/documentation/current/installation_upgrade/) installed (for PostgreSQL database)
- ✅ [cert-manager](https://cert-manager.io/docs/installation/) installed (for webhook certificates)

**Optional but recommended:**
- Ingress controller (nginx, traefik, etc.) for external access

## Step 1: Install the Operator

Install the Keycloak operator using Helm:

```bash
# Add the Helm repository
helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator
helm repo update

# Install the operator
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace \
  --wait
```

Verify the operator is running:

```bash
kubectl get pods -n keycloak-system
# Expected output:
# NAME                                 READY   STATUS    RESTARTS   AGE
# keycloak-operator-xxxxx-xxxxx        1/1     Running   0          30s
```

**Troubleshooting:** If pods are not running, check logs:
```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=50
```

## Step 2: Deploy Keycloak Instance

Create a Keycloak instance with PostgreSQL database managed by the operator:

```bash
kubectl apply -f - <<EOF
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  hostname: keycloak.local  # Change to your domain
  replicas: 3
  database:
    vendor: postgres
    host: keycloak-postgresql.keycloak-system.svc
    name: keycloak
    credentialsSecret: keycloak-db-credentials
  http:
    tlsSecret: ""  # Add your TLS secret name for HTTPS
  resources:
    requests:
      memory: "1Gi"
      cpu: "500m"
    limits:
      memory: "2Gi"
      cpu: "2000m"
EOF
```

Wait for Keycloak to become ready (takes 2-3 minutes):

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

Verify the Keycloak instance:

```bash
# Check status details
kubectl get keycloak keycloak -n keycloak-system -o jsonpath='{.status}' | jq
```

**Note:** Admin credentials are stored in the `keycloak-admin-credentials` secret. You generally don't need direct admin console access - all configuration is done through CRDs.

## Step 3: Create Application Namespace

Create a namespace for your application:

```bash
kubectl create namespace my-app
```

## Step 4: Create Your First Realm

A realm is an identity domain that contains users, roles, and clients.

Create your realm:

```bash
kubectl apply -f - <<EOF
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-app-realm
  namespace: my-app
spec:
  realmName: my-app
  instanceRef:
    name: keycloak
    namespace: keycloak-system
  displayName: "My Application"
  enabled: true
  security:
    registrationAllowed: false
    resetPasswordAllowed: true
    rememberMe: true
  themes:
    loginTheme: keycloak
    accountTheme: keycloak
  # Grant permission for this namespace to create clients
  clientAuthorizationGrants:
    - my-app
EOF
```

Wait for the realm to become ready:

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
kubectl get keycloakrealm my-app-realm -n my-app -o jsonpath='{.status}' | jq
```

**Understanding Authorization:**
- The `clientAuthorizationGrants` field lists which namespaces can create clients in this realm
- In this example, `my-app` namespace can create clients
- This is a declarative, GitOps-friendly authorization model (no tokens required!)

## Step 5: Create an OAuth2/OIDC Client

Create an OAuth2/OIDC client for your application:

```bash
kubectl apply -f - <<EOF
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakClient.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: my-app-client
  namespace: my-app
spec:
  clientId: my-app
  realmRef:
    name: my-app-realm
    namespace: my-app
  name: "My Application"
  description: "OAuth2/OIDC client for my-app"
  enabled: true
  publicClient: false  # confidential client (has secret)
  standardFlowEnabled: true
  implicitFlowEnabled: false
  directAccessGrantsEnabled: true
  serviceAccountsEnabled: false
  redirectUris:
    - "https://my-app.example.com/callback"
    - "http://localhost:3000/callback"  # for local development
  webOrigins:
    - "https://my-app.example.com"
    - "http://localhost:3000"
EOF
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

Test the OAuth2 authorization flow:

```bash
# Get the realm's public URL from status
ISSUER_URL=$(kubectl get keycloakrealm my-app-realm -n my-app \
  -o jsonpath='{.status.publicUrl}')

# Authorization endpoint
AUTH_URL="${ISSUER_URL}/protocol/openid-connect/auth"
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
kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Check Keycloak instance
kubectl get keycloak -n keycloak-system

# Check realm
kubectl get keycloakrealm -n my-app

# Check client
kubectl get keycloakclient -n my-app

# View operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100
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

Now that you have a working Keycloak realm and client, explore these guides:

**Production Deployment:**
- [High Availability](../how-to/ha-deployment.md) - Deploy Keycloak with redundancy and failover
- [Database Setup](../how-to/database-setup.md) - Configure production-grade PostgreSQL database

**Configuration:**
- [SMTP Configuration](../how-to/smtp-configuration.md) - Enable email notifications for password reset, verification, etc.
- [Identity Providers](../identity-providers.md) - Integrate with Google, GitHub, Azure AD, and other SSO providers
- [KeycloakRealm CRD Reference](../reference/keycloak-realm-crd.md) - Complete realm configuration options
- [KeycloakClient CRD Reference](../reference/keycloak-client-crd.md) - Complete client configuration options

**Operations:**
- [Troubleshooting Guide](../operations/troubleshooting.md) - Diagnose and resolve common issues
- [Backup & Restore](../how-to/backup-restore.md) - Protect your Keycloak data

**Understanding the System:**
- [Architecture](../architecture.md) - How the operator works (reconciliation, status management)
- [Security Model](../security.md) - Authorization model and security best practices
- [FAQ](../faq.md) - Answers to common questions

## Troubleshooting

### Operator pods not starting

```bash
# Check operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Check for RBAC issues
kubectl describe clusterrolebinding keycloak-operator

# Check webhook certificates
kubectl get certificate -n keycloak-system
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

# Check realm status conditions
kubectl get keycloakrealm my-app-realm -n my-app -o jsonpath='{.status.conditions}' | jq

# Check operator can reach Keycloak
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep "my-app-realm"
```

### Client creation fails with authorization error

**Symptoms**: Client shows error about namespace not authorized

```bash
# Check realm's authorization grants
kubectl get keycloakrealm my-app-realm -n my-app \
  -o jsonpath='{.spec.clientAuthorizationGrants}' | jq

# Ensure client's namespace is in the grant list
kubectl patch keycloakrealm my-app-realm -n my-app --type=merge -p '
spec:
  clientAuthorizationGrants:
    - my-app
    - other-allowed-namespace
'
```

### Admission webhook failures

```bash
# Check webhook is ready
kubectl get validatingwebhookconfiguration keycloak-operator-webhook

# Check certificate is valid
kubectl get certificate -n keycloak-system keycloak-operator-webhook-cert

# Check webhook logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep webhook
```

## Support

- 📚 [Full Documentation](../index.md)
- 🐛 [Report Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
- 💬 [Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)
