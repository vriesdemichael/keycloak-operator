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
kubectl apply -f 01-keycloak-instance.yaml
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

## Step 3: Create Application Namespace and Secrets

Create a namespace for your application:

```bash
kubectl create namespace my-app
```

Copy the operator authorization token to your application namespace:

```bash
# This token allows your realm to be created on the Keycloak instance
kubectl get secret keycloak-operator-auth-token \
  -n keycloak-system \
  -o yaml | \
  sed 's/namespace: keycloak-system/namespace: my-app/' | \
  kubectl apply -f -
```

Verify the secret was copied:

```bash
kubectl get secret keycloak-operator-auth-token -n my-app
```

## Step 4: Create a Realm

A realm is an identity domain that contains users, roles, and clients.

```bash
kubectl apply -f 02-realm-example.yaml
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

The realm is now available at: `http://localhost:8080/realms/my-app` (via port-forward)

## Step 5: Create an OAuth2 Client

Create an OAuth2/OIDC client for your application:

```bash
kubectl apply -f 03-client-example.yaml
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

- 📖 Read the [Security Model](../../docs/security.md) documentation
- 📊 Learn about [Observability](../../docs/observability.md) features
- 🏗️ Understand the [Architecture](../../docs/architecture.md)
- 🔧 Configure [SMTP for email](../../docs/realm-smtp.md)
- 🎨 Customize [Themes](../../docs/themes.md)
- 🔐 Set up [Identity Providers](../../docs/identity-providers.md)
- 👥 Configure [User Federation](../../docs/user-federation.md)

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

# Verify authorization secret exists
kubectl get secret keycloak-operator-auth-token -n my-app

# Check operator can reach Keycloak
kubectl logs -n keycloak-system -l app=keycloak-operator | grep "my-app-realm"
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

- 📚 [Full Documentation](../../README.md)
- 🐛 [Report Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
- 💬 [Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)
