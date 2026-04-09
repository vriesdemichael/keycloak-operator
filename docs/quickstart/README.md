# Quick Start Guide

Get started with the Keycloak Operator in 10 minutes using the 3-helm-chart approach!

## Prerequisites

Before you begin, ensure you have:

- ✅ Kubernetes cluster (v1.26+)
- ✅ `kubectl` configured to access your cluster
- ✅ [Helm 3.8+](https://helm.sh/docs/intro/install/) installed (required for OCI registry support)
- ✅ Cluster admin permissions (for CRD installation)

### Storage Class Configuration

If using CloudNativePG for the database, ensure your cluster has a suitable StorageClass:

```bash
# Check available storage classes
kubectl get storageclass

# If your cluster doesn't have a 'standard' storageClass, configure it during install:
--set keycloak.database.cnpg.storage.storageClass=<your-storage-class>
```

## The 3-Helm-Chart Approach

This operator uses a modular helm chart structure:

1. **Database** (`cloudnative-pg/cloudnative-pg`) - PostgreSQL cluster
2. **Operator + Keycloak** (`keycloak-operator/keycloak-operator`) - Operator and instance
3. **Application Resources** (`keycloak-realm`, `keycloak-client`) - Your realms and clients

This separation enables:
- ✅ **Shared Database** - Multiple Keycloak instances can use one PostgreSQL cluster
- ✅ **GitOps Friendly** - Each chart in separate Helm release/ArgoCD application
- ✅ **Namespace Isolation** - Realms and clients in their own namespaces
- ✅ **Modular Upgrades** - Update components independently

## Step 1: Install PostgreSQL Database

Install CloudNativePG operator and create a PostgreSQL cluster:

```bash
# Install CloudNativePG operator
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm repo update
helm install cnpg cnpg/cloudnative-pg \
  --namespace cnpg-system \
  --create-namespace \
  --wait
```

The Keycloak operator chart can create the PostgreSQL cluster automatically using `keycloak.database.cnpg.enabled=true`.

## Step 2: Install Operator + Keycloak Instance

Install the operator with Keycloak instance enabled:

```bash
# Install operator + Keycloak with CloudNativePG database (using OCI registry)
helm install keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set keycloak.managed=true \
  --set keycloak.database.cnpg.enabled=true \
  --set keycloak.database.cnpg.clusterName=keycloak-postgres \
  --set keycloak.replicas=3 \
  --wait
```

> **Note: Namespace Creation**
> The chart creates the namespace by default (`namespace.create=true`). Do not use `--create-namespace` flag with the default settings.
> If you prefer to create the namespace yourself, set `--set namespace.create=false` and use `--create-namespace`.

**What this installs:**
- ✅ Keycloak operator (2 replicas for HA)
- ✅ Keycloak instance (3 replicas)
- ✅ PostgreSQL cluster (via CloudNativePG)
- ✅ Admission webhooks with cert-manager certificates
- ✅ Service accounts and RBAC

Verify everything is running:

```bash
# Check operator
kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Check Keycloak instance
kubectl get keycloak -n keycloak-system

# Check PostgreSQL cluster
kubectl get cluster -n keycloak-system

# Expected output:
# NAME       PHASE   AGE
# keycloak   Ready   2m
```

**Using External Database:**

If you have an existing PostgreSQL database:

```bash
helm install keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set namespace.create=false \
  --set keycloak.managed=true \
  --set keycloak.database.host=postgresql.database.svc \
  --set keycloak.database.port=5432 \
  --set keycloak.database.database=keycloak \
  --set keycloak.database.username=keycloak \
  --set keycloak.database.passwordSecret.name=db-password \
  --set keycloak.database.passwordSecret.key=password
```

If you want to work directly with raw `Keycloak`, `KeycloakRealm`, and `KeycloakClient` manifests instead of Helm releases, treat that as an advanced/manual path. See [Helm vs Direct CR Deployments](../how-to/helm-vs-cr-deployments.md) for the extra RBAC and manifest-management work Helm normally handles for you.

## Step 3: Create Application Realm

Create a realm for your application using the realm Helm chart:

```bash
# Create namespace for your app
kubectl create namespace my-app

# Install realm chart
helm install my-app-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace my-app \
  --set realmName=my-app \
  --set displayName="My Application" \
  --set operatorRef.namespace=keycloak-system \
  --set 'clientAuthorizationGrants={my-app}'
```

Wait for the realm to become ready:

```bash
kubectl wait --for=condition=Ready keycloakrealm --all \
  -n my-app \
  --timeout=2m

# Check status
kubectl get keycloakrealm -n my-app
```

## Step 4: Create OAuth2/OIDC Client

Create an OAuth2/OIDC client for your application:

```bash
helm install my-app-client oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  --namespace my-app \
  --set clientId=my-app \
  --set name="My Application" \
  --set realmRef.name=my-app-realm \
  --set realmRef.namespace=my-app \
  --set publicClient=false \
  --set standardFlowEnabled=true \
  --set directAccessGrantsEnabled=true \
  --set 'redirectUris={https://my-app.example.com/callback,http://localhost:3000/callback}' \
  --set 'webOrigins={https://my-app.example.com,http://localhost:3000}'
```

Wait for the client to become ready:

```bash
kubectl wait --for=condition=Ready keycloakclient --all \
  -n my-app \
  --timeout=2m

# Check status
kubectl get keycloakclient -n my-app
```

## Step 5: Use the Injected Client Credentials Secret

The operator automatically creates a Kubernetes secret with OAuth2 credentials in the same namespace as the `KeycloakClient` resource.

If you do not set `secretName`, the client chart defaults to `<release-fullname>-credentials`. In this quick start the Helm release name is `my-app-client`, the rendered client fullname becomes `my-app-client-keycloak-client`, and the generated Secret name becomes `my-app-client-keycloak-client-credentials`.

In a normal deployment, your application should consume that Secret directly through environment-variable injection or a mounted volume. You should not need to read these values manually unless you are debugging.

Example Deployment using `envFrom`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/company/my-app:latest
          envFrom:
            - secretRef:
                name: my-app-client-keycloak-client-credentials
```

Example Deployment using explicit environment-variable mapping:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: ghcr.io/company/my-app:latest
          env:
            - name: CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: my-app-client-keycloak-client-credentials
                  key: client-id
            - name: CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: my-app-client-keycloak-client-credentials
                  key: client-secret
            - name: ISSUER_URL
              valueFrom:
                secretKeyRef:
                  name: my-app-client-keycloak-client-credentials
                  key: issuer
```

The generated secret looks like this conceptually:

```bash
kubectl get secret my-app-client-keycloak-client-credentials -n my-app -o yaml
```

The generated secret includes keys such as `client-id`, `client-secret` for confidential clients, `issuer`, `keycloak-url`, `realm`, `token-endpoint`, `userinfo-endpoint`, and `jwks-endpoint`.

## Step 6: Integrate with Your Application

### Example: Node.js

```javascript
const { Issuer } = require('openid-client');

const issuer = await Issuer.discover(process.env.ISSUER_URL);
const client = new issuer.Client({
  client_id: process.env.CLIENT_ID,
  client_secret: process.env.CLIENT_SECRET,
  redirect_uris: ['http://localhost:3000/callback'],
  response_types: ['code'],
});
```

### Example: Python

```python
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url=os.getenv('ISSUER_URL') + '/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)
```

### Example: Spring Boot

```yaml
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

Check that all components are healthy:

```bash
# Operator
kubectl get pods -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Keycloak instance
kubectl get keycloak -n keycloak-system

# PostgreSQL
kubectl get cluster -n keycloak-system

# Realm
kubectl get keycloakrealm -n my-app

# Client
kubectl get keycloakclient -n my-app
```

All resources should show `PHASE=Ready`.

## Clean Up

```bash
# Delete application resources
helm uninstall my-app-client -n my-app
helm uninstall my-app-realm -n my-app
kubectl delete namespace my-app

# Delete operator and Keycloak
helm uninstall keycloak-operator -n keycloak-system

# Delete database (optional - will delete all data!)
helm uninstall cnpg -n cnpg-system
```

## Advanced: Using with ArgoCD

Structure your GitOps repository:

```
apps/
├── database/
│   └── cloudnative-pg.yaml        # wave: 0
├── keycloak-operator/
│   └── operator-with-instance.yaml # wave: 1
└── my-app/
    ├── realm.yaml                  # wave: 2
    └── client.yaml                 # wave: 3
```

Example ArgoCD Application:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: keycloak-operator
  annotations:
    argocd.argoproj.io/sync-wave: "1"
spec:
  project: default
  source:
    repoURL: ghcr.io/vriesdemichael/charts
    chart: keycloak-operator
    targetRevision: 0.3.x
    helm:
      values: |
        keycloak:
          enabled: true
          database:
            cnpg:
              enabled: true
  destination:
    server: https://kubernetes.default.svc
    namespace: keycloak-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

## Next Steps

**Configuration:**
- [SMTP Configuration](../how-to/smtp-configuration.md) - Email notifications
- [Identity Providers](../guides/identity-providers.md) - Google, GitHub, Azure AD SSO
- [High Availability](../how-to/ha-deployment.md) - Production HA setup

**Understanding the System:**
- [Architecture](../concepts/architecture.md) - How the operator works
- [Security Model](../concepts/security.md) - Authorization and RBAC
- [Drift Detection](../guides/drift-detection.md) - Orphan detection

**CRD References:**
- [KeycloakRealm](../reference/keycloak-realm-crd.md) - All realm options
- [KeycloakClient](../reference/keycloak-client-crd.md) - All client options

## Troubleshooting

### Operator not starting

```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
kubectl describe clusterrolebinding keycloak-operator
kubectl get certificate -n keycloak-system
```

### Keycloak stuck in Pending

```bash
kubectl describe keycloak keycloak -n keycloak-system
kubectl get cluster -n keycloak-system  # Check PostgreSQL
kubectl get events -n keycloak-system --sort-by='.lastTimestamp'
```

### Realm creation fails

```bash
kubectl describe keycloakrealm my-app-realm -n my-app
kubectl get keycloakrealm my-app-realm -n my-app -o jsonpath='{.status.conditions}' | jq
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep my-app-realm
```

### Client authorization error

**Symptom**: Client shows "namespace not authorized"

```bash
# Check realm's authorization grants
kubectl get keycloakrealm my-app-realm -n my-app \
  -o jsonpath='{.spec.clientAuthorizationGrants}' | jq

# Add your namespace to the grant list
helm upgrade my-app-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace my-app \
  --reuse-values \
  --set 'clientAuthorizationGrants={my-app,my-new-namespace}'
```

### Webhook timeout during fresh install

**Symptom**: `Error: failed calling webhook: context deadline exceeded`

This is expected behavior on fresh install - the webhook configuration is created before operator pods are ready.

**Solutions:**
1. **Wait and retry** - The operator will be ready shortly, retry your operation
2. **Use fail-open during install** - Set `--set webhooks.failurePolicy=Ignore` during initial install, then upgrade to `Fail` after operator is running
3. **Remove --wait flag** - Let helm complete without waiting for all resources

```bash
# Option 2: Fail-open install, then upgrade to fail-closed
helm install keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set webhooks.failurePolicy=Ignore

# Wait for operator to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=keycloak-operator \
  -n keycloak-system --timeout=120s

# Upgrade to fail-closed
helm upgrade keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --set webhooks.failurePolicy=Fail
```

## Support

- 📚 [Full Documentation](../index.md)
- 🐛 [Report Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
- 💬 [Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)
