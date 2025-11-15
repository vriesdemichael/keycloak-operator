# Keycloak Operator Helm Charts

> **⚠️ PARTIALLY OUTDATED:** This README contains sections about the old token-based authorization system which was superseded by namespace grant lists (ADR 063).
>
> **Outdated sections:**
> - Installation Flow diagram (shows token workflow)
> - "Understanding the Token System" section
> - Token bootstrap examples
>
> **Current Authorization Model:**
> - **Realm Creation:** Kubernetes RBAC controls who can create realms
> - **Client Creation:** Realm's `clientAuthorizationGrants` list controls which namespaces can create clients
> - **No tokens:** Authorization is purely declarative via grant lists
>
> Individual chart READMEs (keycloak-realm/, keycloak-client/) are up to date.

This directory contains three Helm charts for deploying and managing Keycloak infrastructure with GitOps compatibility.

## Charts Overview

### 1. keycloak-operator

**Purpose:** Install the Keycloak Operator for platform administrators.

**Installs:**
- Operator deployment with HA support
- CRDs (Keycloak, KeycloakRealm, KeycloakClient)
- RBAC (ClusterRole, ClusterRoleBinding, ServiceAccount)
- Optional: Prometheus ServiceMonitor
- Optional: Keycloak instance

**Target Users:** Platform administrators, cluster operators

### 2. keycloak-realm

**Purpose:** Deploy Keycloak realms for development teams.

**Installs:**
- KeycloakRealm custom resource
- Realm configuration (security, themes, tokens, SMTP, etc.)

**Target Users:** Development teams, realm administrators

### 3. keycloak-client

**Purpose:** Deploy OAuth2/OIDC clients for applications.

**Installs:**
- KeycloakClient custom resource
- Client configuration (redirect URIs, scopes, roles, etc.)

**Target Users:** Application developers, service owners

## Installation Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Platform Admin: Install Operator                         │
│    helm install keycloak-operator ./keycloak-operator       │
└─────────────────────────────────────────────────────────────┘
                              ↓
                 Create admission token
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Dev Team: Create First Realm (uses admission token)      │
│    helm install my-realm ./keycloak-realm                   │
│         --set operatorRef.authorizationSecretRef.name=      │
│              admission-token-my-team                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
          Operator generates operational token
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Dev Team: Create Additional Realms (auto-use op token)   │
│    helm install another-realm ./keycloak-realm              │
│         --set realmName=another                             │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Dev Team: Create Client                                  │
│    helm install my-client ./keycloak-client                 │
│         --set realmRef.name=my-realm                        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Understanding the Token System

The operator uses a **two-phase token system** for enhanced security:

1. **Admission Tokens** (one-time, platform team creates)
   - Used to bootstrap a namespace
   - Creates the first realm
   - Triggers automatic generation of operational tokens

2. **Operational Tokens** (auto-rotating, operator manages)
   - Generated automatically after first realm
   - Used by all subsequent realms
   - Rotate every 90 days with zero downtime

See [Security Model](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/security.md#token-rotation) for details.

### Step 1: Install the Operator

```bash
# Install operator
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace

# Wait for operator to be ready
kubectl wait --for=condition=available deployment/keycloak-operator \
  -n keycloak-system --timeout=300s

# The operator automatically creates an admission token
# This token is used by platform teams to bootstrap namespaces
```

### Step 2: Create Admission Token for Application Team

Platform teams create admission tokens for application teams:

```bash
# Generate admission token
ADMISSION_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Create admission token secret in team namespace
kubectl create namespace my-team

kubectl create secret generic admission-token-my-team \
  --from-literal=token="$ADMISSION_TOKEN" \
  --namespace=my-team

# Add required labels
kubectl label secret admission-token-my-team \
  vriesdemichael.github.io/token-type=admission \
  vriesdemichael.github.io/allow-operator-read=true \
  --namespace=my-team

# Store token metadata
TOKEN_HASH=$(echo -n "$ADMISSION_TOKEN" | sha256sum | cut -d' ' -f1)
kubectl patch configmap keycloak-operator-token-metadata \
  --namespace=keycloak-system \
  --type=merge \
  --patch "{
    \"data\": {
      \"$TOKEN_HASH\": \"{\\\"namespace\\\": \\\"my-team\\\", \\\"token_type\\\": \\\"admission\\\", \\\"token_hash\\\": \\\"$TOKEN_HASH\\\", \\\"issued_at\\\": \\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"valid_until\\\": \\\"$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"version\\\": 1, \\\"created_by_realm\\\": null, \\\"revoked\\\": false}\"
    }
  }"
```

### Step 3: Create First Realm (Bootstrap)

Application teams create their first realm using the admission token:

```bash
# Create the first realm (bootstraps operational token)
helm install my-realm ./charts/keycloak-realm \
  --namespace my-team \
  --set realmName=myteam \
  --set displayName="My Team Realm" \
  --set operatorRef.namespace=keycloak-system \

# Wait for realm to be ready
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakrealm/my-realm \
  -n my-team --timeout=300s

# After the first realm is created, the operator automatically generates
# an operational token for this namespace. Additional realms will
# automatically use this operational token.
```

### Step 4: Create Additional Realms (Optional)

After the first realm, subsequent realms automatically use the operational token:

```bash
# Create additional realms without specifying a token
# The operator automatically uses the operational token
helm install another-realm ./charts/keycloak-realm \
  --namespace my-team \
  --set realmName=another \
  --set displayName="Another Realm" \
  --set operatorRef.namespace=keycloak-system

# The operator will automatically find and use the operational token
# that was generated after the first realm creation
```

### Step 5: Create a Client

Create clients within a realm:

```bash
# Get the realm authorization secret name
REALM_SECRET=$(kubectl get keycloakrealm my-realm \
  -n my-team \
  -o jsonpath='{.status.authorizationSecretName}')

# Create a client
helm install my-client ./charts/keycloak-client \
  --namespace my-team \
  --set clientId=myapp \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --set redirectUris[0]="https://myapp.example.com/callback" \
  --set webOrigins[0]="https://myapp.example.com"

# Wait for client to be ready
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakclient/my-client \
  -n my-team --timeout=300s

# Get client secret (for confidential clients)
kubectl get secret my-client-client-secret \
  -n my-team \
  -o jsonpath='{.data.client-secret}' | base64 -d
```

## Using with GitOps

All charts are designed for GitOps workflows. Create values files in your Git repository:

### Example: ArgoCD Application (First Realm)

For the **first realm** in a namespace, use an admission token:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-realm
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/your-repo
    targetRevision: main
    path: charts/keycloak-realm
    helm:
      values: |
        realmName: myteam
        displayName: "My Team Realm"
        operatorRef:
          namespace: keycloak-system
          authorizationSecretRef:
            name: admission-token-my-team  # Created by platform team
        security:
          registrationAllowed: false
          resetPasswordAllowed: true
        smtp:
          enabled: true
          host: smtp.example.com
          from: noreply@myteam.com
          passwordSecret:
            name: smtp-credentials
  destination:
    server: https://kubernetes.default.svc
    namespace: my-team
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### Example: ArgoCD Application (Additional Realms)

For **additional realms** in the same namespace, omit the authorization secret (auto-discovers operational token):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: another-realm
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/your-repo
    targetRevision: main
    path: charts/keycloak-realm
    helm:
      values: |
        realmName: another
        displayName: "Another Realm"
        operatorRef:
          namespace: keycloak-system
          # No authorizationSecretRef needed - operator finds operational token
        security:
          registrationAllowed: false
  destination:
    server: https://kubernetes.default.svc
    namespace: my-team
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## Helm Repository

The charts are published to a Helm repository hosted on GitHub Pages with **full version history**.

### Add the Helm Repository

```bash
# Add the Keycloak Operator Helm repository
helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator/charts

# Update your local Helm chart repository cache
helm repo update
```

### List Available Versions

All chart versions are preserved and available for installation:

```bash
# List all available versions for operator chart
helm search repo keycloak-operator/keycloak-operator --versions

# List all available versions for realm chart
helm search repo keycloak-operator/keycloak-realm --versions

# List all available versions for client chart
helm search repo keycloak-operator/keycloak-client --versions
```

### Install Specific Version

You can install any version of a chart:

```bash
# Install specific operator chart version
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --version 0.1.4 \
  --namespace keycloak-system \
  --create-namespace

# Install specific realm chart version
helm install my-realm keycloak-operator/keycloak-realm \
  --version 0.1.2 \
  --namespace my-team \
  --set realmName=myteam

# Install specific client chart version
helm install my-client keycloak-operator/keycloak-client \
  --version 0.1.1 \
  --namespace my-team \
  --set clientId=myapp
```

### Install from Helm Repository

Install the latest version (recommended for new deployments):

```bash
# Install operator chart (latest)
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace

# Install realm chart (latest)
helm install my-realm keycloak-operator/keycloak-realm \
  --namespace my-team \
  --set realmName=myteam \
  --set operatorRef.namespace=keycloak-system

# Install client chart (latest)
helm install my-client keycloak-operator/keycloak-client \
  --namespace my-team \
  --set clientId=myapp \
  --set realmRef.name=my-realm
```

**Note:** The examples in this README use local chart paths (`./charts/...`) for development and testing. In production, use the Helm repository as shown above.

### Version Compatibility

Each chart version indicates which operator version it's compatible with via the `appVersion` field:

```bash
# Check which operator version a chart deploys
helm show chart keycloak-operator/keycloak-operator --version 0.1.4 | grep appVersion
# Output: appVersion: "v0.2.14"
```

For more details on versioning, see the [Versioning Documentation](https://vriesdemichael.github.io/keycloak-operator/latest/versioning/).

## Chart Documentation

Each chart has its own README with detailed documentation:

- [keycloak-operator/README.md](keycloak-operator/README.md)
- [keycloak-realm/README.md](keycloak-realm/README.md)
- [keycloak-client/README.md](keycloak-client/README.md)

## Configuration

### Operator Chart Values

Key configuration options:

```yaml
operator:
  replicaCount: 2
  image:
    repository: keycloak-operator
    tag: "1.0.0"
  resources:
    limits:
      cpu: 500m
      memory: 512Mi

keycloak:
  enabled: true  # Deploy a Keycloak instance
  replicas: 3
  version: "26.0.0"
```

### Realm Chart Values

Key configuration options:

```yaml
realmName: myteam
displayName: "My Team"

security:
  registrationAllowed: false
  resetPasswordAllowed: true
  bruteForceProtected: true

smtp:
  enabled: true
  host: smtp.example.com
  from: noreply@example.com

tokens:
  accessTokenLifespan: 300
  ssoSessionIdleTimeout: 1800
```

### Client Chart Values

Key configuration options:

```yaml
clientId: myapp

publicClient: false
standardFlowEnabled: true
directAccessGrantsEnabled: true
serviceAccountsEnabled: false

redirectUris:
  - "https://myapp.example.com/callback"

webOrigins:
  - "https://myapp.example.com"

serviceAccountRoles:
  realmRoles:
    - view-users
```

## Testing

Test chart rendering without installing:

```bash
# Operator chart
helm template test-operator ./charts/keycloak-operator

# Realm chart
helm template test-realm ./charts/keycloak-realm \
  --set realmName=test

# Client chart
helm template test-client ./charts/keycloak-client \
  --set clientId=test \
  --set realmRef.name=test-realm \
  --set realmRef.namespace=test \
```

Perform dry-run installation:

```bash
helm install test ./charts/keycloak-operator --dry-run --debug
```

## Upgrading

To upgrade an existing release:

```bash
# Upgrade operator
helm upgrade keycloak-operator ./charts/keycloak-operator \
  -n keycloak-system

# Upgrade realm
helm upgrade my-realm ./charts/keycloak-realm \
  -n my-team \
  --reuse-values \
  --set security.resetPasswordAllowed=false

# Upgrade client
helm upgrade my-client ./charts/keycloak-client \
  -n my-team \
  --reuse-values
```

## Uninstalling

```bash
# Delete client
helm uninstall my-client -n my-team

# Delete realm
helm uninstall my-realm -n my-team

# Delete operator (WARNING: This will delete all Keycloak instances)
helm uninstall keycloak-operator -n keycloak-system
```

## Troubleshooting

### Check Operator Status

```bash
kubectl get deployment keycloak-operator -n keycloak-system
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
```

### Check Realm Status

```bash
kubectl get keycloakrealm -A
kubectl describe keycloakrealm my-realm -n my-team
```

### Check Client Status

```bash
kubectl get keycloakclient -A
kubectl describe keycloakclient my-client -n my-team
```

### Common Issues

**Issue:** Realm stuck in "Failed" state with "Authorization failed" message

**Solution:** Verify the operator token is correct:
```bash
kubectl get secret keycloak-operator-auth-token -n keycloak-system -o jsonpath='{.data.token}' | base64 -d
```

**Issue:** Client stuck in "Failed" state

**Solution:** Verify the realm token is correct and the realm is Ready:
```bash
kubectl get keycloakrealm my-realm -n my-team -o jsonpath='{.status}'
```

## Contributing

Contributions are welcome! Please see the main repository README for guidelines.

## License

See LICENSE file in the repository root.
