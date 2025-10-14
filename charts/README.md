# Keycloak Operator Helm Charts

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
                    Get operator token
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Dev Team: Create Realm                                   │
│    helm install my-realm ./keycloak-realm                   │
│         --set realmName=myteam                              │
│         --set operatorRef.namespace=keycloak-system         │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    Get realm token
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Dev Team: Create Client                                  │
│    helm install my-client ./keycloak-client                 │
│         --set clientId=myapp                                │
│         --set realmRef.name=my-realm                        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Step 1: Install the Operator

```bash
# Install operator
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace

# Wait for operator to be ready
kubectl wait --for=condition=available deployment/keycloak-operator \
  -n keycloak-system --timeout=300s

# Get the operator authorization token
OPERATOR_TOKEN=$(kubectl get secret keycloak-operator-auth-token \
  -n keycloak-system \
  -o jsonpath='{.data.token}' | base64 -d)

echo "Operator token: $OPERATOR_TOKEN"
```

### Step 2: Create a Realm

```bash
# Create a realm
helm install my-realm ./charts/keycloak-realm \
  --namespace my-team \
  --create-namespace \
  --set realmName=myteam \
  --set displayName="My Team Realm" \
  --set operatorRef.namespace=keycloak-system \
  --set operatorRef.authorizationSecretRef.name=keycloak-operator-auth-token

# Wait for realm to be ready
kubectl wait --for=jsonpath='{.status.phase}'=Ready \
  keycloakrealm/my-realm \
  -n my-team --timeout=300s

# Get the realm authorization secret name
REALM_SECRET=$(kubectl get keycloakrealm my-realm \
  -n my-team \
  -o jsonpath='{.status.authorizationSecretName}')

echo "Realm secret: $REALM_SECRET"
```

### Step 3: Create a Client

```bash
# Create a client
helm install my-client ./charts/keycloak-client \
  --namespace my-team \
  --set clientId=myapp \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --set realmRef.authorizationSecretRef.name=$REALM_SECRET \
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

### Example: ArgoCD Application

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
            name: keycloak-operator-auth-token
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
  --set realmRef.authorizationSecretRef.name=test-secret
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
