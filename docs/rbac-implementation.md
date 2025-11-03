# Namespaced RBAC Implementation

This document describes the namespace-scoped RBAC implementation for the Keycloak operator, which provides explicit opt-in access control for secrets and resources.

## Overview

The operator now implements a **least-privilege RBAC model** where:

1. **Minimal cluster-wide permissions**: The operator has minimal read-only ClusterRole permissions
2. **Namespace-scoped management**: Full resource management only in the operator's own namespace
3. **Explicit opt-in**: Teams must create a RoleBinding to grant operator access to their namespace
4. **Secret label requirement**: Secrets must be explicitly labeled for operator access

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Operator Namespace (e.g., keycloak-system)                 │
│                                                              │
│  ├── Operator Deployment                                    │
│  │   └── Watches: All CRDs cluster-wide (list/watch only)  │
│  │                                                           │
│  ├── Keycloak Instance (StatefulSet/Deployment)            │
│  │   └── Runs in same namespace as operator               │
│  │                                                           │
│  └── Full RBAC (Role) - Can manage all resources here      │
└─────────────────────────────────────────────────────────────┘
                        ↓ watches CRDs
┌─────────────────────────────────────────────────────────────┐
│  Team Namespace (e.g., team-a)                              │
│                                                              │
│  ├── KeycloakRealm / KeycloakClient CRDs                   │
│  ├── Secrets (with required label)                          │
│  └── RoleBinding (opt-in for operator access)              │
└─────────────────────────────────────────────────────────────┘
```

## RBAC Components

### 1. ClusterRole: `keycloak-operator-core`

**Purpose**: Minimal cluster-wide permissions for CRD watching and status updates.

**Key Permissions**:
- List/watch CRDs across all namespaces (read-only)
- Update CRD status and finalizers
- Namespace discovery for validation
- Leader election (cluster-wide leases)
- Events creation
- SubjectAccessReview for permission checks

**Does NOT include**:
- Full CRUD on CRDs (only list/watch)
- Secret access
- ConfigMap access
- Workload management (Deployments, StatefulSets, etc.)

### 2. Role: `keycloak-operator-manager`

**Purpose**: Full resource management in the operator's own namespace.

**Scope**: Operator namespace only

**Key Permissions**:
- Full CRUD on CRDs in operator namespace
- Full CRUD on Kubernetes resources (Deployments, StatefulSets, Services, etc.)
- Full CRUD on Secrets and ConfigMaps in operator namespace
- Database management (CNPG clusters)
- Ingress and certificate management

### 3. ClusterRole: `keycloak-operator-namespace-access` (Template)

**Purpose**: Template role for teams to grant operator access to their namespace.

**Key Permissions**:
- Read CRDs (KeycloakRealm, KeycloakClient)
- Read Secrets (with label validation enforced in code)
- Create Events for status reporting

**Usage**: Teams create a RoleBinding in their namespace referencing this ClusterRole.

## Secret Label Requirement

All secrets used by the operator **MUST** have the following label:

```yaml
vriesdemichael.github.io/allow-operator-read: "true"
```

### Why This Matters

This provides an **explicit opt-in mechanism** where:
1. Users must intentionally label secrets before the operator can read them
2. Prevents accidental exposure of unrelated secrets
3. Makes access control auditable and transparent
4. Follows the principle of least surprise

### Example

```bash
# Create a secret
kubectl create secret generic smtp-password \
  --from-literal=password='mypassword' \
  -n my-team

# Label it for operator access
kubectl label secret smtp-password \
  vriesdemichael.github.io/allow-operator-read=true \
  -n my-team
```

## Operator Deployment (Helm Chart)

### Install Operator

```bash
helm install keycloak-operator charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace \
  --set keycloak.enabled=true \
  --set keycloak.database.cnpg.enabled=true
```

### What Gets Created

1. **Namespace**: `keycloak-system` (if `namespace.create=true`)
2. **ServiceAccount**: `keycloak-operator`
3. **ClusterRole**: `keycloak-operator-core` (minimal permissions)
4. **ClusterRole**: `keycloak-operator-namespace-access` (template for teams)
5. **Role**: `keycloak-operator-manager` (in operator namespace)
6. **ClusterRoleBinding**: Links ServiceAccount to core ClusterRole
7. **RoleBinding**: Links ServiceAccount to manager Role
8. **Operator Deployment**: Watches CRDs cluster-wide
9. **Keycloak Instance**: Runs in operator namespace

## Realm Deployment (Helm Chart)

### Deploy Realm to Team Namespace

```bash
# Create namespace
kubectl create namespace my-team

# Create and label secrets
kubectl create secret generic smtp-password \
  --from-literal=password='mypassword' \
  -n my-team

kubectl label secret smtp-password \
  vriesdemichael.github.io/allow-operator-read=true \
  -n my-team

# Deploy realm (creates RoleBinding automatically)
helm install my-realm charts/keycloak-realm \
  --namespace my-team \
  --set realmName=my-team \
  --set operatorRef.namespace=keycloak-system \
  --set rbac.create=true \
  --set smtpServer.enabled=true \
  --set smtpServer.host=smtp.example.com \
  --set smtpServer.from=noreply@my-team.com \
  --set smtpServer.passwordSecret.name=smtp-password
```

### What Gets Created

1. **KeycloakRealm CR**: Defines the realm configuration
2. **RoleBinding**: `my-realm-operator-access` (grants operator access)
3. The operator reconciles the realm in the Keycloak instance

### Verify Access

```bash
# Check RoleBinding
kubectl get rolebinding my-realm-operator-access -n my-team

# Check realm status
kubectl get keycloakrealm my-realm -n my-team

# View realm details
kubectl describe keycloakrealm my-realm -n my-team
```

## Client Deployment (Helm Chart)

### Deploy Client to Team Namespace

```bash
# Get realm authorization secret
REALM_SECRET=$(kubectl get keycloakrealm my-realm \
  -n my-team \
  -o jsonpath='{.status.authorizationSecretName}')

# Deploy client (creates RoleBinding automatically)
helm install my-client charts/keycloak-client \
  --namespace my-team \
  --set clientId=my-client \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --set realmRef.authorizationSecretRef.name=$REALM_SECRET \
  --set rbac.create=true \
  --set rbac.operatorNamespace=keycloak-system
```

### What Gets Created

1. **KeycloakClient CR**: Defines the client configuration
2. **RoleBinding**: `my-client-operator-access` (grants operator access)
3. The operator reconciles the client in the specified realm

## Manual RoleBinding Creation

If you prefer to create RoleBindings manually (or `rbac.create=false`):

```bash
kubectl create rolebinding keycloak-operator-access \
  --clusterrole=keycloak-operator-namespace-access \
  --serviceaccount=keycloak-system:keycloak-operator \
  -n my-team
```

## Error Handling

### Missing RoleBinding

**Error**: `Operator does not have access to namespace 'my-team'`

**Solution**: Create the RoleBinding:

```bash
kubectl create rolebinding keycloak-operator-access \
  --clusterrole=keycloak-operator-namespace-access \
  --serviceaccount=keycloak-system:keycloak-operator \
  -n my-team
```

### Missing Secret Label

**Error**: `Secret 'smtp-password' in namespace 'my-team' is missing required label 'vriesdemichael.github.io/allow-operator-read=true'`

**Solution**: Label the secret:

```bash
kubectl label secret smtp-password \
  vriesdemichael.github.io/allow-operator-read=true \
  -n my-team
```

### Secret Not Found

**Error**: `Secret 'smtp-password' not found in namespace 'my-team'`

**Solution**: Create the secret:

```bash
kubectl create secret generic smtp-password \
  --from-literal=password='mypassword' \
  -n my-team

kubectl label secret smtp-password \
  vriesdemichael.github.io/allow-operator-read=true \
  -n my-team
```

## Revoking Access

To revoke operator access to a namespace:

```bash
kubectl delete rolebinding keycloak-operator-access -n my-team
```

**Note**: Existing resources will continue to work, but the operator will not be able to reconcile changes.

## Auditing

### Find Namespaces with Operator Access

```bash
kubectl get rolebindings -A \
  -o json | jq -r '.items[] | select(.subjects[]?.name == "keycloak-operator") | "\(.metadata.namespace)/\(.metadata.name)"'
```

### Find Labeled Secrets

```bash
kubectl get secrets -A \
  -l vriesdemichael.github.io/allow-operator-read=true \
  -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name
```

### Check Operator Permissions

```bash
# Check if operator can read secrets in a namespace
kubectl auth can-i get secrets \
  --as=system:serviceaccount:keycloak-system:keycloak-operator \
  -n my-team
```

## Migration from Old RBAC

If upgrading from a previous version with cluster-wide secret access:

1. **Upgrade the operator chart** - This updates the RBAC to the new model
2. **Deploy realm/client charts** - These will create RoleBindings automatically
3. **Label all secrets** - Add the required label to existing secrets
4. **Test reconciliation** - Verify everything works as expected

## Security Benefits

1. **Least Privilege**: Operator only has permissions it needs
2. **Explicit Opt-In**: Teams must intentionally grant access
3. **Secret Isolation**: Secrets must be explicitly labeled
4. **Namespace Boundaries**: Clear separation of permissions
5. **Auditable**: Easy to see who has granted access
6. **Revocable**: Teams can revoke access anytime

## Testing

Run the integration tests:

```bash
make test-integration
```

This validates:
- Operator deployment with minimal RBAC
- Realm creation in different namespace
- Client creation in different namespace
- Secret label validation
- RoleBinding creation
- Reconciliation with proper permissions

## Troubleshooting

### Operator Logs

```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100 -f
```

### Check RBAC Resources

```bash
# Check ClusterRoles
kubectl get clusterrole | grep keycloak-operator

# Check Role in operator namespace
kubectl get role -n keycloak-system

# Check RoleBindings in a namespace
kubectl get rolebinding -n my-team
```

### Verify Secret Label

```bash
kubectl get secret smtp-password -n my-team -o jsonpath='{.metadata.labels}'
```

## References

- Operator Chart: `charts/keycloak-operator/`
- Realm Chart: `charts/keycloak-realm/`
- Client Chart: `charts/keycloak-client/`
- Integration Tests: `tests/integration/`
