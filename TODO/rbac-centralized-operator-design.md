# Centralized Operator with Per-Namespace Opt-In RBAC

**Status:** Design in progress  
**Estimated Effort:** 2-3 days  
**Priority:** P0 (Alternative to multi-tier RBAC)

---

## Architecture Overview

### Deployment Model

```
┌─────────────────────────────────────────────────────────────┐
│  keycloak-system namespace (Operator Home)                  │
│                                                               │
│  ├── Operator Deployment                                     │
│  │   └── Watches: Keycloak, KeycloakRealm, KeycloakClient  │
│  │       in ALL namespaces                                  │
│  │                                                           │
│  └── Keycloak StatefulSets/Deployments                      │
│      └── All actual Keycloak instances run here             │
└─────────────────────────────────────────────────────────────┘
                        ↓ watches CRDs
┌─────────────────────────────────────────────────────────────┐
│  team-a namespace (User Namespace)                          │
│                                                               │
│  ├── KeycloakRealm CRDs ← Users define their realms         │
│  ├── KeycloakClient CRDs ← Users define their clients       │
│  ├── Secrets ← Database passwords, SMTP, etc.               │
│  └── RoleBinding ← Explicit grant of access to operator     │
└─────────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Centralized Keycloak Instances**: All actual Keycloak deployments run in `keycloak-system`
2. **Distributed CRDs**: Teams define CRDs in their own namespaces
3. **Distributed Secrets**: Secrets stay in team namespaces
4. **Explicit Opt-In**: Teams grant operator access via RoleBinding
5. **No Cross-Namespace Secret Creation**: Operator only creates secrets in its own namespace

---

## RBAC Design

### 1. Operator ClusterRole (Minimal CRD Watching)

**Purpose:** Watch CRDs across all namespaces, manage resources in operator namespace

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator-core
  labels:
    app.kubernetes.io/name: keycloak-operator
rules:
# Watch CRDs cluster-wide (read-only metadata)
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloakclients", "keycloakrealms"]
  verbs: ["list", "watch"]  # NO get at cluster level

# Update CRD status and finalizers (required by Kopf)
- apiGroups: ["keycloak.mdvr.nl"]
  resources:
  - keycloaks/status
  - keycloakclients/status
  - keycloakrealms/status
  verbs: ["get", "update", "patch"]

- apiGroups: ["keycloak.mdvr.nl"]
  resources:
  - keycloaks/finalizers
  - keycloakclients/finalizers
  - keycloakrealms/finalizers
  verbs: ["update"]

# Namespace discovery (for validation)
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]

# Leader election
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]

# Events (cluster-wide)
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# Self-permission checks
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
```

**Total:** 7 resource types, ~25 verbs (read-only for most)

### 2. Operator Namespace Role (Full Management)

**Purpose:** Manage all Keycloak resources in operator's own namespace

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-operator-manager
  namespace: keycloak-system
rules:
# CRDs in operator namespace (if any are created here)
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloakclients", "keycloakrealms"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Deployments and StatefulSets for Keycloak instances
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

- apiGroups: ["apps"]
  resources: ["deployments/status", "statefulsets/status"]
  verbs: ["get"]

# Services for Keycloak
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Ingresses for Keycloak
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# ConfigMaps for Keycloak configuration
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Secrets for Keycloak (admin passwords, TLS, client secrets)
# These are ONLY secrets created by the operator in its own namespace
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# PVCs for Keycloak data
- apiGroups: [""]
  resources: ["persistentvolumeclaims"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Pods (read-only for health checks)
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]

- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]

# CloudNativePG (read-only, if cluster is in same namespace)
- apiGroups: ["postgresql.cnpg.io"]
  resources: ["clusters", "poolers"]
  verbs: ["get", "list", "watch"]
```

### 3. ClusterRole for User Namespaces (Opt-In Template)

**Purpose:** Define what the operator CAN do when granted access to a user namespace

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator-namespace-access
  labels:
    app.kubernetes.io/name: keycloak-operator
    keycloak.mdvr.nl/role: namespace-access
rules:
# Read CRDs in user namespace
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloakclients", "keycloakrealms"]
  verbs: ["get", "list", "watch", "update", "patch"]
  # NO create/delete - users create these

# Read secrets that are referenced by CRDs
# WITH LABELS ONLY (enforced via validation)
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
  # NO watch/create/update/delete

# Read ConfigMaps that are referenced by CRDs
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]

# Create events for user resources
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# Read CloudNativePG clusters (if database is in user namespace)
- apiGroups: ["postgresql.cnpg.io"]
  resources: ["clusters", "poolers"]
  verbs: ["get", "list", "watch"]
```

**Important:** This ClusterRole is NOT bound by default. Users must create RoleBinding.

### 4. User RoleBinding (Explicit Opt-In)

**Purpose:** User grants operator access to their namespace

Users create this in their namespace to enable the operator:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: keycloak-operator-access
  namespace: team-a  # User's namespace
  labels:
    app.kubernetes.io/name: keycloak-operator
    keycloak.mdvr.nl/managed-by: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: keycloak-operator-namespace-access  # Predefined template
subjects:
- kind: ServiceAccount
  name: keycloak-operator
  namespace: keycloak-system
```

**Security Features:**
- ✅ Users explicitly opt-in per namespace
- ✅ Can revoke access anytime (delete RoleBinding)
- ✅ Auditable: `kubectl get rolebindings -A -l app.kubernetes.io/name=keycloak-operator`
- ✅ Operator has NO access until RoleBinding exists

---

## Secret Access Security

### Problem: Even with RoleBinding, operator can read ALL secrets

Users grant `secrets: [get, list]` permission, which allows reading any secret in the namespace.

### Solution 1: Label-Based Secret Validation (Recommended)

**Operator behavior:**
1. When reading a secret referenced in a CRD, check for label
2. If label missing, reject with clear error message
3. Update CRD status to explain what's needed

**Code implementation:**
```python
async def read_user_secret(
    secret_name: str,
    namespace: str,
    key: str = "password"
) -> str | None:
    """
    Read a secret from a user namespace with label validation.
    
    Security: Requires secret to have label 'keycloak.mdvr.nl/allow-operator-read: true'
    """
    core_api = client.CoreV1Api()
    
    try:
        secret = core_api.read_namespaced_secret(secret_name, namespace)
    except ApiException as e:
        if e.status == 404:
            logger.error(f"Secret {secret_name} not found in namespace {namespace}")
            return None
        elif e.status == 403:
            logger.error(
                f"No access to namespace {namespace}. "
                f"User must create RoleBinding for keycloak-operator."
            )
            return None
        raise
    
    # Validate label
    labels = secret.metadata.labels or {}
    if labels.get("keycloak.mdvr.nl/allow-operator-read") != "true":
        logger.error(
            f"Secret {secret_name} in namespace {namespace} is not labeled "
            f"for operator access. Add label: "
            f"'keycloak.mdvr.nl/allow-operator-read: true'"
        )
        return None
    
    # Read the secret value
    if secret.data and key in secret.data:
        import base64
        return base64.b64decode(secret.data[key]).decode('utf-8')
    
    logger.error(f"Secret {secret_name} missing key '{key}'")
    return None
```

**User secret example:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-password
  namespace: team-a
  labels:
    keycloak.mdvr.nl/allow-operator-read: "true"  # Explicit permission
type: Opaque
data:
  password: <base64-encoded>
```

**Security guarantee:**
- Operator CAN read any secret (due to RBAC)
- Operator WILL ONLY read labeled secrets (due to code validation)
- Unlabeled secrets result in error and CRD status update

### Solution 2: Separate Secret Namespace (Alternative)

**Architecture:**
```
keycloak-system/
  └── secrets/  ← Users must put secrets here
team-a/
  └── CRDs only (no secrets)
```

**Pros:**
- Cleaner RBAC (operator only needs secret access in keycloak-system)
- Centralized secret management

**Cons:**
- Less flexible for users
- Harder to integrate with team-specific secret management
- Doesn't work well with namespace-scoped GitOps

**Verdict:** Solution 1 (labels) is more flexible and user-friendly.

---

## CRD Reference Validation

### Problem: How does operator know which namespace to look in?

When a CRD references a Keycloak instance, we need to know where it lives.

### Solution: Explicit Namespace Reference

**KeycloakRealm CRD:**
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: team-a  # CRD lives here
spec:
  keycloak_instance:
    name: shared-keycloak
    namespace: keycloak-system  # Explicit reference to operator namespace
  
  realm: my-team-realm
  
  smtp:
    host: smtp.example.com
    from: noreply@example.com
    password_secret:
      name: smtp-password
      # namespace: team-a  ← implicit, same as CRD namespace
      key: password
```

**Validation logic:**
```python
def validate_crd_references(crd: dict, crd_namespace: str) -> list[str]:
    """Validate all references in a CRD are accessible."""
    errors = []
    spec = crd.get('spec', {})
    
    # Validate Keycloak instance reference
    kc_ref = spec.get('keycloak_instance', {})
    kc_name = kc_ref.get('name')
    kc_namespace = kc_ref.get('namespace', 'keycloak-system')
    
    if not keycloak_exists(kc_name, kc_namespace):
        errors.append(
            f"Keycloak instance '{kc_name}' not found in namespace '{kc_namespace}'"
        )
    
    # Validate secret references (must be in same namespace as CRD)
    smtp = spec.get('smtp', {})
    if 'password_secret' in smtp:
        secret_ref = smtp['password_secret']
        secret_name = secret_ref.get('name')
        secret_namespace = secret_ref.get('namespace', crd_namespace)
        
        if secret_namespace != crd_namespace:
            errors.append(
                f"Secret references must be in the same namespace as the CRD. "
                f"Secret '{secret_name}' is in '{secret_namespace}', "
                f"but CRD is in '{crd_namespace}'"
            )
        
        if not secret_has_permission_label(secret_name, secret_namespace):
            errors.append(
                f"Secret '{secret_name}' in namespace '{secret_namespace}' "
                f"must have label 'keycloak.mdvr.nl/allow-operator-read: true'"
            )
    
    return errors
```

**Security guarantee:**
- Secrets MUST be in same namespace as CRD (no cross-namespace secret access)
- Operator validates RoleBinding exists before processing CRD
- Clear error messages guide users to fix issues

---

## Client Secret Management

### Challenge: Where do client secrets go?

When KeycloakClient is created, operator generates credentials. Where to store them?

### Solution: Secrets Created in CRD Namespace

**Operator behavior:**
```python
async def create_client_secret(
    client_name: str,
    namespace: str,  # Same namespace as KeycloakClient CRD
    credentials: dict
) -> bool:
    """
    Create a client secret in the user's namespace.
    
    Requires: Operator must have 'secrets: [create]' permission via RoleBinding
    """
    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=f"keycloak-client-{client_name}",
            namespace=namespace,
            labels={
                "keycloak.mdvr.nl/managed-by": "operator",
                "keycloak.mdvr.nl/resource-type": "client-credentials",
                "keycloak.mdvr.nl/client-name": client_name,
            },
            owner_references=[{
                "apiVersion": "keycloak.mdvr.nl/v1",
                "kind": "KeycloakClient",
                "name": client_name,
                "uid": client_uid,
                "controller": True,
                "blockOwnerDeletion": True,
            }],
        ),
        type="Opaque",
        data={
            "client-id": base64.b64encode(credentials['client_id'].encode()).decode(),
            "client-secret": base64.b64encode(credentials['client_secret'].encode()).decode(),
        }
    )
    
    try:
        core_api.create_namespaced_secret(namespace=namespace, body=secret)
        return True
    except ApiException as e:
        if e.status == 403:
            logger.error(
                f"Cannot create secret in namespace {namespace}. "
                f"RoleBinding must grant 'secrets: [create]' permission."
            )
        raise
```

**Updated ClusterRole for namespace access:**
```yaml
# Add to keycloak-operator-namespace-access ClusterRole
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
  # Only for operator-managed secrets (enforced via labels)
```

**Security:**
- Operator-created secrets have label `keycloak.mdvr.nl/managed-by: operator`
- Users can distinguish operator secrets from their own
- Owner references ensure cleanup when CRD is deleted

---

## Installation Flow

### Step 1: Platform Admin Installs Operator

```bash
# Apply operator deployment in keycloak-system
kubectl apply -f k8s/rbac/centralized/
```

This creates:
- `keycloak-system` namespace
- Operator deployment
- ClusterRole `keycloak-operator-core` (minimal watching)
- ClusterRole `keycloak-operator-namespace-access` (template for users)
- Role `keycloak-operator-manager` (operator namespace management)
- ServiceAccount `keycloak-operator`

### Step 2: Platform Admin Creates Shared Keycloak Instance

```yaml
# In keycloak-system namespace
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: shared-keycloak
  namespace: keycloak-system
spec:
  replicas: 3
  database:
    type: cnpg
    cnpg_cluster:
      name: keycloak-db
      namespace: keycloak-system
```

### Step 3: Team Creates CRDs in Their Namespace

```bash
# Team-a creates their namespace
kubectl create namespace team-a
```

```yaml
# team-a/realm.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: team-a-realm
  namespace: team-a
spec:
  keycloak_instance:
    name: shared-keycloak
    namespace: keycloak-system
  realm: team-a
  display_name: "Team A Realm"
```

**At this point, CRD status shows error:**
```
status:
  phase: Failed
  message: "No access to namespace team-a. Create RoleBinding to grant operator access."
```

### Step 4: Team Grants Operator Access

```yaml
# team-a/operator-access.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: keycloak-operator-access
  namespace: team-a
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: keycloak-operator-namespace-access
subjects:
- kind: ServiceAccount
  name: keycloak-operator
  namespace: keycloak-system
```

```bash
kubectl apply -f team-a/operator-access.yaml
```

**Now operator can process the CRD!**

### Step 5: Team Labels Secrets

```yaml
# team-a/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: smtp-password
  namespace: team-a
  labels:
    keycloak.mdvr.nl/allow-operator-read: "true"
type: Opaque
data:
  password: <base64>
```

### Step 6: Team Updates Realm to Use Secret

```yaml
# team-a/realm.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: team-a-realm
  namespace: team-a
spec:
  keycloak_instance:
    name: shared-keycloak
    namespace: keycloak-system
  realm: team-a
  smtp:
    host: smtp.example.com
    from: noreply@team-a.com
    password_secret:
      name: smtp-password
      key: password
```

**Operator validates:**
1. ✅ RoleBinding exists in team-a
2. ✅ Secret exists in team-a
3. ✅ Secret has permission label
4. → Reconciles realm successfully!

---

## Security Analysis

### What Can the Operator Do?

**Without RoleBinding (default state):**
- ✅ Watch CRDs cluster-wide (list/watch only)
- ✅ Update CRD status
- ✅ Manage resources in keycloak-system
- ❌ Cannot read secrets in team-a
- ❌ Cannot read ConfigMaps in team-a
- ❌ Cannot access any team-a resources

**With RoleBinding (user opt-in):**
- ✅ Read CRDs in team-a
- ✅ Read labeled secrets in team-a
- ✅ Create operator-managed secrets in team-a
- ✅ Read ConfigMaps in team-a
- ❌ Cannot read unlabeled secrets (code validation)
- ❌ Cannot delete user secrets
- ❌ Cannot access other user namespaces

### User Guarantees

1. **Namespace Isolation**
   - Operator has NO access to your namespace by default
   - You must explicitly grant access via RoleBinding
   - You can revoke access anytime

2. **Secret Privacy**
   - Operator can only read LABELED secrets
   - Unlabeled secrets are never accessed
   - Operator-created secrets are clearly labeled

3. **Audit Trail**
   - Query which namespaces granted access: `kubectl get rolebindings -A`
   - Query which secrets are readable: `kubectl get secrets -l keycloak.mdvr.nl/allow-operator-read=true`
   - All operator actions are logged with correlation IDs

4. **Revocation**
   - Delete RoleBinding → operator loses access immediately
   - Remove secret label → operator stops reading it
   - Delete CRD → all operator-created resources cleaned up

---

## Comparison with Other Approaches

| Aspect | Current (Scary) | Your Proposal | Solution |
|--------|----------------|---------------|----------|
| **Operator Location** | Any namespace | keycloak-system | ✅ keycloak-system |
| **Keycloak Location** | Any namespace | keycloak-system | ✅ keycloak-system |
| **CRD Location** | Any namespace | User namespaces | ✅ User namespaces |
| **Secret Location** | Any namespace | User namespaces | ✅ User namespaces |
| **Default Access** | All secrets everywhere | All secrets everywhere | ❌ NO access until opt-in |
| **Secret Control** | None | None | ✅ Label-based + RoleBinding |
| **Revocable** | No | No | ✅ Yes (delete RoleBinding) |
| **Auditable** | Hard | Hard | ✅ Easy (query by label) |

---

## Implementation Plan

### Phase 1: RBAC Manifests (4 hours)

1. Create `k8s/rbac/centralized/` directory
2. Create ClusterRole `keycloak-operator-core`
3. Create ClusterRole `keycloak-operator-namespace-access`
4. Create Role `keycloak-operator-manager`
5. Create ServiceAccount and bindings
6. Create install script

### Phase 2: Secret Validation (4 hours)

1. Add `read_user_secret()` function with label validation
2. Update all secret reading code paths
3. Add clear error messages for missing labels
4. Update CRD status with helpful guidance

### Phase 3: Namespace Access Detection (4 hours)

1. Add function to check if RoleBinding exists
2. Update reconcilers to validate access before processing
3. Set CRD status with instructions if access missing
4. Add retry logic when access is granted

### Phase 4: Documentation (4 hours)

1. Update README with centralized architecture
2. Add "Getting Started" guide for teams
3. Add troubleshooting section
4. Create example manifests

### Phase 5: Testing (8 hours)

1. Unit tests for secret validation
2. Unit tests for access detection
3. Integration test: CRD without RoleBinding
4. Integration test: CRD with RoleBinding
5. Integration test: Secret without label
6. Integration test: Full happy path

---

## User Documentation

### For Platform Admins

**Installing the Operator:**
```bash
kubectl apply -f https://github.com/vriesdemichael/keycloak-operator/releases/latest/download/install-centralized.yaml
```

This installs:
- Operator in `keycloak-system` namespace
- Minimal RBAC for cluster-wide CRD watching
- Template ClusterRole for team opt-in

**Creating Shared Keycloak:**
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: shared-keycloak
  namespace: keycloak-system
spec:
  replicas: 3
  database:
    type: postgresql
    host: postgres.keycloak-system.svc
    database: keycloak
    username: keycloak
    password_secret:
      name: keycloak-db-password
      key: password
```

### For Application Teams

**Step 1: Create your namespace**
```bash
kubectl create namespace my-team
```

**Step 2: Grant operator access**
```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: keycloak-operator-access
  namespace: my-team
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: keycloak-operator-namespace-access
subjects:
- kind: ServiceAccount
  name: keycloak-operator
  namespace: keycloak-system
EOF
```

**Step 3: Create secrets with labels**
```bash
kubectl create secret generic smtp-password \
  --from-literal=password='mypassword' \
  --namespace=my-team

kubectl label secret smtp-password \
  keycloak.mdvr.nl/allow-operator-read=true \
  --namespace=my-team
```

**Step 4: Create your CRDs**
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-team
spec:
  keycloak_instance:
    name: shared-keycloak
    namespace: keycloak-system
  realm: my-team
  smtp:
    host: smtp.example.com
    from: noreply@my-team.com
    password_secret:
      name: smtp-password
      key: password
```

**Step 5: Verify**
```bash
kubectl get keycloakrealm my-realm -n my-team -o yaml
# Check status.phase: Ready
```

---

## FAQ

### Q: Why not put secrets in keycloak-system?

**A:** This would force all teams to use the same namespace for secrets, breaking:
- GitOps per-team workflows
- Namespace-scoped secret management tools
- Team autonomy and isolation

### Q: What if a team forgets to create the RoleBinding?

**A:** The CRD status will show:
```yaml
status:
  phase: Failed
  message: "No access to namespace my-team. Create RoleBinding: kubectl apply -f https://..."
```

### Q: Can the operator read secrets in other teams' namespaces?

**A:** Only if that team has created a RoleBinding. Without it, access is denied by RBAC.

### Q: What prevents the operator from reading unlabeled secrets?

**A:** Code validation. The operator checks for the label before reading. If missing, it returns an error and updates the CRD status.

### Q: Can teams revoke access?

**A:** Yes! Delete the RoleBinding:
```bash
kubectl delete rolebinding keycloak-operator-access -n my-team
```

The operator will lose access immediately. Existing resources continue to work, but changes won't be reconciled.

### Q: How do we audit which teams granted access?

**A:** Query RoleBindings:
```bash
kubectl get rolebindings -A \
  -o json | jq '.items[] | select(.subjects[].name == "keycloak-operator")'
```

---

## Success Criteria

- ✅ Operator runs in keycloak-system
- ✅ All Keycloak instances run in keycloak-system
- ✅ Teams define CRDs in their own namespaces
- ✅ Teams keep secrets in their own namespaces
- ✅ Operator has NO access until team grants it via RoleBinding
- ✅ Operator only reads labeled secrets
- ✅ Teams can revoke access anytime
- ✅ Clear error messages guide users
- ✅ All tests pass

---

**This is the sweet spot between security and usability!** ✨
