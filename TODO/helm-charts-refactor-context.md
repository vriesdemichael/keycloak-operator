# Helm Charts & Permission Refactor - Context Document

**Date:** October 9, 2025  
**Purpose:** Complete architectural refactor to implement proper RBAC and Helm chart structure  
**Priority:** P0 - Blocks production adoption

---

## User Requirements

### 1. Keycloak CR Changes
- **Current:** KeycloakCR can be deployed in any namespace
- **New:** KeycloakCR restricted to operator namespace (`keycloak-system`)
  - 1-1 coupling between operator and Keycloak instance
  - Deployed in same namespace as operator
  - Keep as CR (not replaced with plain Deployment) - **Option A confirmed**
  - Eliminates need for ClusterRole to manage Keycloak resources

### 2. Helm Chart Structure
- **Current:** Manual installation (operator first, then CRs manually)
- **New:** 3 separate Helm charts in monorepo structure - **Option B confirmed**

**Chart 1: Operator + Keycloak**
- Operator deployment
- Keycloak instance(s)
- Service Account
- CRDs installation
- Namespace: `keycloak-system`
- Generates authorization secret for child resources

**Chart 2: Realm**
- KeycloakRealm CR
- Role for accessing Keycloak namespace secrets
- RoleBinding to Keycloak service account
- Namespace: User-defined (e.g., `team-a`)
- Must reference operator authorization secret - **Option A confirmed**
- Generates authorization secret for client resources

**Chart 3: Client**
- KeycloakClient CR
- Role for accessing Realm namespace secrets
- RoleBinding to Keycloak service account
- Namespace: User-defined (e.g., `team-a`, `team-b`)
- Must reference realm authorization secret - **Option A confirmed**

### 3. Authorization Mechanism - **Option A confirmed**
Generated random token stored in Secret, referenced by name in child CRs.

**Operator generates secret:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-operator-auth-token
  namespace: keycloak-system
type: Opaque
data:
  token: <random-base64-token>
```

**Realm references it:**
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: team-a
spec:
  operatorRef:
    namespace: keycloak-system  # Must match operator namespace
    authorizationSecretRef:
      name: keycloak-operator-auth-token
      key: token
```

**Client references realm secret:**
```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: my-client
  namespace: team-b
spec:
  realmRef:
    name: my-realm
    namespace: team-a  # Realm's namespace
    authorizationSecretRef:
      name: my-realm-auth-token
      key: token
```

### 4. Ownership & Targeting

**For KeycloakRealm:**
- Spec field: `operatorRef.namespace` (targets specific operator namespace)
- Status field: `managedBy` (shows which operator picked it up)
- Labels on generated secrets: `keycloak.mdvr.nl/realm: <name>`, `keycloak.mdvr.nl/managed-by: operator`

**For KeycloakClient:**
- Spec field: `realmRef.name` + `realmRef.namespace` (targets specific realm)
- Status field: `managedBy`, `parentRealm` (shows ownership chain)
- Labels on generated secrets: `keycloak.mdvr.nl/client: <name>`, `keycloak.mdvr.nl/realm: <realm-name>`

**Note:** OwnerReferences are tricky cross-namespace. Use status fields + labels instead.

### 5. Secret Management
- All secrets stay in their respective namespaces
- Cross-namespace secret references: User must replicate secrets themselves - **Option A confirmed**
- Operator only creates secrets in user namespaces (generated client credentials)
- Authorization tokens must be readable across namespaces (via RBAC)

### 6. Existing RBAC Documents
- `TODO/rbac-centralized-operator-design.md` - **Completely replace**
- `TODO/rbac-security-implementation.md` - **Completely replace**
- These documents represent previous "two-mode RBAC" approach that didn't work out

---

## Current State Analysis

### File Structure
```
k8s/
  operator-deployment.yaml          # Operator in keycloak-system, 2 replicas
  crds/                             # All CRD definitions
    keycloak-crd.yaml               # Keycloak instance
    keycloakrealm-crd.yaml         # Realm with keycloak_instance_ref
    keycloakclient-crd.yaml        # Client with keycloak_instance_ref + realm
  rbac/
    cluster-role.yaml               # 142 lines, VERY permissive
    cluster-role-binding.yaml
    service-account.yaml
    namespace.yaml

src/keycloak_operator/
  handlers/
    keycloak.py                     # Manages Keycloak deployments
    realm.py                        # Manages realms, uses keycloak_instance_ref
    client.py                       # Manages clients, uses keycloak_instance_ref

examples/
  service-account/
    realm.yaml                      # Example realm
    client.yaml                     # Example client
```

### Current ClusterRole (Excessively Permissive)
From `k8s/rbac/cluster-role.yaml`:
- **7 resource types** with full CRUD: deployments, statefulsets, services, ingresses, configmaps, secrets, pvcs
- **Scope:** Cluster-wide (can modify ANY resource of these types anywhere)
- **Security Risk:** Single SA compromise = full cluster access
- **Problem:** Blocks production adoption by security-conscious platform teams

**Total permissions:** ~142 lines, 200+ verbs across 30+ resource types

### Current CRD References

**KeycloakRealm CRD** (`keycloakrealm-crd.yaml`):
```yaml
spec:
  properties:
    keycloak_instance_ref:
      type: object
      properties:
        name: {type: string}
        namespace: {type: string}  # Optional, defaults to same namespace
```

**KeycloakClient CRD** (`keycloakclient-crd.yaml`):
```yaml
spec:
  properties:
    keycloak_instance_ref:
      type: object
      properties:
        name: {type: string}
        namespace: {type: string}  # Optional
    realm:
      type: string  # Just realm name, no namespace
```

### Current Handler Logic

**Realm Handler** (`handlers/realm.py`):
```python
keycloak_ref = realm_spec.keycloak_instance_ref
target_namespace = spec.keycloak_instance_ref.namespace
# Looks up Keycloak in potentially different namespace
# Creates realm in Keycloak via Admin API
```

**Client Handler** (`handlers/client.py`):
```python
keycloak_ref = client_spec.keycloak_instance_ref
# Looks up Keycloak
# Creates client in specified realm via Admin API
# Stores credentials in Secret in client's namespace
```

---

## Required Changes

### 1. CRD Schema Changes

**KeycloakRealm CRD:**
```yaml
spec:
  properties:
    # REMOVE keycloak_instance_ref entirely
    
    # ADD operatorRef with authorization
    operatorRef:
      type: object
      required: true
      properties:
        namespace:
          type: string
          description: "Namespace where operator runs (keycloak-system)"
        authorizationSecretRef:
          type: object
          required: true
          properties:
            name: {type: string}
            key: {type: string, default: "token"}
```

**KeycloakClient CRD:**
```yaml
spec:
  properties:
    # REMOVE keycloak_instance_ref entirely
    
    # CHANGE realm to realmRef with authorization
    realmRef:
      type: object
      required: true
      properties:
        name: {type: string}
        namespace: {type: string}
        authorizationSecretRef:
          type: object
          required: true
          properties:
            name: {type: string}
            key: {type: string, default: "token"}
```

### 2. RBAC Changes

**New ClusterRole (Minimal):**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator
rules:
# Watch CRDs across all namespaces (read-only)
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms", "keycloakclients"]
  verbs: ["get", "list", "watch"]

# Update status and finalizers (Kopf requirement)
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms/status", "keycloakclients/status"]
  verbs: ["get", "update", "patch"]

- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms/finalizers", "keycloakclients/finalizers"]
  verbs: ["update"]

# Read secrets for authorization validation (only referenced secrets)
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

# Create secrets in user namespaces (client credentials)
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["create", "update", "patch", "delete"]
  # Note: This is still broad but unavoidable for cross-namespace secret creation

# Events
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# Leader election
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
```

**New Role in Operator Namespace:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-operator-manager
  namespace: keycloak-system
rules:
# Full management of Keycloak CRD in operator namespace
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Full management of Keycloak workloads
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# All other Keycloak-related resources (services, ingresses, etc.)
- apiGroups: [""]
  resources: ["services", "configmaps", "secrets", "persistentvolumeclaims"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# etc...
```

### 3. Handler Logic Changes

**Authorization Validation (New Utility):**
```python
async def validate_authorization(
    secret_ref: dict[str, str],
    namespace: str,
    expected_token: str
) -> bool:
    """Validate authorization token from referenced secret."""
    core_api = client.CoreV1Api()
    
    try:
        secret = core_api.read_namespaced_secret(
            name=secret_ref["name"],
            namespace=namespace
        )
        
        token = base64.b64decode(secret.data[secret_ref.get("key", "token")]).decode()
        return token == expected_token
        
    except ApiException as e:
        logger.error(f"Cannot read authorization secret: {e}")
        return False
```

**Realm Handler Changes:**
```python
# OLD: keycloak_ref = realm_spec.keycloak_instance_ref
# NEW:
operator_ref = realm_spec.operatorRef

# Validate authorization token
if not await validate_authorization(
    operator_ref.authorizationSecretRef,
    operator_ref.namespace,
    OPERATOR_TOKEN  # Generated at operator startup
):
    raise UnauthorizedError("Invalid authorization token")

# Look up Keycloak instance in operator namespace
keycloak_name = f"keycloak-{operator_ref.namespace}"  # Convention
keycloak_namespace = operator_ref.namespace

# Generate realm authorization token for clients
realm_token = generate_token()
store_realm_token(realm_name, namespace, realm_token)
```

**Client Handler Changes:**
```python
# OLD: keycloak_ref = client_spec.keycloak_instance_ref
# NEW:
realm_ref = client_spec.realmRef

# Validate realm authorization token
if not await validate_authorization(
    realm_ref.authorizationSecretRef,
    realm_ref.namespace,
    get_expected_realm_token(realm_ref.name, realm_ref.namespace)
):
    raise UnauthorizedError("Invalid realm authorization token")

# Look up realm to get operator namespace
realm = await get_realm(realm_ref.name, realm_ref.namespace)
operator_namespace = realm.spec.operatorRef.namespace

# Look up Keycloak instance
keycloak_name = f"keycloak-{operator_namespace}"
```

### 4. Release Management

**Current:** Single semantic-release target (operator image)

**New:** Multiple release targets using conventional commit scopes

From `RELEASES.md`:
```
feat(operator): ...     → operator Docker image release (vX.Y.Z)
feat(chart-operator): ... → operator+keycloak Helm chart (chart-operator-vX.Y.Z)
feat(chart-realm): ...    → realm Helm chart (chart-realm-vX.Y.Z)
feat(chart-client): ...   → client Helm chart (chart-client-vX.Y.Z)
```

---

## Implementation Phases

### Phase 1: CRD Schema Updates
1. Update `keycloakrealm-crd.yaml` - remove `keycloak_instance_ref`, add `operatorRef`
2. Update `keycloakclient-crd.yaml` - remove `keycloak_instance_ref`, change `realm` to `realmRef`
3. Update Pydantic models in `src/keycloak_operator/models/`
4. Update validation logic

### Phase 2: Authorization Infrastructure
1. Create authorization token generation utility
2. Create token storage mechanism (in-memory + Secret backup)
3. Create validation utility
4. Update operator startup to generate operator token

### Phase 3: Handler Updates
1. Update realm handler to use `operatorRef` and validate authorization
2. Update realm handler to generate realm tokens
3. Update client handler to use `realmRef` and validate authorization
4. Update Keycloak handler to restrict to operator namespace

### Phase 4: RBAC Refactor
1. Create new minimal ClusterRole
2. Create new Role for operator namespace
3. Update ClusterRoleBinding
4. Update RoleBinding
5. Test permission reduction

### Phase 5: Helm Charts Creation
1. Create `charts/` directory structure
2. Create `charts/keycloak-operator/` (Chart 1)
3. Create `charts/keycloak-realm/` (Chart 2)
4. Create `charts/keycloak-client/` (Chart 3)
5. Add Chart.yaml for each
6. Add values.yaml for each
7. Add templates for each

### Phase 6: Release Process Updates
1. Update `RELEASES.md` with new chart scopes
2. Update `.github/workflows/release-please.yml` for multi-component releases
3. Add chart versioning automation
4. Update documentation

### Phase 7: Migration Guide & Examples
1. Create migration guide from old to new structure
2. Update all examples in `examples/`
3. Update README.md with new architecture
4. Update integration tests

### Phase 8: Testing
1. Update unit tests for new authorization
2. Update integration tests for new reference structure
3. Add tests for authorization validation
4. Add tests for permission boundaries
5. Test Helm chart installations

---

## Key Decisions Confirmed

1. ✅ Keep KeycloakCR, restrict to operator namespace (Option A)
2. ✅ Authorization via generated secrets with token references (Option A)
3. ✅ Monorepo with 3 Helm charts (Option B)
4. ✅ Ownership via status fields + labels, no cross-namespace OwnerReferences
5. ✅ Completely replace existing RBAC documents
6. ✅ Secret replication is user responsibility for cross-namespace needs

---

## Success Criteria

**Security:**
- ✅ 75%+ reduction in ClusterRole permissions
- ✅ No cluster-wide write permissions for workloads
- ✅ Authorization required for all resource creation
- ✅ Secrets stay in their namespaces

**Usability:**
- ✅ Platform team installs Chart 1 once
- ✅ Dev teams install Chart 2 (realm) with authorization token
- ✅ Dev teams install Chart 3 (client) with realm token
- ✅ No manual RBAC configuration needed per team

**Maintainability:**
- ✅ Clear ownership chain (operator → realm → client)
- ✅ Traceable via status fields and labels
- ✅ Individual component versioning
- ✅ GitOps-compatible

---

## Task for Next Session

Create a comprehensive, step-by-step implementation plan in `TODO/helm-charts-refactor-plan.md` that:
1. Breaks down all 8 phases into detailed actionable steps
2. Includes code snippets for key changes
3. Specifies which files need modification
4. Provides testing checkpoints after each phase
5. Includes rollback strategies
6. Estimates time for each step
7. Identifies dependencies between steps

The plan should be detailed enough that an intern could follow it step-by-step.
