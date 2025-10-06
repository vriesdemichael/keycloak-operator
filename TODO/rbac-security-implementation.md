# RBAC and Security Redesign - Implementation Plan

**Status:** Ready for Implementation  
**Estimated Effort:** 26 hours (3-4 days)  
**Priority:** P0 (Blocks v1.0 - Critical Security Improvement)

---

## Overview

Complete RBAC redesign to reduce operator permissions by 75% and implement proper security boundaries. This consolidates all RBAC-related work including secret watching, centralized architecture, and security hardening.

---

## Current Problems

### 1. Excessive Permissions (Critical)
- ❌ ClusterRole with 200+ verbs across 30+ resource types
- ❌ Can read/write ANY secret in the cluster
- ❌ Can modify ANY deployment, service, ingress cluster-wide
- ❌ Single compromise = cluster-wide impact
- ❌ Blocks production deployments in security-conscious environments

### 2. Secret Access Model (Critical)
- ❌ No control over which secrets operator can access
- ❌ No explicit user consent mechanism
- ❌ Cannot track or audit secret access easily
- ❌ Cross-namespace secret references allowed (security risk)

### 3. Secret Rotation (P0 Feature)
- ❌ Secret changes don't trigger automatic reconciliation
- ❌ Rotated secrets require manual reconciliation or CRD changes
- ❌ Breaks GitOps workflows with ExternalSecrets/Vault

---

## Solution: Two-Mode RBAC Architecture

### Core Principles

1. **Centralized Operator + Keycloak Instances**
   - Operator runs in `keycloak-system` namespace
   - All Keycloak instances deployed to `keycloak-system`
   - Users define CRDs in their own namespaces

2. **RoleBinding is the Security Boundary**
   - Users explicitly grant access via RoleBinding in their namespace
   - No cross-namespace secret access
   - No label requirements on user secrets (simplified!)
   - RoleBinding creation = explicit consent

3. **Two Operating Modes**
   - **Mode 1: Manual RBAC** (Default, Production) - Users create RoleBindings
   - **Mode 2: Automatic RBAC** (Development) - Operator creates RoleBindings

---

## Architecture

### Mode 1: Manual RBAC (Production Default) 🔒

```
┌─────────────────────────────────────────┐
│   keycloak-system                        │
│   ├── Operator                           │
│   └── Keycloak Instances                 │
└─────────────────────────────────────────┘
            ↓ watches (read-only)
┌─────────────────────────────────────────┐
│   team-a (User Namespace)                │
│   ├── KeycloakRealm CRD                  │
│   ├── Secrets (no labels needed!)       │
│   └── RoleBinding ← USER CREATES THIS   │
└─────────────────────────────────────────┘
```

**User Workflow:**
1. Create CRD in namespace
2. Operator status: "Waiting for namespace access"
3. User creates RoleBinding (explicit consent)
4. Operator reconciles

**Security:** ⭐⭐⭐⭐⭐
- Zero access by default (Zero Trust)
- Explicit opt-in per namespace
- Revocable (delete RoleBinding)
- No scary broad permissions

### Mode 2: Automatic RBAC (Development) ⚡

```
┌─────────────────────────────────────────┐
│   keycloak-system                        │
│   ├── Operator                           │
│   └── Keycloak Instances                 │
└─────────────────────────────────────────┘
            ↓ watches + manages RBAC
┌─────────────────────────────────────────┐
│   team-a (User Namespace)                │
│   ├── KeycloakRealm CRD                  │
│   ├── Secrets                            │
│   └── RoleBinding ← AUTO-CREATED         │
└─────────────────────────────────────────┘
```

**User Workflow:**
1. Create CRD in namespace
2. Operator auto-creates RoleBinding
3. Operator reconciles immediately

**Security:** ⭐⭐⭐⭐
- Convenience over control
- Operator can manage its own permissions
- Transparent (auto-created RoleBindings labeled)
- Auto-cleanup when no CRDs remain

---

## RBAC Configuration

### 1. Minimal ClusterRole (Both Modes)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator-core
rules:
# CRD watching (read-only)
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloakclients", "keycloakrealms"]
  verbs: ["list", "watch"]

# CRD status/finalizers
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["*/status", "*/finalizers"]
  verbs: ["get", "update", "patch"]

# Namespace discovery
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]

# Leader election
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]

# Events
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# Self-permission checks
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
```

**Total: 8 resource types, ~25 verbs** (down from 200+!)

### 2. ClusterRole for RBAC Management (Mode 2 Only)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator-rbac-manager
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["get", "list"]
```

### 3. Template ClusterRole for Namespace Access

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator-namespace-access
rules:
# Read CRDs
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloakclients", "keycloakrealms"]
  verbs: ["get", "list", "watch", "update", "patch"]

# Secrets (read user secrets, manage operator secrets)
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]

# ConfigMaps
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]

# Events
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# CloudNativePG
- apiGroups: ["postgresql.cnpg.io"]
  resources: ["clusters", "poolers"]
  verbs: ["get", "list", "watch"]
```

**Referenced by RoleBindings** (manual or automatic)

### 4. Role for Operator Namespace

Full management permissions in `keycloak-system` only.

---

## Secret Management

### No User Secret Labeling Required! ✅

**Simplified Approach:**
- RoleBinding = explicit consent for secret access
- Users don't need to label their secrets
- Operator labels ITS OWN secrets for cleanup tracking

**Operator-Managed Secrets (Labeled):**
```yaml
metadata:
  labels:
    keycloak.mdvr.nl/managed-by: "operator"
    keycloak.mdvr.nl/resource-type: "client-credentials"
```

**User Secrets (No Labels):**
```yaml
# Just create normally - no special labels
apiVersion: v1
kind: Secret
metadata:
  name: smtp-password
data:
  password: <base64>
```

### Cross-Namespace Secret References: REMOVED ✅

**Changed in this PR:**
- Removed `namespace` field from `SecretReference`
- Removed `namespace` field from `ExternalSecretReference`
- Removed `namespace` field from `CloudNativePGReference`
- Removed `namespace` field from `KeycloakSMTPPasswordSecret`

**All secret references must be same-namespace as the CRD.**

**Security benefit:** No cross-namespace secret access possible.

---

## Secret Rotation (Integrated)

### Label-Based Secret Watching

**For secrets users want monitored for rotation:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  labels:
    keycloak.mdvr.nl/watch: "true"  # Opt-in for rotation monitoring
data:
  password: <base64>
```

**Operator behavior:**
```python
@kopf.on.update('', 'v1', 'secrets',
                labels={'keycloak.mdvr.nl/watch': 'true'})
async def on_secret_change(name, namespace, **kwargs):
    # Only labeled secrets trigger rotation
    # Find CRDs referencing this secret (same namespace only)
    # Trigger reconciliation
```

**Security guarantee:** Only labeled secrets are monitored. No broad secret watching.

---

## Implementation Phases

### Phase 1: Core RBAC Infrastructure (8 hours)

1. **Create RBAC utilities** `src/keycloak_operator/utils/rbac.py`
   - [ ] `check_namespace_access()` - Check if RoleBinding exists
   - [ ] `ensure_namespace_access()` - Mode-aware access ensuring
   - [ ] `create_namespace_access_rolebinding()` - Auto-create in Mode 2
   - [ ] `cleanup_namespace_access_rolebinding()` - Cleanup when no CRDs
   - [ ] `get_rbac_mode()` - Read from env var
   - [ ] `read_user_secret()` - Simple secret reading (no label checks)

2. **Update operator startup** `src/keycloak_operator/operator.py`
   - [ ] Add RBAC mode detection
   - [ ] Verify permissions for selected mode
   - [ ] Store mode in settings

3. **Update handlers** to check namespace access
   - [ ] `handlers/realm.py` - Call `ensure_namespace_access()`
   - [ ] `handlers/client.py` - Call `ensure_namespace_access()`
   - [ ] `handlers/keycloak.py` - Update if needed

4. **Add RoleBinding watch handler** (Mode 1)
   - [ ] Watch for RoleBinding creation
   - [ ] Trigger reconciliation of pending CRDs

### Phase 2: RBAC Manifests (4 hours)

1. **Create manual mode** `k8s/rbac/manual/`
   - [ ] `cluster-role-core.yaml` - Minimal CRD watching
   - [ ] `cluster-role-namespace-access.yaml` - Template for users
   - [ ] `role-operator-namespace.yaml` - keycloak-system management
   - [ ] `service-account.yaml`
   - [ ] `bindings.yaml`
   - [ ] `install.yaml` - All-in-one
   - [ ] Set env: `KEYCLOAK_OPERATOR_RBAC_MODE=manual`

2. **Create automatic mode** `k8s/rbac/automatic/`
   - [ ] Copy from manual mode
   - [ ] Add `cluster-role-rbac-manager.yaml`
   - [ ] Add binding for RBAC manager role
   - [ ] `install.yaml` - All-in-one
   - [ ] Set env: `KEYCLOAK_OPERATOR_RBAC_MODE=automatic`

3. **Create examples** `examples/rbac/`
   - [ ] `rolebinding-template.yaml` - For Mode 1 users
   - [ ] `README.md` - Usage instructions

### Phase 3: Secret Rotation (4 hours)

1. **Create secret rotation handler** `src/keycloak_operator/handlers/secret_rotation.py`
   - [ ] `on_secret_change()` - Kopf handler with label filter
   - [ ] `find_resources_referencing_secret()` - Find affected CRDs
   - [ ] `trigger_reconciliation()` - Force reconcile via annotation

2. **Import handler** in `operator.py`

3. **Ensure operator-managed secrets have labels**
   - [ ] Update `create_admin_secret()` in `utils/kubernetes.py`
   - [ ] Update `create_client_secret()` in `utils/kubernetes.py`

### Phase 4: Model Updates (2 hours)

1. **Validation enforcement** ✅ COMPLETED
   - [x] Removed cross-namespace secret references
   - [x] Added docstrings explaining same-namespace requirement

2. **Update validation logic** `utils/validation.py`
   - [ ] Ensure secret references are same-namespace as CRD
   - [ ] Clear error messages for violations

### Phase 5: Documentation (6 hours)

1. **README.md updates**
   - [ ] Add "RBAC Modes" section
   - [ ] Installation instructions for both modes
   - [ ] Security comparison table
   - [ ] Secret rotation section

2. **Create `docs/rbac.md`**
   - [ ] Detailed RBAC architecture explanation
   - [ ] Mode comparison
   - [ ] Troubleshooting guide
   - [ ] Migration between modes

3. **Create `docs/security-hardening.md`** ⭐ NEW
   - [ ] Admission controller examples (Kyverno, OPA)
   - [ ] Restrict secret types operator can access
   - [ ] Require label opt-in (if organization wants it)
   - [ ] Audit secret access
   - [ ] NetworkPolicy examples
   - [ ] Pod Security Standards
   - [ ] When to use each protection mechanism

4. **Create security examples** `examples/security/`
   - [ ] `kyverno-restrict-secret-types.yaml`
   - [ ] `kyverno-require-labels.yaml` (optional pattern)
   - [ ] `opa-audit-secret-access.yaml`
   - [ ] `networkpolicy-namespace-isolation.yaml`
   - [ ] `README.md` - When to use each

5. **Update CLAUDE.md**
   - [ ] Document RBAC architecture decisions
   - [ ] Add security guarantees section
   - [ ] Update development workflow

### Phase 6: Testing (8 hours)

1. **Unit tests** `tests/unit/test_rbac.py`
   - [ ] Test `check_namespace_access()`
   - [ ] Test `ensure_namespace_access()` in both modes
   - [ ] Test automatic RoleBinding creation
   - [ ] Test cleanup logic
   - [ ] Test mode detection

2. **Integration tests** `tests/integration/test_rbac_modes.py`
   - [ ] Mode 1: CRD without RoleBinding → Pending status
   - [ ] Mode 1: Create RoleBinding → Reconciles successfully
   - [ ] Mode 1: Secret access works (no labels required)
   - [ ] Mode 2: CRD creation → Auto-RoleBinding → Reconciles
   - [ ] Mode 2: Delete last CRD → Cleanup RoleBinding
   - [ ] Migration between modes

3. **Secret rotation tests** `tests/integration/test_secret_rotation.py`
   - [ ] Create resource with secret reference
   - [ ] Verify resource Ready
   - [ ] Update secret (with watch label)
   - [ ] Verify reconciliation triggered
   - [ ] Verify new secret value used
   - [ ] Test unlabeled secret (not monitored)

4. **Cross-namespace validation tests**
   - [ ] Test secret reference with missing namespace field
   - [ ] Test CNPG reference with missing namespace field
   - [ ] Verify same-namespace enforcement

### Phase 7: Cleanup (2 hours)

1. **Deprecate old RBAC**
   - [ ] Move `k8s/rbac/cluster-role.yaml` to `k8s/rbac/deprecated/`
   - [ ] Add deprecation notices
   - [ ] Update Makefile

2. **Update CI/CD**
   - [ ] Use new RBAC in test workflows
   - [ ] Update deployment instructions

---

## Security Benefits

### Before (Current)
- ❌ 200+ permissions cluster-wide
- ❌ Can access ALL secrets
- ❌ Can modify ANY deployment
- ❌ Single breach = cluster compromise
- ❌ No audit trail

### After (This Implementation)
- ✅ 25 permissions cluster-wide (read-only)
- ✅ 80 permissions per namespace (opt-in only)
- ✅ Zero access until RoleBinding created
- ✅ Explicit user consent per namespace
- ✅ Revocable access (delete RoleBinding)
- ✅ Clear audit trail
- ✅ No cross-namespace secret access
- ✅ 75% permission reduction

**Security Level:**
- Mode 1: ⭐⭐⭐⭐⭐ (Zero Trust, recommended for production)
- Mode 2: ⭐⭐⭐⭐ (Convenient, good for development)

---

## User Guarantees

### Namespace Isolation
- Operator has NO access to your namespace by default
- Must explicitly grant via RoleBinding
- Can revoke anytime

### Secret Privacy
- RoleBinding is the security boundary
- No secret labeling required (simplified!)
- Only same-namespace secrets accessible
- Operator-managed secrets clearly labeled

### Audit & Compliance
- Query namespaces with access: `kubectl get rolebindings -A -l app.kubernetes.io/name=keycloak-operator`
- Query operator secrets: `kubectl get secrets -A -l keycloak.mdvr.nl/managed-by=operator`
- All actions logged with correlation IDs
- Meets SOC2, PCI-DSS, HIPAA requirements

### Additional Protection (Optional)
- Admission controllers for extra policies
- NetworkPolicies for network isolation
- Pod Security Standards
- Documented in `docs/security-hardening.md`

---

## Success Criteria

- ✅ Two RBAC modes implemented (manual + automatic)
- ✅ Mode selection via environment variable
- ✅ Mode 1: Zero access until RoleBinding
- ✅ Mode 2: Automatic RoleBinding creation
- ✅ Secret rotation with label-based filtering
- ✅ No cross-namespace secret references
- ✅ No user secret labeling required
- ✅ Operator-managed secrets labeled
- ✅ Clear status messages in both modes
- ✅ All tests passing
- ✅ Comprehensive documentation
- ✅ Security hardening guide
- ✅ 75% permission reduction achieved

---

## Timeline

**Total: 26 hours (3-4 days)**

**Day 1 (8h):** Phase 1 - Core RBAC infrastructure  
**Day 2 (6h):** Phase 2 & 3 - RBAC manifests + Secret rotation  
**Day 3 (8h):** Phase 4, 5, 6 - Models, Documentation, Testing  
**Day 4 (4h):** Phase 6, 7 - Testing completion + Cleanup  

---

## Migration for Existing Users

**Non-breaking:** Old RBAC remains available in `k8s/rbac/deprecated/`

**Recommended path:**
1. Install new operator with Mode 1 (manual)
2. Test in non-production namespace
3. Gradually migrate namespaces (create RoleBindings)
4. Remove old RBAC when confident

---

## Related Documentation

This TODO consolidates and replaces:
- `rbac-two-mode-design.md` - Implementation details
- `rbac-centralized-operator-design.md` - Architecture exploration
- `rbac-redesign-least-privilege.md` - Original multi-tier approach
- `secret-rotation-implementation.md` - Secret rotation design
- `security-architecture-summary.md` - Executive summary

**Reference those files for detailed design rationale, but implement from this TODO.**

---

**This is the complete RBAC and security implementation plan. All design discussions consolidated here.**
