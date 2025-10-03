# Keycloak Operator Bug Fixes - Detailed Instructions

## Status Update

**Last Updated:** 2025-10-03

### ✅ BUG #1: FIXED - Admin Authentication Failure
**Completion Date:** 2025-10-03
**Solution:** Fixed via finalizer implementation
- PVC cleanup now automatic in deletion handler
- No more stale credentials persisting between deployments
- See `src/keycloak_operator/handlers/keycloak.py` - deletion handler with PVC cleanup

### ❌ BUG #2: NOT FIXED - Redirect URI Validation Too Strict
**Status:** STILL BLOCKING PRODUCTION USE
**Location:** `src/keycloak_operator/models/client.py:226-229`
**Impact:** Cannot use wildcard redirect URIs like `http://localhost:3000/*`
**Action Required:** Remove or relax the `validate_redirect_uris` validator

---

## Overview
There are TWO bugs that need to be fixed:
1. **Admin authentication failing** (401 Unauthorized) - ✅ FIXED
2. **Redirect URI validation too strict** - ❌ STILL NEEDS FIX

---

## BUG #1: Admin Authentication Failure ✅ FIXED

### Problem
The operator cannot authenticate with Keycloak to create realms and clients. Error in logs:
```
Failed to authenticate with Keycloak: 401 Client Error: Unauthorized
```

### Root Cause
Keycloak uses persistent storage (PVC - PersistentVolumeClaim). When you delete and recreate a Keycloak resource:
1. The PVC with the old database is NOT deleted
2. Keycloak starts and finds an existing database with an admin user
3. The `KC_BOOTSTRAP_ADMIN_PASSWORD` env var is IGNORED (only used when creating NEW admin user)
4. The operator tries to auth with NEW auto-generated password
5. Database has OLD password → 401 Unauthorized

### Solution: Clean Up PVC Before Testing

**Step 1:** Delete the PVC along with the Keycloak resource
```bash
# Check current PVCs
kubectl get pvc

# Delete the Keycloak PVC
kubectl delete pvc my-keycloak-keycloak-data

# Then delete and recreate Keycloak
kubectl delete keycloak my-keycloak
kubectl create -f your-keycloak.yaml
```

**Step 2:** Alternative - Delete the PVC automatically (recommended for production fix)

Modify `src/keycloak_operator/handlers/keycloak.py` to add PVC cleanup in the deletion handler:

Find the deletion handler function (search for `@kopf.on.delete` or finalizer cleanup) and ensure it deletes the PVC. Look for existing cleanup code around line 200-300.

---

## BUG #2: Redirect URI Validation Too Strict

### Problem
Client creation fails with error:
```
Wildcard characters not allowed in redirect URIs
```
When using valid patterns like `http://localhost:3000/*`

### Root Cause
File: `src/keycloak_operator/models/client.py`, lines 224-230

The validator BLOCKS ALL wildcards, but Keycloak actually SUPPORTS wildcard patterns in redirect URIs per OAuth 2.0 spec.

### Solution: Remove or Relax the Validation

**OPTION A: Remove the validation entirely (RECOMMENDED)**

1. Open file: `src/keycloak_operator/models/client.py`
2. Find lines 224-230 (the `validate_redirect_uris` function)
3. DELETE or COMMENT OUT this entire validator:

```python
# BEFORE (lines 224-230) - DELETE THIS:
@field_validator("redirect_uris")
@classmethod
def validate_redirect_uris(cls, v):
    for uri in v:
        if "*" in uri:
            raise ValueError("Wildcard characters not allowed in redirect URIs")
    return v
```

```python
# AFTER - Just remove it completely
# (no replacement needed - Keycloak will validate URIs itself)
```

**OPTION B: Make validation more permissive (alternative)**

If you want to keep SOME validation, allow wildcards in path only:

```python
@field_validator("redirect_uris")
@classmethod
def validate_redirect_uris(cls, v):
    for uri in v:
        # Allow wildcards in path (after ://) but not in domain
        if "://" in uri:
            protocol, rest = uri.split("://", 1)
            if "/" in rest:
                domain, path = rest.split("/", 1)
                # Wildcard OK in path, not in domain
                if "*" in domain:
                    raise ValueError(f"Wildcard not allowed in domain: {uri}")
            elif "*" in rest:
                raise ValueError(f"Wildcard not allowed in domain: {uri}")
    return v
```

**RECOMMENDED: Use Option A** (complete removal) - let Keycloak validate URIs according to its own rules.

---

## Testing Instructions

After making the fixes:

### 1. Build and deploy the operator
```bash
# Build Docker image
docker build -t keycloak-operator:test .

# Load into kind cluster
kind load docker-image keycloak-operator:test --name keycloak-operator-test

# Restart operator
kubectl rollout restart deployment keycloak-operator -n keycloak-system
kubectl rollout status deployment keycloak-operator -n keycloak-system --timeout=60s
```

### 2. Clean up old resources
```bash
# Delete old Keycloak and its PVC
kubectl delete keycloak my-keycloak
kubectl delete pvc my-keycloak-keycloak-data

# Delete old realm and client
kubectl delete keycloakrealm my-realm
kubectl delete keycloakclient my-client
```

### 3. Recreate resources
```bash
# Create Keycloak
cat <<'EOF' | kubectl create -f -
apiVersion: keycloak.mdvr.nl/v1
kind: Keycloak
metadata:
  name: my-keycloak
spec:
  image: "quay.io/keycloak/keycloak:26.0.0"
  replicas: 1
  database:
    type: "postgresql"
    host: "postgres.postgres.svc.cluster.local"
    database: "keycloak"
    username: "keycloak"
    password_secret:
      name: "keycloak-db-secret"
      key: "password"
  admin_access:
    username: "admin"
  service:
    type: "NodePort"
    port: 8080
  resources:
    requests:
      memory: "512Mi"
      cpu: "100m"
    limits:
      memory: "1Gi"
      cpu: "500m"
EOF

# Wait for Keycloak to be ready
kubectl wait --for=condition=ready keycloak/my-keycloak --timeout=5m

# Create Realm
cat <<'EOF' | kubectl create -f -
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
spec:
  realm_name: "myrealm"
  display_name: "My Test Realm"
  keycloak_instance_ref:
    name: my-keycloak
  enabled: true
EOF

# Create Client with wildcard redirect URI
cat <<'EOF' | kubectl create -f -
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: my-client
spec:
  client_id: "my-test-client"
  client_name: "My Test Client"
  keycloak_instance_ref:
    name: my-keycloak
  realm: "myrealm"
  public_client: true
  redirect_uris:
    - "http://localhost:3000/*"
  web_origins:
    - "http://localhost:3000"
  protocol: "openid-connect"
EOF
```

### 4. Verify success
```bash
# Check all resources are Ready
kubectl get keycloak my-keycloak
kubectl get keycloakrealm my-realm
kubectl get keycloakclient my-client

# Check operator logs for success (not errors)
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=50
```

**Expected Results:**
- Keycloak: Phase should be "Ready"
- Realm: Phase should be "Ready" (not empty)
- Client: Phase should be "Ready" (not empty)
- No 401 errors in operator logs
- No validation errors about wildcards

---

## Checklist

- [ ] Fix #1: Delete PVC before testing OR implement automatic PVC cleanup
- [ ] Fix #2: Remove/modify redirect URI validation in `client.py:224-230`
- [ ] Build and load new operator image
- [ ] Clean up old Keycloak, PVC, realm, and client resources
- [ ] Deploy new operator
- [ ] Create fresh Keycloak instance
- [ ] Create realm - verify no 401 errors
- [ ] Create client with wildcard redirect URI - verify no validation errors
- [ ] Verify all resources show "Ready" phase
- [ ] Check operator logs for any errors

---

## Common Mistakes to Avoid

1. **DON'T** just delete and recreate Keycloak without deleting the PVC - the old database will persist
2. **DON'T** modify only the CRD YAML - you must change the Python model file
3. **DON'T** forget to rebuild and reload the Docker image after code changes
4. **DON'T** forget to restart the operator deployment after loading new image
5. **DO** wait for each resource to be fully ready before creating the next one
6. **DO** check operator logs if something fails - error messages are detailed

---

## Files to Modify

1. `src/keycloak_operator/models/client.py` - lines 224-230 (remove redirect URI validator)
2. `src/keycloak_operator/handlers/keycloak.py` - optional: add PVC cleanup in finalizer (search for finalizer/cleanup functions)

## Files Referenced

- **Bug #1 (Authentication):**
  - `src/keycloak_operator/utils/kubernetes.py` - lines 160-181 (admin credentials env vars)
  - `src/keycloak_operator/utils/kubernetes.py` - lines 1075-1150 (create_admin_secret function)
  - `src/keycloak_operator/utils/keycloak_admin.py` - lines 130-163 (authentication logic)
  - `src/keycloak_operator/utils/keycloak_admin.py` - lines 1483-1570 (get_keycloak_admin_client factory)

- **Bug #2 (Redirect URI Validation):**
  - `src/keycloak_operator/models/client.py` - lines 224-230 (validator to remove)
  - `src/keycloak_operator/models/client.py` - lines 146-154 (redirect_uris fields)

---

## Technical Details

### Why PVC persists when Keycloak is deleted
By default, Kubernetes does NOT delete PVCs when you delete a deployment or custom resource. This is a safety feature to prevent data loss. The PVC continues to exist with all the data (including the Keycloak database with the old admin password).

### How Keycloak bootstrap admin works
- `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD` are ONLY used when:
  1. Keycloak starts for the FIRST TIME
  2. The master realm has NO admin user yet
- If an admin user already exists in the database, these env vars are IGNORED
- This is why the auto-generated password doesn't work on second deployment

### Why wildcard redirect URIs are valid
According to OAuth 2.0 specifications and Keycloak documentation:
- Wildcards (`*`) ARE allowed in redirect URIs
- Common pattern: `http://localhost:3000/*` for development
- Keycloak validates these internally
- The operator's validator was being overly strict

---

## Quick Fix Summary

**For immediate testing:**
```bash
# 1. Delete PVC to clear old credentials
kubectl delete pvc my-keycloak-keycloak-data

# 2. Edit client.py and remove lines 224-230 (the validator)

# 3. Rebuild and reload
docker build -t keycloak-operator:test .
kind load docker-image keycloak-operator:test --name keycloak-operator-test
kubectl rollout restart deployment keycloak-operator -n keycloak-system

# 4. Clean and recreate all resources (see Testing Instructions section)
```
