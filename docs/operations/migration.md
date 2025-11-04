# Migration & Upgrade Guide

This guide covers upgrading the Keycloak operator, migrating between token systems, and comparing this operator with the official Keycloak operator.

## Table of Contents

1. [Upgrading the Operator](#upgrading-the-operator)
2. [Upgrading Keycloak Version](#upgrading-keycloak-version)
3. [Migrating from Manual to Automatic Token Rotation](#migrating-from-manual-to-automatic-token-rotation)
4. [Comparison with Official Keycloak Operator](#comparison-with-official-keycloak-operator)
5. [Backup & Rollback](#backup-rollback)

---

## Upgrading the Operator

### Pre-Upgrade Checklist

- [ ] **Backup current state** - Export all Keycloak resources
- [ ] **Review release notes** - Check for breaking changes
- [ ] **Test in non-production** - Upgrade staging environment first
- [ ] **Check database backups** - Ensure recent backup exists
- [ ] **Document current versions** - Record operator and Keycloak versions

### Step 1: Backup Current State

```bash
# Backup all Keycloak resources
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > keycloak-resources-backup-$(date +%Y%m%d).yaml

# Backup operator configuration
helm get values keycloak-operator -n keycloak-operator-system \
  > operator-values-backup-$(date +%Y%m%d).yaml

# Backup token metadata
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml \
  > token-metadata-backup-$(date +%Y%m%d).yaml

# Backup CRDs
kubectl get crd -o yaml | grep -A1000 "vriesdemichael.github.io" \
  > crds-backup-$(date +%Y%m%d).yaml
```

### Step 2: Check Current Version

```bash
# Get current operator version
helm list -n keycloak-operator-system

# Get operator image version
kubectl get deployment keycloak-operator -n keycloak-operator-system \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

### Step 3: Review Release Notes

Check the [Releases Page](https://github.com/vriesdemichael/keycloak-operator/releases) for:
- Breaking changes
- New features
- Bug fixes
- Migration requirements

### Step 4: Upgrade Operator (Helm)

```bash
# Update Helm repository
helm repo update

# Check available versions
helm search repo keycloak-operator --versions

# Upgrade operator
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --values operator-values-backup-$(date +%Y%m%d).yaml \
  --wait
```

**Important**: The `--wait` flag ensures the upgrade completes before returning.

### Step 5: Verify Upgrade

```bash
# Check operator pods are running new version
kubectl get pods -n keycloak-operator-system

# Check operator logs for startup
kubectl logs -n keycloak-operator-system -l app=keycloak-operator --tail=50

# Verify CRDs updated
kubectl get crd keycloaks.vriesdemichael.github.io -o yaml | grep -A5 version

# Check all resources still healthy
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
```

All resources should remain in `Ready` phase.

### Step 6: Test Reconciliation

```bash
# Trigger reconciliation on a test realm
kubectl annotate keycloakrealm <test-realm> -n <test-namespace> \
  reconcile=$(date +%s) --overwrite

# Watch logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator -f

# Verify realm still Ready
kubectl get keycloakrealm <test-realm> -n <test-namespace>
```

### Rollback Procedure

If upgrade fails:

```bash
# Rollback Helm release
helm rollback keycloak-operator -n keycloak-operator-system

# Verify operator rolled back
kubectl get pods -n keycloak-operator-system

# Check resources still healthy
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
```

**Important**: CRD changes cannot be automatically rolled back. You may need to manually restore CRDs from backup:

```bash
kubectl apply -f crds-backup-<date>.yaml
```

---

## Upgrading Keycloak Version

### Supported Keycloak Versions

- **Minimum**: Keycloak 25.0.0 (management port 9000 requirement)
- **Recommended**: Keycloak 26.0.0+
- **Maximum**: Latest Keycloak release

### Pre-Upgrade Checklist

- [ ] **Check Keycloak release notes** - Review breaking changes
- [ ] **Backup database** - CloudNativePG backup or manual export
- [ ] **Test in non-production** - Verify compatibility
- [ ] **Schedule maintenance window** - Plan for brief downtime

### Upgrade Strategy

**Blue-Green Deployment (Recommended)**:
1. Deploy new Keycloak version alongside old version
2. Switch traffic to new version
3. Keep old version for quick rollback
4. Remove old version after verification

**Rolling Update (Simpler)**:
1. Update Keycloak resource with new image tag
2. Operator performs rolling update
3. Brief downtime during pod restarts

### Rolling Update Procedure

```bash
# Check current Keycloak version
kubectl get keycloak <name> -n <namespace> \
  -o jsonpath='{.spec.image.tag}'

# Update to new version
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  image:
    tag: "26.0.0"
'

# Watch rollout
kubectl rollout status statefulset/<keycloak-name> -n <namespace>

# Verify all pods running new version
kubectl get pods -n <namespace> -l app=keycloak \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

### Verify Upgrade

```bash
# Check Keycloak status
kubectl get keycloak <name> -n <namespace>
# Should show PHASE=Ready

# Check all realms still working
kubectl get keycloakrealm --all-namespaces

# Test OAuth2 flow
# (Use test client to verify authentication)

# Check database schema version
kubectl exec -it -n <namespace> <keycloak-pod> -- \
  psql -h <db-host> -U keycloak -d keycloak \
  -c "SELECT * FROM databasechangelog ORDER BY orderexecuted DESC LIMIT 5;"
```

### Rollback to Previous Version

```bash
# Revert to previous image tag
kubectl patch keycloak <name> -n <namespace> --type=merge -p '
spec:
  image:
    tag: "25.0.6"
'

# Watch rollout
kubectl rollout status statefulset/<keycloak-name> -n <namespace>

# Verify rollback
kubectl get pods -n <namespace> -l app=keycloak
```

**Note**: Keycloak database migrations are forward-only. Rolling back may require database restore if schema was upgraded.

---

## Migrating from Manual to Automatic Token Rotation

If you're currently using manual operator tokens (single-tenant dev mode), migrate to automatic token rotation (multi-tenant production mode).

### Current State: Manual Tokens

```yaml
# All realms use operator token (created at operator startup)
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  operatorRef:
    authorizationSecretRef:
      name: keycloak-operator-auth-token  # ← Manual token
```

**Limitations**:
- No automatic rotation
- All teams share one token
- Token compromise affects all realms

### Target State: Automatic Rotation

```yaml
# First realm uses admission token → generates operational token
# Subsequent realms use operational token (auto-rotates every 90 days)
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  operatorRef:
    authorizationSecretRef:
      name: my-app-operator-token  # ← Operational token
```

**Benefits**:
- ✅ Automatic token rotation (90-day cycle)
- ✅ Namespace isolation
- ✅ Zero-downtime rotation
- ✅ Audit trail in metadata

### Migration Procedure

#### Step 1: Create Admission Token (Per Namespace)

For each application namespace:

```bash
NAMESPACE="my-app"

# Generate admission token
ADMISSION_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Create secret
kubectl create secret generic admission-token-${NAMESPACE} \
  --from-literal=token="$ADMISSION_TOKEN" \
  --namespace=${NAMESPACE}

# Add required labels
kubectl label secret admission-token-${NAMESPACE} \
  vriesdemichael.github.io/token-type=admission \
  vriesdemichael.github.io/allow-operator-read=true \
  --namespace=${NAMESPACE}

# Store metadata
TOKEN_HASH=$(echo -n "$ADMISSION_TOKEN" | sha256sum | cut -d' ' -f1)
kubectl patch configmap keycloak-operator-token-metadata \
  --namespace=keycloak-operator-system \
  --type=merge \
  --patch "{
    \"data\": {
      \"$TOKEN_HASH\": \"{\\\"namespace\\\": \\\"${NAMESPACE}\\\", \\\"token_type\\\": \\\"admission\\\", \\\"token_hash\\\": \\\"$TOKEN_HASH\\\", \\\"issued_at\\\": \\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"valid_until\\\": \\\"$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"version\\\": 1, \\\"created_by_realm\\\": null, \\\"revoked\\\": false}\"
    }
  }"
```

#### Step 2: Identify First Realm in Each Namespace

For migration, choose one realm per namespace to be the "bootstrap realm":

```bash
# List realms per namespace
kubectl get keycloakrealm -n ${NAMESPACE}

# Choose the first/primary realm (or any realm you prefer)
FIRST_REALM="my-first-realm"
```

#### Step 3: Update First Realm to Use Admission Token

```bash
# Patch first realm to use admission token
kubectl patch keycloakrealm ${FIRST_REALM} -n ${NAMESPACE} --type=merge -p "
spec:
  operatorRef:
    authorizationSecretRef:
      name: admission-token-${NAMESPACE}
      key: token
"

# Watch for operational token creation
kubectl get secret -n ${NAMESPACE} -w | grep operator-token
```

**What happens:**
1. Operator detects admission token
2. Performs bootstrap process
3. Creates `${NAMESPACE}-operator-token` (operational token)
4. Realm transitions to using operational token
5. Automatic rotation enabled

#### Step 4: Verify Operational Token Created

```bash
# Check operational token exists
kubectl get secret ${NAMESPACE}-operator-token -n ${NAMESPACE}

# Check token metadata
kubectl get secret ${NAMESPACE}-operator-token -n ${NAMESPACE} -o yaml | grep -A10 annotations

# Should see:
#   vriesdemichael.github.io/version: "1"
#   vriesdemichael.github.io/valid-until: "<90 days from now>"
#   vriesdemichael.github.io/created-by-realm: "my-first-realm"
```

#### Step 5: Update Other Realms to Use Operational Token

```bash
# Get all realms in namespace (except first)
kubectl get keycloakrealm -n ${NAMESPACE} -o name | grep -v ${FIRST_REALM}

# Update each realm
for realm in $(kubectl get keycloakrealm -n ${NAMESPACE} -o name | grep -v ${FIRST_REALM}); do
  kubectl patch ${realm} -n ${NAMESPACE} --type=merge -p "
spec:
  operatorRef:
    authorizationSecretRef:
      name: ${NAMESPACE}-operator-token
      key: token
"
done
```

#### Step 6: Cleanup Old Manual Token (Optional)

After all realms migrated:

```bash
# Remove old operator token from namespace
kubectl delete secret keycloak-operator-auth-token -n ${NAMESPACE}

# Verify all realms still Ready
kubectl get keycloakrealm -n ${NAMESPACE}
```

#### Step 7: Repeat for All Namespaces

Repeat Steps 1-6 for each application namespace.

### Migration Verification

```bash
# Check all namespaces have operational tokens
for ns in $(kubectl get ns -o name | grep -E "team-|app-"); do
  echo "Namespace: $ns"
  kubectl get secret -n ${ns##*/} | grep operator-token
done

# Check token metadata ConfigMap
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml | grep -E "operational|admission"

# Verify automatic rotation enabled
# (Check tokens expire 90 days from now)
kubectl get secret ${NAMESPACE}-operator-token -n ${NAMESPACE} \
  -o jsonpath='{.metadata.annotations.vriesdemichael\.github\.io/valid-until}'
```

---

## Comparison with Official Keycloak Operator

### Overview

| Aspect | This Operator | Official Keycloak Operator |
|--------|---------------|----------------------------|
| **Primary Focus** | GitOps-native, multi-tenant | General Keycloak deployment |
| **Language** | Python (Kopf) | Go (Operator SDK) |
| **CRDs** | Keycloak, KeycloakRealm, KeycloakClient | Keycloak, KeycloakRealmImport |
| **Authorization** | Secret-based tokens | RBAC + direct access |
| **Multi-tenancy** | First-class support | Limited |
| **Token Rotation** | Automatic (90-day) | Manual |
| **GitOps Compatibility** | Excellent | Good |
| **Secret Management** | Kubernetes-native | Kubernetes + Keycloak |
| **Database** | CloudNativePG (CNPG) primary | External PostgreSQL |

### When to Use This Operator

✅ **Choose this operator if:**
- Multi-tenant environment (10+ teams)
- GitOps-first workflow (ArgoCD, Flux)
- Strong namespace isolation required
- Automatic token rotation desired
- CloudNativePG database management preferred
- Secret-based delegation model fits your org

### When to Use Official Operator

✅ **Choose official operator if:**
- Single-tenant environment
- Need Keycloak's built-in security model
- Organization policy requires official/upstream operators
- Integration with Red Hat/RHSSO required
- Prefer Go-based operators
- Need features not yet in this operator

### Feature Comparison

#### Realm Management

| Feature | This Operator | Official Operator |
|---------|---------------|-------------------|
| Declarative realm config | ✅ KeycloakRealm CRD | ✅ KeycloakRealmImport |
| Live realm updates | ✅ Automatic reconciliation | ⚠️ Import-based |
| Drift detection | ✅ Built-in | ❌ Not supported |
| Multi-namespace realms | ✅ Fully supported | ⚠️ Limited |
| Realm deletion | ✅ Automatic | ⚠️ Manual |

#### Client Management

| Feature | This Operator | Official Operator |
|---------|---------------|-------------------|
| Declarative client config | ✅ KeycloakClient CRD | ⚠️ Via RealmImport |
| Client secret management | ✅ Automatic Kubernetes secret | ⚠️ Via RealmImport |
| Protocol mappers | ✅ CRD support | ✅ Via RealmImport |
| Service accounts | ✅ CRD support | ✅ Via RealmImport |
| Cross-namespace clients | ✅ Fully supported | ❌ Not supported |

#### Security Model

| Feature | This Operator | Official Operator |
|---------|---------------|-------------------|
| Authorization method | Secret-based tokens | Keycloak admin credentials |
| Token rotation | ✅ Automatic (90-day) | ❌ Manual |
| Multi-tenant isolation | ✅ Namespace-scoped tokens | ⚠️ RBAC-based |
| Audit trail | ✅ K8s API + ConfigMap | ⚠️ Keycloak logs |
| Secret distribution | ✅ GitOps-friendly | ⚠️ Manual |

#### Operations

| Feature | This Operator | Official Operator |
|---------|---------------|-------------------|
| Database management | ✅ CNPG integration | ⚠️ External required |
| Backup/restore | ✅ Via CNPG | ⚠️ Manual |
| High availability | ✅ Multi-replica support | ✅ Multi-replica support |
| Monitoring | ✅ Prometheus metrics | ✅ Prometheus metrics |
| Rate limiting | ✅ Built-in API rate limiting | ❌ Not supported |

### Migration from Official Operator

**Not Automated** - Migration requires manual steps:

1. **Export data from existing Keycloak**:
   ```bash
   # Export realms from existing Keycloak
   kubectl exec -it <keycloak-pod> -- \
     /opt/keycloak/bin/kc.sh export --dir /tmp/export
   ```

2. **Deploy this operator alongside** (different namespace)

3. **Create new Keycloak instance** with this operator

4. **Import realm exports**:
   - Create KeycloakRealm CRDs based on exports
   - Create KeycloakClient CRDs for each client

5. **Switch application traffic** to new Keycloak

6. **Decommission old operator** after verification

**Note**: Direct migration is complex. Recommend running both operators in parallel during transition.

---

## Backup & Rollback

### Pre-Upgrade Backup

Always backup before major changes:

```bash
# Full backup script
#!/bin/bash
BACKUP_DIR="keycloak-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p ${BACKUP_DIR}

# Backup resources
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > ${BACKUP_DIR}/resources.yaml

# Backup operator config
helm get values keycloak-operator -n keycloak-operator-system \
  > ${BACKUP_DIR}/operator-values.yaml

# Backup token metadata
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml \
  > ${BACKUP_DIR}/token-metadata.yaml

# Backup CRDs
kubectl get crd -o yaml | grep -A1000 "vriesdemichael.github.io" \
  > ${BACKUP_DIR}/crds.yaml

# Backup database (if using CNPG)
kubectl cnpg backup keycloak-db -n keycloak-db

echo "Backup complete: ${BACKUP_DIR}"
```

### Database Backup (CloudNativePG)

```bash
# Trigger manual backup
kubectl cnpg backup keycloak-db -n keycloak-db

# List backups
kubectl get backup -n keycloak-db

# Verify backup succeeded
kubectl describe backup <backup-name> -n keycloak-db
```

### Restore from Backup

**Restore Kubernetes Resources**:

```bash
# Restore all resources
kubectl apply -f keycloak-backup-<date>/resources.yaml

# Verify resources restored
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
```

**Restore Database** (see [Backup & Restore Guide](../how-to/backup-restore.md)):

```bash
# Restore from specific backup
kubectl cnpg restore keycloak-db \
  --backup <backup-name> \
  --namespace keycloak-db
```

### Rollback Operator

```bash
# Rollback to previous Helm release
helm rollback keycloak-operator -n keycloak-operator-system

# Or rollback to specific revision
helm history keycloak-operator -n keycloak-operator-system
helm rollback keycloak-operator <revision> -n keycloak-operator-system

# Verify rollback
kubectl get pods -n keycloak-operator-system
```

### Emergency Procedures

**Operator Completely Broken**:

```bash
# Uninstall operator (resources remain)
helm uninstall keycloak-operator -n keycloak-operator-system

# Resources continue working (Keycloak still serves traffic)
# Reinstall operator when ready:
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-operator-system \
  --values operator-values-backup.yaml
```

**Keycloak Database Corrupted**:

```bash
# Restore from backup (requires downtime)
kubectl delete cluster keycloak-db -n keycloak-db
kubectl cnpg restore keycloak-db \
  --backup <backup-name> \
  --namespace keycloak-db

# Wait for database to come back
kubectl wait --for=condition=Ready cluster/keycloak-db \
  -n keycloak-db --timeout=10m

# Restart Keycloak pods
kubectl rollout restart statefulset/<keycloak-name> -n <namespace>
```

---

## Best Practices

### Upgrade Strategy

1. **Test First** - Always test upgrades in non-production
2. **Backup Always** - Never upgrade without recent backup
3. **Read Release Notes** - Check for breaking changes
4. **Rolling Updates** - Use rolling updates for zero downtime
5. **Verify Thoroughly** - Test all critical flows after upgrade
6. **Monitor** - Watch metrics and logs during upgrade
7. **Have Rollback Plan** - Know how to rollback before starting

### Maintenance Windows

Schedule upgrades during low-traffic periods:

```bash
# Check current traffic
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep keycloak_api_requests_total

# Notify users of maintenance window
# Perform upgrade
# Verify and re-enable traffic
```

### Documentation

Document your upgrade:

- Pre-upgrade state (versions, configurations)
- Steps taken
- Issues encountered
- Resolution steps
- Post-upgrade verification
- Rollback procedure used (if any)

---

## Related Documentation

- [End-to-End Setup Guide](../how-to/end-to-end-setup.md)
- [Backup & Restore Guide](../how-to/backup-restore.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [Security Model](../security.md)
