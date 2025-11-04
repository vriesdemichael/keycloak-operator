# Backup & Restore Guide

Backup and restore procedures for Keycloak and PostgreSQL database using CloudNativePG.

## What Gets Backed Up

| Component | Content | Backup Method |
|-----------|---------|---------------|
| **Database** | Users, realms, clients, sessions | CloudNativePG barman |
| **Kubernetes Resources** | CRDs, manifests | kubectl export |
| **Token Metadata** | Token rotation state | ConfigMap backup |
| **Secrets** | Credentials (⚠️ encrypt) | kubectl export |

**Not Backed Up**: Operator code, container images (use image registry).

---

## Quick Backup

### One-Command Backup

```bash
#!/bin/bash
BACKUP_DIR="keycloak-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p ${BACKUP_DIR}

# Backup Kubernetes resources
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > ${BACKUP_DIR}/resources.yaml

# Backup token metadata
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml \
  > ${BACKUP_DIR}/token-metadata.yaml

# Trigger database backup
kubectl cnpg backup keycloak-db -n keycloak-db

echo "Backup complete: ${BACKUP_DIR}"
```

---

## Database Backup

### Configure Automatic Backups

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3

  backup:
    barmanObjectStore:
      destinationPath: s3://my-backup-bucket/keycloak-db
      s3Credentials:
        accessKeyId:
          name: backup-s3-credentials
          key: ACCESS_KEY_ID
        secretAccessKey:
          name: backup-s3-credentials
          key: ACCESS_SECRET_KEY
      wal:
        compression: gzip
      data:
        compression: gzip
    retentionPolicy: "30d"
```

### Scheduled Backups

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: keycloak-db-daily
  namespace: keycloak-db
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  backupOwnerReference: self
  cluster:
    name: keycloak-db
```

### Manual Backup

```bash
# Trigger backup
kubectl cnpg backup keycloak-db -n keycloak-db

# List backups
kubectl get backup -n keycloak-db

# Check backup status
kubectl describe backup <backup-name> -n keycloak-db
```

---

## Kubernetes Resources Backup

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="k8s-backup-$(date +%Y%m%d)"
mkdir -p ${BACKUP_DIR}

# Backup all Keycloak resources
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > ${BACKUP_DIR}/keycloak-resources.yaml

# Backup operator configuration
helm get values keycloak-operator -n keycloak-operator-system \
  > ${BACKUP_DIR}/operator-values.yaml

# Backup token metadata
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml \
  > ${BACKUP_DIR}/token-metadata.yaml

# Backup CRDs
kubectl get crd -o yaml | grep -A1000 "vriesdemichael.github.io" \
  > ${BACKUP_DIR}/crds.yaml

# Backup secrets (⚠️ ENCRYPT THIS FILE)
kubectl get secret --all-namespaces -l vriesdemichael.github.io/managed-by=keycloak-operator \
  -o yaml > ${BACKUP_DIR}/secrets.yaml

echo "Backup saved to: ${BACKUP_DIR}"
echo "⚠️ IMPORTANT: Encrypt secrets.yaml before storing!"
```

### Encrypt Secrets

```bash
# Using GPG
gpg --symmetric --cipher-algo AES256 ${BACKUP_DIR}/secrets.yaml

# Using age
age -p ${BACKUP_DIR}/secrets.yaml > ${BACKUP_DIR}/secrets.yaml.age

# Remove plaintext
rm ${BACKUP_DIR}/secrets.yaml
```

---

## Database Restore

### Full Cluster Restore

```bash
# 1. Delete existing cluster (⚠️ DOWNTIME)
kubectl delete cluster keycloak-db -n keycloak-db

# 2. Wait for PVCs to be deleted
kubectl get pvc -n keycloak-db

# 3. Create restore manifest
cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3

  bootstrap:
    recovery:
      source: keycloak-db-backup

  externalClusters:
    - name: keycloak-db-backup
      barmanObjectStore:
        destinationPath: s3://my-backup-bucket/keycloak-db
        s3Credentials:
          accessKeyId:
            name: backup-s3-credentials
            key: ACCESS_KEY_ID
          secretAccessKey:
            name: backup-s3-credentials
            key: ACCESS_SECRET_KEY
EOF

# 4. Wait for restore
kubectl wait --for=condition=Ready cluster/keycloak-db \
  -n keycloak-db --timeout=10m

# 5. Verify data
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "SELECT COUNT(*) FROM public.realm;"
```

### Point-in-Time Restore

```yaml
bootstrap:
  recovery:
    source: keycloak-db-backup
    recoveryTarget:
      targetTime: "2025-01-15 10:00:00+00"  # UTC timestamp
```

### Restore to New Cluster

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db-restored  # Different name
  namespace: keycloak-db
spec:
  instances: 3
  bootstrap:
    recovery:
      source: keycloak-db-backup

  externalClusters:
    - name: keycloak-db-backup
      barmanObjectStore:
        destinationPath: s3://my-backup-bucket/keycloak-db
        s3Credentials:
          accessKeyId:
            name: backup-s3-credentials
            key: ACCESS_KEY_ID
          secretAccessKey:
            name: backup-s3-credentials
            key: ACCESS_SECRET_KEY
```

---

## Kubernetes Resources Restore

### Restore All Resources

```bash
# 1. Restore CRDs first
kubectl apply -f k8s-backup-20250115/crds.yaml

# 2. Restore secrets (decrypt first)
gpg --decrypt k8s-backup-20250115/secrets.yaml.gpg | kubectl apply -f -

# 3. Restore token metadata
kubectl apply -f k8s-backup-20250115/token-metadata.yaml

# 4. Restore Keycloak resources
kubectl apply -f k8s-backup-20250115/keycloak-resources.yaml

# 5. Verify
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
```

### Selective Restore

```bash
# Restore single realm
kubectl get -f k8s-backup-20250115/keycloak-resources.yaml \
  keycloakrealm/my-realm -n my-app -o yaml | kubectl apply -f -

# Restore single namespace
kubectl get -f k8s-backup-20250115/keycloak-resources.yaml \
  --namespace=my-app -o yaml | kubectl apply -f -
```

---

## Disaster Recovery Procedures

### Scenario 1: Database Corruption

**Symptoms**: Data integrity errors, query failures.

**Recovery**:
```bash
# 1. Scale down Keycloak (prevent new writes)
kubectl scale keycloak keycloak -n keycloak-system --replicas=0

# 2. Restore database from backup (see above)

# 3. Verify database integrity
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "
    SELECT tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
    FROM pg_tables WHERE schemaname = 'public' LIMIT 5;
  "

# 4. Scale up Keycloak
kubectl scale keycloak keycloak -n keycloak-system --replicas=3

# 5. Test authentication
```

**RTO**: 15-30 minutes
**RPO**: Time since last backup

### Scenario 2: Accidental Resource Deletion

**Symptoms**: Realm/client deleted from Kubernetes and Keycloak.

**Recovery**:
```bash
# 1. Find resource in backup
grep -A50 "name: my-realm" k8s-backup-20250115/keycloak-resources.yaml

# 2. Restore resource
kubectl apply -f - <<EOF
# (paste resource YAML)
EOF

# 3. Verify reconciliation
kubectl describe keycloakrealm my-realm -n my-app
```

**RTO**: 5-10 minutes
**RPO**: Last backup time

### Scenario 3: Complete Cluster Loss

**Symptoms**: Entire Kubernetes cluster destroyed.

**Recovery**:
```bash
# 1. Deploy new Kubernetes cluster

# 2. Install operators
helm install cnpg cnpg/cloudnative-pg -n cnpg-system --create-namespace
helm install keycloak-operator ./charts/keycloak-operator -n keycloak-operator-system --create-namespace

# 3. Restore database
# (Use Full Cluster Restore procedure above)

# 4. Restore Kubernetes resources
# (Use Kubernetes Resources Restore procedure above)

# 5. Verify end-to-end
```

**RTO**: 2-4 hours
**RPO**: Last backup time

---

## Backup Verification

### Test Restore Monthly

```bash
#!/bin/bash
# Monthly backup test script

# 1. Create test namespace
kubectl create namespace backup-test

# 2. Restore database to test cluster
cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db-test
  namespace: backup-test
spec:
  instances: 1
  bootstrap:
    recovery:
      source: keycloak-db-backup
  externalClusters:
    - name: keycloak-db-backup
      barmanObjectStore:
        destinationPath: s3://my-backup-bucket/keycloak-db
        s3Credentials:
          accessKeyId:
            name: backup-s3-credentials
            key: ACCESS_KEY_ID
          secretAccessKey:
            name: backup-s3-credentials
            key: ACCESS_SECRET_KEY
EOF

# 3. Wait for restore
kubectl wait --for=condition=Ready cluster/keycloak-db-test -n backup-test --timeout=10m

# 4. Verify data
kubectl exec -it -n backup-test keycloak-db-test-1 -- \
  psql -U keycloak -d keycloak -c "
    SELECT COUNT(*) FROM public.realm;
    SELECT COUNT(*) FROM public.user_entity;
    SELECT COUNT(*) FROM public.client;
  "

# 5. Cleanup
kubectl delete namespace backup-test

echo "Backup test complete ✓"
```

### Backup Monitoring

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: backup-alerts
  namespace: keycloak-db
spec:
  groups:
    - name: backups
      rules:
        - alert: BackupFailed
          expr: increase(cnpg_backup_failures_total[1h]) > 0
          labels:
            severity: critical
          annotations:
            summary: "Backup failed for {{ $labels.cluster }}"

        - alert: BackupOld
          expr: time() - cnpg_backup_last_success_timestamp > 86400
          labels:
            severity: warning
          annotations:
            summary: "No successful backup in 24h for {{ $labels.cluster }}"
```

---

## Best Practices

### 1. Backup Frequency

| Environment | Database | Kubernetes Resources | Retention |
|-------------|----------|---------------------|-----------|
| **Production** | Hourly | Daily | 30 days |
| **Staging** | Daily | Weekly | 14 days |
| **Development** | Daily | Weekly | 7 days |

### 2. Storage Strategy

- **Primary**: S3/GCS/Azure Blob (encrypted)
- **Secondary**: Different region/provider
- **Tertiary**: Offline/tape (compliance)

### 3. Encryption

Always encrypt backups containing:
- Kubernetes secrets
- Database dumps
- Token metadata

### 4. Testing

- Monthly restore tests (automated)
- Quarterly disaster recovery drills
- Document restore procedures
- Train team on restore process

### 5. Retention

```yaml
retentionPolicy: "30d"  # Base backups
  # WAL archives retained for PITR within retention window
```

---

## Troubleshooting

### Backup Fails with S3 Error

```bash
# Test S3 access
kubectl run aws-cli --rm -it --image=amazon/aws-cli -- \
  s3 ls s3://my-backup-bucket/ --region us-east-1

# Verify credentials
kubectl get secret backup-s3-credentials -n keycloak-db -o yaml
```

### Restore Hangs

```bash
# Check cluster events
kubectl describe cluster keycloak-db -n keycloak-db

# Check pod logs
kubectl logs -n keycloak-db keycloak-db-1

# Verify backup exists
kubectl run aws-cli --rm -it --image=amazon/aws-cli -- \
  s3 ls s3://my-backup-bucket/keycloak-db/base/
```

### Data Mismatch After Restore

```bash
# Check backup timestamp
kubectl describe backup <backup-name> -n keycloak-db

# Verify you restored correct backup
# Consider point-in-time recovery if needed
```

---

## Related Documentation

- [Database Setup Guide](./database-setup.md)
- [HA Deployment Guide](./ha-deployment.md)
- [Troubleshooting Guide](../operations/troubleshooting.md)
- [CloudNativePG Backup Documentation](https://cloudnative-pg.io/documentation/current/backup_recovery/)
