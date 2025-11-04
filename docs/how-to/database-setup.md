# Database Setup Guide

This guide covers PostgreSQL database setup for Keycloak using CloudNativePG (CNPG), including configuration, backup, restore, and high availability.

## Overview

Keycloak requires a PostgreSQL database for storing:
- Realm configurations
- User data
- Sessions
- Client configurations
- Events and audit logs

**Recommended Approach**: CloudNativePG (CNPG) operator for Kubernetes-native PostgreSQL management.

---

## Prerequisites

### Required

- Kubernetes cluster 1.26+
- CloudNativePG operator installed
- Storage class available
- Sufficient storage (50GB+ recommended)

### Install CloudNativePG Operator

```bash
# Add Helm repository
helm repo add cnpg https://cloudnative-pg.io/charts
helm repo update

# Install CNPG operator
helm install cnpg cnpg/cloudnative-pg \
  --namespace cnpg-system \
  --create-namespace \
  --set monitoring.podMonitorEnabled=true

# Verify installation
kubectl get pods -n cnpg-system
# Expected: cnpg-cloudnative-pg-xxx Running
```

---

## Quick Start: Basic PostgreSQL Cluster

### 1. Create Namespace

```bash
kubectl create namespace keycloak-db
```

### 2. Create Database Credentials

```bash
# Generate secure password
DB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Create secret
kubectl create secret generic keycloak-db-credentials \
  --from-literal=username=keycloak \
  --from-literal=password="$DB_PASSWORD" \
  --namespace=keycloak-db

# Store password securely (for admin access)
echo "Database password: $DB_PASSWORD" > keycloak-db-password.txt
chmod 600 keycloak-db-password.txt
```

### 3. Deploy PostgreSQL Cluster

```bash
kubectl apply -f - <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3  # 1 primary + 2 replicas

  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"

  bootstrap:
    initdb:
      database: keycloak
      owner: keycloak
      secret:
        name: keycloak-db-credentials

  storage:
    size: 50Gi
EOF
```

### 4. Verify Cluster

```bash
# Check cluster status
kubectl get cluster -n keycloak-db
# Expected: keycloak-db   Cluster in healthy state   3   3m

# Check pods
kubectl get pods -n keycloak-db
# Expected: 3 pods running

# Identify primary
kubectl get cluster keycloak-db -n keycloak-db \
  -o jsonpath='{.status.currentPrimary}'

# Test connection
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "SELECT version();"
```

---

## Production Configuration

### Storage Configuration

#### Cloud Provider Storage Classes

**AWS EBS (gp3)**:
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
  iops: "3000"
  throughput: "125"
allowVolumeExpansion: true
```

**GCP Persistent Disk (SSD)**:
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: pd.csi.storage.gke.io
parameters:
  type: pd-ssd
allowVolumeExpansion: true
```

**Azure Disk (Premium SSD)**:
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: disk.csi.azure.com
parameters:
  skuName: Premium_LRS
allowVolumeExpansion: true
```

#### Use Custom Storage Class

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3
  storage:
    storageClass: fast-ssd  # ← Custom storage class
    size: 100Gi
```

### PostgreSQL Performance Tuning

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3

  postgresql:
    parameters:
      # Connection settings
      max_connections: "200"              # Adjust based on Keycloak replicas

      # Memory settings
      shared_buffers: "512MB"             # 25% of instance memory
      effective_cache_size: "2GB"         # 50-75% of instance memory
      work_mem: "16MB"                    # shared_buffers / max_connections
      maintenance_work_mem: "128MB"       # For VACUUM, CREATE INDEX

      # WAL settings
      wal_buffers: "16MB"
      min_wal_size: "1GB"
      max_wal_size: "4GB"

      # Query planner
      random_page_cost: "1.1"             # For SSD storage
      effective_io_concurrency: "200"     # For SSD storage

      # Checkpoints
      checkpoint_completion_target: "0.9"

      # Logging
      log_line_prefix: "%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h "
      log_checkpoints: "on"
      log_connections: "on"
      log_disconnections: "on"
      log_lock_waits: "on"
      log_min_duration_statement: "1000"  # Log slow queries (>1s)

  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi

  storage:
    storageClass: fast-ssd
    size: 100Gi
```

### High Availability Configuration

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3  # 1 primary + 2 replicas

  # Automatic failover
  primaryUpdateStrategy: unsupervised

  # Replica configuration
  minSyncReplicas: 1
  maxSyncReplicas: 2

  # Anti-affinity: spread across nodes/zones
  affinity:
    podAntiAffinityType: required
    topologyKey: kubernetes.io/hostname

  # Switchover delay
  failoverDelay: 30s

  postgresql:
    parameters:
      # Replication settings
      max_replication_slots: "10"
      max_wal_senders: "10"
      hot_standby: "on"
      wal_level: "replica"

  storage:
    size: 100Gi
```

---

## Backup Configuration

### S3 Backup (Recommended)

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
      # S3 configuration
      destinationPath: s3://my-backup-bucket/keycloak-db
      endpointURL: https://s3.us-east-1.amazonaws.com  # Optional

      # S3 credentials
      s3Credentials:
        accessKeyId:
          name: backup-s3-credentials
          key: ACCESS_KEY_ID
        secretAccessKey:
          name: backup-s3-credentials
          key: ACCESS_SECRET_KEY

      # Compression
      wal:
        compression: gzip
        maxParallel: 2
      data:
        compression: gzip
        jobs: 2

    # Retention policy
    retentionPolicy: "30d"  # Keep backups for 30 days
```

### Create S3 Credentials Secret

```bash
kubectl create secret generic backup-s3-credentials \
  --from-literal=ACCESS_KEY_ID="your-access-key" \
  --from-literal=ACCESS_SECRET_KEY="your-secret-key" \
  --namespace=keycloak-db
```

### MinIO Backup (On-Premises)

```yaml
backup:
  barmanObjectStore:
    destinationPath: s3://keycloak-backups/db
    endpointURL: http://minio.minio-system.svc:9000
    s3Credentials:
      accessKeyId:
        name: backup-minio-credentials
        key: ACCESS_KEY_ID
      secretAccessKey:
        name: backup-minio-credentials
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

# Describe backup
kubectl describe backup <backup-name> -n keycloak-db
```

---

## Restore & Recovery

### Restore from Backup

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db-restored
  namespace: keycloak-db
spec:
  instances: 3

  bootstrap:
    recovery:
      source: keycloak-db-backup
      recoveryTarget:
        targetTime: "2025-01-15 10:00:00.00000+00"  # Optional: point-in-time

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

### Point-in-Time Recovery (PITR)

```yaml
bootstrap:
  recovery:
    source: keycloak-db-backup
    recoveryTarget:
      targetTime: "2025-01-15 10:00:00.00000+00"  # Restore to specific time
      # OR
      targetXID: "12345"  # Restore to specific transaction ID
      # OR
      targetName: "before-migration"  # Restore to named recovery point
```

### Disaster Recovery Procedure

```bash
# 1. Delete corrupted cluster
kubectl delete cluster keycloak-db -n keycloak-db

# 2. Wait for PVCs to be deleted
kubectl get pvc -n keycloak-db

# 3. Apply restore manifest
kubectl apply -f keycloak-db-restore.yaml

# 4. Wait for cluster to become ready
kubectl wait --for=condition=Ready cluster/keycloak-db-restored \
  -n keycloak-db --timeout=10m

# 5. Verify data integrity
kubectl exec -it -n keycloak-db keycloak-db-restored-1 -- \
  psql -U keycloak -d keycloak -c "SELECT COUNT(*) FROM users;"

# 6. Restart Keycloak to reconnect
kubectl rollout restart statefulset/<keycloak-name> -n <keycloak-namespace>
```

---

## Monitoring & Maintenance

### Enable Monitoring

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: keycloak-db
  namespace: keycloak-db
spec:
  instances: 3

  monitoring:
    enabled: true
    podMonitorEnabled: true
    customQueries:
      - name: keycloak_tables_size
        query: |
          SELECT
            schemaname,
            tablename,
            pg_total_relation_size(schemaname||'.'||tablename) AS size_bytes
          FROM pg_tables
          WHERE schemaname = 'public'
        metrics:
          - size_bytes:
              usage: GAUGE
              description: "Table size in bytes"
```

### Prometheus Alerts

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: keycloak-db-alerts
  namespace: keycloak-db
spec:
  groups:
    - name: keycloak-database
      rules:
        - alert: PostgreSQLDown
          expr: cnpg_pg_up == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "PostgreSQL instance down"
            description: "PostgreSQL instance {{ $labels.pod }} is down"

        - alert: PostgreSQLHighConnections
          expr: |
            (cnpg_pg_stat_database_numbackends / cnpg_pg_settings_max_connections) > 0.8
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High database connections"
            description: "{{ $labels.pod }} has {{ $value | humanizePercentage }} connections"

        - alert: PostgreSQLReplicationLag
          expr: cnpg_pg_replication_lag_seconds > 60
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High replication lag"
            description: "Replica {{ $labels.pod }} has {{ $value }}s replication lag"

        - alert: PostgreSQLBackupFailed
          expr: increase(cnpg_backup_failures_total[1h]) > 0
          labels:
            severity: critical
          annotations:
            summary: "Backup failed"
            description: "Backup for {{ $labels.cluster }} failed"
```

### Maintenance Operations

**VACUUM (Automatic)**:
```yaml
postgresql:
  parameters:
    autovacuum: "on"
    autovacuum_max_workers: "3"
    autovacuum_naptime: "60s"
    autovacuum_vacuum_scale_factor: "0.1"
    autovacuum_analyze_scale_factor: "0.05"
```

**Manual VACUUM**:
```bash
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "VACUUM FULL VERBOSE;"
```

**Check Database Size**:
```bash
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "
    SELECT
      pg_size_pretty(pg_database_size('keycloak')) AS db_size,
      pg_size_pretty(pg_total_relation_size('public.users')) AS users_table_size;
  "
```

---

## Connecting Keycloak to Database

### Keycloak CRD Configuration

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  replicas: 3

  database:
    type: cnpg
    cluster: keycloak-db             # ← CNPG cluster name
    namespace: keycloak-db            # ← Database namespace
    credentialsSecret: keycloak-db-credentials  # ← Credentials secret

  # Rest of Keycloak configuration...
```

### Connection Details

CNPG provides two service endpoints:

- **Read-Write (Primary)**: `<cluster-name>-rw.<namespace>.svc`
- **Read-Only (Replicas)**: `<cluster-name>-ro.<namespace>.svc`

Keycloak automatically uses the read-write endpoint for all operations.

### Test Connection from Keycloak

```bash
# Get Keycloak pod
KEYCLOAK_POD=$(kubectl get pods -n keycloak-system -l app=keycloak -o name | head -1)

# Test connection
kubectl exec -it -n keycloak-system ${KEYCLOAK_POD} -- \
  psql -h keycloak-db-rw.keycloak-db.svc -U keycloak -d keycloak -c "SELECT 1;"
```

---

## Troubleshooting

### Cluster Not Starting

```bash
# Check cluster events
kubectl describe cluster keycloak-db -n keycloak-db

# Check pod logs
kubectl logs -n keycloak-db keycloak-db-1

# Check storage
kubectl get pvc -n keycloak-db
kubectl describe pvc -n keycloak-db
```

### Replication Issues

```bash
# Check replication status
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U postgres -c "SELECT * FROM pg_stat_replication;"

# Check replication lag
kubectl get cluster keycloak-db -n keycloak-db \
  -o jsonpath='{.status.instancesStatus}'
```

### Backup Failures

```bash
# Check backup status
kubectl describe backup <backup-name> -n keycloak-db

# Check S3 credentials
kubectl get secret backup-s3-credentials -n keycloak-db -o yaml

# Test S3 access
kubectl run aws-cli --rm -it --image=amazon/aws-cli -- \
  s3 ls s3://my-backup-bucket/keycloak-db/ \
  --region us-east-1
```

### High Disk Usage

```bash
# Check database size
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "
    SELECT
      schemaname,
      tablename,
      pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
    FROM pg_tables
    WHERE schemaname = 'public'
    ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
    LIMIT 10;
  "

# Run VACUUM to reclaim space
kubectl exec -it -n keycloak-db keycloak-db-1 -- \
  psql -U keycloak -d keycloak -c "VACUUM FULL;"
```

---

## Security Best Practices

### 1. Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: keycloak-db-access
  namespace: keycloak-db
spec:
  podSelector:
    matchLabels:
      cnpg.io/cluster: keycloak-db
  ingress:
    # Allow from Keycloak namespace
    - from:
        - namespaceSelector:
            matchLabels:
              name: keycloak-system
      ports:
        - protocol: TCP
          port: 5432

    # Allow from within database namespace (replication)
    - from:
        - podSelector:
            matchLabels:
              cnpg.io/cluster: keycloak-db
      ports:
        - protocol: TCP
          port: 5432
```

### 2. Encrypt Credentials

Use SealedSecrets or external secret managers:

```bash
# Using SealedSecrets
kubeseal -o yaml < keycloak-db-credentials.yaml > keycloak-db-credentials-sealed.yaml
kubectl apply -f keycloak-db-credentials-sealed.yaml
```

### 3. Enable TLS (Optional)

```yaml
spec:
  certificates:
    serverTLSSecret: keycloak-db-tls
    serverCASecret: keycloak-db-ca
```

### 4. Regular Backups

- Enable automated backups (daily minimum)
- Test restore procedures quarterly
- Monitor backup success/failure
- Store backups off-cluster (S3, GCS)

---

## Related Documentation

- [End-to-End Setup Guide](./end-to-end-setup.md)
- [Backup & Restore Guide](./backup-restore.md)
- [High Availability Guide](./ha-deployment.md)
- [Troubleshooting Guide](../operations/troubleshooting.md)
- [CloudNativePG Documentation](https://cloudnative-pg.io/documentation/)
