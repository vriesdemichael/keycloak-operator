# Backup & Restore Guide

This guide covers operator-managed pre-upgrade backups, database restore expectations by tier, and practical recovery workflows.

Use Helm values as the primary configuration path. Raw manifests remain useful for advanced recovery work, but they should not be the first thing users see.

## Automated Pre-Upgrade Backups

## Backup Model By Database Tier

The operator uses the configured database tier to decide what it can automate before a Keycloak major or minor upgrade.

| Tier | Configuration | Automated action | Blocks upgrade |
| --- | --- | --- | --- |
| CNPG | `keycloak.database.cnpg.*` | Create CNPG `Backup` CR and wait for completion | Yes |
| Managed | `keycloak.database.managed.*` | Create `VolumeSnapshot` and wait for `readyToUse` | Yes |
| External | `keycloak.database.external.*` | Log warning only | No |
| Legacy flat-field | top-level DB fields without tier block | Treated like external | No |

Patch-only Keycloak upgrades skip the backup step.

## Helm Configuration

```yaml
keycloak:
  upgradePolicy:
    strategy: BlueGreen
    backupTimeout: 600
    autoTeardown: true
```

Relevant fields:

- `backupTimeout` defaults to `600` seconds
- allowed range is `60` to `3600`
- `strategy` is `Recreate` or `BlueGreen`

## What Happens During Pre-Upgrade Backup

Before a major or minor version upgrade, the reconciler asks the backup service to protect the database first.

Behavior details:

- CNPG backups create a `postgresql.cnpg.io/v1` `Backup` resource
- managed-tier backups create a `snapshot.storage.k8s.io/v1` `VolumeSnapshot`
- existing backup objects with the same generated name are treated idempotently and re-polled
- failures raise a retryable reconciliation error until timeout or success

The main `status.phase` does not switch into a dedicated backup phase during ordinary pre-upgrade backups. Instead, the operator keeps retrying reconciliation while the backup completes.

For blue-green upgrades, the progress state is tracked under `status.blueGreen`, where `BackingUp` is a real sub-state.

## Monitoring Backup Progress

```bash
kubectl get keycloak <name> -n <namespace> -o jsonpath='{.status.phase}'
kubectl get keycloak <name> -n <namespace> -o jsonpath='{.status.blueGreen}' | jq
kubectl logs deploy/<operator-deployment> -n <operator-namespace> | grep -i backup
```

CNPG tier:

```bash
kubectl get backup -n <cnpg-namespace> \
  -l vriesdemichael.github.io/instance=<keycloak-name>,vriesdemichael.github.io/backup-type=pre-upgrade
```

Managed tier:

```bash
kubectl get volumesnapshot -n <namespace> \
  -l vriesdemichael.github.io/instance=<keycloak-name>,vriesdemichael.github.io/backup-type=pre-upgrade
```

## What You Should Back Up

The operator does not maintain a special token-metadata ConfigMap. Do not build backup procedures around one.

Back up these instead:

- database state through your actual tier-specific mechanism
- `Keycloak`, `KeycloakRealm`, and `KeycloakClient` resources
- Helm values used to deploy the operator and managed instances
- referenced application or admin secrets, encrypted at rest

## Helm-First Resource Backup

```bash
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > keycloak-resources-backup-$(date +%Y%m%d).yaml

helm get values keycloak-operator -n keycloak-system \
  > keycloak-operator-values-$(date +%Y%m%d).yaml
```

If you back up secrets, encrypt the output before storing it.

## Manual Backup Operations

### CNPG Manual Backup

```bash
kubectl cnpg backup <cluster-name> -n <cnpg-namespace>
kubectl get backup -n <cnpg-namespace>
kubectl describe backup <backup-name> -n <cnpg-namespace>
```

### Kubernetes Resource Backup

```bash
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces -o yaml \
  > keycloak-resources-backup.yaml

kubectl get secret --all-namespaces \
  -l vriesdemichael.github.io/keycloak-component=client-credentials \
  -o yaml > keycloak-client-secrets.yaml
```

Encrypt exported secrets before storing them outside the cluster.

## Blue-Green Upgrade Recovery Context

Operationally, the upgrade works like this:

1. pre-upgrade backup runs for supported tiers
2. a green deployment is created
3. the operator waits for green readiness
4. the Service selector cuts over atomically to green
5. blue teardown happens automatically when `autoTeardown=true`

Important recovery implication:

- if an upgrade is interrupted, inspect `status.blueGreen` before deleting anything manually
- the green deployment name and current step are persisted there
- do not assume the old Service selector or deployment naming is still authoritative

## Database Restore By Tier

### CNPG

CNPG is the most complete path because the operator can trigger backups and the database platform owns restore primitives.

Use CNPG recovery or point-in-time restore procedures against the backup location you already operate.

### Managed Database

The operator can create a `VolumeSnapshot` before upgrade, but restore depends on your storage and snapshot classes.

You need a documented PVC and restore workflow for the managed tier before you rely on automated upgrade protection.

### External Database

The operator cannot back this up or restore it for you.

Treat database backup, restore, and failover as an external runbook requirement. The operator only reconnects once the external database is healthy again.

## Restore Kubernetes Resources

```bash
kubectl apply -f keycloak-resources-backup.yaml
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
```

Restore secrets only after decrypting them and only from a source you trust.

## Configuration Shapes

Recommended explicit tier configuration:

```yaml
keycloak:
  database:
    type: postgresql
    managed:
      enabled: true
      host: postgres.example.com
      database: keycloak
      username: keycloak
      pvcName: keycloak-db-pvc
```

Legacy flat-field configuration still works, but it is treated as external for backup behavior:

```yaml
keycloak:
  database:
    type: postgresql
    host: postgres.example.com
    database: keycloak
    username: keycloak
```

## Advanced: CNPG Scheduled Backup Example

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: keycloak-db-daily
  namespace: keycloak-db
spec:
  schedule: "0 2 * * *"
  backupOwnerReference: self
  cluster:
    name: keycloak-db
```

## Recovery Checklist

1. stop or gate traffic if the incident is write-sensitive
2. determine the database tier and restore source
3. restore the database first
4. re-apply CRs and Helm values if cluster state was lost
5. verify Keycloak readiness, realms, and clients
6. inspect `status.blueGreen` if the incident happened during an upgrade

## Disaster Recovery Notes

- restore the database before expecting reconciled resources to become healthy again
- for managed and CNPG tiers, verify the restored PVC or cluster is actually serving traffic before restarting Keycloak
- for blue-green interruptions, inspect `status.blueGreen` and the Service selector before deleting blue or green workloads manually

## See Also

- [Database Setup](../how-to/database-setup.md)
- [HA Deployment](../how-to/ha-deployment.md)
- [Migration](./migration.md)
- [Day Two Operations](./day-two.md)
