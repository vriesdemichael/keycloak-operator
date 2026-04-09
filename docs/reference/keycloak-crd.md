# Keycloak CRD Reference

Reference for the `Keycloak` custom resource.

This CR defines the Keycloak instance managed by one operator installation. In normal deployments you create it through the operator Helm chart, but the CR remains the source of truth for the runtime contract.

**API Version:** `vriesdemichael.github.io/v1`
**Kind:** `Keycloak`
**Short Name:** `kc`

## Overview

Important design constraints:

- one operator instance manages one Keycloak instance in its own namespace
- the operator supports Keycloak `24.0.0+`
- the canonical internal model is generated from Keycloak `26.5.2`
- `keycloakVersion` exists so custom images without a useful semver tag can still be reconciled safely

For compatibility details, see [Keycloak Version Support](./keycloak-version-support.md).

## Minimal Example

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: example
  namespace: keycloak-system
spec:
  database:
    type: postgresql
    cnpg:
      clusterName: keycloak-db
```

## Spec Fields

### Core Configuration

| Field | Type | Notes |
| --- | --- | --- |
| `image` | string | Keycloak image to run. Default code constant is `quay.io/keycloak/keycloak:26.5.2`. |
| `keycloakVersion` | string | Optional explicit version override for custom images whose tag is not parseable. |
| `replicas` | integer | Minimum `1`. Multi-replica setups require the usual HA prerequisites. |
| `optimized` | boolean | Use `--optimized` only for pre-built images. The model default is `false`. |
| `operatorRef.namespace` | string | Operator namespace. Defaults to `keycloak-system` when not overridden. |

Example:

```yaml
spec:
  image: ghcr.io/example/keycloak-custom:stable
  keycloakVersion: 26.5.2
  replicas: 2
  optimized: false
  operatorRef:
    namespace: keycloak-system
```

## Database Configuration

The current model is tiered. Prefer one of the sub-objects below instead of the older flat `host` and `database` shape.

| Tier | Field | Purpose |
| --- | --- | --- |
| Tier 1 | `database.cnpg` | CloudNativePG-managed PostgreSQL. Connection details are derived from the CNPG cluster. |
| Tier 2 | `database.managed` | Generic PostgreSQL that the operator can connect to directly. |
| Tier 3 | `database.external` | Externally managed database. The operator can connect but cannot perform managed backups. |

Base field:

| Field | Type | Notes |
| --- | --- | --- |
| `database.type` | string | `postgresql`, `mysql`, `mariadb`, `oracle`, or `mssql` |

### CNPG Tier

```yaml
spec:
  database:
    type: postgresql
    cnpg:
      clusterName: keycloak-db
      namespace: database
```

Behavior:

- the operator resolves the effective host as `<clusterName>-rw`
- the effective credentials secret becomes `<clusterName>-app`
- this is the strongest fit for automated backup and blue-green upgrade support

### Managed Tier

```yaml
spec:
  database:
    type: postgresql
    managed:
      host: postgres-rw.database.svc.cluster.local
      database: keycloak
      username: keycloak
      passwordSecret:
        name: postgres-password
        key: password
      pvcName: keycloak-db-data
      volumeSnapshotClassName: csi-snapclass
      sslMode: verify-full
      connectionPool:
        maxConnections: 50
        minConnections: 10
```

Use this when the operator can reach the database directly but does not own the database lifecycle.

### External Tier

```yaml
spec:
  database:
    type: postgresql
    external:
      host: postgres.example.com
      port: 5432
      database: keycloak
      credentialsSecret: keycloak-db-credentials
      sslMode: verify-full
```

Use this when the database is managed outside the cluster or outside the operator's control plane.

### Legacy Flat Fields

The older flat-field form still works for backward compatibility:

```yaml
spec:
  database:
    type: postgresql
    host: postgres.example.com
    database: keycloak
    username: keycloak
    passwordSecret:
      name: db-password
```

The operator normalizes that legacy form to the same effective contract as the external tier. Prefer the explicit tiered shape for new manifests.

### Shared Database Fields

These appear either on the top-level legacy form or within `managed` and `external`:

| Field | Type | Notes |
| --- | --- | --- |
| `host` | string | required for `managed` and `external` |
| `port` | integer | defaults by database type |
| `database` | string | logical database name |
| `username` | string | optional when using `credentialsSecret` |
| `passwordSecret.name` / `key` | object | direct password secret reference |
| `credentialsSecret` | string | secret containing connection credentials |
| `connectionParams` | map | additional JDBC parameters |
| `connectionPool.maxConnections` | integer | default `20` |
| `connectionPool.minConnections` | integer | default `5` |
| `connectionPool.connectionTimeout` | string | default `30s` |
| `sslMode` | string | `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `migrationStrategy` | string | `auto`, `manual`, `skip` |

## Networking And Runtime

### Service, ingress, and TLS

| Field | Type | Notes |
| --- | --- | --- |
| `service.type` | string | `ClusterIP`, `NodePort`, `LoadBalancer`, `ExternalName` |
| `service.httpPort` | integer | default `8080` |
| `service.httpsPort` | integer | default `8443` |
| `service.annotations` | map | provider-specific tuning |
| `ingress.enabled` | boolean | create ingress |
| `ingress.className` | string | ingress class |
| `ingress.host` | string | external hostname |
| `ingress.path` | string | default `/` |
| `ingress.tlsEnabled` | boolean | default `true` |
| `ingress.tlsSecretName` | string | ingress TLS secret |
| `tls.enabled` | boolean | enable Keycloak-side TLS |
| `tls.secretName` | string | `tls.crt` / `tls.key` secret |
| `tls.hostname` | string | SNI hostname |

### Runtime tuning

| Field | Type | Notes |
| --- | --- | --- |
| `resources.requests` / `limits` | map | pod CPU and memory sizing |
| `env` | list | Kubernetes-style env entries; supports `valueFrom` |
| `jvmOptions` | list | additional JVM flags |
| `serviceAccount` | string | custom workload identity service account |
| `startupProbe` / `livenessProbe` / `readinessProbe` | object | Kubernetes probe overrides |
| `podSecurityContext` | object | pod-level security controls |
| `securityContext` | object | container-level security controls |

## Operational Controls

These fields are newer than the older docs and are where most drift had accumulated.

### Realm capacity

| Field | Type | Notes |
| --- | --- | --- |
| `realmCapacity.maxRealms` | integer | optional cap on managed realm count |
| `realmCapacity.allowNewRealms` | boolean | stop accepting new realms without freezing existing ones |
| `realmCapacity.capacityMessage` | string | operator-visible status message |

### Upgrade orchestration

| Field | Type | Notes |
| --- | --- | --- |
| `upgradePolicy.backupTimeout` | integer | backup timeout in seconds |
| `upgradePolicy.strategy` | string | `Recreate` or `BlueGreen` |
| `upgradePolicy.autoTeardown` | boolean | remove old deployment automatically after cutover |

`BlueGreen` requires a CNPG or managed database tier.

### Maintenance mode

| Field | Type | Notes |
| --- | --- | --- |
| `maintenanceMode.enabled` | boolean | enable ingress traffic controls during upgrade |
| `maintenanceMode.mode` | string | `read-only` or `full-block` |
| `maintenanceMode.excludePaths` | list | health and allow-list paths |
| `maintenanceMode.blockedPaths` | list | regex-capable blocked paths in `read-only` mode |

### Cache isolation

| Field | Type | Notes |
| --- | --- | --- |
| `cacheIsolation.clusterName` | string | explicit cache cluster label |
| `cacheIsolation.autoSuffix` | boolean | append version to cluster name |
| `cacheIsolation.autoRevision` | boolean | derive stable revision-based cluster name |

### Tracing

| Field | Type | Notes |
| --- | --- | --- |
| `tracing.enabled` | boolean | enable OTEL support |
| `tracing.endpoint` | string | OTLP gRPC collector endpoint |
| `tracing.serviceName` | string | trace service name |
| `tracing.sampleRate` | float | `0.0` to `1.0` |

Built-in tracing support requires Keycloak `26.0.0+`.

## Status Fields

The operator writes status under `status`.

### Common phases

You will typically see phases such as:

- `Pending`
- `Provisioning`
- `Reconciling`
- `Ready`
- `Updating`
- `Degraded`
- `Failed`
- `Paused`
- `BackingUp`

### Important status fields

| Field | Type | Meaning |
| --- | --- | --- |
| `phase` | string | current lifecycle phase |
| `message` / `reason` | string | human-readable summary and machine-leaning reason |
| `observedGeneration` | integer | last applied spec generation |
| `replicas`, `readyReplicas`, `availableReplicas` | integer | pod readiness and availability |
| `deployment`, `service`, `ingress` | string | managed resource names |
| `persistentVolumeClaims` | list | PVCs owned or tracked by the instance |
| `authorizationSecretName` | string | realm-authorization secret for delegated namespace flows |
| `endpoints.public`, `admin`, `internal`, `management` | string | resolved URLs |
| `realmCount` | integer | currently managed realm count |
| `acceptingNewRealms` | boolean | whether new realm creation is allowed |
| `capacityStatus` | string | capacity message surfaced by the operator |
| `version` | string | running Keycloak version |
| `capabilities` | list | detected runtime capabilities |
| `lastHealthCheck`, `healthStatus` | string | health observations |
| `stats` | object | operational counters |
| `blueGreen` | object | in-progress blue-green state machine details |

`status.blueGreen.state` can move through states such as `BackingUp`, `ProvisioningGreen`, `WaitingForGreen`, `CuttingOver`, `TearingDownBlue`, `Completed`, and `Failed`.

## Examples

### Blue-green upgrade with CNPG

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: production
  namespace: keycloak-system
spec:
  image: quay.io/keycloak/keycloak:26.5.2
  replicas: 2
  optimized: false
  database:
    type: postgresql
    cnpg:
      clusterName: keycloak-db
  ingress:
    enabled: true
    className: nginx
    host: auth.example.com
    tlsSecretName: auth-example-com-tls
  upgradePolicy:
    strategy: BlueGreen
    backupTimeout: 900
    autoTeardown: true
  maintenanceMode:
    enabled: true
    mode: read-only
  cacheIsolation:
    autoRevision: true
```

### Managed PostgreSQL with capacity control

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: shared-platform
  namespace: keycloak-system
spec:
  database:
    type: postgresql
    managed:
      host: postgres-rw.database.svc.cluster.local
      database: keycloak
      username: keycloak
      passwordSecret:
        name: postgres-password
      pvcName: keycloak-db-data
  realmCapacity:
    maxRealms: 50
    allowNewRealms: true
    capacityMessage: Shared realm platform nearing limit
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
```

### Custom image with explicit version and tracing

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: observability-demo
  namespace: keycloak-system
spec:
  image: ghcr.io/example/keycloak-custom:stable
  keycloakVersion: 26.5.2
  tracing:
    enabled: true
    endpoint: http://otel-collector.observability.svc.cluster.local:4317
    serviceName: keycloak-production
    sampleRate: 0.25
  database:
    type: postgresql
    external:
      host: postgres.example.com
      database: keycloak
      credentialsSecret: keycloak-db-credentials
      sslMode: verify-full
```

## See Also

- [KeycloakRealm CRD Reference](./keycloak-realm-crd.md)
- [Keycloak Version Support](./keycloak-version-support.md)
- [High Availability Deployment](../how-to/ha-deployment.md)
- [ADR 062: One Keycloak Per Operator](../decisions/generated-markdown/062-one-keycloak-per-operator.md)
- [ADR 088: Blue-Green Keycloak Upgrade Strategy](../decisions/generated-markdown/088-blue-green-keycloak-upgrade-strategy.md)
- [ADR 091: Legacy Flat DB Config Normalized To External Tier](../decisions/generated-markdown/091-legacy-flat-db-config-normalized-to-external-tier.md)
- [ADR 092: Blue-Green Upgrade State Machine](../decisions/generated-markdown/092-blue-green-upgrade-state-machine.md)
