# Keycloak Operator Helm Chart

Official Helm chart for deploying the Keycloak Operator - a Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients with full GitOps compatibility.

## Overview

This chart installs the Keycloak Operator which enables declarative management of:

- **Keycloak instances** - Deploy and configure Keycloak servers
- **Keycloak realms** - Identity domains with users, roles, and authentication settings
- **Keycloak clients** - OAuth2/OIDC applications with automated credential management

**Target Users:** Platform administrators and cluster operators who want to provide Keycloak-as-a-Service to development teams.

This chart is the recommended deployment path for the operator. Managing raw `Keycloak` manifests directly is supported, but it is an advanced/manual workflow. See [Helm vs Direct CR Deployments](../../docs/how-to/helm-vs-cr-deployments.md).

The chart follows the one-operator-per-Keycloak model. In managed mode, the chart is built around a single Keycloak instance in the operator namespace, and admission controls enforce a one-Keycloak-per-namespace limit to avoid ownership and resource conflicts.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.8+
- (Optional) [CloudNativePG operator](https://cloudnative-pg.io/) for managed PostgreSQL databases
- (Optional) Prometheus Operator for monitoring
- (Optional) Grafana for dashboards

## Installation

### Quick Start

```bash
# Install the operator from OCI registry
helm install keycloak-operator \
  oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace
```

### Install from Source

```bash
# Clone the repository
git clone https://github.com/vriesdemichael/keycloak-operator.git
cd keycloak-operator

# Install the chart
helm install keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace
```

### Verify Installation

```bash
# Check operator deployment
kubectl get deployment -n keycloak-system
kubectl get pods -n keycloak-system

# View operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=50
```

The operator should be in `Running` state within 1-2 minutes.

## Configuration

### Values Reference

#### Operator Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.replicaCount` | Number of operator replicas for HA | `2` |
| `operator.instanceId` | Operator instance ID for multi-operator deployments. Auto-generated if empty. | `""` |
| `operator.image.repository` | Operator container image repository | `ghcr.io/vriesdemichael/keycloak-operator` |
| `operator.image.tag` | Operator image tag (overrides chart appVersion) | `"v0.2.14"` |
| `operator.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `operator.imagePullSecrets` | Image pull secrets | `[]` |
| `operator.resources.limits.cpu` | CPU limit | `500m` |
| `operator.resources.limits.memory` | Memory limit | `512Mi` |
| `operator.resources.requests.cpu` | CPU request | `100m` |
| `operator.resources.requests.memory` | Memory request | `128Mi` |
| `operator.nodeSelector` | Node selector for operator pods | `{kubernetes.io/os: linux}` |
| `operator.tolerations` | Pod tolerations | See [values.yaml](values.yaml) |
| `operator.affinity` | Pod affinity rules | Pod anti-affinity enabled by default |
| `operator.securityContext` | Pod security context | See [values.yaml](values.yaml) |
| `operator.containerSecurityContext` | Container security context | See [values.yaml](values.yaml) |
| `operator.livenessProbe` | Liveness probe configuration | `/healthz` endpoint |
| `operator.readinessProbe` | Readiness probe configuration | `/healthz` endpoint |
| `operator.env` | Additional environment variables | `[]` |

**Environment Variables:**

Common environment variables you can set via `operator.env`:

```yaml
operator:
  env:
    - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
      value: "50"  # Global API rate limit (requests/second)
    - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
      value: "5"   # Per-namespace rate limit
    - name: RECONCILE_JITTER_MAX_SECONDS
      value: "5.0" # Max jitter to prevent thundering herd
```

#### Namespace Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace.name` | Namespace to create/use for operator | `keycloak-system` |
| `namespace.create` | Create the namespace | `true` |
| `namespace.podSecurityStandards.enforce` | Pod Security Standards enforcement level | `restricted` |
| `namespace.podSecurityStandards.audit` | Pod Security Standards audit level | `restricted` |
| `namespace.podSecurityStandards.warn` | Pod Security Standards warning level | `restricted` |

#### Service Account & RBAC

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name (auto-generated if empty) | `""` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `rbac.create` | Create ClusterRole and ClusterRoleBinding | `true` |
| `rbac.createLeaderElectionRole` | Create namespace-scoped leader election role | `true` |

#### CRDs

| Parameter | Description | Default |
|-----------|-------------|---------|
| `crds.install` | Install CRDs as part of chart | `true` |
| `crds.keep` | Keep CRDs on chart uninstall (prevents data loss) | `true` |

**Important:** Setting `crds.keep: false` will delete all Keycloak resources when uninstalling the chart.

#### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.enabled` | Enable Prometheus ServiceMonitor | `false` |
| `monitoring.namespace` | Namespace for monitoring resources | `""` (uses operator namespace) |
| `monitoring.labels` | Additional labels for ServiceMonitor | `{}` |
| `monitoring.interval` | Scrape interval | `30s` |
| `monitoring.scrapeTimeout` | Scrape timeout | `10s` |

##### Drift Detection

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.driftDetection.enabled` | Enable drift detection | `true` |
| `monitoring.driftDetection.intervalSeconds` | Scan interval (seconds) | `300` |
| `monitoring.driftDetection.autoRemediate` | Auto-delete orphaned resources | `false` |
| `monitoring.driftDetection.minimumAgeHours` | Minimum age before deletion (hours) | `24` |
| `monitoring.driftDetection.scope.realms` | Detect realm drift | `true` |
| `monitoring.driftDetection.scope.clients` | Detect client drift | `true` |
| `monitoring.driftDetection.scope.identityProviders` | Detect identity provider drift | `true` |
| `monitoring.driftDetection.scope.roles` | Detect role drift | `true` |

##### Prometheus Rules

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.prometheusRules.enabled` | Enable PrometheusRule resource | `false` |
| `monitoring.prometheusRules.namespace` | Namespace for PrometheusRule | `""` (uses operator namespace) |
| `monitoring.prometheusRules.labels` | Labels for Prometheus discovery | `{}` |
| `monitoring.prometheusRules.interval` | Evaluation interval | `30s` |
| `monitoring.prometheusRules.slowReconciliationThreshold` | Slow reconciliation alert threshold (seconds) | `30` |
| `monitoring.prometheusRules.additionalRules` | Custom Prometheus rules | `[]` |

##### Grafana Dashboard

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.grafanaDashboard.enabled` | Enable Grafana dashboard ConfigMap | `false` |
| `monitoring.grafanaDashboard.namespace` | Namespace for dashboard ConfigMap | `""` (uses operator namespace) |
| `monitoring.grafanaDashboard.labels` | Labels for Grafana sidecar discovery | `{}` |

**Example:** Enable monitoring with Prometheus Operator:

```yaml
monitoring:
  enabled: true
  labels:
    prometheus: kube-prometheus  # Match your Prometheus selector

  prometheusRules:
    enabled: true
    labels:
      prometheus: kube-prometheus

  grafanaDashboard:
    enabled: true
    labels:
      grafana_dashboard: "1"  # For grafana sidecar
```

#### Optional Keycloak Instance

The chart can optionally deploy a Keycloak instance:

##### Operating Modes

- `keycloak.managed: true` deploys and manages a `Keycloak` CR in the operator namespace.
- `keycloak.managed: false` connects the operator to an existing Keycloak instance using `keycloak.url` and `keycloak.adminSecret`.

Managed mode is the normal path when this chart owns the platform deployment. External mode is for bring-your-own-Keycloak setups where the operator should reconcile realms and clients against an already running instance.

For managed Keycloak instances, set `keycloak.admin.existingSecret` when you want the operator to source admin credentials from an existing Kubernetes `Secret` instead of generating them. The referenced secret must live in the same namespace as the managed `Keycloak` and include `username` and `password` keys.

These settings are not interchangeable:

- `keycloak.admin.existingSecret` configures the managed `Keycloak` CR and is only used when `keycloak.managed=true`.
- `keycloak.adminSecret` and `keycloak.adminPasswordKey` configure how the operator authenticates to Keycloak. They are required for `keycloak.managed=false` and default to the generated proxy secret in managed mode.
- `keycloak.verifySsl` controls TLS certificate verification for HTTPS operator-to-Keycloak traffic. Leave it unset to auto-detect from `keycloak.url`: managed/internal HTTP defaults to no verification, external HTTPS defaults to verification.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keycloak.managed` | Deploy and manage a Keycloak instance | `true` |
| `keycloak.name` | Keycloak instance name | `keycloak` |
| `keycloak.url` | Existing Keycloak URL when `managed=false` | `""` |
| `keycloak.adminUsername` | Username the operator uses when authenticating to Keycloak | `admin` |
| `keycloak.adminSecret` | Secret name the operator reads for the admin password | `""` |
| `keycloak.adminPasswordKey` | Key in `keycloak.adminSecret` containing the admin password | `password` |
| `keycloak.verifySsl` | Override TLS certificate verification for HTTPS Keycloak URLs; `null` auto-detects from the URL scheme | `null` |
| `keycloak.admin.existingSecret` | Existing secret to seed admin credentials for a managed Keycloak instance | `""` |
| `keycloak.replicas` | Number of Keycloak replicas | `1` |
| `keycloak.version` | Keycloak version (image tag) | `"26.4.1"` |
| `keycloak.image` | Keycloak container image | `quay.io/keycloak/keycloak` |
| `keycloak.database.type` | Database type | `postgresql` |
| `keycloak.database.host` | Database host | `""` |
| `keycloak.database.port` | Database port | `5432` |
| `keycloak.database.database` | Database name | `keycloak` |
| `keycloak.database.username` | Database username | `keycloak` |
| `keycloak.database.passwordSecret.name` | Secret containing DB password | `keycloak-db-password` |
| `keycloak.database.passwordSecret.key` | Key in secret | `password` |
| `keycloak.database.cnpg.enabled` | Use CloudNativePG cluster | `false` |
| `keycloak.database.cnpg.clusterName` | CNPG cluster name | `keycloak-postgres` |
| `keycloak.ingress.enabled` | Enable ingress | `false` |
| `keycloak.ingress.className` | Ingress class name | `""` |
| `keycloak.ingress.annotations` | Ingress annotations | `{}` |
| `keycloak.ingress.host` | Ingress hostname | `keycloak.example.com` |
| `keycloak.ingress.path` | Ingress path | `/` |
| `keycloak.ingress.tlsEnabled` | Enable TLS for ingress | `true` |
| `keycloak.ingress.tlsSecretName` | Secret containing TLS certificate | `""` |
| `keycloak.resources` | Keycloak resource limits/requests | See [values.yaml](values.yaml) |
| `keycloak.env` | Environment variables for managed Keycloak pods | `[]` |
| `operator.rateLimiting.*` | Global and per-namespace API throttling | See [values.yaml](values.yaml) |
| `operator.circuitBreaker.*` | Keycloak API circuit breaker settings | See [values.yaml](values.yaml) |
| `operator.tracing.*` | OpenTelemetry tracing configuration | See [values.yaml](values.yaml) |
| `operator.reconciliation.pause.*` | Pause reconciliation by resource type | See [values.yaml](values.yaml) |

`keycloak.env` uses the same Kubernetes env entry structure as `operator.env`, so you can use `valueFrom.secretKeyRef` with Secrets created by `extraManifests`, External Secrets Operator, or Sealed Secrets.

##### Production Controls

These are the operator runtime controls most teams end up tuning in production.

**Rate Limiting**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.rateLimiting.global.tps` | Global Keycloak API requests per second across all namespaces | `50.0` |
| `operator.rateLimiting.global.burst` | Allowed global burst capacity | `100` |
| `operator.rateLimiting.namespace.tps` | Fair-share per-namespace requests per second | `5.0` |
| `operator.rateLimiting.namespace.burst` | Allowed per-namespace burst capacity | `10` |

**Circuit Breaker**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.circuitBreaker.enabled` | Enable Keycloak API circuit breaker protection | `true` |
| `operator.circuitBreaker.failureThreshold` | Consecutive failures before the circuit opens | `5` |
| `operator.circuitBreaker.recoveryTimeout` | Seconds before trying half-open recovery | `30` |
| `operator.circuitBreaker.apiTimeout` | Timeout for individual Keycloak API calls | `30` |

**Metrics & Tracing**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.metrics.port` | Prometheus metrics port | `8081` |
| `operator.metrics.host` | Bind address for `/metrics` | `0.0.0.0` |
| `operator.tracing.enabled` | Enable OpenTelemetry export | `false` |
| `operator.tracing.endpoint` | OTLP gRPC collector endpoint | `http://localhost:4317` |
| `operator.tracing.serviceName` | Trace service name | `keycloak-operator` |
| `operator.tracing.sampleRate` | Trace sampling ratio | `1.0` |
| `operator.tracing.insecure` | Disable TLS to the collector | `false` |
| `operator.tracing.propagateToKeycloak` | Propagate tracing config to managed Keycloak | `true` |

**Reconciliation Tuning**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `operator.reconciliation.timerIntervals.keycloak` | Periodic Keycloak health check interval in seconds | `300` |
| `operator.reconciliation.timerIntervals.realm` | Periodic realm reconciliation interval in seconds | `300` |
| `operator.reconciliation.timerIntervals.client` | Periodic client reconciliation interval in seconds | `300` |
| `operator.reconciliation.jitterMaxSeconds` | Startup jitter to prevent thundering-herd behavior | `10.0` |
| `operator.reconciliation.pause.keycloak` | Pause Keycloak reconciliation | `false` |
| `operator.reconciliation.pause.realms` | Pause realm reconciliation | `false` |
| `operator.reconciliation.pause.clients` | Pause client reconciliation | `false` |
| `operator.reconciliation.pause.message` | Status message shown while paused | `Reconciliation paused by operator configuration` |

Pause controls require an operator restart to take effect because they are wired through deployment environment variables. Delete handlers still continue, so pause is suitable for maintenance windows and upgrades but not as a hard delete lock.

**Webhook Quotas**

The admission webhook also enforces per-namespace quotas. Realms and clients are configurable. Keycloak instances are intentionally not a free-form quota: the platform supports one Keycloak instance per namespace by design, matching [ADR 062](../../docs/decisions/generated-markdown/062-one-keycloak-per-operator.md).

**Example:** Deploy Keycloak with CloudNativePG:

```yaml
keycloak:
  managed: true
  replicas: 3
  version: "26.4.1"
  database:
    type: postgresql
    cnpg:
      enabled: true
      clusterName: keycloak-postgres
```

**Example:** Provide Keycloak env vars from an extra manifest secret:

```yaml
extraManifests:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: keycloak-runtime-env
    type: Opaque
    stringData:
      proxy-headers: xforwarded

keycloak:
  managed: true
  env:
    - name: KC_PROXY_HEADERS
      valueFrom:
        secretKeyRef:
          name: keycloak-runtime-env
          key: proxy-headers
```
```

#### Extra Manifests

| Parameter | Description | Default |
|-----------|-------------|---------|
| `extraManifests` | Additional Kubernetes manifests to deploy | `[]` |

Use this for deploying ExternalSecrets, SealedSecrets, ConfigMaps, etc.

**Example:**

```yaml
extraManifests:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: keycloak-db-password
    stringData:
      password: "my-secure-password"
```

#### Common Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `commonLabels` | Labels applied to all resources | `{}` |
| `commonAnnotations` | Annotations applied to all resources | `{}` |

## Usage Examples

### Basic Installation

Install operator with default settings:

```bash
helm install keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace
```

### High Availability Setup

Deploy operator with 3 replicas and resource guarantees:

```yaml
# values-ha.yaml
operator:
  replicaCount: 3
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi

  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app.kubernetes.io/name: keycloak-operator
          topologyKey: kubernetes.io/hostname
```

```bash
helm install keycloak-operator keycloak-operator/keycloak-operator \
  -f values-ha.yaml \
  --namespace keycloak-system \
  --create-namespace
```

### With Monitoring Enabled

Enable Prometheus metrics and Grafana dashboard:

```yaml
# values-monitoring.yaml
monitoring:
  enabled: true
  labels:
    prometheus: kube-prometheus

  driftDetection:
    enabled: true
    autoRemediate: false

  prometheusRules:
    enabled: true
    labels:
      prometheus: kube-prometheus

  grafanaDashboard:
    enabled: true
    namespace: monitoring
    labels:
      grafana_dashboard: "1"
```

```bash
helm install keycloak-operator keycloak-operator/keycloak-operator \
  -f values-monitoring.yaml \
  --namespace keycloak-system \
  --create-namespace
```

### Deploy with Keycloak Instance

Deploy operator and Keycloak instance together:

```yaml
# values-with-keycloak.yaml
keycloak:
  managed: true
  replicas: 3
  version: "26.4.1"

  database:
    type: postgresql
    host: postgres-postgresql.default.svc.cluster.local
    port: 5432
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
      key: password

  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    host: keycloak.example.com
    path: /
    tlsEnabled: true
    tlsSecretName: keycloak-tls
```

```bash
helm install keycloak-operator keycloak-operator/keycloak-operator \
  -f values-with-keycloak.yaml \
  --namespace keycloak-system \
  --create-namespace
```

### Multi-Operator Deployment

Deploy multiple operators for workload isolation:

```yaml
# values-production.yaml
operator:
  instanceId: "production-operator"

namespace:
  name: keycloak-production
```

```bash
# Production operator
helm install keycloak-prod keycloak-operator/keycloak-operator \
  -f values-production.yaml \
  --namespace keycloak-production \
  --create-namespace

# Staging operator
helm install keycloak-staging keycloak-operator/keycloak-operator \
  --set operator.instanceId=staging-operator \
  --set namespace.name=keycloak-staging \
  --namespace keycloak-staging \
  --create-namespace
```

## Post-Installation

### Quick Start

After installation, you can create realms and clients. Authorization is controlled by:

1. **Realm Creation**: Kubernetes RBAC (who can create KeycloakRealm resources)
2. **Client Creation**: Namespace grant lists (realm's `clientAuthorizationGrants`)

> **📖 See the [Complete Quick Start Guide](https://vriesdemichael.github.io/keycloak-operator/latest/quickstart/README/) for detailed setup instructions.**

#### 1. Create a Realm

```bash
# Wait for operator to be ready
kubectl wait --for=condition=available deployment/keycloak-operator \
  -n keycloak-system --timeout=300s
```

#### 2. Deploy a Keycloak Instance

Before creating realms, you need a Keycloak instance. You have two options:

**Option A: Using the chart's built-in Keycloak (Quick Evaluation)**

Set `keycloak.managed: true` during installation:

```yaml
# values-with-keycloak.yaml
keycloak:
  managed: true
  replicas: 1
  version: "26.4.1"
  database:
    type: postgresql
    host: postgres-postgresql.default.svc.cluster.local
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
```

**Option B: Using the Keycloak CRD (Production)**

Deploy Keycloak using the CRD for more control:

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/Keycloak.json
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak-system
spec:
  replicas: 3
  database:
    type: postgresql
    host: postgres-rw
    database: keycloak
    username: keycloak
    passwordSecret:
      name: postgres-password
  ingress:
    enabled: true
    host: keycloak.example.com
    className: nginx
```

See the [Keycloak CRD Reference](../../docs/reference/keycloak-crd.md) for complete configuration options.

> **Database Setup:** You'll need a PostgreSQL database. For production, we recommend [CloudNativePG](https://cloudnative-pg.io/). For evaluation, you can use any PostgreSQL instance.

#### 3. Create Your First Realm

Create a realm using the realm chart:

```bash
# Install realm chart
helm install my-realm keycloak-operator/keycloak-realm \
  --set realmName=my-app \
  --set operatorRef.namespace=keycloak-system \
  --namespace my-team \
  --create-namespace
```

Or using a Custom Resource:

```yaml
# yaml-language-server: $schema=https://vriesdemichael.github.io/keycloak-operator/schemas/v1/KeycloakRealm.json
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-team
spec:
  realmName: my-app
  operatorRef:
    namespace: keycloak-system
      key: token
  security:
    registrationAllowed: false
    resetPasswordAllowed: true
```

### 3. Verify Deployment

```bash
# Check operator status
kubectl get deployment -n keycloak-system
kubectl get pods -n keycloak-system

# Check custom resources
kubectl get keycloak -A
kubectl get keycloakrealm -A
kubectl get keycloakclient -A

# View operator logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
```

## Upgrading

### Upgrade the Chart

```bash
# Upgrade to latest version
helm upgrade keycloak-operator \
  oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --reuse-values
```

### Upgrade with New Values

```bash
helm upgrade keycloak-operator keycloak-operator/keycloak-operator \
  --namespace keycloak-system \
  --reuse-values \
  --set operator.image.tag=v0.3.0
```

### Upgrade from Source

```bash
# Pull latest changes
git pull origin main

# Upgrade the chart
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --namespace keycloak-system \
  --reuse-values
```

## Uninstalling

```bash
# Uninstall the chart
helm uninstall keycloak-operator -n keycloak-system
```

**⚠️ Warning:** If `crds.keep: false`, this will delete all Keycloak instances, realms, and clients managed by the operator!

### Clean Uninstall

To completely remove everything including CRDs:

```bash
# Uninstall chart
helm uninstall keycloak-operator -n keycloak-system

# Delete CRDs (⚠️ deletes all Keycloak resources!)
kubectl delete crd keycloaks.vriesdemichael.github.io
kubectl delete crd keycloakrealms.vriesdemichael.github.io
kubectl delete crd keycloakclients.vriesdemichael.github.io

# Delete namespace
kubectl delete namespace keycloak-system
```

## Troubleshooting

### Operator Pods Not Starting

**Symptom:** Pods stuck in `Pending` or `CrashLoopBackOff`

```bash
# Check pod status
kubectl get pods -n keycloak-system
kubectl describe pod -n keycloak-system -l app.kubernetes.io/name=keycloak-operator

# Check logs
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
```

**Common causes:**
- Image pull errors - verify `operator.imagePullSecrets`
- Resource constraints - check node resources
- RBAC issues - verify `rbac.create: true`

### CRDs Not Installed

**Symptom:** `error: unable to recognize "realm.yaml": no matches for kind "KeycloakRealm"`

```bash
# Check if CRDs are installed
kubectl get crd | grep keycloak

# Reinstall with CRDs
helm upgrade keycloak-operator keycloak-operator/keycloak-operator \
  --set crds.install=true \
  --namespace keycloak-system
```

### Monitoring Not Working

**Symptom:** Prometheus not scraping metrics

```bash
# Check ServiceMonitor
kubectl get servicemonitor -n keycloak-system

# Verify labels match Prometheus selector
kubectl get servicemonitor keycloak-operator -n keycloak-system -o yaml | grep -A5 labels
```

**Solution:** Ensure `monitoring.labels` matches your Prometheus `serviceMonitorSelector`:

```yaml
monitoring:
  enabled: true
  labels:
    prometheus: kube-prometheus  # Must match Prometheus selector
```

### High Resource Usage

**Symptom:** Operator consuming excessive CPU/memory

```bash
# Check resource usage
kubectl top pod -n keycloak-system
```

**Solutions:**
1. Reduce rate limits if managing many resources
2. Increase resource limits
3. Deploy multiple operators for workload distribution

```yaml
operator:
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
  env:
    - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
      value: "30"  # Reduce if needed
```

## Documentation

- **Main Documentation:** https://github.com/vriesdemichael/keycloak-operator
- **Quick Start Guide:** [docs/quickstart/README.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/quickstart/README.md)
- **Security Model:** [docs/security.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/security.md)
- **Architecture:** [docs/architecture.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/architecture.md)
- **Drift Detection:** [docs/drift-detection.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/drift-detection.md)
- **Observability:** [docs/observability.md](https://github.com/vriesdemichael/keycloak-operator/blob/main/docs/observability.md)

## Related Charts

- **[keycloak-realm](../keycloak-realm/README.md)** - Deploy Keycloak realms
- **[keycloak-client](../keycloak-client/README.md)** - Deploy OAuth2/OIDC clients

## Support

- **Issues:** https://github.com/vriesdemichael/keycloak-operator/issues
- **Discussions:** https://github.com/vriesdemichael/keycloak-operator/discussions

## License

MIT License - see [LICENSE](https://github.com/vriesdemichael/keycloak-operator/blob/main/LICENSE) for details.
