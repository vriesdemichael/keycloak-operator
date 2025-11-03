# Keycloak Operator Helm Chart

Official Helm chart for deploying the Keycloak Operator - a Kubernetes operator for managing Keycloak instances, realms, and OAuth2/OIDC clients with full GitOps compatibility.

## Overview

This chart installs the Keycloak Operator which enables declarative management of:
- **Keycloak instances** - Deploy and configure Keycloak servers
- **Keycloak realms** - Identity domains with users, roles, and authentication settings
- **Keycloak clients** - OAuth2/OIDC applications with automated credential management

**Target Users:** Platform administrators and cluster operators who want to provide Keycloak-as-a-Service to development teams.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.8+
- (Optional) [CloudNativePG operator](https://cloudnative-pg.io/) for managed PostgreSQL databases
- (Optional) Prometheus Operator for monitoring
- (Optional) Grafana for dashboards

## Installation

### Quick Start

```bash
# Add the Helm repository
helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator
helm repo update

# Install the operator
helm install keycloak-operator keycloak-operator/keycloak-operator \
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
| `operator.createAdmissionToken` | Create admission token for namespace bootstrapping | `true` |
| `operator.admissionTokenName` | Name of the admission token secret | `keycloak-operator-auth-token` |
| `operator.admissionToken` | Token value (auto-generated if empty) | `""` |
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

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keycloak.enabled` | Deploy a Keycloak instance | `false` |
| `keycloak.name` | Keycloak instance name | `keycloak` |
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
| `keycloak.admin.username` | Admin username | `admin` |
| `keycloak.admin.passwordSecret.name` | Secret containing admin password | `keycloak-admin-password` |
| `keycloak.admin.passwordSecret.key` | Key in secret | `password` |
| `keycloak.ingress.enabled` | Enable ingress | `false` |
| `keycloak.ingress.className` | Ingress class name | `""` |
| `keycloak.ingress.annotations` | Ingress annotations | `{}` |
| `keycloak.ingress.hosts` | Ingress hosts | See [values.yaml](values.yaml) |
| `keycloak.ingress.tls` | Ingress TLS configuration | `[]` |
| `keycloak.resources` | Keycloak resource limits/requests | See [values.yaml](values.yaml) |

**Example:** Deploy Keycloak with CloudNativePG:

```yaml
keycloak:
  enabled: true
  replicas: 3
  version: "26.4.1"
  database:
    type: postgresql
    cnpg:
      enabled: true
      clusterName: keycloak-postgres
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
  enabled: true
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
    hosts:
      - host: keycloak.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: keycloak-tls
        hosts:
          - keycloak.example.com
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
  admissionTokenName: keycloak-operator-prod-auth

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

### 1. Retrieve the Operator Token

After installation, get the admission token for creating realms:

```bash
# Wait for operator to be ready
kubectl wait --for=condition=available deployment/keycloak-operator \
  -n keycloak-system --timeout=300s

# Get the admission token
kubectl get secret keycloak-operator-auth-token \
  -n keycloak-system \
  -o jsonpath='{.data.token}' | base64 -d

# Or export to variable
OPERATOR_TOKEN=$(kubectl get secret keycloak-operator-auth-token \
  -n keycloak-system \
  -o jsonpath='{.data.token}' | base64 -d)

echo $OPERATOR_TOKEN
```

### 2. Create Your First Realm

Use the operator token to create a realm:

```bash
# Install realm chart
helm install my-realm keycloak-operator/keycloak-realm \
  --set realmName=my-app \
  --set operatorRef.namespace=keycloak-system \
  --set operatorRef.authorizationSecretRef.name=keycloak-operator-auth-token \
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
    authorizationSecretRef:
      name: admission-token-my-team  # First realm uses admission token
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
# Update Helm repository
helm repo update

# Upgrade to latest version
helm upgrade keycloak-operator keycloak-operator/keycloak-operator \
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

### Admission Token Not Created

**Symptom:** Secret `keycloak-operator-auth-token` doesn't exist

```bash
# Check secret
kubectl get secret keycloak-operator-auth-token -n keycloak-system

# Verify configuration
helm get values keycloak-operator -n keycloak-system | grep -A5 operator

# Reinstall with token creation enabled
helm upgrade keycloak-operator keycloak-operator/keycloak-operator \
  --set operator.createAdmissionToken=true \
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
