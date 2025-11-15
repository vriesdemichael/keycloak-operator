# Observability

This document describes the observability features available in the Keycloak operator, including status conditions, metrics, and monitoring capabilities.

## Status Conditions

All custom resources (Keycloak, KeycloakRealm, KeycloakClient) expose Kubernetes-standard status conditions that can be used by GitOps tools like Argo CD and Flux CD to determine resource health.

### Standard Conditions

Each resource implements the following condition types:

#### Ready
Indicates whether the resource is fully reconciled and operational.

- **Status**: `True`, `False`, or `Unknown`
- **Reason**: `ReconciliationSucceeded`, `ReconciliationFailed`, `ReconciliationInProgress`
- **Usage**: Primary health indicator for GitOps tools

#### Available
Indicates whether the resource is available for use (Kubernetes standard).

- **Status**: `True` or `False`
- **Reason**: `ReconciliationSucceeded`, `ReconciliationFailed`
- **Usage**: Determines if the resource can serve its purpose

#### Progressing
Indicates an ongoing reconciliation operation (Kubernetes standard).

- **Status**: `True` or `False`
- **Reason**: `ReconciliationInProgress`
- **Usage**: Shows active reconciliation work

#### Degraded
Indicates the resource is operational but not in optimal state.

- **Status**: `True` or `False`
- **Reason**: `PartialFunctionality`, `ReconciliationFailed`
- **Usage**: Alerts about suboptimal conditions

### Checking Resource Status

View the status of a resource:

```bash
# Get resource with status
kubectl get keycloak my-keycloak -o yaml

# Check conditions specifically
kubectl get keycloak my-keycloak -o jsonpath='{.status.conditions}' | jq

# Check if a resource is ready
kubectl get keycloak my-keycloak -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
```

### Example Status Output

```yaml
status:
  phase: Ready
  message: Keycloak instance is ready
  lastUpdated: "2025-10-15T20:00:00Z"
  observedGeneration: 5
  conditions:
    - type: Ready
      status: "True"
      reason: ReconciliationSucceeded
      message: Reconciliation completed successfully
      lastTransitionTime: "2025-10-15T20:00:00Z"
      observedGeneration: 5
    - type: Available
      status: "True"
      reason: ReconciliationSucceeded
      message: Resource is available
      lastTransitionTime: "2025-10-15T20:00:00Z"
      observedGeneration: 5
  deployment: my-keycloak-keycloak
  service: my-keycloak-keycloak
  endpoints:
    admin: http://my-keycloak-keycloak.default.svc.cluster.local:8080
    public: http://my-keycloak-keycloak.default.svc.cluster.local:8080
    management: http://my-keycloak-keycloak.default.svc.cluster.local:9000
```

## ObservedGeneration

All resources track `observedGeneration` which indicates the generation of the spec that was last reconciled. This is crucial for GitOps workflows:

- **Match**: When `status.observedGeneration` equals `metadata.generation`, the resource is fully reconciled
- **Mismatch**: When they differ, reconciliation is pending or in progress
- **Usage**: GitOps tools use this to detect drift and sync status

Example check:

```bash
# Check if resource is fully synced
kubectl get keycloak my-keycloak -o json | \
  jq 'if .status.observedGeneration == .metadata.generation then "Synced" else "OutOfSync" end'
```

## Resource-Specific Status Fields

### Keycloak Status

```yaml
status:
  deployment: my-keycloak-keycloak  # Name of the deployment
  service: my-keycloak-keycloak      # Name of the service
  adminSecret: my-keycloak-admin-credentials  # Admin credentials secret
  endpoints:
    admin: http://...    # Admin API endpoint
    public: http://...   # Public endpoint
    management: http://... # Management endpoint (health checks)
```

### KeycloakRealm Status

```yaml
status:
  realmName: my-realm  # Actual realm name in Keycloak
  keycloakInstance: default/keycloak  # Referenced Keycloak instance
  features:
    userRegistration: true
    passwordReset: true
    identityProviders: 2
    userFederationProviders: 1
    customThemes: true
```

### KeycloakClient Status

```yaml
status:
  client_id: my-client  # Client ID
  client_uuid: abc-123  # UUID in Keycloak
  realm: my-realm  # Realm name
  keycloak_instance: default/keycloak  # Keycloak instance reference
  credentials_secret: my-client-credentials  # Client credentials secret
  public_client: false  # Whether this is a public client
  endpoints:
    auth: https://keycloak.example.com/realms/my-realm
    token: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token
    userinfo: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/userinfo
```

## Prometheus Metrics

The operator exposes Prometheus metrics on port 8080 at `/metrics`.

### Available Metrics

#### Reconciliation Metrics

```prometheus
# Reconciliation operations counter
kopf_reconciliation_total{resource_type="keycloak|realm|client", namespace="...", name="...", operation="reconcile|update|delete"}

# Reconciliation duration histogram
kopf_reconciliation_duration_seconds{resource_type="...", namespace="...", name="...", operation="..."}

# Active reconciliations gauge
kopf_reconciliation_active{resource_type="...", namespace="...", operation="..."}
```

#### Resource Status Metrics

```prometheus
# Resource status by phase
keycloak_operator_resource_status{resource_type="keycloak|realm|client", namespace="...", phase="Ready|Failed|Pending"}
```

#### Error Metrics

```prometheus
# Error counter by type
keycloak_operator_errors_total{error_type="...", resource_type="...", namespace="..."}
```

### Scraping Metrics

Configure Prometheus to scrape the operator:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: keycloak-operator-metrics
  labels:
    app: keycloak-operator
spec:
  ports:
    - name: metrics
      port: 8080
      targetPort: 8080
  selector:
    app: keycloak-operator
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: keycloak-operator
spec:
  selector:
    matchLabels:
      app: keycloak-operator
  endpoints:
    - port: metrics
      interval: 30s
```

## Logging

The operator uses structured logging with correlation IDs for request tracing.

### Log Levels

- **DEBUG**: Detailed operational information
- **INFO**: General operational messages
- **WARNING**: Warning conditions (degraded but functioning)
- **ERROR**: Error conditions requiring attention

### Viewing Logs

```bash
# Follow operator logs
kubectl logs -f -l app=keycloak-operator -n keycloak-operator-system

# View logs with correlation ID
kubectl logs -l app=keycloak-operator -n keycloak-operator-system | grep "correlation_id=abc-123"

# Check reconciliation logs for specific resource
kubectl logs -l app=keycloak-operator -n keycloak-operator-system | \
  grep "resource_name=my-keycloak"
```

### Log Format

Logs include structured fields:

```json
{
  "timestamp": "2025-10-15T20:00:00Z",
  "level": "INFO",
  "logger": "KeycloakReconciler",
  "message": "Reconciliation completed successfully",
  "resource_type": "keycloak",
  "resource_name": "my-keycloak",
  "namespace": "default",
  "correlation_id": "abc-123",
  "duration": 2.5
}
```

## Health Checks

The operator pod exposes health endpoints:

- **Liveness**: HTTP GET on `/healthz` (port 8080)
- **Readiness**: HTTP GET on `/ready` (port 8080)

## GitOps Integration

### Argo CD Health Assessment

Argo CD automatically uses the `Ready` condition to determine resource health:

```yaml
# Argo CD will show:
# - Healthy: Ready=True
# - Progressing: Progressing=True or observedGeneration mismatch
# - Degraded: Ready=False or Degraded=True
```

### Flux CD Health Assessment

Flux CD checks the `Ready` condition and `observedGeneration`:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: keycloak-resources
spec:
  healthChecks:
    - apiVersion: vriesdemichael.github.io/v1
      kind: Keycloak
      name: my-keycloak
      namespace: default
```

## Circuit Breaker Status

The operator uses a circuit breaker to protect the Keycloak API from overload. When the circuit breaker opens:

1. The operator logs: `Circuit breaker open for Keycloak at http://...`
2. API calls return HTTP 503 (Service Unavailable)
3. Reconciliation is retried with exponential backoff
4. The circuit resets after 60 seconds of no failures

Check circuit breaker state in logs:

```bash
kubectl logs -l app=keycloak-operator | grep "circuit breaker"
```

## Troubleshooting with Status

### Resource Stuck in Pending

```bash
# Check status conditions
kubectl describe keycloak my-keycloak

# Look for the message in status
kubectl get keycloak my-keycloak -o jsonpath='{.status.message}'

# Check if generation matches (sync status)
kubectl get keycloak my-keycloak -o json | \
  jq '{generation: .metadata.generation, observedGeneration: .status.observedGeneration}'
```

### Reconciliation Failures

```bash
# Check Ready condition for reason
kubectl get keycloak my-keycloak -o json | \
  jq '.status.conditions[] | select(.type=="Ready")'

# View recent events
kubectl get events --field-selector involvedObject.name=my-keycloak

# Check operator logs for this resource
kubectl logs -l app=keycloak-operator | grep "resource_name=my-keycloak"
```

### Performance Issues

```bash
# Query Prometheus for slow reconciliations
histogram_quantile(0.95,
  rate(kopf_reconciliation_duration_seconds_bucket[5m])
) by (resource_type)

# Check active reconciliation count
kopf_reconciliation_active
```
