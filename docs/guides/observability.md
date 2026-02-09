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

The operator exposes Prometheus metrics on port 8081 at `/metrics`.

### Available Metrics

#### Reconciliation Metrics

```prometheus
# Reconciliation operations counter
keycloak_operator_reconciliation_total{resource_type="keycloak|realm|client", namespace="...", result="success|failure"}

# Reconciliation duration histogram
keycloak_operator_reconciliation_duration_seconds{resource_type="...", namespace="...", operation="reconcile|update|delete"}

# Active resources gauge
keycloak_operator_active_resources{resource_type="...", namespace="...", phase="Ready|Failed|Pending"}
```

#### Resource Status Metrics

```prometheus
# Resource status by phase
keycloak_operator_active_resources{resource_type="keycloak|realm|client", namespace="...", phase="Ready|Failed|Pending"}
```

#### Error Metrics

```prometheus
# Error counter by type
keycloak_operator_reconciliation_errors_total{error_type="...", resource_type="...", namespace="...", retryable="true|false"}
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
      port: 8081
      targetPort: 8081
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

- **Liveness**: HTTP GET on `/healthz` (port 8081)
- **Readiness**: HTTP GET on `/ready` (port 8081)

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

## Distributed Tracing

The Keycloak operator supports OpenTelemetry distributed tracing for end-to-end visibility into reconciliation operations. When enabled, traces are exported to an OTLP collector and can be viewed in tools like Jaeger, Tempo, or any OTEL-compatible backend.

### Enabling Tracing

Configure tracing in your Helm values:

```yaml
operator:
  tracing:
    # Enable OpenTelemetry tracing
    enabled: true

    # OTLP collector endpoint (gRPC protocol)
    # Examples:
    # - "http://otel-collector.monitoring:4317" (in-cluster)
    # - "http://tempo.monitoring:4317" (Grafana Tempo)
    # - "http://jaeger-collector.monitoring:4317" (Jaeger)
    endpoint: "http://otel-collector.monitoring:4317"

    # Service name for traces (identifies the operator)
    serviceName: "keycloak-operator"

    # Trace sampling rate (0.0-1.0)
    # 1.0 = 100% of traces, 0.1 = 10% of traces
    # Lower values reduce overhead in high-throughput environments
    sampleRate: 1.0

    # Use insecure connection to OTLP collector (no TLS)
    insecure: true

    # Propagate tracing to managed Keycloak instances
    # Enables end-to-end distributed tracing
    propagateToKeycloak: true
```

### What Gets Traced

When tracing is enabled, the operator creates spans for:

1. **Kopf Handlers**: Reconciliation operations for Keycloak, KeycloakRealm, and KeycloakClient resources
2. **HTTP Requests**: All outgoing HTTP requests to Keycloak are automatically instrumented
3. **Keycloak API Calls**: Admin API operations include trace context

Each span includes semantic attributes:

```text
k8s.namespace: default
k8s.resource.name: my-keycloak
k8s.resource.type: keycloak
kopf.handler: handle_keycloak_create
```

### End-to-End Tracing with Keycloak

When `propagateToKeycloak: true`, the operator configures managed Keycloak instances to export traces to the same collector. This enables:

- Visibility into Keycloak internal operations (authentication, token issuance)
- Trace correlation between operator reconciliation and Keycloak processing
- Full request lifecycle from operator to Keycloak database

**Requirements**: Keycloak 26.x or later (has built-in OpenTelemetry support via Quarkus)

The Keycloak CR will automatically include:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: example
spec:
  tracing:
    enabled: true
    endpoint: "http://otel-collector.monitoring:4317"
    serviceName: "keycloak"
    sampleRate: 1.0
```

### Viewing Traces

#### Jaeger

```bash
# Port-forward Jaeger UI
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686

# Open in browser: http://localhost:16686
# Search for service: keycloak-operator
```

#### Grafana Tempo

```bash
# Access Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000

# Navigate to Explore > Tempo
# Search by service name: keycloak-operator
```

### Trace Propagation

The operator uses W3C Trace Context (`traceparent` header) for trace propagation. This is automatically added to:

- Keycloak Admin API requests
- Any HTTP requests made via httpx or aiohttp clients

Example trace context header:

```text
traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
```

### Debugging with Traces

Traces are particularly useful for debugging:

1. **Slow Reconciliations**: Identify which Keycloak API calls are slow
2. **Failures**: See the exact sequence of operations before an error
3. **Cross-Service Issues**: Trace requests from operator through Keycloak to database

Example: Finding slow realm reconciliations

1. Search for traces with `service.name = keycloak-operator`
2. Filter by operation: `reconcile_realm`
3. Sort by duration to find outliers
4. Drill into spans to see individual API calls

### Environment Variables

The following environment variables control tracing:

| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_TRACING_ENABLED` | Enable tracing | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | `http://localhost:4317` |
| `OTEL_SERVICE_NAME` | Service name for traces | `keycloak-operator` |
| `OTEL_SAMPLE_RATE` | Sampling rate (0.0-1.0) | `1.0` |
| `OTEL_EXPORTER_OTLP_INSECURE` | Use insecure connection | `true` |
| `OTEL_PROPAGATE_TO_KEYCLOAK` | Propagate to Keycloak | `true` |

### Integration Examples

#### With OpenTelemetry Collector

Deploy the OpenTelemetry Collector to receive and export traces:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
  namespace: monitoring
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317

    processors:
      batch:
        timeout: 1s

    exporters:
      jaeger:
        endpoint: jaeger-collector.monitoring:14250
        tls:
          insecure: true

    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [batch]
          exporters: [jaeger]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      containers:
      - name: collector
        image: otel/opentelemetry-collector-contrib:0.96.0
        ports:
        - containerPort: 4317
          name: otlp-grpc
        volumeMounts:
        - name: config
          mountPath: /etc/otelcol-contrib/config.yaml
          subPath: config.yaml
      volumes:
      - name: config
        configMap:
          name: otel-collector-config
---
apiVersion: v1
kind: Service
metadata:
  name: otel-collector
  namespace: monitoring
spec:
  selector:
    app: otel-collector
  ports:
  - port: 4317
    name: otlp-grpc
```

#### With Grafana Tempo

```yaml
operator:
  tracing:
    enabled: true
    endpoint: "http://tempo.monitoring:4317"
    serviceName: "keycloak-operator"
```

### Performance Considerations

- **Sampling**: For high-throughput environments, reduce `sampleRate` (e.g., 0.1 for 10%)
- **Batch Processing**: The operator uses `BatchSpanProcessor` for efficient trace export
- **Overhead**: With 1.0 sampling, expect ~5-10% overhead on reconciliation time
- **Storage**: Traces consume storage in your backend; configure retention appropriately

## Debugging Test Failures with Traces

The operator's integration test infrastructure includes trace collection for post-mortem debugging of test failures.

### How It Works

1. **OTEL Collector Deployment**: The test cluster includes an OpenTelemetry Collector that writes traces to JSONL files
2. **Test Context Markers**: Each test is logged with `[TRACE_CONTEXT]` markers that include test names and timestamps
3. **Trace Retrieval**: After tests complete, traces are extracted from the collector pod and saved as artifacts

### Analyzing Traces After CI Failures

When integration tests fail in CI:

1. Download the `test-logs-*` artifact from the failed GitHub Actions run
2. Look in `test-logs/traces/` for `traces.jsonl`
3. Use the analysis tool to find relevant traces:

```bash
# Show summary of all traces
python scripts/analyze-trace.py test-logs/traces/traces.jsonl --summary

# Show only error spans
python scripts/analyze-trace.py test-logs/traces/traces.jsonl --errors-only

# Filter by test name
python scripts/analyze-trace.py test-logs/traces/traces.jsonl --filter "test_create_realm"

# Show traces in tree format
python scripts/analyze-trace.py test-logs/traces/traces.jsonl --tree

# Filter by time range (use timestamps from test logs)
python scripts/analyze-trace.py test-logs/traces/traces.jsonl \
    --time-range "2024-01-01T10:00:00" "2024-01-01T10:05:00"
```

### Correlating Traces with Tests

Test logs include markers like:

```
[TRACE_CONTEXT] START tests/integration/test_realm.py::test_create 2024-01-01T10:00:00.123456+00:00
[TRACE_CONTEXT] END tests/integration/test_realm.py::test_create 2024-01-01T10:00:05.654321+00:00 duration=5531ms outcome=passed
```

Use these timestamps with `--time-range` to find traces for specific tests.

### Local Debugging with Traces

When running tests locally with `make test`, traces are collected to `.tmp/traces/`:

```bash
# Run tests
make test

# Analyze traces from the test run
python scripts/analyze-trace.py .tmp/traces/traces.jsonl --summary
python scripts/analyze-trace.py .tmp/traces/traces.jsonl --errors-only
```

### Trace Content

Traces capture:

- **Reconciliation loops**: Start/end of each reconcile operation
- **Keycloak API calls**: HTTP method, endpoint, status code, duration
- **Resource operations**: Create, update, delete of Keycloak resources
- **Errors**: Exception details and stack traces
- **Context**: Namespace, resource name, reconciliation phase
