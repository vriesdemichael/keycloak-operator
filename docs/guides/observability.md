# Observability

This guide covers status reporting, metrics, health endpoints, logging, and tracing for the Keycloak operator.

## Status Conditions and Phases

All primary resources expose Kubernetes-style conditions and an operator phase.

Common condition types:

- `Ready`
- `Available`
- `Progressing`
- `Degraded`

Common reasons include:

- `ReconciliationSucceeded`
- `ReconciliationFailed`
- `ReconciliationInProgress`
- `ReconciliationPaused`

Common phases you will see in practice:

- `Pending`
- `Reconciling`
- `Ready`
- `Degraded`
- `Failed`
- `Updating`
- `Paused`

## Observed Generation

`status.observedGeneration` tells you which spec generation the operator has processed.

- when it matches `metadata.generation`, the resource has been reconciled against the latest spec
- when it does not match, reconciliation is still pending or in progress

Example:

```bash
kubectl get keycloak my-keycloak -o json | jq '{generation: .metadata.generation, observedGeneration: .status.observedGeneration}'
```

## Resource-Specific Status Fields

### Keycloak

`Keycloak.status` includes fields such as:

```yaml
status:
  phase: Ready
  deployment: my-keycloak-keycloak
  service: my-keycloak-keycloak
  adminSecret: my-keycloak-admin-credentials
  endpoints:
    admin: http://my-keycloak-keycloak.default.svc.cluster.local:8080
    public: http://my-keycloak-keycloak.default.svc.cluster.local:8080
    management: http://my-keycloak-keycloak.default.svc.cluster.local:9000
```

Notes:

- `management` is present only when the Keycloak version supports the separate management port.
- Keycloak 24.x uses port `8080` for health endpoints.
- Keycloak 25.x and later use port `9000` for the management interface.

### KeycloakRealm

`KeycloakRealm.status` includes:

- `realmName`
- `keycloakInstance`
- `features`
- `endpoints`
- `userFederationStatus`

The realm reconciler also populates standard OIDC endpoints in status when it can resolve the Keycloak base URL.

### KeycloakClient

`KeycloakClient.status` includes:

```yaml
status:
  phase: Ready
  clientId: my-client
  internalId: 12345678-1234-1234-1234-123456789abc
  realm: my-realm
  keycloakInstance: default/my-keycloak
  credentialsSecret: my-client-credentials
  authorizationGranted: true
  endpoints:
    issuer: https://keycloak.example.com/realms/my-realm
    auth: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/auth
    token: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token
    userinfo: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/userinfo
    jwks: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/certs
    endSession: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/logout
```

## Metrics Endpoint

The operator pod exposes its own health and metrics server on:

- host: `METRICS_HOST` or `0.0.0.0`
- port: `METRICS_PORT` or `8081`

Endpoints:

- `/metrics`
- `/healthz`
- `/ready`

This endpoint belongs to the operator deployment and is what the chart's `ServiceMonitor` scrapes when `monitoring.enabled=true`.

Do not confuse the operator metrics port `8081` with the managed Keycloak management port `9000`. Keycloak application metrics and management endpoints are separate from the operator's `/metrics` endpoint.

## Prometheus Metrics

### Reconciliation

```prometheus
keycloak_operator_reconciliation_total{resource_type,namespace,result}
keycloak_operator_reconciliation_duration_seconds{resource_type,namespace,operation}
keycloak_operator_reconciliation_errors_total{resource_type,namespace,error_type,retryable}
keycloak_operator_reconciliation_skipped_total{resource_type,namespace}
keycloak_operator_active_resources{resource_type,namespace,phase}
```

### Database and API Protection

```prometheus
keycloak_operator_database_connection_status{namespace,database_type}
keycloak_operator_database_connection_duration_seconds{namespace,database_type}
keycloak_operator_api_rate_limit_wait_seconds{namespace,limit_type}
keycloak_operator_api_rate_limit_acquired_total{namespace,limit_type}
keycloak_operator_api_rate_limit_timeouts_total{namespace,limit_type}
keycloak_operator_api_rate_limit_budget_available{namespace}
keycloak_operator_circuit_breaker_state{keycloak_instance,keycloak_namespace}
```

### Drift Detection and Federation

```prometheus
keycloak_operator_orphaned_resources{resource_type,operator_instance}
keycloak_operator_config_drift{resource_type,cr_namespace}
keycloak_operator_unmanaged_resources{resource_type}
keycloak_operator_drift_check_duration_seconds{resource_type}
keycloak_operator_drift_check_errors_total{resource_type}
keycloak_operator_drift_check_last_success_timestamp
keycloak_operator_user_federation_status{realm,provider_id}
```

### Secret Rotation

```prometheus
keycloak_operator_secret_rotation_total{namespace,result}
keycloak_operator_secret_rotation_errors_total{namespace}
```

## Real Prometheus Queries

Slow reconciliations:

```prometheus
histogram_quantile(0.95, sum by (le, resource_type) (rate(keycloak_operator_reconciliation_duration_seconds_bucket[5m])))
```

Failed reconciliations:

```prometheus
sum by (resource_type, namespace) (increase(keycloak_operator_reconciliation_errors_total[5m]))
```

Open circuit breakers:

```prometheus
keycloak_operator_circuit_breaker_state == 1
```

Disconnected federation providers:

```prometheus
keycloak_operator_user_federation_status == 0
```

## Logging

The operator supports structured logging and selective noise reduction.

Useful settings include:

- `LOG_LEVEL`
- `JSON_LOGS`
- `CORRELATION_IDS`
- `LOG_HEALTH_PROBES`
- `WEBHOOK_LOG_LEVEL`

Example:

```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator
```

## Tracing

Tracing is configured through the operator chart under `operator.tracing`.

```yaml
operator:
  tracing:
    enabled: true
    endpoint: http://otel-collector.monitoring:4317
    serviceName: keycloak-operator
    sampleRate: 1.0
    insecure: true
    propagateToKeycloak: true
```

Key points:

- `insecure` defaults to `false`
- set `insecure: true` only for local development or when TLS is terminated elsewhere
- `propagateToKeycloak: true` tells the chart to render a `spec.tracing` block into the managed `Keycloak` CR so Keycloak exports traces to the same collector
- the propagated Keycloak tracing configuration uses the same collector endpoint and sample rate, but Keycloak reports as its own service rather than as the operator
- `propagateToKeycloak: true` only works for chart-managed Keycloak instances and only when the managed Keycloak version supports built-in tracing
- built-in Keycloak tracing requires Keycloak `26.0.0+`

With propagation enabled, the operator and the managed Keycloak pods can participate in the same distributed trace across reconciliation work, ingress traffic, and Keycloak request handling.

Environment variables:

- `OTEL_TRACING_ENABLED`
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_SERVICE_NAME`
- `OTEL_SAMPLE_RATE`
- `OTEL_EXPORTER_OTLP_INSECURE`
- `OTEL_PROPAGATE_TO_KEYCLOAK`

## Monitoring Setup

The operator chart can create a `ServiceMonitor` when `monitoring.enabled=true`.

```yaml
monitoring:
  enabled: true
  interval: 30s
  scrapeTimeout: 10s
```

## Troubleshooting

### Resource stuck in `Paused`

Check whether operator pause controls are enabled for that resource type.

### Missing management endpoint

This is normal for Keycloak 24.x. The separate management port exists only for 25.x and later.

### Trace propagation not working end-to-end

- verify the operator tracing config
- verify `propagateToKeycloak: true` is set when you expect the managed Keycloak pods to emit traces too
- verify Keycloak version is `26.0.0+`
- verify collector reachability from both operator and Keycloak pods

## See Also

- [Drift Detection](./drift-detection.md)
- [Keycloak Version Support](../reference/keycloak-version-support.md)
- [Troubleshooting](../operations/troubleshooting.md)
