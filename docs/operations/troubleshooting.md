# Troubleshooting Guide

This guide focuses on practical diagnosis of operator, Keycloak, realm, and client issues using the current implementation contracts.

Use Helm values and normal reconciliation flows as the primary fix path. Raw `kubectl patch` commands are useful as temporary diagnostics, not as the steady-state operating model.

!!! tip "Recovering from a failure or data loss?"
    See the [Disaster Recovery](./disaster-recovery.md) guide for recovery order, what you actually lose without a database restore, and common recovery scenarios.

## Quick Diagnostics

```bash
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
kubectl get pods -n keycloak-system
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | tail -20
```

## Understand The Status You Are Seeing

Common phases across the operator include:

- `Pending`
- `Provisioning`
- `Reconciling`
- `Ready`
- `Degraded`
- `Updating`
- `Failed`
- `Paused`

Additional upgrade progress for managed Keycloak instances may appear under `status.blueGreen`, including states such as `BackingUp`.

Practical interpretation:

- `Pending`, `Provisioning`, and `Reconciling` usually mean the operator is still working
- `Degraded` means the resource is running but needs attention
- `Failed` means the current reconciliation path hit a terminal problem
- `Paused` means operator configuration intentionally suspended reconciliation

## Version And Port Confusion

Supported Keycloak versions start at `24.x`.

Important port split:

- Keycloak `24.x` uses `8080` for health handling
- Keycloak `25.x+` exposes the separate management interface on `9000`
- operator metrics are on the operator pod, typically `8081`

Treat `9000` as version-conditional. On `24.x`, health and management behavior still lives on `8080`.

## Admin Credentials Secret Lifecycle

Managed Keycloak instances use a proxy secret named:

- `<keycloak-name>-admin-credentials`

That secret always contains:

- `username`
- `password`

The operator reads from that proxy secret when it needs to authenticate to Keycloak.

If `keycloak.admin.existingSecret` is configured, the operator copies the source secret into the proxy secret and marks it as externally sourced. Otherwise it generates credentials itself.

## Operator Issues

### Symptom: Operator Pods Are Restarting Or Failing Readiness

Check:

```bash
kubectl get pods -n keycloak-system
kubectl describe pod -n keycloak-system <pod-name>
kubectl logs -n keycloak-system <pod-name> --previous
```

Common causes:

- resource pressure or OOMKilled restarts
- missing RBAC
- bad image configuration
- cluster API or webhook startup issues

## Keycloak Instance Issues

## Symptom: Operator Not Reconciling A Resource

Check:

```bash
kubectl describe keycloakrealm <name> -n <namespace>
kubectl get keycloakrealm <name> -n <namespace> -o yaml
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep '<namespace>'
```

Common causes:

- bad `operatorRef`
- namespace not actually authorized by the referenced realm
- admission validation failure
- reconciliation pause enabled for that resource type

## Symptom: Keycloak Pod Fails Health Checks

Check the version first.

```bash
kubectl get keycloak <name> -n <namespace> -o jsonpath='{.spec.image}{"\n"}'
kubectl logs -n <namespace> <keycloak-pod> --tail=100
```

If the deployment expects `9000` on a `24.x` image, you are debugging stale assumptions, not a real platform bug.

### Symptom: Realm Stuck In Pending/Provisioning

Check:

```bash
kubectl describe keycloakrealm <name> -n <namespace>
kubectl get keycloakrealm <name> -n <namespace> -o yaml
kubectl get keycloak <name> -n <namespace>
```

Common causes:

- the referenced Keycloak instance is still provisioning
- `operatorRef` points at the wrong namespace or instance
- the realm is blocked on authorization or validation before first reconcile

## Authorization Issues

### Symptom: Namespace Grant Looks Correct But Client Creation Still Fails

Check the realm-side grant list directly:

```bash
kubectl get keycloakrealm <realm-name> -n <realm-namespace> \
  -o jsonpath='{.spec.clientAuthorizationGrants}' | jq

kubectl get keycloakclient <client-name> -n <client-namespace> \
  -o jsonpath='{.status.authorizationGranted}{"\n"}{.status.authorizationMessage}{"\n"}'
```

Things to verify:

- the client namespace is present in `spec.clientAuthorizationGrants`
- the `realmRef` points at the realm you actually intended
- the realm and client namespaces are not being confused
- the realm’s `operatorRef` points at the correct operator-managed Keycloak

This operator authorizes client creation through Kubernetes RBAC plus realm-managed namespace grants. A valid ServiceAccount alone is not enough if the realm grant list does not include the client namespace.

## Client Issues

## Symptom: Manual Admin Console Changes Keep Disappearing

That is usually normal drift correction.

Direct UI access is not technically impossible, but it is the wrong source of truth for managed configuration. If you change realms or clients manually in the admin console, the operator may reconcile them back to the CR spec.

Use the CRs or Helm values instead.

## Symptom: Client Credentials Stop Working After Rotation

Check:

```bash
kubectl get secret <client-secret-name> -n <namespace> -o yaml
kubectl get keycloakclient <name> -n <namespace> -o jsonpath='{.status.lastSecretRotation}{"\n"}'
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator | grep rotation
```

Likely cause:

- the workload did not restart or reload after atomic secret rotation

Fix the restart coordination, usually with Reloader or an equivalent policy.

## Symptom: Rate Limiting Or Slow Reconciliation

Inspect the operator’s metrics endpoint, not the managed Keycloak pod:

```bash
kubectl exec -n keycloak-system deploy/keycloak-operator -- \
  curl -s localhost:8081/metrics | grep rate_limit
```

If you need to adjust rate limits, change the chart values under:

- `operator.rateLimiting.global.*`
- `operator.rateLimiting.namespace.*`
- `operator.reconciliation.jitterMaxSeconds`

Then upgrade the chart instead of injecting ad hoc env var overrides.

## Symptom: Host-Side Access To Keycloak Fails

Tests and local debugging from the host often require port forwarding because cluster-internal DNS names are not resolvable from your laptop or WSL host.

Use:

```bash
kubectl port-forward -n <namespace> svc/<keycloak-service> 8080:8080
```

Then hit `http://localhost:8080` locally.

## Symptom: Authorization Looks Correct But Clients Still Fail

Check all of these together:

- the `KeycloakClient.spec.realmRef`
- the target realm’s namespace authorization configuration
- the realm’s `spec.clientAuthorizationGrants`
- the `operatorRef` on the realm or Keycloak instance
- whether the client namespace and realm namespace are actually the ones you think they are

Cross-namespace mistakes are common and look deceptively similar to permission bugs.

## See Also

- [Day Two Operations](./day-two.md)
- [Observability](../guides/observability.md)
- [Multi-Tenant](../how-to/multi-tenant.md)
- [Keycloak Version Support](../reference/keycloak-version-support.md)
