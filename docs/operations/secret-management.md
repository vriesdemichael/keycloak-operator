# Secret Management

This guide covers generated client credentials, manual client secret binding, automated rotation, and GitOps-friendly secret provisioning.

Use the Helm charts as the primary configuration path. Direct CR edits still work, but they are the advanced path.

## What The Operator Manages

For confidential `KeycloakClient` resources, the operator can create and maintain a Kubernetes Secret named:

- `<client-name>-credentials` by default
- `secretName` if you set one explicitly

The managed client credentials secret contains:

- `client-id`
- `client-secret` for confidential clients
- `keycloak-url`
- `realm`
- `token-endpoint`
- `userinfo-endpoint`
- `jwks-endpoint`
- `issuer`

Applications should consume that Secret directly from the cluster instead of copying values into Git-managed manifests.

## Helm-First Configuration

The `keycloak-client` chart is the primary entry point.

### Generated Client Credentials

```yaml
manageSecret: true
secretName: my-app-oidc
secretRotation:
  enabled: true
  rotationPeriod: 90d
  rotationTime: "03:00"
  timezone: UTC
```

This renders a `KeycloakClient` that lets the operator generate the secret and rotate it on schedule.

### Manual Existing Secret Binding

If the client secret already exists outside the operator, bind it explicitly:

```yaml
clientSecret:
  name: my-precreated-client-secret
  key: client-secret
```

Important constraints:

- `clientSecret` and `secretRotation.enabled=true` cannot be used together
- `clientSecret` cannot be used for public clients
- the referenced secret must live in the same namespace as the `KeycloakClient`

The chart already enforces the first rule by omitting the rendered `secretRotation` block when `clientSecret.name` is set.

## Automated Rotation

Automated client secret rotation is atomic.

When Keycloak rotates a standard client secret, the previous secret becomes invalid immediately. There is no built-in secret history or overlap window.

Rotation is configured on the client resource:

```yaml
secretRotation:
  enabled: true
  rotationPeriod: 90d
  rotationTime: "03:00"
  timezone: UTC
```

Field semantics:

- `rotationPeriod` accepts `s`, `m`, `h`, and `d` units
- `rotationTime` is optional and uses `HH:MM` format
- `timezone` uses IANA timezone names such as `UTC` or `Europe/Amsterdam`

The operator stores the last successful rotation timestamp in two places:

- Secret annotation `keycloak-operator/rotated-at`
- `KeycloakClient.status.lastSecretRotation`

The rotation daemon recalculates the next run from that timestamp, so pod restarts do not lose schedule state.

### Rotation Failure Behavior

If rotation fails, the daemon retries with backoff and records rotation error metrics.

Rotation only runs while the client remains operational. If client reconciliation is paused at the operator level, the rotation daemon pauses too.

## Restart Coordination

Because rotation is atomic, workloads that use the secret must reload it quickly.

### Stakater Reloader

This is the simplest pattern for most clusters.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    reloader.stakater.com/auto: "true"
spec:
  template:
    spec:
      containers:
        - name: my-app
          env:
            - name: CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: my-app-oidc
                  key: client-id
            - name: CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: my-app-oidc
                  key: client-secret
```

### Kyverno Restart Policy

If you standardize on Kyverno, mutate workloads when the managed credentials secret changes.

Target the actual operator-managed secret label contract.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restart-on-keycloak-client-secret-change
spec:
  rules:
    - name: restart-deployments-using-rotated-client-secret
      match:
        any:
          - resources:
              kinds:
                - Secret
              selector:
                matchLabels:
                  vriesdemichael.github.io/keycloak-component: client-credentials
      mutate:
        targets:
          - apiVersion: apps/v1
            kind: Deployment
        context:
          - name: deployments
            apiCall:
              urlPath: "/apis/apps/v1/namespaces/{{request.object.metadata.namespace}}/deployments"
              jmesPath: "items[?spec.template.spec.containers[].env[].valueFrom.secretKeyRef.name.contains(@, '{{request.object.metadata.name}}')]"
        foreach:
          - list: "deployments"
            patchStrategicMerge:
              spec:
                template:
                  metadata:
                    annotations:
                      ops.keycloak.io/restartedAt: "{{ time_now_utc() }}"
```

## Provisioning Secrets With GitOps Tools

### External Secrets Operator

Use ESO when the source of truth for a secret lives in Vault, AWS Secrets Manager, 1Password, or another external backend.

Typical pattern:

1. ESO materializes the secret into the application namespace.
2. The `KeycloakClient` references that secret through `clientSecret` for manual binding, or the application references the operator-managed credentials secret.
3. The application deployment reloads when the effective secret changes.

### Sealed Secrets

Use Sealed Secrets when you want Git-stored encrypted manifests that are decrypted in-cluster.

This works well for:

- pre-created `clientSecret` values
- application-side credentials or sidecar configuration
- admin/bootstrap secrets for managed `Keycloak` instances

## Operator Read-Access Label

Some secret references across the operator require explicit opt-in so the operator may read them safely. Where that applies, label the secret with:

```yaml
metadata:
  labels:
    vriesdemichael.github.io/keycloak-allow-operator-read: "true"
```

That label is especially relevant for secret references used by realm features such as SMTP, identity providers, and user federation.

## Operational Notes

- secret rotation is only meaningful for confidential clients
- manual `clientSecret` binding is the right choice when another secret system owns the credential lifecycle
- generated credentials plus rotation are the right choice when the operator owns the client lifecycle end to end
- application restart automation is mandatory if you enable rotation
- if you use Kyverno or another policy engine, match the real client-credentials secret labels instead of inventing a separate secret type label

## See Also

- [Day Two Operations](./day-two.md)
- [Backup & Restore](./backup-restore.md)
- the `charts/keycloak-client` README for chart-specific values details
