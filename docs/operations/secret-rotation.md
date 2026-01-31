# Automated Secret Rotation

The Keycloak Operator supports automated rotation of client secrets. This improves security by ensuring that long-lived credentials are automatically refreshed.

!!! warning "Atomic Rotation"
    Keycloak's standard `client-secret` authentication mechanism does not support history or multiple active secrets. Rotation is **atomic**, meaning the old secret is invalidated immediately when the new one is generated.

    You **MUST** use a mechanism like [Stakater Reloader](https://github.com/stakater/Reloader) or [Kyverno](https://kyverno.io/) to trigger an immediate rolling restart of your applications when the secret changes. Without this, your applications will fail authentication until they are restarted.

## Configuration

Secret rotation is configured in the `KeycloakClient` CRD:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: my-client
spec:
  # ... other config ...
  secretRotation:
    enabled: true
    rotationPeriod: "90d"      # e.g., 90d, 24h, 10m
    rotationTime: "03:00"      # Optional: Specific time to rotate (HH:MM)
    timezone: "UTC"            # Optional: Timezone for rotationTime
```

### Fields

| Field | Description | Default |
|-------|-------------|---------|
| `enabled` | Enable automated rotation | `false` |
| `rotationPeriod` | How often to rotate. Supports `s` (seconds), `m` (minutes), `h` (hours), `d` (days). | `90d` |
| `rotationTime` | Target time of day for rotation in `HH:MM` format. The operator will wait until this time on the day of expiration. | None |
| `timezone` | IANA timezone for `rotationTime` calculations. | `UTC` |

## Handling Application Restarts (Zero Downtime)

Since rotation is atomic, your applications must pick up the new secret immediately. Kubernetes Deployments do not automatically restart when a referenced Secret changes. You need an external controller to handle this.

### Option A: Stakater Reloader (Recommended)

[Reloader](https://github.com/stakater/Reloader) watches for changes in ConfigMaps and Secrets and triggers rolling upgrades on Pods.

1. Install Reloader in your cluster.
2. Annotate your **Application Deployment** (not the Secret):

```yaml
kind: Deployment
metadata:
  name: my-app
  annotations:
    reloader.stakater.com/auto: "true"
spec:
  # ...
```

When the Keycloak Operator rotates the secret, Reloader will detect the change and restart `my-app` immediately.

### Option B: Kyverno Policy

If you use [Kyverno](https://kyverno.io/), you can enforce a policy that restarts deployments when their secrets change.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restart-on-secret-change
spec:
  rules:
  - name: watch-secret-changes
    match:
      any:
      - resources:
          kinds:
          - Secret
          selector:
            matchLabels:
              vriesdemichael.github.io/keycloak-secret-type: client-credentials
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
                  ops.keycloak.io/restartedAt: "{{time_now_utc()}}"
```

## How It Works

1. **Initialization:** When a client is created (or rotation is enabled), the operator sets a `keycloak-operator/rotated-at` timestamp annotation on the Kubernetes Secret.
2. **Check:** The operator checks this timestamp on every reconciliation loop.
3. **Trigger:** When `now > rotated_at + rotationPeriod` (and `rotationTime` is reached), rotation triggers.
4. **Action:**
    - The Operator calls Keycloak to regenerate the secret.
    - The Kubernetes Secret is updated with the new value.
    - The `rotated-at` timestamp is updated.
    - **Note:** The previous secret is discarded as it is no longer valid in Keycloak.
