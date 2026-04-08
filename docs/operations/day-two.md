# Day Two Operations

Day-two operations cover the routine and incident-driven work that happens after initial deployment: maintenance windows, controlled pauses, secret sourcing, upgrades, and operational recovery.

The operator is GitOps-first. The goal is not to remove operator control during operations, but to give you explicit levers so human actions and reconciliation do not fight each other.

## Operational Principles

- prefer declarative changes through Helm values or Git-managed manifests
- use pause controls for intentional maintenance windows instead of hoping reconciliations stay quiet
- use external secret systems such as External Secrets Operator or Sealed Secrets when you need GitOps-friendly secret provisioning
- treat raw `kubectl patch` work as a temporary emergency path, not the normal workflow

## Reconciliation Pause

The operator supports per-resource-type reconciliation pause.

When paused:

- create and update reconciliation is skipped
- resource status moves to `Paused`
- the `Ready` condition becomes `False` with reason `ReconciliationPaused`
- delete handlers still run

Configure pause through the operator chart:

```yaml
operator:
  reconciliation:
    pause:
      keycloak: true
      realms: false
      clients: false
      message: "Maintenance window: Keycloak upgrade in progress"
```

Equivalent environment variables:

- `RECONCILE_PAUSE_KEYCLOAK`
- `RECONCILE_PAUSE_REALMS`
- `RECONCILE_PAUSE_CLIENTS`
- `RECONCILE_PAUSE_MESSAGE`

### Pause Side Effects

- client secret rotation daemons pause when client reconciliation is paused
- drift detection continues to run independently
- delete operations are still allowed

Use pause when you need to avoid configuration churn during:

- Keycloak upgrades
- controlled database work
- bulk platform changes
- incident response where you need stable operator behavior

## Maintenance Mode

Maintenance mode is a separate feature from reconciliation pause.

It lives under `keycloak.maintenanceMode` in the operator chart and is meant for blue-green upgrade traffic control.

```yaml
keycloak:
  maintenanceMode:
    enabled: true
    mode: full-block
    excludePaths:
      - /health
      - /health/live
      - /health/ready
      - /health/started
```

Modes:

- `full-block`: returns maintenance responses for normal traffic
- `read-only`: blocks the configured maintenance paths regardless of HTTP method while leaving normal authentication and token endpoints available

By default, `read-only` mode targets the admin console, account console, self-registration, and broker-linking routes. That means existing sessions, login flows, and token exchange endpoints stay available unless you explicitly extend the blocked path list.

Use maintenance mode when you need traffic shaping at the ingress layer. Use reconciliation pause when you need operator quieting. They solve different problems.

## Admin Credentials

Admin credentials use a proxy-secret pattern.

The operator always maintains:

- `<keycloak-name>-admin-credentials`

Keycloak pods consume that proxy secret, regardless of whether credentials are generated or sourced from an existing secret.

There are two different configuration layers here:

- `keycloak.admin.existingSecret` is the managed-Keycloak input. It tells the operator where to source the admin username and password for the managed `Keycloak` CR.
- `keycloak.adminSecret` plus `keycloak.adminPasswordKey` are the operator's own connection settings. In managed mode they normally point at the generated proxy secret; in external mode they must point at the external Keycloak admin password secret.

### Generated Mode

If you do not provide an explicit secret, the operator generates credentials and annotates the proxy secret with:

- `vriesdemichael.github.io/credential-source: generated`
- `vriesdemichael.github.io/rotation-enabled: "true"`

### External Secret Mode

The operator chart exposes the managed-Keycloak source secret through `keycloak.admin.existingSecret`:

```yaml
keycloak:
  admin:
    existingSecret: my-custom-admin-secret
```

Requirements for the referenced secret:

- same namespace as the `Keycloak`
- contains `username` and `password` keys

In this mode the operator:

- validates the referenced secret
- copies its contents into `<name>-admin-credentials`
- annotates the proxy secret with:
  - `vriesdemichael.github.io/credential-source: external:<secret-name>`
  - `vriesdemichael.github.io/rotation-enabled: "false"`
- never rotates or overwrites the source secret itself

## Database Tier Awareness

Day-two behavior depends on the database tier behind the Keycloak instance.

### CNPG

- operator can resolve the database connection from the CNPG cluster reference
- CNPG-native backup workflows integrate cleanly with operator-driven operations
- best fit for fully managed GitOps environments

### Managed Database

- operator uses explicit connection details from the spec
- storage lifecycle is outside operator control
- upgrade and restore planning must account for the external database service

### External Database

- fully operator-external lifecycle
- operator can validate connectivity, but backup and restore remain your responsibility
- treat upgrade, restore, and failover procedures as platform-runbook concerns
- pair this with a documented backup and restore process before attempting Keycloak upgrades or manual recovery

## Recommended Operational Workflow

For planned maintenance:

1. enable reconciliation pause for the affected resource types
2. enable maintenance mode if you must gate user traffic during the operation
3. execute the infrastructure or Keycloak change
4. verify status, metrics, and endpoints
5. disable maintenance mode and pause controls

## See Also

- [Backup & Restore](./backup-restore.md)
- [Secret Management](./secret-management.md)
- [Migration](./migration.md)
- [Escape Hatch](./escape-hatch.md)
