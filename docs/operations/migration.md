# Migration & Upgrade Guide

This guide covers operator upgrades, managed Keycloak upgrades, and migration guidance for users coming from other Keycloak deployment models.

For supported Keycloak versions, use [Keycloak Version Support](../reference/keycloak-version-support.md) as the single source of truth.

!!! tip "Recovering from a complete failure?"
    See the [Disaster Recovery](./disaster-recovery.md) guide for recovery order and what survives a database loss without a restore.

## Upgrade The Operator

Helm is the primary upgrade path.

```bash
helm upgrade keycloak-operator \
  oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
  --namespace keycloak-system \
  --values operator-values.yaml \
  --version <chart-version> \
  --wait
```

Before upgrading:

- export current CRs
- save the current Helm values
- review the release notes
- test the change outside production first

After upgrading:

- verify operator pods are healthy
- verify managed `Keycloak`, `KeycloakRealm`, and `KeycloakClient` resources return to healthy phases
- check operator logs for reconciliation or validation failures

## Upgrade Managed Keycloak

Prefer Helm-driven upgrades over ad hoc `kubectl patch` work.

```yaml
keycloak:
  version: "26.4.1"
  upgradePolicy:
    strategy: BlueGreen
    backupTimeout: 600
    autoTeardown: true
```

Then apply the change with your normal `helm upgrade` flow.

## Version Rules That Matter

- Keycloak `24.x` is supported
- Keycloak `25.x+` introduces the separate management port `9000`
- Keycloak `26.x+` is required for built-in tracing propagation

The operator handles the `24.x` versus `25.x+` health-port difference automatically, so upgrade guidance should treat `9000` as version-conditional rather than universal.

## Upgrade Strategies

### Recreate

`Recreate` updates the existing deployment in place and is the simpler strategy.

Users may see a brief interruption during pod replacement.

### BlueGreen

`BlueGreen` is implemented and is the preferred strategy when you want the operator to cut traffic over only after the replacement deployment is ready.

Operationally:

1. the operator validates the version change
2. pre-upgrade backup runs for supported tiers
3. a green deployment is provisioned
4. readiness is checked
5. the Service selector is switched atomically
6. blue teardown happens automatically when `autoTeardown=true`

Progress is tracked in `status.blueGreen`, not just in the top-level phase.

## Cache Isolation During Upgrades

When multiple Keycloak pods run during an upgrade, cache isolation prevents different major versions from joining the same JGroups cluster.

Priority order:

1. `cacheIsolation.clusterName`
2. `cacheIsolation.autoRevision`
3. `cacheIsolation.autoSuffix`
4. no isolation override

Recommended Helm configuration for semver-tagged images:

```yaml
keycloak:
  version: "26.4.1"
  cacheIsolation:
    autoRevision: true
```

Important nuance:

- `autoRevision` only works with semver image tags
- if you use `latest`, nightly tags, or non-semver custom tags, the operator logs a warning and cannot derive a major-version isolation name
- use `clusterName` for non-semver image tags

## Session And Flow Impact

Not all upgrade strategies behave the same way.

- `Recreate` can interrupt active login flows and short-lived in-memory state
- `BlueGreen` minimizes user-facing interruption because traffic only shifts after green is ready
- database-backed realm, client, and user state persists across both strategies

## Migrating From Other Keycloak Solutions

The migration toolkit is the primary path for bringing existing Keycloak exports into this operator’s Helm-first model.

Use [Migration Toolkit](../how-to/migration-toolkit.md) together with [Exporting Realms & Users](../how-to/export-realms.md) when you are migrating from:

- the official Keycloak operator
- standalone Keycloak exports
- older realm-operator-based workflows

Typical flow:

1. export realms from the source Keycloak
2. transform them with `keycloak-migrate`
3. review the generated realm and client values files
4. deploy those values with the Helm charts
5. import users separately where required

## Operator Upgrade Verification And Rollback

Useful verification commands:

```bash
kubectl get pods -n keycloak-system
kubectl get keycloak,keycloakrealm,keycloakclient --all-namespaces
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100
```

Rollback guidance:

- operator-only rollback uses Helm release history
- managed Keycloak version rollback is declarative, but database schema changes may still require restore procedures
- interrupted blue-green upgrades should be investigated through `status.blueGreen` before forcing deployment changes

## Comparison With Official Keycloak Operator

| Topic | This operator | Official operator |
| --- | --- | --- |
| Tenant model | multi-namespace, namespace-grant based | more cluster-admin centered |
| Realm/client desired state | dedicated CRDs | import-heavy realm workflow |
| Client secret handling | Kubernetes-native managed Secret flow | less client-focused CR surface |
| GitOps shape | Helm-first charts plus CRDs | good for Keycloak deployment, less focused on cross-namespace client provisioning |

The migration toolkit is the preferred bridge from export-based or import-heavy workflows into the operator’s Helm-first model.

## See Also

- [Backup & Restore](./backup-restore.md)
- [Escape Hatch](./escape-hatch.md)
- [Keycloak Version Support](../reference/keycloak-version-support.md)
- [Migration Toolkit](../how-to/migration-toolkit.md)
