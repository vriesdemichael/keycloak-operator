# Frequently Asked Questions

This page answers the questions that come up most often when teams adopt the operator.

## Authorization & Security

### How does authorization work in this operator?

The operator uses Kubernetes RBAC plus realm-managed namespace grants.

There are two separate checks:

1. creating or changing `KeycloakRealm` resources is controlled by Kubernetes RBAC
2. creating `KeycloakClient` resources against a realm is controlled by that realm’s `clientAuthorizationGrants`

Example:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
spec:
  clientAuthorizationGrants:
    - my-app
    - partner-team
```

See [Security Model](./concepts/security.md).

### Why not use traditional RBAC alone?

Pure RBAC is not expressive enough for the main cross-namespace client ownership case.

It can answer questions like “may this subject create `KeycloakClient` objects in namespace X?”, but it does not naturally answer “may namespace X create clients in realm Y but not realm Z?” without pushing that ownership logic into brittle cluster-wide RBAC structure.

The realm grant list solves that cleanly:

- realm owners manage access declaratively in Git
- cluster admins do not need to keep updating cross-namespace RoleBindings for every realm relationship
- the authorization intent stays attached to the realm that owns it

### How do I grant a team access to create clients in my realm?

Add the team namespace to `clientAuthorizationGrants` in the realm definition and reconcile it through Helm or your GitOps workflow.

If you need a temporary diagnostic check, you can inspect it directly:

```bash
kubectl get keycloakrealm my-realm -n my-namespace \
  -o jsonpath='{.spec.clientAuthorizationGrants}' | jq
```

See [Multi-Tenant](./how-to/multi-tenant.md).

## Scaling & Performance

### Will this scale beyond basic high availability?

Yes, but capacity depends on the Keycloak workload, database tier, cluster resources, and traffic shape. This repository does not currently publish a benchmark-backed scale ceiling, so the docs should not pretend otherwise.

What is supported:

- operator HA through multiple operator replicas with leader election
- managed Keycloak horizontal scaling by increasing `keycloak.replicas`
- automatic JGroups DNS_PING discovery for managed Keycloak replicas
- CNPG or other PostgreSQL topologies sized for the actual write and connection load

Important distinction:

- operator replicas improve availability
- separate operator deployments are the capacity-scaling model for the control plane
- Keycloak replicas scale the managed application itself

See [High Availability Deployment](./how-to/ha-deployment.md).

### How many requests can the operator handle?

The operator ships with rate limiting enabled by default.

Default chart values:

- `operator.rateLimiting.global.tps = 50`
- `operator.rateLimiting.global.burst = 100`
- `operator.rateLimiting.namespace.tps = 5`
- `operator.rateLimiting.namespace.burst = 10`

Adjust those through the operator chart values, not by copying stale environment-variable snippets from old docs.

See [Observability](./guides/observability.md).

## Access & Administration

### Can I access the Keycloak admin console?

You can, but it is discouraged as an operating model.

This operator is designed around declarative configuration through Helm values and CRs. Manual admin-console edits are not the source of truth and may be reverted by reconciliation or drift correction.

Use the admin API or admin console for debugging only when CR status and logs are not enough.

### How do I verify configuration without relying on the admin console?

Use Kubernetes-native inspection first:

```bash
kubectl describe keycloakrealm <name> -n <namespace>
kubectl get keycloakrealm <name> -n <namespace> -o yaml
kubectl get keycloakclient <name> -n <namespace> -o yaml
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100
```

If you have to query Keycloak directly for debugging, remember that the management-port behavior depends on version:

- `24.x` uses `8080`
- `25.x+` uses `9000` for the management interface

See [Troubleshooting](./operations/troubleshooting.md).

## Compatibility & Requirements

### What Keycloak versions are supported?

Supported versions start at Keycloak `24.x`.

Use [Keycloak Version Support](./reference/keycloak-version-support.md) as the single source of truth for:

- validated versions
- canonical version behavior
- `24.x` versus `25.x+` management-port handling
- version-gated features such as tracing and Organizations

### What database backends are supported?

Primary path:

- CloudNativePG for Kubernetes-native PostgreSQL operations

Supported but externally operated path:

- external PostgreSQL
- generic managed PostgreSQL through the managed tier settings

This operator does not support MySQL, MariaDB, or H2 as target production backends.

See [Database Setup](./how-to/database-setup.md).

### Can I migrate from the official Keycloak operator?

Yes, but the migration path is export-and-transform, not a magic in-place CRD conversion.

Use:

1. [Exporting Realms & Users](./how-to/export-realms.md)
2. [Migration Toolkit](./how-to/migration-toolkit.md)
3. [Migration & Upgrade Guide](./operations/migration.md)

## Deployment & Operations

### When should I use this operator instead of the official Keycloak operator?

Use this operator when you want:

- Helm-first and GitOps-first workflows
- namespace-grant-based client ownership
- explicit cross-namespace tenancy boundaries
- Kubernetes-native secret and RBAC patterns

The official operator may still be the better fit when an organization requires upstream alignment over this project’s API and tenancy model.

See [Migration & Upgrade Guide](./operations/migration.md#comparison-with-official-keycloak-operator).

### Can I use this operator with Argo CD or Flux?

Yes. Helm and GitOps are the default operating model.

Start with the Helm-first deployment guidance in [Helm vs Direct CR Deployments](./how-to/helm-vs-cr-deployments.md), then see the GitOps examples in [charts/README.md on GitHub](https://github.com/vriesdemichael/keycloak-operator/blob/main/charts/README.md#using-with-gitops).

### Why is there no `User` CR?

Because users are stateful data, not desired-state configuration.

Realms and clients fit the declarative model well. Users, sessions, credentials, and other live identity records do not. They are migrated and imported through dedicated workflows instead of being continuously reconciled as CRs.

See [Migration Toolkit](./how-to/migration-toolkit.md) and [Exporting Realms & Users](./how-to/export-realms.md).

### Why only `KeycloakRealm` and `KeycloakClient`, and not many smaller CRDs?

Because the supported API surface is intentionally centered on the two ownership boundaries that matter most in practice:

- realm-scoped configuration belongs in `KeycloakRealm`
- client-scoped configuration belongs in `KeycloakClient`

That keeps ownership clear, avoids CRD sprawl, and matches how platform teams and application teams usually divide responsibility.

## Security

### Are secrets encrypted?

The operator relies on the Kubernetes and secret-management systems around it.

- encryption at rest depends on your cluster configuration
- GitOps-safe workflows should use tools such as External Secrets Operator, Sealed Secrets, or SOPS-backed pipelines
- secret read access is intentionally constrained and, for some features, requires the operator-read label contract

See [Secret Management](./operations/secret-management.md) and [RBAC Implementation](./rbac-implementation.md).

### How do I revoke access from a compromised namespace?

Remove the namespace from the realm’s `clientAuthorizationGrants`, reconcile the realm, delete the `KeycloakClient` objects in that namespace, and rotate any affected client credentials.

If the namespace was consuming generated client secrets, also verify that the workload access path and any mirrored secrets are cleaned up.

## See Also

- [Security Model](./concepts/security.md)
- [High Availability Deployment](./how-to/ha-deployment.md)
- [Migration Toolkit](./how-to/migration-toolkit.md)
- [Exporting Realms & Users](./how-to/export-realms.md)
