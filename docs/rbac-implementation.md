# Namespaced RBAC Implementation

This operator uses a Helm-first, least-privilege RBAC model for multi-namespace realm and client management.

The short version:

- The operator watches Keycloak, KeycloakRealm, and KeycloakClient resources cluster-wide.
- Full workload management happens only in the operator namespace, where the managed Keycloak instance runs.
- Other namespaces must opt in before the operator can reconcile secrets or workload-adjacent resources there.
- Secret access is enforced twice: Kubernetes RBAC must allow the read, and the secret must carry an explicit allow label.

For the practical namespace onboarding flow, see [Multi-Tenant Setup](./how-to/multi-tenant.md).

## Access Model

The implementation combines Kubernetes authorization with operator-side validation:

1. A team installs a realm or client chart into its namespace.
2. If `rbac.create=true`, that chart creates a `RoleBinding` to the operator's shared namespace-access `ClusterRole`.
3. When the operator needs a secret from that namespace, it first runs a `SubjectAccessReview` to confirm the service account can read secrets there.
4. After RBAC passes, the operator validates that the specific secret is labeled for operator access.
5. Only then does it read the secret.

That last step matters. The label requirement is not just recommended by convention. It is enforced in the operator code.

## Architecture

```text
cluster
├─ operator namespace (for example keycloak-system)
│  ├─ keycloak-operator ServiceAccount
│  ├─ keycloak-operator-core ClusterRoleBinding
│  ├─ keycloak-operator-manager RoleBinding
│  ├─ Keycloak CR and managed workloads
│  └─ full CRUD on operator-owned resources in this namespace
│
├─ delegated team namespace A
│  ├─ KeycloakRealm / KeycloakClient resources
│  ├─ labeled Secrets the operator is allowed to read
│  └─ RoleBinding -> shared namespace-access ClusterRole
│
└─ delegated team namespace B
   └─ same opt-in pattern
```

This design follows [ADR 017: Kubernetes RBAC Over Keycloak Security](./decisions/generated-markdown/017-kubernetes-rbac-over-keycloak-security.md), [ADR 032: Minimal RBAC With Namespaced Service Accounts](./decisions/generated-markdown/032-minimal-rbac-with-namespaced-service-accounts.md), [ADR 054: Namespace Watch Scope Requires Cluster RBAC](./decisions/generated-markdown/054-namespace-watch-scope-requires-cluster-rbac.md), and [ADR 062: One Keycloak Per Operator](./decisions/generated-markdown/062-one-keycloak-per-operator.md).

## RBAC Objects

### `keycloak-operator-core`

Installed by the operator chart as a `ClusterRole` plus `ClusterRoleBinding`.

Purpose:

- watch Keycloak CRDs across namespaces
- update status and finalizers
- create events
- perform `SubjectAccessReview` checks
- support Kopf peering, leases, and webhook registration

It is intentionally not the broad "do everything everywhere" role.

### `keycloak-operator-manager`

Installed by the operator chart as a namespace-scoped `Role` plus `RoleBinding` in the operator namespace.

Purpose:

- manage the Keycloak deployment or stateful resources in the operator namespace
- manage services, ingresses, config maps, secrets, CNPG resources, snapshots, and related support objects owned there

This is where the operator has full control, because this is where the managed Keycloak instance lives.

### `keycloak-operator-namespace-access`

Installed by the operator chart as a reusable `ClusterRole` template.

Purpose:

- delegated access for team namespaces
- permits read and update paths the operator needs for realms, clients, secrets, events, and cleanup in those namespaces

Realm and client charts do not create this `ClusterRole`. They create a namespaced `RoleBinding` that points at it.

## Secret Label Requirement

Secrets that the operator reads outside its own namespace must include this label:

```yaml
vriesdemichael.github.io/keycloak-allow-operator-read: "true"
```

Why the extra label check exists even after RBAC:

- it makes secret access explicit instead of accidental
- it prevents a permissive namespace RoleBinding from implicitly exposing every secret
- it gives teams a simple audit handle for operator-readable secrets

Example:

```bash
kubectl create secret generic smtp-password \
  --from-literal=password='super-secret' \
  -n my-team

kubectl label secret smtp-password \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n my-team
```

## Helm-Managed Workflow

Helm is the normal path.

### Operator chart

Installing the operator chart with RBAC enabled creates:

- the operator service account
- `keycloak-operator-core`
- `keycloak-operator-manager`
- `keycloak-operator-namespace-access`
- the matching bindings

Example:

```bash
helm install keycloak-operator charts/keycloak-operator \
  --namespace keycloak-system \
  --create-namespace \
  --set rbac.create=true
```

### Realm chart

With `rbac.create=true`, the realm chart creates a namespace-local `RoleBinding` that targets the operator's shared namespace-access `ClusterRole`.

Relevant values on the realm chart:

- `operatorRef.namespace`: namespace where the operator runs
- `rbac.operatorServiceAccountName`: optional operator service account override
- `rbac.operatorClusterRoleName`: optional shared ClusterRole override

If `rbac.operatorServiceAccountName` is left empty, the chart derives the subject name as `keycloak-operator-<operatorRef.namespace>`.

```bash
helm install my-realm charts/keycloak-realm \
  --namespace my-team \
  --set operatorRef.namespace=keycloak-system \
  --set rbac.operatorServiceAccountName=keycloak-operator-keycloak-system \
  --set rbac.create=true
```

Use the explicit service-account override whenever the operator release uses a non-default service account name. That is part of the normal Helm-managed path, not just the manual-RoleBinding fallback.

### Client chart

With `rbac.create=true`, the client chart does the same for client reconciliation.

Relevant values on the client chart:

- `rbac.operatorNamespace`: namespace where the operator runs
- `rbac.operatorServiceAccountName`: optional operator service account override
- `rbac.operatorClusterRoleName`: optional shared ClusterRole override

If `rbac.operatorServiceAccountName` is left empty, the chart derives the subject name as `keycloak-operator-<rbac.operatorNamespace>`.

```bash
helm install my-client charts/keycloak-client \
  --namespace my-team \
  --set realmRef.name=my-realm \
  --set realmRef.namespace=my-team \
  --set rbac.create=true \
  --set rbac.operatorNamespace=keycloak-system \
  --set rbac.operatorServiceAccountName=keycloak-operator-keycloak-system
```

This matters whenever the operator is not in the chart defaults or when the operator service account name was overridden at install time.

## What Changes When `rbac.create=false`

This is the advanced or policy-driven path.

When `rbac.create=false` on the realm or client chart:

- the chart still creates the CR
- the chart does not create the namespace `RoleBinding`
- reconciliation fails until platform admins or namespace owners create an equivalent `RoleBinding`

Manual binding example:

```bash
kubectl create rolebinding keycloak-operator-access \
  --clusterrole=keycloak-operator-namespace-access \
  --serviceaccount=keycloak-system:keycloak-operator \
  -n my-team
```

If your operator service account name differs from `keycloak-operator`, bind the actual service account name created by your operator chart release. The Helm values above let you keep that aligned even when `rbac.create=true`.

## Common Failures

### Missing namespace binding

Typical message:

```text
Operator does not have access to namespace 'my-team'
```

Meaning:

- the `SubjectAccessReview` failed
- the operator service account is not bound in that namespace

Fix:

- enable `rbac.create` on the realm or client chart, or
- create the `RoleBinding` manually

### Missing allow label

Typical message:

```text
Secret 'smtp-password' in namespace 'my-team' is missing required label 'vriesdemichael.github.io/keycloak-allow-operator-read=true'
```

Meaning:

- Kubernetes RBAC allowed the read attempt
- the operator refused to consume that secret because it was not explicitly opted in

Fix:

```bash
kubectl label secret smtp-password \
  vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -n my-team
```

### Secret not found

Typical message:

```text
Secret 'smtp-password' not found in namespace 'my-team'
```

Fix the reference or create the secret in the same namespace as the CR that uses it.

## Auditing

Find delegated namespaces:

```bash
kubectl get rolebindings -A \
  -o json | jq -r '.items[] | select(.roleRef.kind == "ClusterRole") | select(.roleRef.name | endswith("-namespace-access")) | "\(.metadata.namespace)/\(.metadata.name)"'
```

Find secrets explicitly shared with the operator:

```bash
kubectl get secrets -A \
  -l vriesdemichael.github.io/keycloak-allow-operator-read=true \
  -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name
```

Check whether the operator service account can read secrets in one namespace:

```bash
kubectl auth can-i get secrets \
  --as=system:serviceaccount:keycloak-system:keycloak-operator \
  -n my-team
```

## Troubleshooting

Inspect operator logs:

```bash
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=200 -f
```

Inspect the RBAC objects created by the operator chart:

```bash
kubectl get clusterrole | grep keycloak-operator
kubectl get role -n keycloak-system
kubectl get rolebinding -n my-team
```

Inspect one labeled secret:

```bash
kubectl get secret smtp-password -n my-team -o jsonpath='{.metadata.labels}'
```

## See Also

- [Multi-Tenant Setup](./how-to/multi-tenant.md)
- [KeycloakRealm CRD Reference](./reference/keycloak-realm-crd.md)
- [KeycloakClient CRD Reference](./reference/keycloak-client-crd.md)
- [ADR 017: Kubernetes RBAC Over Keycloak Security](./decisions/generated-markdown/017-kubernetes-rbac-over-keycloak-security.md)
- [ADR 032: Minimal RBAC With Namespaced Service Accounts](./decisions/generated-markdown/032-minimal-rbac-with-namespaced-service-accounts.md)
- [ADR 054: Namespace Watch Scope Requires Cluster RBAC](./decisions/generated-markdown/054-namespace-watch-scope-requires-cluster-rbac.md)
- [ADR 062: One Keycloak Per Operator](./decisions/generated-markdown/062-one-keycloak-per-operator.md)
