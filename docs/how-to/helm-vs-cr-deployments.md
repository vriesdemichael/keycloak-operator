# Helm vs Direct CR Deployments

Helm charts are the recommended deployment path for this operator.

Direct `Keycloak`, `KeycloakRealm`, and `KeycloakClient` manifests are supported for advanced/manual workflows, but they come with extra responsibilities that the charts normally handle for you.

## Recommended Path: Helm

Use Helm when you want the supported, documented, GitOps-friendly workflow.

Helm charts give you:

- Consistent defaults that match the current chart, schema, and template contracts
- Automatic RBAC and RoleBinding wiring for realm and client namespaces
- A clearer separation between platform-owned and application-owned releases
- Safer upgrades and easier diffing in GitOps tools such as ArgoCD or Flux
- Less chance of drifting from required labels, secret references, or field naming conventions

Typical deployment flow:

1. Install the operator chart and, if desired, a managed Keycloak instance.
2. Install one or more `keycloak-realm` releases in tenant namespaces.
3. Install one or more `keycloak-client` releases in authorized tenant namespaces.

See [Quick Start](../quickstart/README.md) and [End-to-End Setup](end-to-end-setup.md).

## Advanced Path: Direct CR Manifests

Working directly with CR manifests is an advanced/manual path.

It can make sense when:

- You are integrating with an existing manifest pipeline that does not use Helm
- You want full manual control over every generated resource
- You are debugging or developing the operator itself
- You are intentionally managing the surrounding Kubernetes resources outside the charts

If you choose this path, you must manage the wiring that Helm normally provides.

## What Helm Normally Handles For You

### Namespace Access RBAC

The realm and client charts can create the namespace-scoped RoleBindings that allow the operator to read required secrets in the tenant namespace.

If you bypass Helm, you must create and maintain those RoleBindings yourself.

See [RBAC Implementation](../rbac-implementation.md) and [Multi-Tenant Setup](multi-tenant.md).

### Secret Access Requirements

Some secrets must be explicitly readable by the operator.

That includes cases such as:

- SMTP password secrets for realms
- identity provider secrets
- manually managed client secrets
- database or external Keycloak credentials where applicable

If you bypass Helm, you must make sure the right RoleBindings and required labels are present.

### Required Secret Label

Secrets the operator reads from tenant namespaces must use the operator-read label:

```yaml
metadata:
  labels:
    vriesdemichael.github.io/keycloak-allow-operator-read: "true"
```

Without that label, reconciliation will fail even if the Secret exists.

### Cross-Namespace Authorization

`KeycloakClient` creation is controlled by realm-side namespace grants.

If you bypass Helm, you still need to configure `clientAuthorizationGrants` correctly on the `KeycloakRealm` side. The chart does not invent those grants for you; it only makes the deployment workflow clearer.

Example:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: team-a
spec:
  realmName: my-realm
  operatorRef:
    namespace: keycloak-system
  clientAuthorizationGrants:
    - team-a
    - team-b
```

### Chart Defaults and Validated Shapes

The charts encode the current expected values structure and map those values into valid CR shapes.

If you bypass Helm, you must track the CRD schema and field names yourself. That matters for areas such as:

- database configuration tiers
- SMTP configuration
- ingress settings
- secret references
- newer upgrade and tracing features

## Choosing the Right Path

Use Helm if you want:

- the supported default workflow
- easier GitOps integration
- fewer manual RBAC mistakes
- documentation that matches copy-paste examples more closely

Use direct CRs if you want:

- full manual control
- explicit ownership of all surrounding Kubernetes manifests
- an advanced/debugging workflow

## Example Comparison

### Helm-first realm deployment

```bash
helm install my-realm oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  --namespace my-app \
  --create-namespace \
  --set realmName=my-app \
  --set operatorRef.namespace=keycloak-system \
  --set 'clientAuthorizationGrants={my-app}'
```

### Direct realm CR deployment

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: my-realm
  namespace: my-app
spec:
  realmName: my-app
  operatorRef:
    namespace: keycloak-system
  clientAuthorizationGrants:
    - my-app
```

The direct CR is only part of the job. You still need to ensure the operator can read the namespace secrets it needs and that the surrounding RBAC and Secret conventions are correct.

## See Also

- [Quick Start](../quickstart/README.md)
- [End-to-End Setup](end-to-end-setup.md)
- [Multi-Tenant Setup](multi-tenant.md)
- [RBAC Implementation](../rbac-implementation.md)
- [Security Model](../concepts/security.md)
