# Day Two Operations

Day two operations refer to the ongoing management, maintenance, and incident response for a system after its initial deployment. For Keycloak, these operations require a stable, predictable, and mature configuration strategy to prevent automation from fighting against human interventions during critical incidents or routine maintenance.

## Philosophy

The Keycloak Operator is built with a GitOps-first mentality, prioritizing predictable system states. To support mature day two operations, the operator:
- **Decouples intent from generated state:** Explicitly tracks the source of configuration (e.g., auto-generated vs. manually provided secrets).
- **Supports manual overrides safely:** Provides mechanisms for humans to take control without the operator immediately reverting those changes and causing an outage.
- **Annotates generated resources:** Adds metadata to generated resources to make their origin and lifecycle policies transparent to human operators.

## Admin Credentials Management

One of the most critical aspects of day two operations is managing Keycloak's admin credentials. In a production environment, secrets are often managed by external systems like HashiCorp Vault, AWS Secrets Manager, or External Secrets Operator.

To integrate cleanly with these systems without disrupting the operator's automation, you can provide an explicit `existingSecret`.

### How it Works

1. **Proxy Secret Architecture:** The operator creates and maintains a proxy secret named `<name>-admin-credentials` (e.g., `my-keycloak-admin-credentials`) in the same namespace as the Keycloak instance. The Keycloak pods *always* mount this proxy secret.
2. **Auto-Generated Mode:** By default, if you do not specify an existing secret, the operator generates a secure 16-character password and populates the proxy secret. It adds annotations indicating it was generated and is eligible for automatic rotation (if enabled).
3. **Manual / External Mode:** When you provide `spec.admin.existingSecret` in your Keycloak CR, the operator will:
    - Validate that the referenced secret exists and contains both `username` and `password` keys.
    - Synchronize the contents of the referenced secret into the proxy secret.
    - Annotate the proxy secret to explicitly state that its `credential-source` is an external secret, and that `rotation-enabled` is false.
    - **Crucially:** It will *never* attempt to overwrite, modify, or rotate the secret you provided.

This proxy architecture ensures that even if you rotate the external secret, the proxy secret will be updated gracefully during the next reconciliation loop, without requiring direct changes to the Keycloak deployment environment variables or potentially causing temporary mismatches in credential retrieval.

### Example: Using an External Secret

First, create a secret containing the credentials. This is often done by a system like External Secrets Operator.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-custom-admin-secret
type: Opaque
stringData:
  username: "admin"
  password: "super-secure-password-from-vault"
```

Then, configure the Keycloak custom resource to use this secret:

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: example-keycloak
spec:
  # Other configurations...
  admin:
    existingSecret: "my-custom-admin-secret"
```

When you inspect the resulting proxy secret (`example-keycloak-admin-credentials`), you will notice annotations that clarify its origin:

```yaml
metadata:
  annotations:
    vriesdemichael.github.io/credential-source: "external:my-custom-admin-secret"
    vriesdemichael.github.io/rotation-enabled: "false"
```

## Maintenance Mode (Coming Soon)

Future releases of the operator will include explicit support for Maintenance Mode, allowing you to gracefully pause specific reconciliations or upgrades while performing day two operations such as database migrations or manual scale-downs.

## Backups and Restore

Please see the [Backup & Restore](backup-restore.md) guide for detailed instructions on backing up and restoring your Keycloak instance.
