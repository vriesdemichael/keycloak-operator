# Migration Toolkit

The migration toolkit (`keycloak-migrate`) transforms Keycloak realm export JSON into Helm values compatible with the `keycloak-realm` and `keycloak-client` charts.

It is a standalone Go binary and should be treated as a separate release component.

## Who Should Read This?

This guide is for you if you are:

- migrating from a standalone or self-managed Keycloak deployment into this operator
- migrating from the official Keycloak operator through export-and-transform workflows
- reusing the toolkit’s `import-users` workflow after generating `users.json`

If you are looking for the exit path away from this operator, start with [Escape Hatch](../operations/escape-hatch.md).

## Version Compatibility

The toolkit transforms exports generically, but the target operator only supports the Keycloak versions documented in [Keycloak Version Support](../reference/keycloak-version-support.md).

That means a successful transform does not override the operator’s supported-version rules. Validate your target Keycloak version before deploying transformed output.

## Installation

Download the toolkit from the GitHub Releases page for this repository.

Release tags use the `migration-toolkit-vX.Y.Z` format.

```bash
gh release download migration-toolkit-v<version> \
  --repo vriesdemichael/keycloak-operator \
  --pattern '*keycloak-migrate*'
```

You can also download the binary asset from:

`https://github.com/vriesdemichael/keycloak-operator/releases?q=migration-toolkit`

After download, place the binary on your `PATH` or invoke it directly from your download directory.

## Quick Start

1. export your realm using [Exporting Realms & Users](./export-realms.md)
2. transform the export into Helm values
3. review secrets, unsupported features, and next steps
4. deploy the generated values with Helm
5. import users separately if needed

Example:

```bash
./keycloak-migrate transform \
  --input realm-export.json \
  --output-dir ./migration-output \
  --operator-namespace keycloak-system
```

Generated structure:

```text
migration-output/
└── my-realm/
    ├── realm-values.yaml
    ├── clients/
    │   └── my-app/
    │       └── values.yaml
    ├── secrets.yaml
    ├── secrets-inventory.json
    ├── users.json
    ├── unsupported-features.json
    └── NEXT-STEPS.md
```

## Generated Output

The generated files are meant to separate declarative configuration from sensitive material and migration follow-up work.

### Secrets Output

What you get depends on `--secret-mode`:

- `plain` produces Kubernetes `Secret` manifests in `secrets.yaml`
- `eso` produces `ExternalSecret` manifests that point at your external secret store
- `sealed-secrets` produces `SealedSecret` manifests that still need sealing with your controller key

`secrets-inventory.json` is an operator-facing migration artifact that contains the extracted secret material inventory. Treat it as sensitive and do not commit it.

### `NEXT-STEPS.md`

`NEXT-STEPS.md` is not filler text. It is generated from the actual transformation result and summarizes:

- how many clients, secrets, and users were extracted
- which secret mode was used
- whether unsupported features were detected
- the checklist items you still need to complete before or after deployment

For plain-secret mode, it also warns that `secrets.yaml` contains regular Kubernetes `Secret` manifests and should be handled as sensitive material.

## Minimal Expected Realm Output

The generated `realm-values.yaml` should look structurally like this:

```yaml
realmName: my-realm
displayName: "My Realm"
operatorRef:
  namespace: keycloak-system
clientAuthorizationGrants:
  - my-team
rbac:
  create: true
```

That is the contract you should validate against when reviewing generated output.

## Command Reference

### `transform`

Transforms a Keycloak realm export into Helm chart values.

```bash
keycloak-migrate transform [flags]
```

#### Input flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input`, `-i` | | Path to a single realm export JSON file |
| `--input-dir` | | Path to directory containing realm export JSON files |

One of `--input` or `--input-dir` is required. They are mutually exclusive.

#### Output flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output-dir`, `-o` | `./output` | Output directory for generated files |

#### Namespace flags

| Flag | Default | Description |
|------|---------|-------------|
| `--operator-namespace` | `keycloak-system` | Namespace where the Keycloak operator runs |
| `--realm-namespace` | *(operator namespace)* | Target namespace for realm CRs |
| `--client-grants` | *(none)* | Comma-separated list of namespaces authorized to create clients |

#### Secret handling

| Flag | Default | Description |
|------|---------|-------------|
| `--secret-mode` | `plain` | Output mode: `plain`, `eso`, `sealed-secrets` |
| `--eso-store` | | ExternalSecret store name (required when `--secret-mode=eso`) |
| `--eso-store-kind` | `ClusterSecretStore` | ExternalSecret store kind |
| `--manage-secrets` | `false` | Enable `manageSecret` for confidential clients |

#### Client filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--skip-internal-clients` | `true` | Skip Keycloak internal clients (account, admin-cli, broker, realm-management, security-admin-console) |

## Secret Modes

The toolkit never writes plaintext secrets into `values.yaml` files. Instead, secrets are extracted and output according to the chosen mode.

### `plain` (default)

Generates standard Kubernetes `Secret` manifests using `stringData` (plaintext values — Kubernetes handles base64 encoding internally). The generated `secrets.yaml` should be applied before deploying the Helm charts but **must not be committed to git**.

```bash
keycloak-migrate transform --input export.json --secret-mode plain
```

### `eso` (External Secrets Operator)

Generates `ExternalSecret` manifests that reference an external secret store. You must populate the actual secrets in your backend (AWS Secrets Manager, Vault, etc.) using the keys shown in the generated manifests.

```bash
keycloak-migrate transform \
  --input export.json \
  --secret-mode eso \
  --eso-store my-vault-store \
  --eso-store-kind ClusterSecretStore
```

### `sealed-secrets` (Bitnami Sealed Secrets)

Generates `SealedSecret` manifests with placeholder values. You must seal them with `kubeseal` before applying.

```bash
keycloak-migrate transform --input export.json --secret-mode sealed-secrets
```

## Client Secret Behavior

By default, the toolkit sets `manageSecret: false` and `secretRotation.enabled: false` for all confidential clients. This prevents the operator from rotating secrets that may be in use by workloads outside Kubernetes.

To enable operator-managed secrets:

```bash
keycloak-migrate transform --input export.json --manage-secrets
```

!!! warning "Secret rotation can break external consumers"
    Only enable `--manage-secrets` if all consumers of the client secret are managed within your Kubernetes cluster and can tolerate secret rotation.

## Processing a Directory

When migrating multiple realms, export them to a directory and process all at once:

```bash
# Export produces files like:
#   exports/my-realm-realm.json
#   exports/another-realm-realm.json

keycloak-migrate transform \
  --input-dir ./exports \
  --output-dir ./migration-output
```

The toolkit processes each `.json` file in the directory independently.

## Unsupported Features

The toolkit still emits `unsupported-features.json` when the export contains items it cannot express in the generated Helm values.

Current behavior:

- warnings are printed during transformation
- `unsupported-features.json` captures the unsupported items in structured form
- `NEXT-STEPS.md` includes the follow-up checklist for anything that needs manual handling

Do not treat this as a theoretical file. It is still part of the transform output, and the generated `unsupported-features.json` for your export is the authoritative source for what still needs manual handling.

## User Migration

The toolkit extracts users from the export into `users.json` but does **not** generate CRDs for them. User management is stateful data, not desired-state configuration, and is deliberately outside the scope of this operator's CRD model.

Use the `import-users` subcommand to import `users.json` into a running Keycloak instance managed by this operator:

```bash
./keycloak-migrate import-users \
  --input migration-output/my-realm/users.json \
  --keycloak my-keycloak \
  --namespace keycloak-system \
  --realm my-realm
```

For all options see [`import-users` command reference](#import-users) below. For background on user migration strategies, see [Exporting Realms & Users](./export-realms.md).

---

### `import-users`

Imports the `users.json` file produced by `transform` into a Keycloak realm using the Partial Import API. The import is idempotent by default (SKIP mode): running it twice does not duplicate users.

```bash
./keycloak-migrate import-users [flags]
```

#### Input flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `users.json` | Path to `users.json` from `keycloak-migrate transform` |
| `--max-age` | `24h` | Reject input files older than this duration (0 = no limit) |

#### Credential resolution — cluster mode

Reads admin credentials directly from the Kubernetes cluster using your current `kubeconfig` context. No explicit credentials needed.

| Flag | Default | Description |
|------|---------|-------------|
| `--keycloak` | | Name of the `Keycloak` CR to read credentials from |
| `--namespace`, `-n` | *(current namespace)* | Namespace of the `Keycloak` CR |

#### Credential resolution — explicit flags

For environments where RBAC does not permit reading secrets from the cluster.

| Flag | Default | Description |
|------|---------|-------------|
| `--server-url` | | Keycloak server URL (e.g. `https://keycloak.example.com`) |
| `--username` | | Admin username |
| `--password` | | Admin password |

!!! tip "Credential resolution priority"
    If `--username` or `--password` is provided, explicit credentials are used and `--server-url` is required. Otherwise, `--keycloak` triggers cluster-based credential resolution. Exactly one mode must be chosen.

#### Import behaviour flags

| Flag | Default | Description |
|------|---------|-------------|
| `--realm` | *(required)* | Name of the realm to import users into |
| `--mode` | `skip` | How to handle existing users: `skip`, `fail`, `overwrite` |
| `--batch-size` | `500` | Users sent per API call (Partial Import is non-atomic) |
| `--dry-run` | `false` | Print what would be done without making API calls |

#### Import modes

| Mode | Behaviour |
|------|-----------|
| `skip` | Already-existing users are silently skipped. Re-running is safe. **(Default)** |
| `fail` | Stop on the first user that already exists (HTTP 409). |
| `overwrite` | Replace existing users with data from the file. |

!!! warning "SKIP mode and partial failures"
    Any API-level error (as opposed to a skip) causes the command to exit non-zero immediately. Check the output for details. Batches that completed before the failure are **not** rolled back.

#### Examples

```bash
# Cluster credentials from current kubeconfig
./keycloak-migrate import-users \
  --input ./migration/users.json \
  --keycloak my-keycloak \
  --namespace keycloak-system \
  --realm my-realm

# Explicit credentials (e.g. in a CI pipeline)
./keycloak-migrate import-users \
  --input ./migration/users.json \
  --server-url https://keycloak.example.com \
  --username admin \
  --password "$KEYCLOAK_ADMIN_PASSWORD" \
  --realm my-realm

# Dry run to preview what would be sent
./keycloak-migrate import-users \
  --input ./migration/users.json \
  --keycloak my-keycloak --namespace keycloak-system \
  --realm my-realm \
  --dry-run

# Accept an older export file (skip age check)
./keycloak-migrate import-users \
  --input ./migration/users.json \
  --keycloak my-keycloak --namespace keycloak-system \
  --realm my-realm \
  --max-age 0
```

## Example: Full Migration

```yaml
# Argo CD application for the realm
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: prod-realm
  annotations:
    argocd.argoproj.io/sync-wave: "10"
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/your-gitops-repo.git
    targetRevision: main
    path: gitops/keycloak/production/realm
  destination:
    server: https://kubernetes.default.svc
    namespace: production
```

```yaml
# Argo CD application for a client in an authorized namespace
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: prod-client-my-app
  annotations:
    argocd.argoproj.io/sync-wave: "20"
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/your-gitops-repo.git
    targetRevision: main
    path: gitops/keycloak/production/clients/my-app
  destination:
    server: https://kubernetes.default.svc
    namespace: production
```

Typical full migration flow:

1. export the realm from the source Keycloak
2. transform it with `./keycloak-migrate transform`
3. review `unsupported-features.json` and `NEXT-STEPS.md`
4. commit the generated realm and client values into your GitOps repository
5. sync the realm application first
6. sync client applications in later waves after the realm and its namespace grants are present
7. run `./keycloak-migrate import-users` after the target realm is ready

## See Also

- [Exporting Realms & Users](./export-realms.md)
- [Migration & Upgrade Guide](../operations/migration.md)
- [Escape Hatch](../operations/escape-hatch.md)
- [Keycloak Version Support](../reference/keycloak-version-support.md)
