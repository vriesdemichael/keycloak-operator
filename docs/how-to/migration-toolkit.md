# Migration Toolkit

The migration toolkit (`keycloak-migrate`) transforms Keycloak realm export JSON files into Helm chart `values.yaml` files compatible with the `keycloak-realm` and `keycloak-client` charts.

It is a standalone Go binary with zero runtime dependencies.

## Installation

### Build from source

```bash
# Clone the operator repository
git clone https://github.com/vriesdemichael/keycloak-operator.git
cd keycloak-operator

# Build the binary (requires Go; see tools/migration-toolkit/go.mod for the minimum version)
task toolkit:build

# The binary is at .tmp/keycloak-migrate
.tmp/keycloak-migrate version
```

### Manual build

```bash
cd tools/migration-toolkit
go build -o keycloak-migrate .
./keycloak-migrate version
```

## Quick Start

1. **Export your realm** using the [Realm Export Guide](./export-realms.md).

2. **Transform the export:**

    ```bash
    keycloak-migrate transform \
      --input realm-export.json \
      --output-dir ./migration-output \
      --operator-namespace keycloak-system
    ```

3. **Review the output:**

    ```
    migration-output/
    └── my-realm/
        ├── realm-values.yaml          # Helm values for keycloak-realm chart
        ├── clients/
        │   ├── my-app/
        │   │   └── values.yaml        # Helm values for keycloak-client chart
        │   └── another-client/
        │       └── values.yaml
        ├── secrets.yaml               # Secret/ExternalSecret/SealedSecret manifests
        ├── secrets-inventory.json     # Extracted secrets (DO NOT COMMIT)
        ├── users.json                 # Extracted users (for manual import)
        ├── unsupported-features.json  # Features not yet supported by the operator
        └── NEXT-STEPS.md             # Actionable migration checklist
    ```

4. **Deploy with Helm:**

    ```bash
    helm install my-realm keycloak-realm -f migration-output/my-realm/realm-values.yaml
    helm install my-app keycloak-client -f migration-output/my-realm/clients/my-app/values.yaml
    ```

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

Some Keycloak features are not yet supported by the operator. The toolkit handles these gracefully:

- **Warnings** are printed to stderr during transformation
- **`unsupported-features.json`** lists all unsupported features with links to tracking GitHub issues
- **`NEXT-STEPS.md`** documents manual actions needed after migration

The toolkit never fails due to unsupported features — it transforms what it can and documents the rest.

### Currently unsupported

Refer to the generated `unsupported-features.json` for the full list. Common examples include:

- Custom authentication flows and flow bindings ([#531](https://github.com/vriesdemichael/keycloak-operator/issues/531))
- OTP policy ([#532](https://github.com/vriesdemichael/keycloak-operator/issues/532))
- WebAuthn policy ([#533](https://github.com/vriesdemichael/keycloak-operator/issues/533))
- Browser security headers ([#534](https://github.com/vriesdemichael/keycloak-operator/issues/534))
- Scope mappings ([#535](https://github.com/vriesdemichael/keycloak-operator/issues/535))

## User Migration

The toolkit extracts users from the export into `users.json` but does **not** generate CRDs for them. User management is stateful data, not desired-state configuration, and is deliberately outside the scope of this operator's CRD model.

For user migration options, see the [Realm Export Guide — Import Users](./export-realms.md#3-import-users-data-migration).

## Example: Full Migration

```bash
# 1. Export from Keycloak (see export-realms.md)

# 2. Transform with ESO secret management
keycloak-migrate transform \
  --input ./exports/production-realm.json \
  --output-dir ./gitops/keycloak \
  --operator-namespace keycloak-system \
  --realm-namespace production \
  --secret-mode eso \
  --eso-store vault-backend \
  --client-grants team-a,team-b

# 3. Review the output
cat gitops/keycloak/production/NEXT-STEPS.md

# 4. Populate secrets in your backend
# (follow instructions in NEXT-STEPS.md)

# 5. Deploy
helm install prod-realm keycloak-realm \
  -f gitops/keycloak/production/realm-values.yaml \
  -n production

for client_dir in gitops/keycloak/production/clients/*/; do
  client_name=$(basename "$client_dir")
  helm install "$client_name" keycloak-client \
    -f "$client_dir/values.yaml" \
    -n production
done

# 6. Import users via Admin Console Partial Import
#    (see NEXT-STEPS.md for details)
```
