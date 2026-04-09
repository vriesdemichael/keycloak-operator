# Documentation & Release Versioning

This project publishes several independently versioned artifacts. Use release tags and chart metadata as the source of truth when choosing what to deploy.

## Components

The repository currently publishes these components:

| Component | Current version | Release tag format | Notes |
| --- | --- | --- | --- |
| Operator image | `v0.9.9` | `vX.Y.Z` | Container image published to GHCR |
| Operator chart | `0.7.0` | `chart-operator-vX.Y.Z` | Deploys the operator and optional managed Keycloak |
| Realm chart | `0.4.8` | `chart-realm-vX.Y.Z` | Deploys `KeycloakRealm` resources |
| Client chart | `0.4.5` | `chart-client-vX.Y.Z` | Deploys `KeycloakClient` resources |
| Migration toolkit | independent | `migration-toolkit-vX.Y.Z` | Standalone Go binary |

The operator chart is intentionally versioned separately from the operator image.

## Which Version Should Users Follow?

- for operator deployment, follow the operator chart version
- for operator runtime behavior, the chart `appVersion` tells you which operator image it deploys
- for realm and client configuration, follow the realm and client chart versions independently
- for migration commands, follow the migration toolkit release tag

The operator chart currently maps like this:

| Artifact | Value |
| --- | --- |
| Operator chart version | `0.7.0` |
| Operator chart `appVersion` | `v0.9.9` |
| Result | chart `0.7.0` deploys operator image `v0.9.9` |

That means a user may legitimately be running chart `0.7.0` with operator image `v0.9.9`, while the realm and client charts are on different versions.

## OCI-First Installation

OCI is the primary installation path.

```bash
helm install keycloak-operator \
    oci://ghcr.io/vriesdemichael/charts/keycloak-operator \
    --namespace keycloak-system \
    --create-namespace \
    --version 0.7.0
```

```bash
helm install my-realm \
    oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
    --namespace my-team \
    --version 0.4.8
```

```bash
helm install my-client \
    oci://ghcr.io/vriesdemichael/charts/keycloak-client \
    --namespace my-team \
    --version 0.4.5
```

## Documentation Versioning

Documentation is versioned with `mike`.

- `latest` tracks the most recent operator chart release snapshot
- `dev` tracks the current main branch
- versioned docs such as `v0.7.0` correspond to operator chart releases

This means documentation snapshots are keyed to operator chart releases, not to every realm chart, client chart, or migration toolkit release.

Realm and client chart releases update the documentation content, but they do not automatically create a new versioned docs snapshot for every chart release.

## How To Pick Matching Documentation

1. check the installed operator chart version
2. open the matching docs snapshot if it exists
3. use the realm and client chart versions that match your deployed releases, not assumptions based on the operator chart alone

Examples:

```bash
helm list -n keycloak-system
helm show chart oci://ghcr.io/vriesdemichael/charts/keycloak-operator --version 0.7.0
helm show chart oci://ghcr.io/vriesdemichael/charts/keycloak-realm --version 0.4.8
helm show chart oci://ghcr.io/vriesdemichael/charts/keycloak-client --version 0.4.5
```

## Migration Toolkit Releases

The migration toolkit is a separate component.

- it is released from `tools/migration-toolkit/`
- it uses `migration-toolkit-vX.Y.Z` tags
- it should be treated as its own compatibility surface

Download it from the GitHub Releases page for this repository:

```bash
gh release download migration-toolkit-v<version> \
    --repo vriesdemichael/keycloak-operator \
    --pattern '*keycloak-migrate*'
```

Release page:

`https://github.com/vriesdemichael/keycloak-operator/releases?q=migration-toolkit`

## About `pyproject.toml`

The `pyproject.toml` version is currently `0.1.0`, but that is not the authoritative release version for deployed operator artifacts.

For users, the authoritative sources are:

- operator release tags such as `v0.9.9`
- chart versions in each `Chart.yaml`
- migration toolkit release tags

Do not use `pyproject.toml` alone to decide what version of the operator is running in a cluster.

## Local Documentation Work

Use the Taskfile for normal local docs validation:

```bash
task docs:build
```

For maintainers working with versioned documentation metadata:

```bash
uv run --group docs mike list
```

`mike serve` is for human local preview workflows, not for automated agent use.

## See Also

- [Keycloak Version Support](./reference/keycloak-version-support.md)
- [Migration & Upgrade Guide](./operations/migration.md)
- [Quickstart](./quickstart/README.md)
- [End-to-End Setup](./how-to/end-to-end-setup.md)
