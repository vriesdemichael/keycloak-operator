# Documentation & Chart Versioning

This project maintains versioned documentation and Helm charts to ensure you can access information and artifacts for any release.

## Documentation Versions

The documentation is versioned using [mike](https://github.com/jimporter/mike), which provides:

- **Version Selector**: A dropdown in the documentation header to switch between versions
- **Stable Documentation**: Each operator chart release has its own documentation snapshot
- **Development Version**: The `dev` version reflects the latest main branch

!!! info "Chart-Driven Versioning"
    Documentation versions follow the **operator chart** version, not the operator image version.
    This ensures documentation stays synchronized with the Helm charts users actually deploy.

### Available Versions

- **latest** - Documentation for the most recent operator chart release
- **dev** - Documentation from the main branch (may include unreleased features)
- **v0.1.x** - Documentation for specific operator chart releases (e.g., v0.1.4, v0.1.3)

### Accessing Specific Versions

Use the version selector in the top-left corner of the documentation, or access versions directly:

- Latest: [https://vriesdemichael.github.io/keycloak-operator/](https://vriesdemichael.github.io/keycloak-operator/)
- Development: [https://vriesdemichael.github.io/keycloak-operator/dev/](https://vriesdemichael.github.io/keycloak-operator/dev/)
- Specific version: `https://vriesdemichael.github.io/keycloak-operator/v0.1.4/`

## Helm Chart Versions

All chart versions are preserved in the Helm repository. You can view available versions and install specific ones.

### List Available Versions

```bash
# Add the Helm repository
helm repo add keycloak-operator https://vriesdemichael.github.io/keycloak-operator/charts
helm repo update

# List all available versions
helm search repo keycloak-operator --versions
```

### Install Specific Version

```bash
# Install a specific operator chart version
helm install my-keycloak keycloak-operator/keycloak-operator --version 0.1.4

# Install a specific realm chart version
helm install my-realm keycloak-operator/keycloak-realm --version 0.1.2

# Install a specific client chart version
helm install my-client keycloak-operator/keycloak-client --version 0.1.1
```

### Chart Version History

Each chart maintains its own independent version:

- **keycloak-operator** - The operator deployment chart
- **keycloak-realm** - Realm management chart
- **keycloak-client** - Client management chart

All versions are available in the Helm repository index:
[https://vriesdemichael.github.io/keycloak-operator/charts/index.yaml](https://vriesdemichael.github.io/keycloak-operator/charts/index.yaml)

## Version Alignment

Documentation versions align with the operator chart versions:

| Component | Version | Description |
|-----------|---------|-------------|
| **Documentation** | v0.1.4 | Matches operator chart version |
| **Operator Chart** | 0.1.4 | Helm chart for deploying the operator |
| **Operator Image** | v0.2.14 | Container image (referenced in chart's `appVersion`) |
| **Realm Chart** | 0.1.3 | Helm chart for realm resources |
| **Client Chart** | 0.1.2 | Helm chart for client resources |

!!! tip "Finding Compatible Versions"
    The operator chart's `appVersion` field indicates which operator image version it deploys:
    ```bash
    helm show chart keycloak-operator/keycloak-operator --version 0.1.4 | grep appVersion
    # Output: appVersion: "v0.2.14"
    ```

    Documentation version v0.1.4 corresponds to operator chart version 0.1.4, which deploys operator image v0.2.14.

## Release Process

### Operator Chart Releases

When an operator chart release is published (e.g., `chart-operator-v0.1.4`):

1. A new documentation version is created (e.g., `v0.1.4`) and set as `latest`
2. The new chart version is added to the Helm repository
3. All previous chart versions and documentation remain accessible
4. The chart's `appVersion` indicates which operator image it deploys

### Realm/Client Chart Releases

When a realm or client chart release is published (e.g., `chart-realm-v0.1.3`):

1. The `latest` documentation is updated in-place to reflect new features
2. No new documentation version is created (prevents version explosion)
3. The new chart version is added to the Helm repository
4. All previous chart versions remain available

### Operator Image Releases

When an operator image release is published (e.g., `v0.2.14`):

1. The operator chart's `appVersion` is updated automatically (via PR)
2. This triggers an operator chart release
3. Which then creates new versioned documentation (see above)

### Development Updates

When changes are pushed to the `main` branch:

1. The `dev` documentation version is updated
2. No new versioned documentation is created
3. Helm charts are not published (only on release)

## Migration Between Versions

### Upgrading Operator

```bash
# Check current version
helm list

# Update Helm repository
helm repo update

# Upgrade to latest version
helm upgrade my-keycloak keycloak-operator/keycloak-operator

# Or upgrade to specific version
helm upgrade my-keycloak keycloak-operator/keycloak-operator --version 0.1.4
```

### Documentation for Your Version

Always refer to documentation matching your installed operator chart version:

1. Check your operator chart version:
   ```bash
   helm list -n keycloak-system
   # Look at the CHART column, e.g., "keycloak-operator-0.1.4"
   ```

2. Find the matching documentation version in the version selector (e.g., `v0.1.4`)

3. If your version is not listed, use the closest earlier version or `latest`

## Retention Policy

- **Documentation**: All versions are retained indefinitely
- **Helm Charts**: All versions are retained indefinitely
- **Container Images**: See [GitHub Container Registry retention policy](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages#retention-and-deletion)

## Building Local Versioned Docs

For development or offline use:

```bash
# Install dependencies
uv sync --group docs

# List versions
uv run --group docs mike list

# Serve all versions locally
uv run --group docs mike serve
# Access at http://localhost:8000

# Deploy a new version (maintainers only)
uv run --group docs mike deploy --push v0.2.15 latest
```

## Troubleshooting

### Version Selector Not Showing

If the version selector doesn't appear:

1. Clear browser cache
2. Verify you're on the main documentation site (not a GitHub Pages preview)
3. Check that multiple versions exist (use `mike list`)

### Chart Version Not Available

If a chart version isn't showing:

```bash
# Force refresh the Helm repository
helm repo update keycloak-operator

# Check repository index directly
curl https://vriesdemichael.github.io/keycloak-operator/charts/index.yaml

# Search with debug output
helm search repo keycloak-operator --versions --debug
```

### Older Documentation Missing Content

Some pages may not exist in older versions if they were added later. The version selector shows when each version was created, helping you understand which features were available.
