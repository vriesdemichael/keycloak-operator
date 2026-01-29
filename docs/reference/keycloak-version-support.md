# Keycloak Version Support

This document describes which Keycloak versions are supported by the operator and how version compatibility is handled.

## Supported Versions

| Major Version | Supported Versions | Status |
|--------------|-------------------|--------|
| **26.x** | 26.0.8+ | ✅ Fully Supported (26.5.2 is Canonical) |
| **25.x** | 25.0.0+ | ✅ Supported |
| **24.x** | 24.0.0+ | ✅ Supported |
| **23.x and earlier** | - | ❌ Not Supported |

### Validated Versions

The following versions have been explicitly validated with the full integration test suite (840 unit tests + 135 integration tests):

| Version | Date Validated | Status |
|---------|---------------|--------|
| 24.0.0 | 2026-01-28 | ✅ Pass |
| 25.0.0 | 2026-01-28 | ✅ Pass |
| 26.0.8 | 2026-01-29 | ✅ Pass |
| 26.1.5 | 2026-01-29 | ✅ Pass |
| 26.2.0 | 2026-01-29 | ✅ Pass |
| 26.3.0 | 2026-01-29 | ✅ Pass |
| 26.4.0 | 2026-01-29 | ✅ Pass |
| 26.5.2 | 2026-01-28 | ✅ Pass (Canonical) |

See `scripts/keycloak_versions.yaml` for the complete validation history.

### Minimum Version Requirement

The operator requires **Keycloak 24.0.0 or later**.

### Port Behavior by Version

The operator automatically detects the Keycloak version and configures health probes accordingly:

| Version | Health Check Port | Notes |
|---------|------------------|-------|
| **24.x** | 8080 (HTTP port) | No separate management interface |
| **25.x+** | 9000 (management port) | Uses dedicated `KC_HTTP_MANAGEMENT_PORT` |

When using custom images, you can specify `keycloakVersion` in the CR spec to override version detection.

## Canonical Model Architecture

The operator uses a **single canonical model** approach for type safety and maintainability:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Operator Code                               │
│  (Reconcilers, Handlers, Validation - written against v26.5.2) │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│              Canonical Pydantic Models (v26.5.2)                │
│           keycloak_operator/models/keycloak_api.py              │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Version Adapters                              │
│    V26Adapter │ V25Adapter │ V24Adapter                         │
│  (Handles version-specific conversions and validations)         │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Keycloak API                                │
│              (24.x, 25.x, or 26.x instance)                     │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Single Model**: All operator code uses Pydantic models generated from Keycloak 26.5.2 (the canonical version)
2. **Version Detection**: When connecting to Keycloak, the operator detects the server version
3. **Adapter Selection**: The appropriate adapter (V24, V25, or V26) is selected based on version
4. **Outbound Conversion**: When sending data to Keycloak, the adapter converts canonical models to the target version format
5. **Inbound Conversion**: When receiving data from Keycloak, the adapter converts responses back to canonical format
6. **Validation**: The adapter validates CRD specs against version-specific constraints

## Version-Specific Behaviors

### Keycloak 25.0.0+ Changes

The **management port** (9000) was introduced in Keycloak 25.0.0:

- Health checks (`/health/started`, `/health/live`, `/health/ready`) moved to port 9000
- Metrics endpoint (`/metrics`) moved to port 9000
- The operator automatically detects this and configures probes accordingly

For 24.x instances, the operator uses port 8080 for all health checks.

### Keycloak 26.4.0+ Changes

The following fields were **removed** in 26.4.0:

- `oAuth2DeviceCodeLifespan`
- `oAuth2DevicePollingInterval`

If you specify these fields in a `KeycloakRealm` spec targeting 26.4.0+, the operator will:

1. Report an **error** in the CR status conditions
2. Fail the reconciliation with a clear message

### Keycloak 26.3.0+ Changes

The `configuration` field in `ClientPolicyConditionRepresentation` and `ClientPolicyExecutorRepresentation` changed type:

- **Before 26.3.0**: `list[Any]`
- **26.3.0+**: `dict[str, Any]`

The adapter automatically converts between these formats:

- When sending to Keycloak < 26.3.0: Converts dict → list
- When receiving from Keycloak < 26.3.0: Converts list → dict

A **warning** is added to the CR status conditions when this conversion occurs.

### Keycloak 26.0.0+ Features

The **Organizations** feature is only available in Keycloak 26.0.0+. If you enable `organizationsEnabled: true` on a 25.x or 24.x instance, the operator will:

1. Report an **error** in the CR status conditions
2. Fail the reconciliation with a message explaining the minimum version requirement

## Status Conditions

The operator reports version compatibility information in the CR status conditions:

```yaml
status:
  conditions:
    - type: VersionCompatibility/ClientPolicyConfigConverted
      status: "True"
      reason: ClientPolicyConfigConverted
      message: "Client policy configuration converted from dict to list for Keycloak 26.2.0"
      lastTransitionTime: "2025-01-28T14:30:00Z"
```

### Condition Types

| Type | Level | Description |
|------|-------|-------------|
| `VersionCompatibility/*Warning` | Warning | Non-blocking issue, operation will proceed |
| `VersionCompatibility/*Error` | Error | Blocking issue, reconciliation fails |

## Checking Your Keycloak Version

The operator automatically detects the Keycloak version. You can verify the detected version by checking the operator logs:

```bash
kubectl logs -n keycloak-system deployment/keycloak-operator | grep "Keycloak version"
```

Or check the Keycloak CR status:

```bash
kubectl get keycloak my-keycloak -o jsonpath='{.status.version}'
```

## Upgrading Keycloak

When upgrading Keycloak versions:

1. **Check compatibility** - Review the version-specific behaviors above
2. **Update Keycloak** - Perform the Keycloak upgrade
3. **Verify operator** - The operator will automatically detect the new version and use the appropriate adapter
4. **Update CRD specs** - Remove any deprecated fields (e.g., OAuth2 device fields for 26.4.0+)

## Testing with Multiple Versions

The operator's integration tests run against the canonical version (26.5.2) in CI/CD. However, all validated versions listed above have been manually tested with the full integration test suite.

### Validating a New Version

To validate support for a specific Keycloak version:

```bash
# Set the version and run the full test suite
KEYCLOAK_VERSION=26.3.0 make test
```

This will:

1. Run code quality checks
2. Create a fresh Kind cluster
3. Deploy Keycloak with the specified version
4. Run 840 unit tests and 135 integration tests
5. Report pass/fail status

If all tests pass, the version should be added to `scripts/keycloak_versions.yaml` under `validated_versions`.

## Regenerating Models

If you need to update the canonical models (e.g., when a new Keycloak version is released):

```bash
# Update the canonical version in keycloak_versions.yaml
# Then regenerate the models
uv run scripts/generate_keycloak_models.py
```

See the [Keycloak API Reference](../AGENTS.md#keycloak-api-reference) section in AGENTS.md for more details.
