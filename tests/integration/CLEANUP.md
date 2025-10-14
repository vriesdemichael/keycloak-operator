# Integration Test Cleanup System

This document describes the robust cleanup infrastructure for integration tests.

## Overview

The cleanup system ensures that test resources are reliably cleaned up even when:
- Finalizers block resource deletion
- The operator is not processing resources
- CRD schemas change and resources become invalid
- Tests fail or are interrupted

## Key Components

### 1. Cleanup Utilities (`cleanup_utils.py`)

Core utilities for defensive resource cleanup:

- **`CleanupTracker`**: Tracks failed cleanups across tests for reporting
- **`delete_custom_resource_with_retry`**: Graceful deletion with force-delete fallback
- **`force_remove_finalizers`**: "Break glass" operation to unstick resources
- **`cleanup_namespace_resources`**: Clean all Keycloak resources in a namespace
- **`force_delete_namespace`**: Force namespace deletion if stuck
- **`ensure_clean_test_environment`**: Pre-flight check for stale resources

### 2. Test Fixtures (`conftest.py`)

Enhanced fixtures with automatic cleanup:

- **`cleanup_tracker`**: Session-scoped tracker for reporting failures
- **`check_test_environment`**: Auto-runs before tests to detect stale resources
- **`test_namespace`**: Creates namespace with robust cleanup
- **`managed_realm`**: Factory for creating realms with automatic cleanup
- **`managed_client`**: Factory for creating clients with automatic cleanup

### 3. Manual Cleanup Script

For when tests leave stuck resources:

```bash
# Clean all test resources
make clean-test-resources

# Or use the script directly
./scripts/clean-test-resources.sh --force
```

## Usage in Tests

### Basic Test Namespace

The `test_namespace` fixture automatically cleans up after each test:

```python
@pytest.mark.integration
async def test_something(test_namespace):
    # test_namespace is cleaned up automatically
    # even if test fails or resources get stuck
    pass
```

### Managed Realms

Use `managed_realm` fixture for automatic realm cleanup:

```python
@pytest.mark.integration
async def test_realm_feature(managed_realm, test_namespace):
    # Create realm
    realm_name, realm_manifest = await managed_realm(
        realm_name="test-realm",
        operator_namespace="keycloak-system",
    )
    
    # Use realm in test
    # ...
    
    # Cleanup happens automatically, even on test failure
```

### Managed Clients

Use `managed_client` fixture for automatic client cleanup:

```python
@pytest.mark.integration
async def test_client_feature(managed_client, managed_realm):
    # Create realm first
    realm_name, _ = await managed_realm(
        realm_name="test-realm",
        operator_namespace="keycloak-system",
    )
    
    # Create client
    client_name, client_manifest = await managed_client(
        client_name="test-client",
        realm_name=realm_name,
        client_id="test-client-id",
    )
    
    # Use client in test
    # ...
    
    # Both realm and client are cleaned up automatically
```

### Custom Resource Cleanup

For resources not created through fixtures:

```python
from tests.integration.cleanup_utils import delete_custom_resource_with_retry

@pytest.mark.integration
async def test_custom_resource(k8s_custom_objects, test_namespace, cleanup_tracker):
    # Create resource manually
    resource_name = "my-resource"
    # ...
    
    try:
        # Test code
        pass
    finally:
        # Ensure cleanup
        success = await delete_custom_resource_with_retry(
            k8s_custom_objects=k8s_custom_objects,
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=resource_name,
            timeout=120,
            force_after=60,
        )
        
        if not success:
            cleanup_tracker.record_failure(
                resource_type="keycloakrealm",
                name=resource_name,
                namespace=test_namespace,
                error="Cleanup timeout",
            )
```

## How It Works

### Graceful Deletion with Fallback

1. **Initial deletion**: Standard Kubernetes delete with foreground propagation
2. **Wait period**: Poll for resource deletion (configurable timeout)
3. **Force-delete trigger**: After `force_after` seconds, remove finalizers
4. **Final verification**: Confirm resource is deleted

### Namespace Cleanup Flow

1. **Resource cleanup**: Delete all Keycloak clients and realms
2. **Force-delete stuck resources**: Remove finalizers if needed
3. **Namespace deletion**: Delete namespace with foreground propagation
4. **Verification**: Wait for namespace to be fully removed

### Cleanup Tracking

All cleanup failures are tracked and reported at the end of the test session:

```
⚠️  WARNING: Failed to clean up the following resources:
  - keycloakrealm test-namespace/stuck-realm: Timeout during cleanup
  - namespace test-abc123: Timeout during namespace deletion
```

## Troubleshooting

### Resources Won't Delete

If resources are stuck after tests:

```bash
# Option 1: Use make target
make clean-test-resources

# Option 2: Use script directly with confirmation
./scripts/clean-test-resources.sh

# Option 3: Force without confirmation
./scripts/clean-test-resources.sh --force
```

### Namespace Stuck in Terminating

The cleanup utilities will automatically remove finalizers after a timeout. If manual intervention is needed:

```bash
# Remove finalizers from stuck resources
kubectl patch keycloakrealm stuck-realm -n test-namespace \
  --type json -p='[{"op": "remove", "path": "/metadata/finalizers"}]'

# If that fails (validation error), delete namespace directly
kubectl delete namespace test-namespace --force --grace-period=0
```

### CRD Schema Changed

When CRD schemas change (like the camelCase conversion), old resources may become invalid and undeletable through normal means. The cleanup system handles this by:

1. Attempting graceful deletion first
2. Removing finalizers if grace period expires
3. Force-deleting the namespace if needed

## Best Practices

### DO

- ✅ Use `managed_realm` and `managed_client` fixtures when possible
- ✅ Track cleanup failures with `cleanup_tracker`
- ✅ Use unique names for resources (fixtures handle this automatically)
- ✅ Let the cleanup system handle failures gracefully
- ✅ Run `make clean-test-resources` before test runs if environment is dirty

### DON'T

- ❌ Create resources without cleanup tracking
- ❌ Use fixed resource names (causes conflicts in parallel tests)
- ❌ Ignore cleanup failures in test logs
- ❌ Manually delete namespaces during test runs
- ❌ Assume resources will clean up normally (they might not!)

## Monitoring Cleanup

### During Test Run

Watch for cleanup warnings in test output:

```
WARNING: Some resources failed to clean up in test-abc123: ['keycloakrealms/stuck-realm']
```

### After Test Run

Check the cleanup report at the end:

```
============================================================
CLEANUP TRACKER REPORT
============================================================
Failed to clean up the following resources:
  - keycloakrealm test-abc123/stuck-realm: Timeout during cleanup
```

### Pre-Flight Check

The `check_test_environment` fixture runs before tests and warns about stale resources:

```
⚠️  WARNING: Found stale test resources. Consider running cleanup:
Found 2 stale test resources:
  - namespace/test-old-123
  - namespace/test-old-456
```

## Configuration

### Timeouts

Adjust timeouts in fixture calls:

```python
# Longer timeout for slow operations
success = await delete_custom_resource_with_retry(
    ...,
    timeout=300,        # Wait up to 5 minutes
    force_after=180,    # Force-delete after 3 minutes
)
```

### Cleanup Script

Customize namespace prefix:

```bash
./scripts/clean-test-resources.sh --prefix "my-test-"
```

## Implementation Details

### Force-Delete Strategy

The system uses a multi-stage approach:

1. **Graceful**: Standard Kubernetes deletion
2. **Finalizer Removal**: Remove blocking finalizers
3. **Namespace Force**: Force-delete at namespace level

This ensures cleanup even when:
- Operator is down
- Resources are invalid
- Finalizers are stuck
- API validation fails

### Safety Measures

- Confirmation prompt in manual script (disable with `--force`)
- Cleanup tracking prevents silent failures
- Pre-flight checks warn about dirty state
- Graceful period before force operations
- Detailed logging of all cleanup actions

## See Also

- [TESTING.md](./TESTING.md) - General integration testing guidelines
- [cleanup_utils.py](./cleanup_utils.py) - Cleanup utility implementation
- [conftest.py](./conftest.py) - Test fixtures implementation
