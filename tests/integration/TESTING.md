# Integration Testing Guidelines

This document outlines critical rules and patterns for writing integration tests for the Keycloak operator.

## Overview

The integration test suite uses several optimizations for speed and reliability:
- **Shared Keycloak instances** for simple tests (60s startup amortized across tests)
- **Parallel execution** with pytest-xdist (default: 8 workers)
- **Port-forwarding** for host-to-cluster communication
- **Fresh Kind cluster** per test run

## Critical Rules

### 1. Port-Forward for Keycloak Access

**ALWAYS use the `keycloak_port_forward` fixture when accessing Keycloak from tests.**

Tests run on the host (WSL/macOS/Linux) and cannot resolve cluster-internal DNS names like `keycloak.namespace.svc.cluster.local`.

#### ❌ WRONG - Will fail with DNS resolution error
```python
async def test_something(test_namespace):
    admin_client = get_keycloak_admin_client("my-keycloak", test_namespace)
    # FAILS: Cannot resolve my-keycloak-keycloak.test-xxx.svc.cluster.local
```

#### ✅ CORRECT - Use port-forward fixture
```python
async def test_something(test_namespace, keycloak_port_forward):
    # Set up port-forward
    local_port = await keycloak_port_forward("my-keycloak", test_namespace)

    # Create admin client using localhost
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
    from keycloak_operator.utils.kubernetes import get_admin_credentials

    username, password = get_admin_credentials("my-keycloak", test_namespace)
    admin_client = KeycloakAdminClient(
        server_url=f"http://localhost:{local_port}",
        username=username,
        password=password,
    )
    admin_client.authenticate()
```

### 2. Shared vs Dedicated Keycloak Instances

#### Use Shared Instance When:
- ✅ Testing basic CRUD operations
- ✅ Testing simple configurations
- ✅ Test doesn't modify global Keycloak state
- ✅ Test can run in parallel with others

#### Use Dedicated Instance When:
- ✅ Testing complex features (e.g., service account roles, custom flows)
- ✅ Modifying global state (realms, authentication flows)
- ✅ Testing cascading deletions or finalizers
- ✅ Need guaranteed isolation

#### Pattern for Shared Instance
```python
@pytest.mark.integration
async def test_simple_client_creation(
    k8s_custom_objects,
    test_namespace,
    sample_client_spec,
    wait_for_condition,
    shared_operator,  # Uses shared instance
):
    """Simple test using shared Keycloak."""
    keycloak_name = shared_operator["name"]
    keycloak_namespace = shared_operator["namespace"]

    # Create client in shared instance
    client_manifest = {
        **sample_client_spec,
        "spec": {
            **sample_client_spec["spec"],
            "keycloak_instance_ref": {
                "name": keycloak_name,
                "namespace": keycloak_namespace,
            },
        },
    }
    # ... rest of test
```

#### Pattern for Dedicated Instance
```python
@pytest.mark.integration
@pytest.mark.timeout(600)  # Longer timeout for dedicated instance
async def test_complex_feature(
    k8s_custom_objects,
    test_namespace,
    sample_keycloak_spec,
    wait_for_keycloak_ready,
):
    """Complex test requiring dedicated Keycloak instance."""
    import uuid
    keycloak_name = f"dedicated-{uuid.uuid4().hex[:8]}"

    try:
        # Create dedicated instance
        k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloaks",
            body={**sample_keycloak_spec, "metadata": {"name": keycloak_name}},
        )

        # Wait for ready (can take 60+ seconds)
        await wait_for_keycloak_ready(keycloak_name, test_namespace, timeout=600)

        # Test logic here...

    finally:
        # ALWAYS cleanup dedicated resources
        with contextlib.suppress(ApiException):
            k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                name=keycloak_name,
            )
```

### 3. Parallel Test Safety

Tests run in parallel (8 workers by default). Follow these rules:

#### ✅ Safe Patterns
```python
# Use unique names with UUID
import uuid
client_name = f"test-client-{uuid.uuid4().hex[:8]}"

# Use test_namespace fixture (unique per test)
async def test_something(test_namespace):
    # test_namespace is unique, no conflicts
    pass

# Use shared instance for simple tests
async def test_something(shared_operator):
    # Shared instance handles parallelism internally
    pass
```

#### ❌ Unsafe Patterns
```python
# Fixed names = race conditions
client_name = "test-client"  # WRONG: Will conflict between parallel tests

# Shared namespace = conflicts
namespace = "test"  # WRONG: Use test_namespace fixture instead

# Modifying shared instance global state
async def test_something(shared_operator):
    # WRONG: Don't modify master realm or global settings
    admin_client.update_realm("master", {...})
```

### 4. Wait Helpers - Automatic Debugging

**Use the consolidated wait helpers from `wait_helpers.py` instead of custom wait functions.**

These helpers automatically collect operator logs and Kubernetes events when timeouts occur, making debugging much easier.

#### Available Helpers

```python
from .wait_helpers import (
    wait_for_resource_ready,
    wait_for_resource_failed,
    wait_for_resource_condition,
    wait_for_resource_deleted,
)
```

#### wait_for_resource_ready()

Wait for a resource to reach Ready (or Degraded) phase. **Raises `ResourceNotReadyError` with full debugging info on timeout.**

```python
async def test_something(
    k8s_custom_objects,
    test_namespace,
    operator_namespace,
):
    # Create resource
    await k8s_custom_objects.create_namespaced_custom_object(...)

    # Wait for ready - automatically gets logs/events on failure
    await wait_for_resource_ready(
        k8s_custom_objects=k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name="my-realm",
        timeout=120,
        operator_namespace=operator_namespace,  # Enables log collection
        allow_degraded=True,  # Accept Degraded as ready (default: True)
    )
```

**On timeout, automatically shows:**
- Last resource status
- Kubernetes events for the resource
- Operator logs (last 100 lines)
- Any exceptions encountered

#### wait_for_resource_condition()

Wait for custom condition with automatic debugging:

```python
async def test_something(k8s_custom_objects, test_namespace, operator_namespace):
    # Custom condition
    def _auth_failed(resource: dict) -> bool:
        status = resource.get("status", {})
        phase = status.get("phase")
        message = status.get("message", "")
        return phase == "Failed" and "Authorization" in message

    resource = await wait_for_resource_condition(
        k8s_custom_objects=k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name="my-realm",
        condition_func=_auth_failed,
        timeout=120,
        operator_namespace=operator_namespace,
        expected_phases=("Failed with auth error",),  # For error messages
    )
    # Returns the resource dict when condition is met
```

#### wait_for_resource_failed()

Wait for Failed phase:

```python
await wait_for_resource_failed(
    k8s_custom_objects=k8s_custom_objects,
    group="vriesdemichael.github.io",
    version="v1",
    namespace=test_namespace,
    plural="keycloakrealms",
    name="my-realm",
    timeout=120,
    operator_namespace=operator_namespace,
)
```

#### wait_for_resource_deleted()

Wait for resource deletion (404):

```python
await wait_for_resource_deleted(
    k8s_custom_objects=k8s_custom_objects,
    group="vriesdemichael.github.io",
    version="v1",
    namespace=test_namespace,
    plural="keycloakrealms",
    name="my-realm",
    timeout=120,
)
```

#### ❌ DON'T: Create local wait functions

```python
# WRONG - Duplicates code and loses debugging
async def _wait_resource_ready(plural: str, name: str) -> bool:
    async def _condition() -> bool:
        resource = await k8s_custom_objects.get_namespaced_custom_object(...)
        status = resource.get("status", {}) or {}
        phase = status.get("phase")
        return phase == "Ready"
    return await wait_for_condition(_condition, timeout=90)

ready = await _wait_resource_ready("keycloakrealms", "my-realm")
assert ready, "Resource did not become ready"  # Unhelpful error message
```

#### ✅ DO: Use consolidated helpers

```python
# CORRECT - Automatic debugging on failure
await wait_for_resource_ready(
    k8s_custom_objects=k8s_custom_objects,
    group="vriesdemichael.github.io",
    version="v1",
    namespace=test_namespace,
    plural="keycloakrealms",
    name="my-realm",
    timeout=90,
    operator_namespace=operator_namespace,
)
# If this times out, you automatically get:
# - Last resource status
# - K8s events
# - Operator logs
```

#### Legacy wait_for_condition Fixture

The generic `wait_for_condition` fixture is deprecated for custom resource waits. Only use it for non-resource waits (Secrets, etc):

```python
# OK - Waiting for a Secret (not a custom resource)
async def check_secret_exists() -> bool:
    try:
        await k8s_core_v1.read_namespaced_secret(name, namespace)
        return True
    except ApiException as e:
        if e.status == 404:
            return False
        raise

assert await wait_for_condition(check_secret_exists, timeout=30)
```

### 5. Status Phase Expectations

The operator uses these status phases:

- **Unknown**: Resource just created, reconciliation hasn't started yet
- **Pending**: Reconciliation started, waiting for dependencies
- **Provisioning**: Creating Kubernetes resources (deployments, services)
- **Ready**: Resource is healthy and operational
- **Degraded**: Resource exists but health checks failing
- **Failed**: Unrecoverable error during reconciliation
- **Updating**: Spec changed, reconciliation in progress

#### Timer Handler Behavior
Timer handlers (health checks) run every 60 seconds and:
- ⏭️ Skip resources in `Unknown`, `Pending`, or `Failed` phases
- ✅ Check resources in `Ready` or `Degraded` phases
- 🔍 Can transition `Ready` → `Degraded` if health checks fail
- 🔍 Can transition `Degraded` → `Ready` if health checks pass

#### Test Wait Patterns
```python
async def _wait_for_ready(plural: str, name: str) -> None:
    """Wait for resource to reach Ready phase."""
    async def _condition() -> bool:
        resource = k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural=plural,
            name=name,
        )
        status = resource.get("status", {}) or {}
        phase = status.get("phase")

        # Accept Ready or Degraded (resource exists and is operational)
        # Degraded might occur during startup before health checks pass
        return phase in ("Ready", "Degraded")

    assert await wait_for_condition(_condition, timeout=420, interval=5), (
        f"Resource {plural}/{name} did not become Ready"
    )
```

### 6. Timeouts

Use appropriate timeouts based on resource type:

```python
# Simple tests with shared instance
@pytest.mark.timeout(300)  # 5 minutes

# Tests with dedicated Keycloak instance
@pytest.mark.timeout(600)  # 10 minutes (includes ~60s Keycloak startup)

# Complex multi-resource tests
@pytest.mark.timeout(900)  # 15 minutes

# Wait conditions
await wait_for_keycloak_ready(name, namespace, timeout=600)  # Keycloak startup
await wait_for_condition(check_ready, timeout=420)  # Other resources
```

### 7. Resource Cleanup

**ALWAYS cleanup resources in `finally` blocks for dedicated instances:**

```python
try:
    # Create resources
    k8s_custom_objects.create_namespaced_custom_object(...)

    # Test logic

finally:
    # Cleanup in reverse dependency order
    with contextlib.suppress(ApiException):
        # Delete clients first
        k8s_custom_objects.delete_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
        )

    with contextlib.suppress(ApiException):
        # Then realms
        k8s_custom_objects.delete_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

    with contextlib.suppress(ApiException):
        # Finally Keycloak instance
        k8s_custom_objects.delete_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )
```

**Shared instances are cleaned up automatically** - don't delete them!

### 8. Common Fixtures

```python
# Unique namespace per test
test_namespace: str

# Shared Keycloak instance (optimized)
shared_operator: dict[str, str]  # {"name": "...", "namespace": "..."}

# Port-forward for host access
keycloak_port_forward: Callable[[str, str], Awaitable[int]]

# Wait utilities
wait_for_condition: Callable
wait_for_keycloak_ready: Callable

# Kubernetes clients
k8s_core_v1: client.CoreV1Api
k8s_apps_v1: client.AppsV1Api
k8s_custom_objects: client.CustomObjectsApi

# Sample specs (templates)
sample_keycloak_spec: dict
sample_realm_spec: dict
sample_client_spec: dict
```

## Complete Test Template

```python
"""Integration test for [feature description]."""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.integration
@pytest.mark.timeout(300)  # Adjust based on complexity
async def test_feature_name(
    k8s_custom_objects,
    k8s_core_v1,
    test_namespace,
    shared_operator,  # Or create dedicated if needed
    sample_client_spec,
    wait_for_condition,
    keycloak_port_forward,  # If accessing Keycloak API
) -> None:
    """Test description explaining what this verifies."""

    # Use shared instance for simple tests
    keycloak_name = shared_operator["name"]
    keycloak_namespace = shared_operator["namespace"]

    # Generate unique names
    client_name = f"test-{uuid.uuid4().hex[:8]}"

    try:
        # Create test resources
        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": test_namespace},
            "spec": {
                **sample_client_spec["spec"],
                "keycloak_instance_ref": {
                    "name": keycloak_name,
                    "namespace": keycloak_namespace,
                },
            },
        }

        k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            body=client_manifest,
        )

        # Wait for ready
        async def check_ready() -> bool:
            try:
                resource = k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )
                phase = resource.get("status", {}).get("phase")
                return phase == "Ready"
            except ApiException:
                return False

        assert await wait_for_condition(check_ready, timeout=420), (
            f"Client {client_name} did not become Ready"
        )

        # If accessing Keycloak API, use port-forward
        if need_keycloak_access:
            local_port = await keycloak_port_forward(keycloak_name, keycloak_namespace)

            from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
            from keycloak_operator.utils.kubernetes import get_admin_credentials

            username, password = get_admin_credentials(keycloak_name, keycloak_namespace)
            admin_client = KeycloakAdminClient(
                server_url=f"http://localhost:{local_port}",
                username=username,
                password=password,
            )
            admin_client.authenticate()

            # Test logic using admin_client

        # Assertions
        assert something

    finally:
        # Cleanup (only for resources created in this test)
        with contextlib.suppress(ApiException):
            k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
            )
```

## Running Tests

```bash
# Run complete test suite (quality + fresh cluster + unit + integration with coverage)
make test

# Run specific test
uv run pytest tests/integration/test_example.py::TestClass::test_method -v

# Run with less parallelism (useful for debugging)
uv run pytest tests/integration/ -n 2 -v

# Run without parallelism (sequential)
uv run pytest tests/integration/ -n 0 -v

# Run with verbose output
uv run pytest tests/integration/ -v -s
```

### Test Logging and Diagnostics

When running `make test-pre-commit`, comprehensive logging is automatically enabled:

**Logs are written to:**
- `.tmp/test-pre-commit.log` - Complete timestamped log of all test steps
- `.tmp/test-logs/` - Diagnostic logs collected from cluster (always collected, even on success)

**What's automatically collected:**
- Cluster information (`cluster-info.log`)
- All operator pod logs (`operator-logs.log`)
- Operator deployment status (`operator-status.log`)
- All Keycloak custom resources (`test-resources.log`)
- All cluster events sorted by time (`events.log`)
- All pods across all namespaces (`all-pods.log`)

**Benefits:**
- Fast debugging without re-running failed tests
- Complete visibility into what happened during test runs
- Timestamps for tracking slow steps
- No manual log collection needed

**Example usage:**
```bash
# Run pre-commit tests
make test-pre-commit

# If tests fail, check the logs:
cat .tmp/test-pre-commit.log  # Full execution log with timestamps
cat .tmp/test-logs/operator-logs.log  # Operator pod logs
cat .tmp/test-logs/events.log  # Kubernetes events
```

## Debugging Failed Tests

1. **Check operator logs:**
   ```bash
   kubectl logs -n keycloak-test-system -l app.kubernetes.io/name=keycloak-operator --tail=200
   ```

2. **Check resource status:**
   ```bash
   kubectl get keycloaks,keycloakrealms,keycloakclients -A
   kubectl describe keycloak <name> -n <namespace>
   ```

3. **Check for stuck resources:**
   ```bash
   kubectl get namespaces | grep test-
   ```

4. **Clean up stuck tests:**
   ```bash
   kubectl delete namespace test-<uuid>
   ```

## Common Pitfalls

### ❌ Forgetting port-forward
**Symptom:** `NameResolutionError` or DNS failures
**Fix:** Add `keycloak_port_forward` fixture and use localhost

### ❌ Using shared instance for destructive tests
**Symptom:** Parallel tests failing randomly
**Fix:** Create dedicated instance for tests that modify global state

### ❌ Not cleaning up dedicated resources
**Symptom:** Namespace stuck in Terminating
**Fix:** Always use `finally` blocks with `contextlib.suppress(ApiException)`

### ❌ Hardcoded resource names
**Symptom:** `AlreadyExists` errors in parallel runs
**Fix:** Use `uuid.uuid4().hex[:8]` for unique names

### ❌ Expecting instant reconciliation
**Symptom:** Tests fail waiting for Ready
**Fix:** Use proper `wait_for_condition` with adequate timeout (420s minimum)

### ❌ Wrong phase expectations
**Symptom:** Test waits forever for "Running" phase that doesn't exist
**Fix:** Wait for `phase == "Ready"` or `phase in ("Ready", "Degraded")`

### ❌ Creating realms without proper service account setup
**Symptom:** Realm creation fails with authentication/authorization errors when trying to create clients or users
**Fix:** Always create realms using the Helm chart pattern which sets up required service accounts:

```python
# ❌ WRONG - Missing service account setup
realm_manifest = {
    "apiVersion": "vriesdemichael.github.io/v1",
    "kind": "KeycloakRealm",
    "metadata": {"name": realm_name, "namespace": test_namespace},
    "spec": {
        "keycloak_instance_ref": {
            "name": keycloak_name,
            "namespace": keycloak_namespace,
        },
        "realm": {"realm": realm_name, "enabled": True},
    },
}

# ✅ CORRECT - Follow Helm chart pattern with service account
from tests.integration.conftest import create_realm_with_sa

realm_name = f"test-realm-{uuid.uuid4().hex[:8]}"
realm_manifest = create_realm_with_sa(
    realm_name=realm_name,
    keycloak_name=keycloak_name,
    keycloak_namespace=keycloak_namespace,
    test_namespace=test_namespace,
)

k8s_custom_objects.create_namespaced_custom_object(
    group="vriesdemichael.github.io",
    version="v1",
    namespace=test_namespace,
    plural="keycloakrealms",
    body=realm_manifest,
)
```

**Why this matters:**
- The operator needs proper service account credentials to manage resources within a realm
- Without the service account, operations like creating clients or users will fail with authentication errors
- The Helm chart automatically sets up these service accounts, so tests should follow the same pattern
- The `create_realm_with_sa` helper in conftest.py encapsulates this setup

## Test Coverage Collection

Integration tests support coverage collection from the operator running in Kubernetes.

### How It Works

1. **Coverage-Enabled Image**: The operator is built with coverage instrumentation using `images/operator/Dockerfile.test`
2. **Auto-Start**: Coverage collection starts automatically via `images/operator/test-inject/sitecustomize.py` (imported at Python startup)
3. **Data Storage**: Coverage data is stored in `/tmp/coverage/` inside the operator pod
4. **Retrieval**: After tests complete, coverage files are copied from the pod to host
5. **Combination**: Unit test coverage and integration test coverage are merged

### Running Tests with Coverage

```bash
# Run complete test suite with coverage (recommended)
make test

# Or set environment variable manually
INTEGRATION_COVERAGE=true uv run pytest tests/integration/ -v -n auto --dist=loadscope
```

### Viewing Coverage Reports

```bash
# Generate HTML report
coverage html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

### Coverage Files

- **Configuration**: `.coveragerc` - Coverage settings
- **Unit test data**: `.coverage` - Generated by pytest-cov
- **Integration data**: `.tmp/coverage/.coverage.*` - Retrieved from operator pod
- **Combined data**: `.coverage` (after combination)
- **Reports**: `coverage.xml` (Codecov), `htmlcov/` (local viewing)

### How Coverage Collection Works

The coverage-enabled operator image includes:
- `coverage` package installed
- `.coveragerc` configuration file
- `images/operator/test-inject/sitecustomize.py` auto-imported at startup
- `COVERAGE_PROCESS_START=/app/.coveragerc` environment variable

When tests run with `INTEGRATION_COVERAGE=true`:
1. Operator is deployed using the coverage-instrumented image
2. Coverage starts automatically when Python interpreter starts
3. All operator code execution is tracked
4. Coverage data files are created in `/tmp/coverage/`
5. After tests, the `shared_operator` fixture retrieves these files
6. Combined with unit test coverage for complete report

### CI/CD Integration

The CI/CD pipeline automatically:
- Builds both standard and coverage-enabled images
- Runs integration tests with coverage enabled
- Retrieves coverage from operator pod
- Combines unit + integration coverage
- Uploads to Codecov for tracking

No manual intervention required in CI.
