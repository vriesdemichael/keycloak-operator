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
            group="keycloak.mdvr.nl",
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
                group="keycloak.mdvr.nl",
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

### 4. Status Phase Expectations

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
            group="keycloak.mdvr.nl",
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

### 5. Timeouts

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

### 6. Resource Cleanup

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
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakclients",
            name=client_name,
        )

    with contextlib.suppress(ApiException):
        # Then realms
        k8s_custom_objects.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloakrealms",
            name=realm_name,
        )

    with contextlib.suppress(ApiException):
        # Finally Keycloak instance
        k8s_custom_objects.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )
```

**Shared instances are cleaned up automatically** - don't delete them!

### 7. Common Fixtures

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
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=test_namespace,
            plural="keycloakclients",
            body=client_manifest,
        )

        # Wait for ready
        async def check_ready() -> bool:
            try:
                resource = k8s_custom_objects.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
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
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_name,
            )
```

## Running Tests

```bash
# Run all integration tests
make test-integration

# Run specific test
uv run pytest tests/integration/test_example.py::TestClass::test_method -v

# Run with less parallelism (useful for debugging)
uv run pytest tests/integration/ -n 2 -v

# Run without parallelism (sequential)
uv run pytest tests/integration/ -n 0 -v

# Run with verbose output
uv run pytest tests/integration/ -v -s
```

## Debugging Failed Tests

1. **Check operator logs:**
   ```bash
   make operator-logs
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
