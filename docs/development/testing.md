# Testing Guide

This guide covers the current repository test workflow. For the detailed integration-test rules, patterns, and fixture contracts, read `tests/integration/TESTING.md` before you add or change integration tests.

## Quick Start

```bash
task test:unit
task test:integration
task test:all
```

Use them like this:

- `task test:unit`: fast host-side unit tests with coverage output
- `task test:integration`: integration tests on a guaranteed fresh Kind cluster
- `task test:all`: quality checks, docs validation, unit tests, integration coverage, and log collection

## What `task test:integration` Actually Does

This task is not a thin wrapper around `pytest`. It provisions the integration environment first.

Current flow:

1. `task cluster:create`
2. `task infra:all`
3. load the operator and supporting test images into Kind
4. run the integration pytest suite with xdist and reruns enabled

Do not describe this task as “reusing the current cluster.” It rebuilds the expected integration environment before running tests.

## What `task test:all` Adds

`task test:all` is the full repository gate.

It runs:

1. `task quality:check`
2. `task quality:validate-docs`
3. `task test:unit`
4. `task test:integration-coverage`
5. log and diagnostic collection

The integration-coverage path retrieves coverage data from the operator pod with `scripts/retrieve-coverage.sh` and combines host and cluster coverage with `scripts/combine-coverage.sh`.

## Coverage Instrumentation

Integration coverage does not come from the normal production image.

- the test image is built from the `test` target in `images/operator/Dockerfile`
- runtime coverage injection lives in `images/operator/test-inject/`
- `.coveragerc` and `images/operator/coveragerc.container` drive host and in-cluster coverage behavior

If you change the coverage image or retrieval flow, update this page and the related scripts together.

## Cleanup Semantics

Be precise here, because this page used to overpromise automatic cleanup.

- individual tests are expected to clean up the resources they create
- logs and diagnostics are written into `.tmp/test-logs`
- the Kind cluster is not guaranteed to disappear automatically after each test command
- use `task cluster:destroy` when you want the cluster removed explicitly

The real model is “resource cleanup during tests, explicit cluster teardown when requested.”

## Critical Integration Rules

The most important rules from `tests/integration/TESTING.md` are:

- use `keycloak_port_forward` when host-side tests need to talk to Keycloak
- use shared instances for simple CRUD-style tests
- use dedicated instances for destructive or globally mutating scenarios
- generate unique names with UUIDs because the suite runs in parallel
- use shared wait helpers so timeouts include logs and events automatically

Example pattern:

```python
import uuid

import pytest
from tests.integration.wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.timeout(300)
async def test_realm_creation(
    k8s_custom_objects,
    test_namespace,
    operator_namespace,
) -> None:
    realm_name = f"test-realm-{uuid.uuid4().hex[:8]}"

    # create resource here

    await wait_for_resource_ready(
        k8s_custom_objects=k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_name,
        timeout=120,
        operator_namespace=operator_namespace,
    )
```

## Debugging Failing Integration Tests

Useful first steps:

```bash
kubectl get keycloaks,keycloakrealms,keycloakclients -A
kubectl get events -A --sort-by='.lastTimestamp'
kubectl logs -n keycloak-test-system -l app.kubernetes.io/name=keycloak-operator --tail=200
```

If `task test:all` fails, it already collects logs. Read `.tmp/test-logs` before you rerun blindly.

## When To Read The Deeper Guide

Read `tests/integration/TESTING.md` directly when you are:

- adding new integration tests
- deciding between shared and dedicated Keycloak fixtures
- debugging port-forward issues or race conditions
- writing waits or timeout handling

## Related Guides

- [Development Guide](../development.md)
- [Version Support](../reference/keycloak-version-support.md)
