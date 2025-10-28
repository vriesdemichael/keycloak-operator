# Test Cleanup & Cluster Reuse Strategy

## Context
Discussion on 2025-10-27 about improving integration test workflow to enable cluster reuse for faster iterations.

## Key Insight: What Actually Needs Resetting?

Between test runs, we identified what truly needs to be cleaned:

### Must Reset
1. **Keycloak instance** → Contains polluted state (realms/clients from tests)
2. **Keycloak database (CNPG)** → Contains all Keycloak state, must be wiped
3. **Test namespaces** → Where test resources live

### Does NOT Need Reset
1. **Operator** → Unchanged unless code updates
2. **CRDs** → Static, don't change between runs
3. **RBAC** → Static permissions
4. **Operator namespace** → Only auth token secret needs refresh

## Current Problem

The existing `clean-test-resources` script only cleans test namespaces with `test-` prefix. It does NOT:
- Reset Keycloak instance state
- Delete the CNPG database cluster
- Clean operator namespace state

This means cluster reuse leaves polluted Keycloak state.

## Proposed Solution

### New Script: `scripts/clean-integration-state.sh`

Resets state WITHOUT tearing down cluster.

### Refactored Makefile Structure

Organize targets into logical sections for clarity.

## Usage Patterns

### First Run (or after code changes)
```bash
make test-integration-fresh
```

### Subsequent Runs (faster - reuses cluster)
```bash
make clean-integration-state && make test-integration
```

### Just clean stuck resources
```bash
make clean-test-resources
```

## Benefits

✅ **Fast iterations** - No cluster rebuild (saves 2-3 minutes)  
✅ **Clean state** - Database truly reset, not just Keycloak restart  
✅ **Clear workflow** - Explicit targets for fresh vs reuse  
✅ **Better organized** - Makefile sections by purpose
