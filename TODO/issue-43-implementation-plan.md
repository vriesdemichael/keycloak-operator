# Issue #43: Keycloak State Drift Detection - Implementation Plan

**Issue**: [#43 - Keycloak state drift detection](https://github.com/vriesdemichael/keycloak-operator/issues/43)  
**Branch**: `feature/issue-43-keycloak-state-drift-detection`  
**Started**: 2025-10-28  
**Status**: In Progress

## Overview

Implement drift detection between Keycloak actual state and CRs in the cluster. Expose metrics for observability and provide configurable auto-remediation.

## Design Decisions (Finalized)

- ✅ **Ownership Tracking**: Store in Keycloak resource attributes
- ✅ **Operator Identity**: `<helm-release>-<namespace>` (configurable via Helm)
- ✅ **Existing Resources**: Ignore (no adoption - breaking change acceptable)
- ✅ **Drift Detection**: Periodic background checks (default 5min interval)
- ✅ **Auto-Remediation**: Configurable (default: disabled), 24h minimum age safety
- ✅ **Scope**: Full scope (realms, clients, identity providers, roles)
- ✅ **Orphan Definition**: Owned by this operator + CR not found at expected namespace/name

## Ownership Attributes Schema

```json
{
  "attributes": {
    "io.kubernetes.managed-by": "keycloak-operator",
    "io.kubernetes.operator-instance": "keycloak-operator-production",
    "io.kubernetes.cr-namespace": "team-a",
    "io.kubernetes.cr-name": "my-realm",
    "io.kubernetes.created-at": "2025-10-28T12:00:00Z"
  }
}
```

## Metrics to Expose

```prometheus
# Drift detection metrics
keycloak_operator_orphaned_resources{type="realm|client|idp|role", name="...", operator_instance="...", age_hours="..."} 1

keycloak_operator_config_drift{type="realm|client|idp|role", name="...", cr_namespace="...", cr_name="..."} 1

keycloak_unmanaged_resources{type="realm|client|idp|role", name="..."} 1

# Remediation metrics (when auto-fix enabled)
keycloak_operator_remediation_total{type="realm|client|idp|role", action="deleted|updated", reason="orphaned|drift"} counter

keycloak_operator_remediation_errors_total{type="realm|client|idp|role", action="deleted|updated"} counter

# Drift detection health
keycloak_operator_drift_check_duration_seconds{} histogram
keycloak_operator_drift_check_errors_total{} counter
keycloak_operator_drift_check_last_success_timestamp{} gauge
```

---

## Phase 1: Foundation & Configuration

### 1.1 Operator Instance ID Configuration
- [x] Add `operator.instanceId` to Helm `values.yaml`
- [x] Add auto-generation logic: `<helm-release>-<namespace>`
- [x] Add `OPERATOR_INSTANCE_ID` environment variable to deployment
- [x] Add drift detection configuration to Helm values
- [ ] Add validation that instance ID is set during operator startup
- [ ] Document in Helm chart README

### 1.2 Ownership Attribute Constants
- [x] Create `src/utils/ownership.py` with attribute key constants:
  - `ATTR_MANAGED_BY = "io.kubernetes.managed-by"`
  - `ATTR_OPERATOR_INSTANCE = "io.kubernetes.operator-instance"`
  - `ATTR_CR_NAMESPACE = "io.kubernetes.cr-namespace"`
  - `ATTR_CR_NAME = "io.kubernetes.cr-name"`
  - `ATTR_CREATED_AT = "io.kubernetes.created-at"`
- [x] Add helper functions:
  - `create_ownership_attributes(cr_namespace, cr_name) -> dict`
  - `is_owned_by_this_operator(attributes: dict) -> bool`
  - `is_managed_by_operator(attributes: dict) -> bool`
  - `get_cr_reference(attributes: dict) -> tuple[str, str]`  # Returns (namespace, name)
  - `get_resource_age_hours(attributes: dict) -> float | None`

### 1.3 Modify Resource Creation to Add Ownership
- [x] Update `src/services/realm_reconciler.py` - add ownership attrs to realm creation
- [x] Update `src/services/client_reconciler.py` - add ownership attrs to client creation
- [ ] Update identity provider creation (in realm reconciler) - add ownership attrs
- [ ] Update role creation - add ownership attrs (future - complex, roles are realm-scoped)
- [ ] Add unit tests for ownership attribute injection
- [ ] Verify attributes are correctly stored in Keycloak (manual test)

---

## Phase 2: Drift Detection Core

### 2.1 Drift Detection Configuration
- [ ] Add to Helm `values.yaml`:
  ```yaml
  monitoring:
    driftDetection:
      enabled: true
      intervalSeconds: 300  # 5 minutes
      autoRemediate: false
      minimumAgeHours: 24  # Safety: don't delete orphans < 24h old
      scope:
        realms: true
        clients: true
        identityProviders: true
        roles: true
  ```
- [ ] Update operator deployment ConfigMap/env vars
- [ ] Add configuration dataclass in settings

### 2.2 Drift Detection Service
- [ ] Create `src/services/drift_detection_service.py`
- [ ] Implement `DriftDetector` class with methods:
  - `scan_for_drift()` - main entry point
  - `check_realm_drift() -> list[DriftResult]`
  - `check_client_drift() -> list[DriftResult]`
  - `check_identity_provider_drift() -> list[DriftResult]`
  - `check_role_drift() -> list[DriftResult]`
  - `is_orphaned(resource_attrs) -> bool`
  - `is_config_drift(resource, cr_spec) -> bool`
  - `is_unmanaged(resource_attrs) -> bool`
- [ ] Add `DriftResult` dataclass:
  ```python
  @dataclass
  class DriftResult:
      resource_type: str  # realm, client, idp, role
      resource_name: str
      drift_type: str  # orphaned, config_drift, unmanaged
      keycloak_resource: dict
      cr_namespace: str | None
      cr_name: str | None
      age_hours: float | None
  ```

### 2.3 Orphan Detection Logic
- [ ] Implement `is_orphaned()` method:
  - Check if resource has `io.kubernetes.operator-instance` matching ours
  - Extract `cr-namespace` and `cr-name` from attributes
  - Query Kubernetes API to check if CR exists
  - Return `True` if CR not found, `False` otherwise
- [ ] Handle missing attributes gracefully (treat as unmanaged)
- [ ] Add unit tests with mocked Kubernetes API responses

### 2.4 Config Drift Detection Logic
- [ ] Implement `is_config_drift()` method:
  - Fetch current CR spec from Kubernetes
  - Fetch current Keycloak resource state
  - Compare relevant fields (exclude status/metadata)
  - Return `True` if differences found
- [ ] Add field comparison logic (ignore timestamps, computed fields)
- [ ] Add unit tests for config comparison

### 2.5 Kubernetes API Integration
- [ ] Add methods to query CRs by namespace/name:
  - `get_realm_cr(namespace, name) -> KeycloakRealm | None`
  - `get_client_cr(namespace, name) -> KeycloakClient | None`
  - `get_idp_cr(namespace, name) -> KeycloakIdentityProvider | None`
- [ ] Handle 404 errors gracefully
- [ ] Add error handling for API failures

---

## Phase 3: Metrics & Observability

### 3.1 Prometheus Metrics Setup
- [ ] Add drift metrics to `src/infrastructure/metrics.py`:
  - `orphaned_resources` (Gauge)
  - `config_drift` (Gauge)
  - `unmanaged_resources` (Gauge)
  - `remediation_total` (Counter)
  - `remediation_errors_total` (Counter)
  - `drift_check_duration_seconds` (Histogram)
  - `drift_check_errors_total` (Counter)
  - `drift_check_last_success_timestamp` (Gauge)
- [ ] Add label helpers for resource type, name, namespace

### 3.2 Metrics Exposure
- [ ] Update drift detector to emit metrics after each scan:
  - Reset gauges before scan
  - Set gauge values based on drift results
  - Update histograms/counters
- [ ] Add error handling and error metrics
- [ ] Verify metrics are exposed on `/metrics` endpoint

### 3.3 Grafana Dashboard (Optional)
- [ ] Create example Grafana dashboard JSON
- [ ] Add panels for:
  - Orphaned resources count over time
  - Config drift by resource type
  - Unmanaged resources
  - Remediation actions (if enabled)
- [ ] Document in `docs/monitoring.md`

---

## Phase 4: Background Task Scheduler

### 4.1 Periodic Drift Check Task
- [ ] Create `src/tasks/drift_check_task.py`
- [ ] Implement background task using `asyncio` or `kopf` timer:
  - Run every `intervalSeconds` (from config)
  - Call `DriftDetector.scan_for_drift()`
  - Emit metrics
  - Log drift findings
- [ ] Add task lifecycle management (start/stop with operator)
- [ ] Add error handling with exponential backoff on failures

### 4.2 Task Health Monitoring
- [ ] Update `drift_check_last_success_timestamp` metric after successful scan
- [ ] Increment `drift_check_errors_total` on failures
- [ ] Log warnings if drift check hasn't succeeded in 2x interval period
- [ ] Add structured logging for drift findings

---

## Phase 5: Auto-Remediation (Optional, Configurable)

### 5.1 Remediation Configuration Validation
- [ ] Validate `autoRemediate` flag from config
- [ ] Validate `minimumAgeHours` is set and > 0
- [ ] Log clear warning if auto-remediation is enabled
- [ ] Add startup banner indicating remediation status

### 5.2 Orphan Deletion Logic
- [ ] Implement `remediate_orphan(drift_result)`:
  - Check resource age >= `minimumAgeHours`
  - If age < minimum, skip with log message
  - Delete resource from Keycloak via Admin API
  - Increment `remediation_total` counter
  - Log deletion with resource details
- [ ] Add error handling and retry logic
- [ ] Increment `remediation_errors_total` on failures

### 5.3 Config Drift Remediation Logic
- [ ] Implement `remediate_config_drift(drift_result)`:
  - Fetch current CR spec
  - Update Keycloak resource to match CR spec
  - Increment `remediation_total` counter
  - Log update with changed fields
- [ ] Add error handling and retry logic
- [ ] Handle conflicts (CR changed during remediation)

### 5.4 Safety Checks
- [ ] Verify resource is still orphaned before deleting (re-check CR existence)
- [ ] Add dry-run logging mode (log what would be done, don't execute)
- [ ] Add maximum batch size (don't delete >N resources in one run)
- [ ] Add circuit breaker for remediation failures

### 5.5 Remediation Testing
- [ ] Create orphaned realm (delete CR, keep Keycloak resource)
- [ ] Wait 24+ hours (or manually override timestamp for testing)
- [ ] Enable auto-remediation
- [ ] Verify orphan is deleted
- [ ] Verify metrics are updated
- [ ] Test config drift remediation (modify Keycloak, verify it's reverted)

---

## Phase 6: Testing & Documentation

### 6.1 Unit Tests
- [ ] Test ownership attribute creation
- [ ] Test `is_orphaned()` logic with various scenarios
- [ ] Test `is_config_drift()` with different resource states
- [ ] Test metric emission
- [ ] Test minimum age safety check
- [ ] Test remediation logic (mocked Keycloak API)

### 6.2 Integration Tests
- [ ] Create test realm via CR
- [ ] Verify ownership attributes in Keycloak
- [ ] Delete CR, trigger drift check
- [ ] Verify orphan metric is set
- [ ] Enable auto-remediation, verify cleanup after 24h
- [ ] Test config drift detection and remediation

### 6.3 Documentation
- [ ] Update `README.md` with drift detection feature
- [ ] Create `docs/drift-detection.md` with:
  - Feature overview
  - Configuration options
  - Metrics reference
  - Troubleshooting guide
  - Safety considerations
- [ ] Update Helm chart README with new values
- [ ] Add example alerts (Prometheus AlertManager rules)
- [ ] Document migration path (existing resources will be ignored)

### 6.4 Changelog
- [ ] Add entry to `CHANGELOG.md`:
  - **BREAKING**: Resources created before this version will not be managed (no ownership attributes)
  - **FEATURE**: Drift detection with Prometheus metrics
  - **FEATURE**: Optional auto-remediation with 24h safety window
  - **FEATURE**: Full scope support (realms, clients, IDPs, roles)

---

## Phase 7: Review & Cleanup

### 7.1 Code Review
- [ ] Self-review all changes
- [ ] Run linters (`make lint`)
- [ ] Run type checks (`make type-check`)
- [ ] Run tests (`make test`)
- [ ] Check test coverage

### 7.2 Manual Testing
- [ ] Deploy to test cluster
- [ ] Create various drift scenarios
- [ ] Verify metrics are accurate
- [ ] Test auto-remediation (if enabled)
- [ ] Verify no impact when disabled
- [ ] Check resource usage (CPU/memory) with drift checks

### 7.3 PR Preparation
- [ ] Squash/clean up commits
- [ ] Write comprehensive PR description
- [ ] Link to issue #43
- [ ] Add screenshots of metrics/Grafana dashboards
- [ ] Request review

### 7.4 Post-Merge Cleanup
- [ ] Delete this plan file
- [ ] Close issue #43
- [ ] Update project status in `CLAUDE.md` if needed

---

## Notes & Decisions Log

**2025-10-28**: Initial plan created
- Decided on attribute-based ownership tracking
- Clarified `cr-namespace` vs operator namespace
- Confirmed 24h minimum age for auto-remediation
- No adoption of existing resources (breaking change OK)

---

## Blockers & Questions

_None currently_

---

## Progress Tracking

**Phase 1**: ⬜ Not Started  
**Phase 2**: ⬜ Not Started  
**Phase 3**: ⬜ Not Started  
**Phase 4**: ⬜ Not Started  
**Phase 5**: ⬜ Not Started  
**Phase 6**: ⬜ Not Started  
**Phase 7**: ⬜ Not Started  

**Overall Progress**: 0/7 phases complete
