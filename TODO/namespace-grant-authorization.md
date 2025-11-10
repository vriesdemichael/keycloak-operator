# Namespace Grant Authorization Implementation Plan

**Issue**: #102 - Simplify authorization: dual-token to namespace grant list  
**Branch**: `feature/namespace-grant-authorization`  
**Created**: 2025-11-10  
**Status**: Planning

## Overview
Transform the authorization system from a complex dual-token model to a GitOps-native namespace grant list approach. This simplifies realm/client management while maintaining security through Kubernetes RBAC and explicit namespace grants.

## Operational Instructions
**CRITICAL**: This file tracks implementation progress across sessions.

**Rules**:
1. Update checkboxes (`[ ]` → `[x]`) as you complete tasks
2. Add notes under tasks if you encounter issues or make decisions
3. Before starting work, review this file to understand current state
4. After completing tasks, update this file before committing
5. If a session crashes, start next session by reading this file
6. Do not delete completed tasks - they serve as audit trail

**Workflow**:
- Start each work session: `cat TODO/namespace-grant-authorization.md`
- Complete a task: mark checkbox, add notes if needed
- End work session: commit this file with your code changes
- Resume after crash: read this file, continue from last unchecked task

## Core Changes Summary
- **Realm creation**: Unrestricted (RBAC-controlled only)
- **Client creation**: Restricted by namespace grant list in realm spec
- **Operator tokens**: Internal only, no user-facing token management
- **Capacity management**: Optional limits on realm creation per operator

---

## Phase 1: Architecture & Documentation
**Goal**: Establish foundation before code changes

### 1.1 Decision Records
- [x] Review existing ADRs related to authorization/tokens
  - [x] ADR 003: Least privilege everywhere
  - [x] ADR 004: Everything must be GitOpsable
  - [x] ADR 017: Kubernetes RBAC over Keycloak security
  - [x] Document which ADRs are affected by this change
  - Note: Also reviewed ADR 005 (no plaintext secrets) and ADR 016 (multi-namespace)
- [x] Create new ADR for namespace grant authorization
  - [x] Document decision to remove user-facing tokens
  - [x] Document decision to make realms unrestricted
  - [x] Document grant list validation approach
  - [x] Document capacity management design
  - [x] Include rationale, alternatives, and trade-offs
  - Created: docs/decisions/063-namespace-grant-list-authorization.yaml
- [x] Mark superseded ADRs (if any) as deprecated
  - Marked ADR 026 (three-layer token delegation) as superseded
  - Marked ADR 039 (token rotation and bootstrap) as superseded
- [x] Validate all ADRs: `make validate-decisions`

### 1.2 Documentation Updates
- [ ] Update main README.md
  - [ ] Remove token generation/management sections
  - [ ] Add namespace grant list examples
  - [ ] Update quick start guide
  - [ ] Update features list
- [ ] Update architecture documentation
  - [ ] Document new authorization flow
  - [ ] Update sequence diagrams
  - [ ] Document capacity management
- [ ] Create migration guide
  - [ ] Steps for users migrating from token-based auth
  - [ ] How to convert existing setups
  - [ ] Breaking changes and deprecation notices
- [ ] Update operations guide
  - [ ] How to grant/revoke namespace access
  - [ ] How to set realm capacity limits
  - [ ] How to handle capacity exhaustion
- [ ] Update security documentation
  - [ ] New authorization model
  - [ ] RBAC requirements
  - [ ] Security considerations

### 1.3 Examples & User Documentation
- [ ] Update example manifests in `examples/`
  - [ ] Remove authorization secret references
  - [ ] Add clientAuthorizationGrants examples
  - [ ] Add realmCapacity examples
  - [ ] Add multi-namespace scenarios
- [ ] Create comprehensive examples
  - [ ] Single-namespace (simple case)
  - [ ] Multi-namespace with grants
  - [ ] Capacity-limited operator
  - [ ] Public realm (all namespaces)
- [ ] Update inline documentation
  - [ ] CRD field descriptions
  - [ ] Code comments in reconcilers
  - [ ] API documentation

---

## Phase 2: Data Models & CRDs
**Goal**: Define new data structures

### 2.1 Pydantic Models
- [x] Update `src/keycloak_operator/models/realm.py`
  - [x] Add `clientAuthorizationGrants` field (list of namespace strings)
  - [x] Remove `authorization_secret_ref` from OperatorRef
  - [x] Add status field: `authorizedClientNamespaces`
  - [x] Add validation for namespace format
  - [x] Update docstrings
- [x] Update `src/keycloak_operator/models/client.py`
  - [x] Remove `authorization_secret_ref` from RealmRef
  - [x] Add status field: `authorizationGranted` and `authorizationMessage`
  - [x] Update docstrings
- [x] Update `src/keycloak_operator/models/keycloak.py`
  - [x] Add `RealmCapacity` model (maxRealms, allowNewRealms, capacityMessage)
  - [x] Add status fields: `realmCount`, `acceptingNewRealms`, `capacityStatus`
  - [x] Update docstrings
- [x] Update `src/keycloak_operator/models/common.py`
  - [x] Keep AuthorizationSecretRef for internal operator tokens
  - Note: TokenMetadata and AuthorizationStatus kept for potential internal use

### 2.2 JSON Schemas
- [ ] Update `_schemas/v1/KeycloakRealm.json`
  - [ ] Add `clientAuthorizationGrants` array
  - [ ] Remove `authorizationSecretRef` from operatorRef
  - [ ] Add status properties
  - [ ] Update descriptions
- [ ] Update `_schemas/v1/KeycloakClient.json`
  - [ ] Remove `authorizationSecretRef` from realmRef
  - [ ] Add status properties
  - [ ] Update descriptions
- [ ] Update `_schemas/v1/Keycloak.json`
  - [ ] Add `realmCapacity` object
  - [ ] Add status properties
  - [ ] Update descriptions
- [ ] Sync to `_schemas/latest/`
  - [ ] Copy all updated schemas
  - [ ] Verify no breaking changes to existing fields

### 2.3 Kubernetes CRDs
- [ ] Update `charts/keycloak-operator/crds/keycloakrealm-crd.yaml`
  - [ ] Add `clientAuthorizationGrants` to spec
  - [ ] Remove `authorizationSecretRef` from operatorRef
  - [ ] Add status subresource fields
  - [ ] Update OpenAPI validation
  - [ ] Update field descriptions
- [ ] Update `charts/keycloak-operator/crds/keycloakclient-crd.yaml`
  - [ ] Remove `authorizationSecretRef` from realmRef
  - [ ] Add status subresource fields
  - [ ] Update OpenAPI validation
  - [ ] Update field descriptions
- [ ] Update `charts/keycloak-operator/crds/keycloak-crd.yaml`
  - [ ] Add `realmCapacity` to spec
  - [ ] Add status subresource fields
  - [ ] Update OpenAPI validation
  - [ ] Update field descriptions
- [ ] Validate CRD changes
  - [ ] Run `kubectl apply --dry-run=server` on test cluster
  - [ ] Verify backwards compatibility where possible
  - [ ] Document breaking changes

---

## Phase 3: Reconciler Logic
**Goal**: Implement authorization enforcement

### 3.1 Keycloak Reconciler
- [ ] Update `src/keycloak_operator/services/keycloak_reconciler.py`
  - [ ] Add realm counting logic
  - [ ] Update status with current realm count
  - [ ] Update status with `acceptingNewRealms` flag
  - [ ] Handle capacity configuration changes
  - [ ] Add logging for capacity management
- [ ] Add capacity helpers
  - [ ] Function to check if new realms allowed
  - [ ] Function to get current realm count
  - [ ] Function to update capacity status

### 3.2 Realm Reconciler
- [ ] Update `src/keycloak_operator/services/realm_reconciler.py`
  - [ ] Add capacity check before creating new realm
  - [ ] Reject new realms if capacity exhausted
  - [ ] Allow existing realms to reconcile normally
  - [ ] Remove authorization token validation
  - [ ] Update status with authorized namespaces list
  - [ ] Add events for capacity rejection
  - [ ] Add logging for grant list changes
- [ ] Add grant list helpers
  - [ ] Function to get grant list from realm spec
  - [ ] Function to check if namespace is in grant list
  - [ ] Function to update authorized namespaces status

### 3.3 Client Reconciler
- [ ] Update `src/keycloak_operator/services/client_reconciler.py`
  - [ ] Remove authorization token validation
  - [ ] Add realm lookup (cross-namespace read)
  - [ ] Add grant list validation
  - [ ] Check client namespace against grant list
  - [ ] Reject if namespace not in grant list
  - [ ] Update status with authorization result
  - [ ] Add clear error messages for authorization failures
  - [ ] Add events for authorization decisions
  - [ ] Add logging for authorization checks
- [ ] Add authorization helpers
  - [ ] Function to fetch realm CR
  - [ ] Function to validate namespace authorization
  - [ ] Function to format authorization errors

### 3.4 Status Management
- [ ] Add status update utilities
  - [ ] Helper to update realm authorization status
  - [ ] Helper to update client authorization status
  - [ ] Helper to update capacity status
  - [ ] Ensure status updates don't cause unnecessary reconciliations

---

## Phase 4: RBAC & Security
**Goal**: Ensure proper Kubernetes permissions

### 4.1 RBAC Analysis
- [ ] Review current RBAC in `charts/keycloak-operator/templates/rbac.yaml`
  - [ ] Document what operator can currently do
  - [ ] Identify required changes for grant list validation
  - [ ] Ensure cross-namespace realm reads are permitted
- [ ] Review secret management permissions
  - [ ] Keep internal operator token permissions
  - [ ] Remove user-facing secret sync if present
- [ ] Review namespace permissions
  - [ ] Ensure operator can list/watch all relevant namespaces
  - [ ] Ensure proper events permissions

### 4.2 RBAC Updates
- [ ] Update operator ClusterRole
  - [ ] Ensure cross-namespace KeycloakRealm read access
  - [ ] Ensure KeycloakClient watch/list/get in all namespaces
  - [ ] Ensure status update permissions for all CRDs
  - [ ] Ensure event creation permissions
- [ ] Update ServiceAccount
  - [ ] Verify it's bound to correct roles
- [ ] Update RoleBindings/ClusterRoleBindings
  - [ ] Ensure correct namespace scoping
- [ ] Document RBAC model
  - [ ] What operator can do
  - [ ] What users need to do (create realm/client CRs)
  - [ ] Least privilege verification

### 4.3 Security Review
- [ ] Validate least privilege compliance
  - [ ] Operator only has necessary permissions
  - [ ] No excessive cluster-wide permissions
- [ ] Validate GitOps compliance
  - [ ] All configuration in Git-trackable resources
  - [ ] No manual secret distribution required
- [ ] Document security model
  - [ ] Authorization flow
  - [ ] Attack surface analysis
  - [ ] Threat model updates

---

## Phase 5: Helm Charts
**Goal**: Update all charts for new model

### 5.1 Operator Chart
- [ ] Update `charts/keycloak-operator/values.yaml`
  - [ ] Remove token-related configuration
  - [ ] Add capacity management examples
  - [ ] Update documentation
- [ ] Update `charts/keycloak-operator/templates/deployment.yaml`
  - [ ] Remove token secret mounts if present
  - [ ] Update environment variables
- [ ] Update `charts/keycloak-operator/templates/rbac.yaml`
  - [ ] Apply RBAC changes from Phase 4
- [ ] Update `charts/keycloak-operator/Chart.yaml`
  - [ ] Update version (breaking change)
  - [ ] Update description
- [ ] Update `charts/keycloak-operator/README.md`
  - [ ] Remove token documentation
  - [ ] Add grant list documentation
  - [ ] Add capacity management documentation

### 5.2 Realm Chart
- [ ] Update `charts/keycloak-realm/values.yaml`
  - [ ] Remove authorizationSecretRef
  - [ ] Add clientAuthorizationGrants examples
  - [ ] Update documentation
- [ ] Update `charts/keycloak-realm/templates/realm.yaml`
  - [ ] Remove secret references
  - [ ] Add grant list templating
- [ ] Update `charts/keycloak-realm/Chart.yaml`
  - [ ] Update version (breaking change)
  - [ ] Update description
- [ ] Update `charts/keycloak-realm/README.md`
  - [ ] Remove token documentation
  - [ ] Add grant list usage
  - [ ] Add examples

### 5.3 Client Chart
- [ ] Update `charts/keycloak-client/values.yaml`
  - [ ] Remove authorizationSecretRef
  - [ ] Update documentation
- [ ] Update `charts/keycloak-client/templates/client.yaml`
  - [ ] Remove secret references
- [ ] Update `charts/keycloak-client/Chart.yaml`
  - [ ] Update version (breaking change)
  - [ ] Update description
- [ ] Update `charts/keycloak-client/README.md`
  - [ ] Remove token documentation
  - [ ] Document that authorization is realm-side now

### 5.4 Chart Testing
- [ ] Update chart tests if present
- [ ] Validate chart rendering: `helm template`
- [ ] Validate chart installation: `helm install --dry-run`
- [ ] Test upgrade path from old charts

---

## Phase 6: Testing Strategy
**Goal**: Comprehensive test coverage (NO SHORTCUTS!)

### 6.1 Unit Tests - Models
- [ ] Test `realm.py` model
  - [ ] Test clientAuthorizationGrants validation
  - [ ] Test namespace format validation
  - [ ] Test serialization/deserialization
  - [ ] Test backwards compatibility
- [ ] Test `client.py` model
  - [ ] Test realmRef without authorizationSecretRef
  - [ ] Test status fields
  - [ ] Test serialization/deserialization
- [ ] Test `keycloak.py` model
  - [ ] Test realmCapacity validation
  - [ ] Test capacity status fields
  - [ ] Test serialization/deserialization

### 6.2 Unit Tests - Reconcilers
- [ ] Test `keycloak_reconciler.py`
  - [ ] Test realm count calculation
  - [ ] Test capacity enforcement
  - [ ] Test status updates
  - [ ] Test allowNewRealms flag handling
  - [ ] Test capacity message propagation
- [ ] Test `realm_reconciler.py`
  - [ ] Test capacity check before creation
  - [ ] Test realm creation when capacity allows
  - [ ] Test realm creation rejection when full
  - [ ] Test existing realm reconciliation when full
  - [ ] Test status updates for authorized namespaces
  - [ ] Test grant list changes detection
- [ ] Test `client_reconciler.py`
  - [ ] Test realm lookup (cross-namespace)
  - [ ] Test namespace in grant list → success
  - [ ] Test namespace not in grant list → rejection
  - [ ] Test missing realm → error
  - [ ] Test grant list empty → all rejected
  - [ ] Test status updates for authorization
  - [ ] Test error message clarity
  - [ ] Test wildcard grants (if supported)

### 6.3 Unit Tests - Helpers
- [ ] Test authorization helper functions
  - [ ] Test grant list parsing
  - [ ] Test namespace validation
  - [ ] Test error formatting
- [ ] Test capacity helper functions
  - [ ] Test realm counting
  - [ ] Test capacity calculations
  - [ ] Test status formatting

### 6.4 Integration Tests - Authorization Flow
- [ ] Test `test_namespace_grant_authorization.py` (NEW)
  - [ ] Test realm creation (unrestricted)
  - [ ] Test client creation with grant → success
  - [ ] Test client creation without grant → rejection
  - [ ] Test grant addition → client creation succeeds
  - [ ] Test grant removal → new clients rejected, existing work
  - [ ] Test cross-namespace realm reference
  - [ ] Test multiple namespaces in grant list
  - [ ] Test same namespace (realm and client together)
- [ ] Test `test_capacity_management.py` (NEW)
  - [ ] Test realm creation when capacity allows
  - [ ] Test realm creation when capacity full
  - [ ] Test existing realms work when capacity full
  - [ ] Test capacity status updates
  - [ ] Test capacity message propagation
  - [ ] Test capacity limit changes (increase/decrease)
  - [ ] Test allowNewRealms flag toggle

### 6.5 Integration Tests - Backwards Compatibility
- [ ] Test migration scenarios
  - [ ] Test resources without grant list (should reject clients)
  - [ ] Test resources without capacity (should allow unlimited)
  - [ ] Test upgrade from old CRD version

### 6.6 Integration Tests - E2E Workflows
- [ ] Test `test_grant_workflow_e2e.py` (NEW)
  - [ ] Full workflow: create realm → grant namespace → create client → verify
  - [ ] Full workflow: create client first → grant → verify reconciliation
  - [ ] Full workflow: revoke grant → verify rejection → re-grant → verify success
  - [ ] Multi-namespace workflow: 3 namespaces, different grants
- [ ] Test error handling
  - [ ] Test clear error messages for authorization failures
  - [ ] Test clear error messages for capacity exhaustion
  - [ ] Test status conditions reflect errors correctly

### 6.7 Integration Tests - Updates to Existing Tests
- [ ] Update `test_authorization_delegation.py`
  - [ ] Remove token-based authorization tests (may delete entire file)
  - [ ] Or convert to grant-based authorization tests
- [ ] Update `test_drift_detection.py`
  - [ ] Ensure works with new authorization model
  - [ ] Remove token drift detection if present
- [ ] Update `test_helm_charts.py`
  - [ ] Update to use grant lists
  - [ ] Remove token secret tests
- [ ] Review all other integration tests
  - [ ] Identify tests affected by authorization changes
  - [ ] Update or remove as needed
  - [ ] Ensure comprehensive coverage remains

### 6.8 Test Execution & Validation
- [ ] Run unit tests: `make test-unit`
  - [ ] All unit tests pass
  - [ ] Coverage meets threshold (check pyproject.toml)
- [ ] Run integration tests: `make test-integration`
  - [ ] All integration tests pass
  - [ ] New authorization tests pass
  - [ ] Capacity management tests pass
  - [ ] E2E workflows pass
- [ ] Run full pre-commit: `make test-pre-commit`
  - [ ] Quality checks pass
  - [ ] All tests pass on fresh cluster
  - [ ] No regressions

---

## Phase 7: Migration & Cleanup
**Goal**: Remove old code, prepare for release

### 7.1 Code Cleanup
- [ ] Remove unused token management code
  - [ ] Search for `AuthorizationSecretRef` usage
  - [ ] Remove if only used for user-facing auth
  - [ ] Keep if used for internal operator tokens
- [ ] Remove token generation utilities (if any)
- [ ] Remove token validation code from reconcilers
- [ ] Remove token sync logic (cross-namespace secret copying)
- [ ] Update imports and dependencies
- [ ] Run linters: `make quality`

### 7.2 Test Cleanup
- [ ] Remove obsolete test files
  - [ ] Token-based authorization tests
  - [ ] Token generation tests
  - [ ] Token sync tests
- [ ] Remove obsolete test fixtures
- [ ] Remove obsolete test utilities
- [ ] Ensure test coverage doesn't decrease

### 7.3 Documentation Cleanup
- [ ] Remove token-related documentation
  - [ ] README sections
  - [ ] Guide sections
  - [ ] Example manifests
- [ ] Update all cross-references
- [ ] Search for "token", "authorization secret" references
- [ ] Update troubleshooting guides

### 7.4 Example Cleanup
- [ ] Remove token-based examples
- [ ] Ensure all examples use grant lists
- [ ] Ensure examples are self-contained
- [ ] Test all examples on fresh cluster

---

## Phase 8: Final Validation
**Goal**: Everything works, nothing breaks

### 8.1 Pre-Commit Validation
- [ ] Run `make test-pre-commit`
  - [ ] Quality checks pass (ruff, mypy)
  - [ ] Unit tests pass (100%)
  - [ ] Integration tests pass (100%)
  - [ ] Fresh cluster setup works
- [ ] Fix any failures
- [ ] Repeat until all green

### 8.2 Manual Testing
- [ ] Deploy on clean cluster
  - [ ] Install operator chart
  - [ ] Create realm without grants
  - [ ] Try to create client → should fail
  - [ ] Add grant to realm
  - [ ] Create client → should succeed
  - [ ] Remove grant
  - [ ] Try to create new client → should fail
  - [ ] Existing client should still work
- [ ] Test capacity management
  - [ ] Set maxRealms to 1
  - [ ] Create 1 realm → should succeed
  - [ ] Try to create 2nd realm → should fail
  - [ ] Set allowNewRealms to false
  - [ ] Try to create realm → should fail with message
  - [ ] Existing realm should reconcile normally
- [ ] Test cross-namespace scenarios
  - [ ] Realm in ns1, client in ns2
  - [ ] Grant ns2 access
  - [ ] Verify client creation works
  - [ ] Revoke grant
  - [ ] Verify new client fails

### 8.3 Documentation Review
- [ ] Read through all updated documentation
- [ ] Verify examples are accurate
- [ ] Verify migration guide is complete
- [ ] Verify ADRs are consistent
- [ ] Spell check and grammar check

### 8.4 Final Checks
- [ ] All checkboxes in this plan marked done
- [ ] All tests passing
- [ ] All documentation updated
- [ ] All examples working
- [ ] Breaking changes documented
- [ ] Migration guide complete
- [ ] Ready for PR

---

## Open Questions & Decisions

### Q1: Realm naming - enforce namespace prefix?
- **Status**: TBD
- **Options**: 
  - Enforce in reconciler (reject without prefix)
  - Validate in admission webhook
  - Document as best practice only
- **Decision**: _To be made during implementation_

### Q2: Grant updates - emit events?
- **Status**: TBD
- **Decision**: _To be made during implementation_

### Q3: Revocation - existing clients continue?
- **Status**: DECIDED
- **Recommendation**: Yes, only block new creation
- **Decision**: Yes - existing clients continue to work after grant revocation, only new client creation is blocked. This is by design to avoid breaking running applications.

### Q4: Wildcard grants - support `namespace: "*"`?
- **Status**: TBD
- **Options**:
  - Support for public realms
  - Require explicit namespace listing
  - Add separate `public: true` flag
- **Decision**: _To be made during implementation_

### Q5: Capacity - hard limit or soft warning?
- **Status**: TBD
- **Recommendation**: Hard limit with clear message
- **Decision**: _To be made during implementation_

---

## Progress Tracking

### Current Phase: Phase 1 - Architecture & Documentation
- **Started**: 2025-11-10
- **Status**: Not started
- **Blocker**: None
- **Next Step**: Review existing ADRs

### Session Notes

#### Session 1 (2025-11-10 19:51 UTC)
- Created comprehensive implementation plan
- Identified 8 phases with detailed tasks
- Emphasized testing requirements (no shortcuts!)
- Added operational instructions for crash recovery
- Ready to begin Phase 1

#### Session 2 (2025-11-10 20:00 UTC)
- [x] Completed Phase 1.1: Decision Records (ADR 063 created, ADR 026 & 039 superseded)
- [x] Completed Phase 2.1: Pydantic Models (realm, client, keycloak updated)
- [x] Partially completed Phase 3: Reconciler Logic
  - [x] realm_reconciler: Removed token auth, added capacity checking
  - [x] client_reconciler: Removed token auth, added grant list validation  
  - [x] keycloak_reconciler: Added capacity status updates
- [ ] In progress: Fixing test files
  - [x] Fixed conftest.py fixtures
  - [x] Fixed test_models.py
  - [x] Fixed test_realm_smtp.py
  - [ ] Need to fix remaining integration tests (test_authorization_delegation.py and others)
  - Note: test_authorization_delegation.py tests token system - will need to delete or completely rewrite

**Decision made**: Q3 - Existing clients continue working after grant revocation (by design)

---

## Completion Criteria

- [ ] All 8 phases completed
- [ ] All checkboxes marked done
- [ ] All tests passing (unit + integration)
- [ ] All documentation updated
- [ ] Breaking changes documented
- [ ] Migration guide complete
- [ ] Manual testing successful
- [ ] ADRs created/updated
- [ ] `make test-pre-commit` passes
- [ ] Ready to ask user about opening PR

---

## Notes for Future Sessions

**If you are an AI resuming this work after a crash/restart:**

1. **First action**: Read this entire file to understand current state
2. **Check progress**: Find the last completed checkbox in each phase
3. **Review session notes**: Read the latest session entry at bottom
4. **Continue work**: Start from first unchecked task in current phase
5. **Update progress**: Mark checkboxes and add notes as you work
6. **Before committing**: Update session notes with your progress

**Important reminders:**
- DO NOT skip tests - they are critical
- DO NOT cheap out on integration tests
- DO update this file as you progress
- DO commit this file with your code changes
- DO read issue #102 if you need context
