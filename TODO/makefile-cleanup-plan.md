# Makefile & Test Cleanup Refactoring Plan

## Goal
Refactor Makefile for clarity, add proper state cleanup to enable cluster reuse, ensure parity with GitHub Actions.

## Principles
1. Pre-commit flow must be complete and reliable
2. Idempotent test cluster setup (ensure-kind-cluster guarantees clean state)
3. Enable fast iterations via partial cleanup
4. Remove unused/outdated targets and scripts
5. Test every change as we go

---

## Phase 1: Analysis & Cleanup

### 1.1 Identify Unused Scripts
- [x] Check which scripts are actually used in Makefile
- [x] Remove unused scripts (keep generate-keycloak-models.sh)
  - [x] deploy-test-keycloak.sh (removed)
  - [x] common.sh (removed)
  - [x] config.sh (removed)
- [x] Test that nothing breaks after removal

### 1.2 Identify Outdated Makefile Targets
- [x] List all targets that should be removed:
  - [x] docs targets (docs-serve, docs-build)
  - [x] production image build target (build - non-test)
  - [x] deploy targets (deploy, deploy-local, helm-deploy-operator, helm-uninstall-operator)
  - [x] operator-logs target
  - [x] operator-logs-tail target
  - [x] operator-status target
  - [x] dev-setup target (outdated workflow)
- [x] Document which targets to keep (all test-related ones)

---

## Phase 2: Create New Cleanup Script

### 2.1 Create `scripts/clean-integration-state.sh`
- [x] Create script that:
  - [x] Deletes test namespaces (test-*)
  - [x] Deletes Keycloak instance in operator namespace
  - [x] Deletes CNPG cluster
  - [x] Deletes operator auth token secret
  - [x] Deletes token metadata configmap
  - [x] Waits for resources to terminate
- [x] Make script executable
- [ ] Test script manually
- [ ] Verify cluster is clean after running it

---

## Phase 3: Refactor Makefile

### 3.1 Remove Outdated Targets
- [x] Remove docs targets
- [x] Remove production build/deploy targets
- [x] Remove operator-logs target
- [x] Remove operator-status target
- [x] Test `make help` shows clean list

### 3.2 Restructure with Clear Sections
- [x] Add section headers (comments)
- [x] Group related targets:
  - [x] Quality & Development
  - [x] Unit Testing
  - [x] Integration Testing
  - [x] Test Cluster Management
  - [x] Cleanup & Maintenance
- [x] Test `make help` output is well organized

### 3.3 Add New Cleanup Targets
- [x] Add `clean-integration-state` target
- [ ] Test `clean-integration-state` works correctly
- [x] Integrated into `ensure-kind-cluster`

### 3.4 Ensure Idempotent Cluster Setup
- [x] Update `ensure-kind-cluster` to:
  - [x] Check if cluster exists
  - [x] If exists, run `clean-integration-state`
  - [x] If not exists, run `kind-setup` + `install-cnpg`
- [ ] Test cluster setup is truly idempotent
- [ ] Test running it twice in a row works

### 3.5 Update Pre-commit Flow
- [x] Ensure test-pre-commit:
  - [x] Runs quality checks
  - [x] Tears down cluster
  - [x] Sets up fresh cluster
  - [x] Runs unit tests
  - [x] Runs integration tests
- [ ] Test complete pre-commit flow
- [ ] Verify it matches GitHub Actions workflow

---

## Phase 4: Verify GitHub Actions Parity

### 4.1 Compare Workflows
- [ ] Review .github/workflows/ci-cd.yml
- [ ] Ensure Makefile targets match CI steps
- [ ] Document any differences
- [ ] Add comments in Makefile referencing CI parity

---

## Phase 5: Documentation & Testing

### 5.1 Update Documentation
- [ ] Update CLAUDE.md with new workflow
- [ ] Add examples of fast iteration workflow
- [ ] Document when to use which target

### 5.2 Final Testing
- [ ] Test fresh cluster setup: `make test-pre-commit`
- [ ] Test cluster reuse: `make clean-integration-state && make test-integration`
- [ ] Test partial steps work individually
- [ ] Verify quality checks
- [ ] Verify unit tests
- [ ] Run at least one integration test

---

## Checklist Summary

Total tasks: ~40
- Phase 1: Analysis & Cleanup (6 tasks)
- Phase 2: Create Cleanup Script (5 tasks)
- Phase 3: Refactor Makefile (13 tasks)
- Phase 4: Verify Parity (4 tasks)
- Phase 5: Documentation & Testing (6 tasks)

## Notes
- Test each change before moving to next
- Keep make targets simple and composable
- Prioritize clarity over brevity
- Ensure backwards compatibility where reasonable
