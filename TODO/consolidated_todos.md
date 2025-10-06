# Consolidated TODOs - Keycloak Operator

**Last Updated:** 2025-10-05
**Status:** Active development with clear priorities

---

## 🔥 P0 - Critical (Must Complete Before v1.0)

### Automatic Secret Rotation Handling
**Estimated Effort:** 1-2 days
**Source:** Operator enhancement for production secret management

**Current State:**
- ✅ ExternalSecrets already supported (operator uses secret references everywhere)
- ❌ Secret changes don't trigger automatic reconciliation
- ❌ Rotated secrets require manual reconciliation or CRD change to apply

**Required Implementation:**
- [ ] Add Kopf watch on Secret resources
- [ ] When a secret changes, find all Keycloak/Realm/Client resources that reference it
- [ ] Trigger reconciliation for those resources
- [ ] Add integration test for secret rotation (create resource with secret ref, update secret, verify reconciliation)

**Implementation Notes:**
```python
@kopf.on.update('', 'v1', 'secrets')
async def on_secret_change(name, namespace, **kwargs):
    # Find all resources referencing this secret
    # Trigger reconciliation for each
```

**Impact:** Automatic secret rotation without manual intervention, critical for ExternalSecrets/Vault workflows

---

## 🔧 P1 - High Priority (Complete for Production Readiness)

### 0. Consistent Event Emission
**Estimated Effort:** 1 day
**Source:** manual-todos (moved from P0)

- [ ] Implement consistent Kubernetes event emission across all reconcilers
- [ ] Add event types: Normal (created, updated, ready) and Warning (failed, degraded)
- [ ] Write tests to verify event emission

**Impact:** Better observability in kubectl describe output

---

### 1. Complete Keycloak API Model Integration ✅ COMPLETED
**Completion Date:** 2025-10-05
**Actual Effort:** ~5 hours (faster than estimated!)
**Source:** keycloak-api-integration-step-by-step.md

**Completed Work:**
- ✅ Updated 19 admin client methods to use typed Pydantic models:
  - ✅ Realm methods: `export_realm`, `get_realms` (2 methods)
  - ✅ Client methods: `get_client_by_name`, `get_realm_clients`, `get_client_uuid` (3 methods)
  - ✅ User methods: `get_service_account_user` (1 method)
  - ✅ Role methods: `get_realm_role`, `get_client_role`, `assign_realm_roles_to_user`, `assign_client_roles_to_user`, `get_client_roles`, `create_client_role`, `update_client_role` (7 methods)
  - ✅ Protocol mapper methods: `get_client_protocol_mappers`, `create_client_protocol_mapper`, `update_client_protocol_mapper` (3 methods)
  - ✅ Advanced config methods: `configure_authentication_flow`, `configure_identity_provider`, `configure_user_federation` (3 methods)
- ✅ All methods accept both `Model | dict[str, Any]` for backward compatibility
- ✅ All methods return typed Pydantic models instead of dicts
- ✅ Updated reconcilers and handlers to use property access
- ✅ Added comprehensive usage examples to CLAUDE.md
- ✅ All quality checks passing (ruff + ty/mypy)
- ✅ All 167 unit tests passing

**Impact:** ✅ **ACHIEVED** - Type-safe API interactions, catches errors before API calls, better IDE support

**Files Modified:**
- `src/keycloak_operator/utils/keycloak_admin.py` - Updated 19 methods with Pydantic types
- `src/keycloak_operator/handlers/client.py` - Fixed property access for ClientRepresentation
- `tests/integration/test_service_account_roles.py` - Fixed property access for UserRepresentation
- `CLAUDE.md` - Added "Admin Client Usage Examples" section with 6 detailed examples

---

### 2. Documentation Improvements
**Estimated Effort:** 1 week
**Source:** manual-todos (P1 Documentation)

- [ ] Create documentation site using material-mkdocs (like pydantic)
  - [ ] Set up mkdocs.yml configuration
  - [ ] Migrate content from README to docs/
  - [ ] Add API reference documentation
  - [ ] Add architecture diagrams
- [ ] Add "Status/Maturity" section to README:
  - [ ] Production readiness status
  - [ ] Known limitations
  - [ ] Compatibility matrix
- [ ] Add "Roadmap" section to README with planned features
- [ ] Document compatibility matrix:
  - [ ] Supported Keycloak versions (≥25.0.0)
  - [ ] Supported Kubernetes versions
  - [ ] Supported OpenShift versions
- [ ] Add CONTRIBUTING.md:
  - [ ] Development setup with uv
  - [ ] How to run tests
  - [ ] Code style guidelines
  - [ ] How to submit PRs
- [ ] Cleanup old/outdated info in CLAUDE.md and README.md
- [ ] Remove unused files from repository

**Impact:** Better onboarding for new contributors, clearer production readiness

---

### 3. CI/CD Enhancements
**Estimated Effort:** 1-2 days
**Source:** manual-todos (P1 CI/CD)

**Status:** ✅ CI/CD pipeline already implemented (commit d61348b)! Only minor enhancements remain:

**Completed:**
- ✅ GitHub Actions workflows set up (quality checks, unit tests, integration tests)
- ✅ ghcr.io image publishing (latest + semver tags)
- ✅ Multi-arch support (amd64, arm64)
- ✅ release-please integration (automated releases)
- ✅ Issue templates (bug report, feature request)
- ✅ PR template

**Remaining Enhancements:**
- [ ] Add CI status badges to README:
  - [ ] Build status
  - [ ] Test coverage
  - [ ] Latest release version
- [ ] Add integration test run on pull requests (currently only on main)

**Impact:** Professional project image, better visibility of build status

---

### 4. Feature: Password Policy Configuration
**Estimated Effort:** 6-8 hours
**Source:** intern-implementation-guide.md (Priority 2)

**Implementation Steps:**
1. [ ] Update KeycloakRealm CRD with `password_policy` field:
   ```yaml
   security:
     password_policy: "length(12) and digits(1) and specialChars(1)"
   ```
2. [ ] Add Pydantic model validation in `KeycloakRealmSecurity`:
   - [ ] Validate policy directive format
   - [ ] Add field validator for common directives
3. [ ] Update realm reconciler to include password policy in realm config
4. [ ] Write unit tests for password policy validation
5. [ ] Write integration test: create realm with password policy
6. [ ] Document with examples in README.md:
   - [ ] Show common password policy patterns
   - [ ] Link to Keycloak password policy documentation

**Impact:** Declarative password security configuration, removes manual UI configuration

**Current Status:** NOT STARTED

---

## 📋 P2 - Medium Priority (Quality of Life)

### 1. Helm Chart for Operator Deployment
**Estimated Effort:** 1-2 days
**Source:** manual-todos (P2 Deployment)

- [ ] Create minimal Helm chart in `charts/keycloak-operator/`:
  - [ ] Chart.yaml with version and description
  - [ ] values.yaml with configurable options
  - [ ] Templates for deployment, RBAC, CRDs
  - [ ] README.md with installation instructions
- [ ] Add Helm installation to main README.md
- [ ] Test Helm chart installation on different K8s versions
- [ ] Consider publishing to Artifact Hub

**Impact:** Easier operator installation and upgrades

---

### 2. GitOps Integration Testing
**Estimated Effort:** 2-3 days
**Source:** phase6b-critical-production-blockers.todo (Integration Tests)

- [ ] Write GitOps workflow tests with ArgoCD:
  - [ ] Deploy operator via ArgoCD
  - [ ] Verify drift detection works
  - [ ] Test resource sync behavior
- [ ] Write GitOps workflow tests with Flux:
  - [ ] Deploy operator via Flux
  - [ ] Verify HelmRelease reconciliation
  - [ ] Test kustomization behavior
- [ ] Add multi-replica operator behavior tests:
  - [ ] Verify leader election works correctly
  - [ ] Test failover scenarios
- [ ] Add chaos engineering tests:
  - [ ] Pod failures during reconciliation
  - [ ] Network partition scenarios
  - [ ] Database connection failures

**Impact:** Confidence in production GitOps deployments

---

## 🚀 P3 - Low Priority (Future Enhancements)

### 1. CRD Design Improvements
**Estimated Effort:** 1-2 weeks
**Source:** manual-todos (CRD Design Improvements)

- [ ] Review and finalize `keycloak.spec.admin_access` least privilege model
- [ ] Consider operator env var formalization in CRD fields
- [ ] Review TLS configuration options for ingress integration

**Impact:** Cleaner API, better security defaults

**Note:** These are API-breaking changes - defer to v2.0

---

### 2. Feature: Authorization Services
**Estimated Effort:** 8-12 weeks (multi-phase project)
**Source:** intern-implementation-guide.md (Priority 4)

**This is a complex long-term project - break into phases:**

**Phase 1: Research and Design (2-3 weeks)**
- [ ] Study Keycloak Authorization Services documentation
- [ ] Analyze API endpoints in keycloak-api-spec.yaml
- [ ] Design CRD structure (embedded vs separate CRDs)
- [ ] Write design document with use cases
- [ ] Get design review approval

**Phase 2: Minimal Implementation (4-6 weeks)**
- [ ] Add `authorization_services_enabled` to KeycloakClient
- [ ] Implement basic resource management
- [ ] Add simple policy types (role-based, time-based)
- [ ] Write comprehensive tests
- [ ] Document with examples

**Phase 3: Advanced Features (4-6 weeks)**
- [ ] Complex policy types (JavaScript, aggregated)
- [ ] Permission management
- [ ] Scope management
- [ ] Policy evaluation APIs
- [ ] Performance optimization

**Impact:** Fine-grained API permissions (UMA 2.0), advanced authorization

**Current Status:** NOT STARTED - requires dedicated focus and Keycloak expertise

---

### 3. Integration Test with GitHub Actions
**Estimated Effort:** 1 week
**Source:** manual-todos (P0 Testing - marked future)

- [ ] Set up Kind cluster in GitHub Actions
- [ ] Run full integration test suite in CI
- [ ] Add test result reporting
- [ ] Cache Docker images for faster CI

**Impact:** Catch integration issues earlier

**Note:** Deferred until P1 CI/CD pipeline is complete

---

## 📊 Progress Summary

### Completed Recently
- ✅ Service Account Role Mappings (2025-10-01 to 2025-10-02)
- ✅ SMTP Configuration (2025-10-05, commit db554e6)
- ✅ Bug Fixes: Authentication and Validation (2025-10-03 to 2025-10-04)
- ✅ CRD-Pydantic Schema Alignment (2025-10-04, commit c06001b)
- ✅ Finalizers and Cascading Deletion (2025-10-04)
- ✅ Production Mode Switch (2025-10-05, commit 1e64bc9)
- ✅ ObservedGeneration Tracking (completed)
- ✅ Leader Election (completed)
- ✅ H2 Database Removal (completed)
- ✅ CRD Design Improvements: version and enabled field removal (2025-10-05, commit 11cdf60)
- ✅ Complete CI/CD Pipeline (2025-10-05, commit d61348b):
  - GitHub Actions workflows (quality, tests, integration)
  - ghcr.io image publishing with multi-arch support
  - release-please integration
  - Issue and PR templates
- ✅ **Complete Keycloak API Model Integration (2025-10-05)**:
  - Updated 19 admin client methods with typed Pydantic models
  - All quality checks passing, 167 unit tests passing
  - Comprehensive documentation with usage examples

### Current Focus Areas
1. **Secret Rotation Handling** (P0) - 1-2 days for automatic secret watches
2. **Documentation Improvements** (P1) - 1 week effort (MkDocs site, status section, etc.)
3. **Password Policy Feature** (P1) - 6-8 hours effort
4. **Consistent Event Emission** (P1) - 1 day for better observability

### Estimated Time to v1.0
- **Critical items (P0):** 1-2 days (just secret rotation!)
- **High priority items (P1):** ~1.5 weeks (API model integration done!)
- **Total to production readiness:** ~2 weeks 🎉

---

## 📝 Notes

### Recently Removed (Completed)
The following TODO files were completed and removed on 2025-10-05:
- `bug-fixes-authentication-and-validation.md` (all bugs fixed)
- `crd-model-schema-mismatches.md` (all mismatches resolved)
- `smtp-configuration-implementation.md` (feature completed)

### GitOps SRE Review Recommendations
Most recommendations from the 2025-01-29 GitOps SRE review have been addressed:
- ✅ Finalizers implemented
- ✅ ObservedGeneration tracking
- ✅ Leader election
- ✅ Database validation issues addressed
- ⚠️ Some medium-priority recommendations remain (NetworkPolicy, secret rotation)

See `gitops-sre-comprehensive-review.md` for detailed review notes (historical reference).

### Organization
- Keep this file updated as items are completed
- Archive completed items in the "Recently Removed" section
- Review quarterly to reassess priorities
- Move items between priority levels as needed

---

**Last Review:** 2025-10-05
**Next Review:** 2025-11-05 (monthly review cycle)
