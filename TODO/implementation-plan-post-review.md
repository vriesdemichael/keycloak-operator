# Implementation Plan: Post-SRE Review
**Date:** 2025-10-15
**Context:** Corrections applied to initial review - several items were misunderstood and are NOT issues

## Review Corrections (NOT Issues)
- ✅ **Status conditions already exist** in models (`KeycloakCondition`, `KeycloakRealmCondition`) - VERIFIED
- ✅ **Multi-tenancy isolation via secrets is correct** - realm-based with authorization tokens is the design
- ✅ **Python dependency management is fine** - Docker + uv.lock + simple dependencies mitigate concerns
- ✅ **Container size 330MB** not 500MB (acceptable for Python)
- ✅ **Secret-based authorization is better than RBAC** - enables delegation without operator RBAC changes (scalable)
- ✅ **Retry logic is correct** - TemporaryError retries, PermanentError doesn't (by design)
- ✅ **CNPG treated as generic PostgreSQL** - correct abstraction level

---

## P0: Critical for v1.0 (4-5 weeks)

### 1. Verify Status Conditions Population (3 days)
**Status:** Models have conditions, need to verify reconcilers populate them correctly

**Task:**
- Audit all reconcilers to ensure they call `_add_condition()` with proper condition types
- Ensure at minimum these conditions are set:
  - `Ready` (True/False/Unknown)
  - `Reconciling` (set during reconciliation, removed after)
  - `Available` (for failed states)
- Test with Argo CD or Flux CD to verify health detection works
- Document condition types in CRD descriptions

**Files to check:**
- `src/keycloak_operator/services/keycloak_reconciler.py` - verify conditions are set
- `src/keycloak_operator/services/realm_reconciler.py` - verify conditions are set
- `src/keycloak_operator/services/client_reconciler.py` - verify conditions are set

**Acceptance criteria:**
- Argo CD shows proper health status for Keycloak/Realm/Client resources
- All status transitions set appropriate conditions

---

### 2. Implement Circuit Breaker (3-4 days)
**Problem:** Keycloak API calls can hammer external service if it's down

**Task:**
- Add `pybreaker` dependency to `pyproject.toml`
- Wrap Keycloak Admin API calls in circuit breaker
- Configure thresholds:
  - `failure_threshold=5` - open circuit after 5 failures
  - `recovery_timeout=60` - try again after 60 seconds
- Update reconcilers to handle `CircuitBreakerError` as `TemporaryError`
- Add tests for circuit breaker behavior

**Files to modify:**
- `pyproject.toml` - add pybreaker dependency
- `src/keycloak_operator/utils/keycloak_admin.py` - wrap HTTP methods with circuit breaker
- `src/keycloak_operator/services/*_reconciler.py` - handle circuit breaker errors
- `tests/unit/test_circuit_breaker.py` - new test file

**Example implementation:**
```python
from pybreaker import CircuitBreaker

# In KeycloakAdminClient.__init__
self.breaker = CircuitBreaker(
    fail_max=5,
    timeout_duration=60,
    exclude=[ValidationError]  # Don't count validation errors
)

# Wrap methods
def _make_request(self, method: str, endpoint: str, **kwargs):
    try:
        return self.breaker.call(self._http_request, method, endpoint, **kwargs)
    except CircuitBreakerError:
        raise TemporaryError("Circuit breaker open - Keycloak API unavailable")
```

---

### 3. Add Exponential Backoff (2 days)
**Problem:** Kopf retries immediately on failure, should use exponential backoff

**Task:**
- Add `backoff` parameter to all Kopf handlers
- Use `backoff=1.5` for exponential backoff (1s, 1.5s, 2.25s, 3.375s, ...)
- Document retry behavior in code comments

**Files to modify:**
- `src/keycloak_operator/handlers/keycloak_handlers.py`
- `src/keycloak_operator/handlers/realm_handlers.py`
- `src/keycloak_operator/handlers/client_handlers.py`

**Example:**
```python
# Before
@kopf.on.create('keycloaks')
async def create_keycloak(spec, **kwargs):
    ...

# After
@kopf.on.create('keycloaks', backoff=1.5)
async def create_keycloak(spec, **kwargs):
    # Retries with exponential backoff: 1s, 1.5s, 2.25s, etc.
    ...
```

---

### 4. Document & Test Upgrade Strategy (1 week)
**Problem:** No documented upgrade path, no tests for operator upgrades

**Task:**
- Create `docs/operations/upgrades.md` with upgrade procedures
- Test upgrade scenario: deploy v0.2.x → upgrade to current version
- Verify existing Keycloak/Realm/Client resources survive operator restart
- Add upgrade test to CI
- Document CRD upgrade process (kubectl apply vs helm upgrade)

**Files to create:**
- `docs/operations/upgrades.md` - upgrade documentation
- `tests/integration/test_operator_upgrade.py` - upgrade test

**Upgrade doc should cover:**
1. Backup recommendations (etcd backup, resource export)
2. CRD upgrade process (must update CRDs before operator)
3. Helm chart upgrade command
4. Rollback procedure
5. Version compatibility matrix

---

## P1: Important for v1.0 (2-3 weeks)

### 5. Operational Runbook (3-4 days)
**Task:** Create comprehensive operational documentation

**Files to create:**
- `docs/operations/runbook.md` - main runbook
- `docs/operations/troubleshooting.md` - troubleshooting guide
- `docs/operations/monitoring.md` - monitoring setup

**Runbook sections:**
1. **Common Failure Scenarios**
   - Keycloak pod not starting (database connection, image pull, resource limits)
   - Realm reconciliation stuck in Pending
   - Client creation fails with 409 Conflict
   - Operator pod crashlooping

2. **Database Operations**
   - Database migration during Keycloak upgrade
   - Connection pool exhaustion
   - CNPG cluster recovery

3. **Keycloak Version Upgrades**
   - Backup database before upgrade
   - Update image in Keycloak CR
   - Monitor startup probes
   - Verify realms/clients still work

4. **Disaster Recovery**
   - Restore from CNPG backup
   - Re-import realms from Git
   - Regenerate authorization tokens

---

### 6. Security Model Documentation (2 days)
**Task:** Explain the secret-based authorization design (this is a STRENGTH, not weakness)

**Files to create:**
- `docs/security.md` - security model documentation
- `docs/architecture/authorization.md` - detailed authorization design

**Documentation should explain:**
1. **Why Secret-Based vs RBAC**
   - Scalability: Delegate to 100 teams without touching operator RBAC
   - No GitOps bottleneck for new teams
   - Secret acts as capability token (bearer token pattern)

2. **Security Properties**
   - Operator generates cryptographically random tokens
   - Tokens stored in K8s secrets (encrypted at rest if cluster configured)
   - Realm-level isolation (token grants access to specific Keycloak instance)
   - Cross-namespace references validated via token

3. **Best Practices**
   - Rotate authorization tokens periodically
   - Use External Secrets Operator for Vault integration (if needed)
   - NetworkPolicy examples to restrict access
   - Audit logging recommendations

4. **Delegation Workflow**
   ```bash
   # Platform team creates Keycloak instance
   kubectl apply -f keycloak.yaml

   # Operator generates token, stores in secret
   # Platform team shares secret with app team
   kubectl get secret keycloak-auth-token -n platform -o yaml | \
     kubectl apply -n app-team -f -

   # App team can now create realms without platform team involvement
   kubectl apply -f realm.yaml
   ```

---

### 7. Monitoring Dashboard (2 days)
**Task:** Create Grafana dashboard for operator observability

**Files to create:**
- `k8s/monitoring/grafana-dashboard.json` - Grafana dashboard definition
- `k8s/monitoring/prometheus-rules.yaml` - Prometheus alert rules
- `docs/operations/monitoring.md` - monitoring setup guide

**Dashboard panels:**
1. **Reconciliation Metrics**
   - Reconciliation success/failure rate (per resource type)
   - Reconciliation duration (p50, p95, p99)
   - Queue depth / pending reconciliations

2. **Resource Counts**
   - Total Keycloaks (by phase: Ready, Pending, Failed)
   - Total Realms (by phase)
   - Total Clients (by phase)

3. **External Dependencies**
   - Keycloak API latency
   - Database connection pool usage
   - Circuit breaker state (open/closed)

4. **Operator Health**
   - Leader election status
   - Pod restarts
   - Memory/CPU usage

**Alert rules:**
- Reconciliation failure rate >10% for 5 minutes
- No Ready Keycloak instances (all Failed/Pending)
- Circuit breaker open for >5 minutes
- Operator pod crashlooping

---

## P2: Nice-to-Have (Post-v1.0)

### 8. Quick Start Guide (2 days)
**Task:** Add comprehensive getting started guide to README

**Files to modify:**
- `README.md` - add "Quick Start" section at top
- Create `examples/quickstart/` directory with manifests

**Quick start should cover:**
1. **5-minute setup**
   ```bash
   # Install operator
   helm install keycloak-operator charts/keycloak-operator/

   # Create Keycloak instance
   kubectl apply -f examples/quickstart/keycloak.yaml

   # Create realm
   kubectl apply -f examples/quickstart/realm.yaml

   # Create OIDC client
   kubectl apply -f examples/quickstart/client.yaml

   # Get client credentials
   kubectl get secret my-client-credentials -o yaml
   ```

2. **Example manifests**
   - `examples/quickstart/keycloak.yaml` - minimal Keycloak with CNPG
   - `examples/quickstart/realm.yaml` - basic realm
   - `examples/quickstart/client.yaml` - OIDC client for web app

---

### 9. Performance Testing (1 week)
**Task:** Add load tests to understand performance characteristics

**Files to create:**
- `tests/performance/test_load.py` - performance test suite
- `docs/performance.md` - performance characteristics documentation

**Tests to add:**
1. **Keycloak instance creation**
   - Create 50 Keycloak instances simultaneously
   - Measure time to all Ready
   - Expected: ~60s Keycloak startup × 50 / 20 workers = ~150s

2. **Realm creation**
   - Create 100 realms across 10 Keycloak instances
   - Measure reconciliation latency
   - Expected: <5s per realm

3. **Client creation**
   - Create 1000 clients across realms
   - Measure throughput (clients/second)
   - Expected: ~10-20 clients/second

**Document findings:**
- Maximum recommended Keycloaks per operator pod
- Maximum realms per Keycloak before performance degrades
- Scaling recommendations (horizontal scaling with Kopf peering)

---

## Summary of Main Actions (Priority Order)

### Must Do for v1.0 (P0):
1. ✅ Verify status conditions are populated correctly (3 days)
2. ✅ Implement circuit breaker for Keycloak API (3-4 days)
3. ✅ Add exponential backoff to Kopf handlers (2 days)
4. ✅ Document and test upgrade strategy (1 week)

**Total P0 effort:** ~3 weeks

### Should Do for v1.0 (P1):
5. ✅ Write operational runbook (3-4 days)
6. ✅ Document security model (2 days)
7. ✅ Create monitoring dashboard (2 days)

**Total P1 effort:** ~1.5 weeks

### Nice to Have (P2):
8. Quick start guide (2 days)
9. Performance testing (1 week)

**Total P2 effort:** ~1.5 weeks

---

## Context for Fresh Implementation

### Project Architecture
- **Language:** Python 3.12 with `uv` package manager
- **Framework:** Kopf (Kubernetes Operator Framework)
- **Type Safety:** Pydantic models throughout (including auto-generated from Keycloak OpenAPI spec)
- **Testing:** pytest with Kind clusters, parallel execution with pytest-xdist
- **CRDs:** Keycloak, KeycloakRealm, KeycloakClient
- **Database:** CloudNativePG (CNPG) for PostgreSQL

### Key Files
- `src/keycloak_operator/operator.py` - Main entry point with Kopf handlers registration
- `src/keycloak_operator/services/*_reconciler.py` - Reconciliation logic
- `src/keycloak_operator/services/base_reconciler.py` - Base class with `_add_condition()` helper
- `src/keycloak_operator/utils/keycloak_admin.py` - Keycloak Admin API client (1885 lines)
- `src/keycloak_operator/models/*.py` - Pydantic models for CRDs
- `src/keycloak_operator/handlers/*.py` - Kopf event handlers

### Current Status
- Core functionality complete: Keycloak, Realm, Client CRUD works
- RBAC v2 is acknowledged as in-progress (separate effort)
- Status conditions exist in models but need verification they're populated
- Error hierarchy exists (TemporaryError, PermanentError) and works correctly
- Integration tests comprehensive but missing upgrade/performance tests

### Development Commands
```bash
# Code quality
make quality  # Runs ruff check, mypy, ruff format

# Testing
make test-unit              # Fast unit tests
make test-integration       # Integration tests (uses existing Kind cluster)
make test-integration-clean # Fresh Kind cluster

# Deployment
make deploy-local  # Deploy current code to existing cluster
make deploy        # Full deployment (creates cluster if needed)

# Monitoring
make operator-logs        # Show last 200 lines
make operator-status      # Check deployment status
```

### Don't Reinvent
- ✅ Status condition models exist - just verify they're used
- ✅ Error hierarchy works - don't change it
- ✅ Secret-based authorization is correct - document it, don't replace it
- ✅ CNPG integration is correct - don't add special handling

### Focus Areas
1. **Resilience:** Circuit breaker + exponential backoff
2. **Operations:** Runbooks + monitoring + upgrade docs
3. **Communication:** Explain the secret delegation pattern (it's a feature!)
4. **Testing:** Upgrade tests + performance tests
