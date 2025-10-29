# Implementation Plan: Rate Limiting & Async Conversion

## Overview

This plan addresses issue #31 by implementing comprehensive rate limiting for Keycloak API calls and converting the entire codebase to async/await pattern.

## Problem Statement

The Keycloak operator is susceptible to:
1. **API flooding** after operator restart (all resources reconcile simultaneously)
2. **Database connection loss** triggering mass reconciliation attempts
3. **DDoS attacks** via spam creation of realms/clients (1000s of resources)

## Solution Architecture

### Three-Layer Protection Strategy

#### Layer 1: Global Rate Limiting
- **Purpose**: Protect Keycloak from total overload
- **Implementation**: Token bucket algorithm at global scope
- **Configuration**: `KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS` (default: 50 req/s)
- **Burst capacity**: `KEYCLOAK_API_GLOBAL_BURST` (default: 100)

#### Layer 2: Per-Namespace Rate Limiting
- **Purpose**: Fair resource allocation across teams/namespaces
- **Implementation**: Token bucket per origin namespace
- **Configuration**: `KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS` (default: 5 req/s)
- **Burst capacity**: `KEYCLOAK_API_NAMESPACE_BURST` (default: 10)
- **Key insight**: Namespace = the resource's origin, not Keycloak instance location

#### Layer 3: Jitter & Backoff
- **Purpose**: Prevent thundering herd on operator restart
- **Implementation**: Random delay (0-5s) at reconciliation start
- **Configuration**: `RECONCILE_JITTER_MAX_SECONDS` (default: 5.0)

### Example Scenarios Protected

| Scenario | Protection Mechanism |
|----------|---------------------|
| Creating 1000 realms in `team-a` namespace | Namespace rate limit (5 req/s) = 200 seconds minimum |
| 20 teams each creating 100 realms | Global rate limit (50 req/s) enforces fair sharing |
| Operator restart with 50+ resources | Jitter spreads reconciliation over 0-5s window + rate limits |
| Database connection loss | Circuit breaker + rate limiting prevents API hammering |

## Implementation Phases

### Phase 1: Core Infrastructure ✅ COMPLETED

**Status**: Committed in `b8309ff`

**Completed Work**:
- ✅ Rate limiter module (`src/keycloak_operator/utils/rate_limiter.py`)
  - Token bucket implementation with async locks
  - Two-level rate limiting (global + namespace)
  - Idle bucket cleanup for memory management
  - Metrics-ready design
- ✅ Configuration constants in `constants.py`
- ✅ Operator startup handler integration via `kopf.Memo`

**Testing**: Unit tests needed for token bucket algorithm

---

### Phase 2: Async Conversion - KeycloakAdminClient

**File**: `src/keycloak_operator/utils/keycloak_admin.py` (~1920 lines)

**Priority**: CRITICAL (blocks all other phases)

#### Changes Required

1. **Replace HTTP library**
   ```python
   # OLD: requests.Session (sync)
   import requests
   self.session = requests.Session()

   # NEW: aiohttp.ClientSession (async)
   import aiohttp
   self.session = aiohttp.ClientSession()
   ```

2. **Add rate limiter integration**
   ```python
   def __init__(self, ..., rate_limiter: RateLimiter | None = None):
       self.rate_limiter = rate_limiter
   ```

3. **Convert authentication**
   ```python
   # OLD
   def authenticate(self) -> None:
       response = self.session.post(auth_url, data=auth_data)

   # NEW
   async def authenticate(self) -> None:
       async with self.session.post(auth_url, data=auth_data) as response:
           token_data = await response.json()
   ```

4. **Convert _make_request (core method)**
   ```python
   # OLD
   def _make_request(self, method: str, endpoint: str, ...) -> requests.Response:
       self._ensure_authenticated()
       response = self.session.request(method=method, url=url, ...)

   # NEW
   async def _make_request(
       self,
       method: str,
       endpoint: str,
       namespace: str,  # NEW: for rate limiting
       ...
   ) -> aiohttp.ClientResponse:
       await self._ensure_authenticated()

       # Apply rate limiting
       if self.rate_limiter:
           await self.rate_limiter.acquire(namespace)

       async with self.session.request(method=method, url=url, ...) as response:
           return response
   ```

5. **Convert all 40+ public methods**
   - `create_realm()` → `async def create_realm()`
   - `get_realm()` → `async def get_realm()`
   - `update_realm()` → `async def update_realm()`
   - `delete_realm()` → `async def delete_realm()`
   - (37 more methods...)

6. **Update circuit breaker**
   - Option A: Remove `pybreaker` (already have rate limiting)
   - Option B: Find async-compatible circuit breaker library
   - **Recommendation**: Remove, rate limiter provides sufficient protection

7. **Error handling migration**
   ```python
   # OLD
   except requests.HTTPError as e:
       status_code = e.response.status_code

   # NEW
   except aiohttp.ClientResponseError as e:
       status_code = e.status
   ```

#### Estimated Impact
- **Lines changed**: ~250 lines
- **Methods converted**: 40 methods
- **Risk**: HIGH (core infrastructure)
- **Testing**: Extensive unit tests required

---

### Phase 3: Update Reconciler Classes

**Files**:
- `src/keycloak_operator/services/keycloak_instance_reconciler.py`
- `src/keycloak_operator/services/keycloak_realm_reconciler.py`
- `src/keycloak_operator/services/keycloak_client_reconciler.py`

**Priority**: HIGH (required for handlers)

#### Changes Required

1. **Add rate limiter to constructor**
   ```python
   class KeycloakRealmReconciler:
       def __init__(self, rate_limiter: RateLimiter | None = None):
           self.rate_limiter = rate_limiter
   ```

2. **Convert all methods to async**
   ```python
   # OLD
   def reconcile(self, name: str, namespace: str, ...) -> dict:

   # NEW
   async def reconcile(self, name: str, namespace: str, ...) -> dict:
   ```

3. **Update admin client usage**
   ```python
   # OLD
   admin_client = get_keycloak_admin_client(...)
   realm = admin_client.get_realm(realm_name)

   # NEW
   admin_client = await get_keycloak_admin_client(
       ...,
       rate_limiter=self.rate_limiter,
   )
   realm = await admin_client.get_realm(realm_name, namespace=namespace)
   ```

4. **Pass namespace through all API calls**
   - Namespace = resource origin (for rate limiting)
   - Not the Keycloak instance namespace!

#### Estimated Impact
- **Lines changed**: ~100 lines across 3 files
- **Methods converted**: ~15 methods per file
- **Risk**: MEDIUM (business logic)

---

### Phase 4: Update All Handlers

**Files**:
- `src/keycloak_operator/handlers/keycloak.py`
- `src/keycloak_operator/handlers/realm.py`
- `src/keycloak_operator/handlers/client.py`
- `src/keycloak_operator/handlers/token_rotation.py`

**Priority**: HIGH (user-facing)

#### Changes Required

1. **Add kopf.Memo parameter**
   ```python
   # OLD
   @kopf.on.create("keycloakrealms", ...)
   async def ensure_keycloak_realm(
       spec: dict, name: str, namespace: str, **kwargs
   ):

   # NEW
   @kopf.on.create("keycloakrealms", ...)
   async def ensure_keycloak_realm(
       spec: dict,
       name: str,
       namespace: str,
       memo: kopf.Memo,  # NEW
       **kwargs
   ):
   ```

2. **Add jitter at handler entry**
   ```python
   import random
   import asyncio
   from keycloak_operator.constants import RECONCILE_JITTER_MAX

   async def ensure_keycloak_realm(...):
       # Add jitter to prevent thundering herd
       jitter = random.uniform(0, RECONCILE_JITTER_MAX)
       await asyncio.sleep(jitter)

       # Continue with reconciliation...
   ```

3. **Pass rate limiter to reconcilers**
   ```python
   reconciler = KeycloakRealmReconciler(rate_limiter=memo.rate_limiter)
   await reconciler.reconcile(
       name=name,
       namespace=namespace,  # This is the rate limit key!
       spec=spec,
       ...
   )
   ```

4. **Update all handler types**
   - `@kopf.on.create` handlers
   - `@kopf.on.update` handlers
   - `@kopf.on.delete` handlers
   - `@kopf.on.resume` handlers
   - `@kopf.timer` handlers

#### Estimated Impact
- **Lines changed**: ~60 lines across 4 files
- **Handlers updated**: ~15 handlers
- **Risk**: MEDIUM (user-facing)

---

### Phase 5: Update Helper Functions

**File**: `src/keycloak_operator/utils/keycloak_admin.py`

**Function**: `get_keycloak_admin_client()`

**Priority**: HIGH (used by all reconcilers)

#### Changes Required

```python
# OLD
def get_keycloak_admin_client(
    keycloak_name: str,
    keycloak_namespace: str,
    namespace: str,
) -> KeycloakAdminClient:
    # ... get credentials ...
    return KeycloakAdminClient(
        server_url=server_url,
        username=username,
        password=password,
    )

# NEW
async def get_keycloak_admin_client(
    keycloak_name: str,
    keycloak_namespace: str,
    namespace: str,
    rate_limiter: RateLimiter | None = None,  # NEW
) -> KeycloakAdminClient:
    # ... get credentials ...
    return KeycloakAdminClient(
        server_url=server_url,
        username=username,
        password=password,
        rate_limiter=rate_limiter,  # NEW
    )
```

#### Estimated Impact
- **Lines changed**: ~10 lines
- **Risk**: LOW

---

### Phase 6: Add Prometheus Metrics

**File**: `src/keycloak_operator/observability/metrics.py`

**Priority**: MEDIUM (observability)

#### Metrics to Add

```python
from prometheus_client import Counter, Histogram, Gauge

# Rate limit wait time
rate_limit_wait_seconds = Histogram(
    'keycloak_api_rate_limit_wait_seconds',
    'Time spent waiting for rate limit tokens',
    ['namespace', 'limit_type'],  # limit_type: 'global' or 'namespace'
    buckets=[0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

# Token acquisitions
rate_limit_acquired_total = Counter(
    'keycloak_api_rate_limit_acquired_total',
    'Total rate limit tokens acquired',
    ['namespace', 'limit_type']
)

# Timeouts
rate_limit_timeouts_total = Counter(
    'keycloak_api_rate_limit_timeouts_total',
    'Rate limit timeout errors',
    ['namespace', 'limit_type']
)

# Available tokens (current state)
rate_limit_tokens_available = Gauge(
    'keycloak_api_tokens_available',
    'Currently available rate limit tokens',
    ['namespace']  # empty string for global bucket
)
```

#### Integration Points

Update `rate_limiter.py` to record metrics:
```python
async def acquire(self, namespace: str, timeout: float = 30.0) -> None:
    start_time = time.monotonic()

    # Acquire tokens...

    # Record metrics
    wait_time = time.monotonic() - start_time
    rate_limit_wait_seconds.labels(
        namespace=namespace,
        limit_type='namespace'
    ).observe(wait_time)

    rate_limit_acquired_total.labels(
        namespace=namespace,
        limit_type='namespace'
    ).inc()
```

#### Estimated Impact
- **Lines changed**: ~50 lines
- **Risk**: LOW

---

### Phase 7: Comprehensive Testing

**Priority**: CRITICAL (quality assurance)

#### Unit Tests

**File**: `tests/unit/test_rate_limiter.py` (NEW)

Test coverage:
- ✅ Token bucket refill rate accuracy
- ✅ Burst capacity enforcement
- ✅ Two-level (global + namespace) interaction
- ✅ Timeout behavior
- ✅ Concurrent access (multiple async tasks)
- ✅ Idle bucket cleanup

**File**: `tests/unit/test_async_keycloak_admin.py` (NEW)

Test coverage:
- ✅ Async authentication flow
- ✅ Rate limiter integration
- ✅ Error handling (aiohttp exceptions)
- ✅ All CRUD operations (mocked)

#### Integration Tests

**File**: `tests/integration/test_rate_limiting.py` (NEW)

Test scenarios:
- ✅ **Single namespace spam**: Create 100 realms in one namespace
  - Expected: Rate limited to ~5 req/s (namespace limit)
  - Duration: ~20 seconds minimum

- ✅ **Multi-namespace load**: 10 namespaces creating 10 realms each
  - Expected: Rate limited to 50 req/s (global limit)
  - Fair distribution across namespaces

- ✅ **Operator restart simulation**: 50 existing resources reconcile
  - Expected: Jitter spreads reconciliation over 0-5s
  - Rate limiting prevents API flood

- ✅ **Circuit breaker interaction**: Simulate Keycloak downtime
  - Expected: Rate limiter timeouts, not infinite retries

**File**: `tests/integration/test_async_handlers.py` (MODIFY)

Update existing integration tests:
- Verify handlers still work after async conversion
- Check jitter doesn't break reconciliation
- Ensure rate limiting doesn't cause test timeouts

#### Estimated Impact
- **New test files**: 3 files
- **Lines of test code**: ~500 lines
- **Test execution time**: +5 minutes (rate limiting waits)
- **Risk**: None (tests only)

---

### Phase 8: Documentation Updates

**Files to update**:
- `README.md` - Add rate limiting section
- `CLAUDE.md` - Document async patterns
- `docs/architecture.md` - Rate limiting design (if exists)

#### README.md Addition

```markdown
## Rate Limiting

The operator implements two-level rate limiting to protect Keycloak:

### Configuration

```yaml
env:
  # Global rate limit (all namespaces combined)
  - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
    value: "50"  # requests per second
  - name: KEYCLOAK_API_GLOBAL_BURST
    value: "100"  # burst capacity

  # Per-namespace rate limit (fair sharing)
  - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
    value: "5"  # requests per second
  - name: KEYCLOAK_API_NAMESPACE_BURST
    value: "10"  # burst capacity

  # Jitter to prevent thundering herd
  - name: RECONCILE_JITTER_MAX_SECONDS
    value: "5.0"  # 0-5 second random delay
```

### Monitoring

Prometheus metrics available at `:8081/metrics`:
- `keycloak_api_rate_limit_wait_seconds` - Time waiting for tokens
- `keycloak_api_rate_limit_acquired_total` - Successful token acquisitions
- `keycloak_api_rate_limit_timeouts_total` - Rate limit timeout errors
- `keycloak_api_tokens_available` - Current available tokens per namespace

### Protection Scenarios

| Scenario | Protection |
|----------|-----------|
| Spam 1000 realms in one namespace | Limited to 5 req/s = 200s minimum |
| Multiple teams overwhelming Keycloak | Global 50 req/s enforced |
| Operator restart (50+ resources) | Jitter + rate limiting prevents flood |
```

#### Estimated Impact
- **Lines changed**: ~100 lines across 3 files
- **Risk**: None

---

## Implementation Timeline

### Week 1: Core Conversion
- Day 1-2: Phase 2 (KeycloakAdminClient async conversion)
- Day 3: Phase 3 (Reconcilers async conversion)
- Day 4: Phase 4 (Handlers update)
- Day 5: Phase 5 (Helper functions)

### Week 2: Testing & Polish
- Day 1-2: Phase 7 (Unit tests)
- Day 3-4: Phase 7 (Integration tests)
- Day 5: Phase 6 (Metrics) + Phase 8 (Documentation)

## Risk Mitigation

### High-Risk Changes
- **KeycloakAdminClient conversion**: Core infrastructure
  - Mitigation: Comprehensive unit tests with mocked HTTP
  - Rollback: Keep old sync version in git history

- **Integration test timeouts**: Rate limiting adds delays
  - Mitigation: Adjust test timeouts, use test-specific rate limits
  - Solution: Environment variable overrides for tests

### Testing Strategy
1. ✅ Unit tests first (fast feedback)
2. ✅ Integration tests with single resource (smoke test)
3. ✅ Integration tests with rate limiting scenarios
4. ✅ Load testing (100+ resources)

## Success Criteria

### Functional Requirements
- ✅ All handlers remain functional after async conversion
- ✅ Rate limiting prevents API flooding (measured in tests)
- ✅ Namespace fairness enforced (one namespace can't monopolize)
- ✅ Operator restart doesn't cause API flood

### Performance Requirements
- ✅ Reconciliation latency < 5 seconds (excluding rate limit waits)
- ✅ Rate limiting overhead < 10ms per request
- ✅ Memory usage stable (idle bucket cleanup works)

### Quality Requirements
- ✅ 90%+ test coverage on new code
- ✅ All existing integration tests pass
- ✅ No regressions in functionality
- ✅ Documentation updated

## Configuration Examples

### Development (Permissive)
```yaml
env:
  - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
    value: "100"
  - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
    value: "20"
  - name: RECONCILE_JITTER_MAX_SECONDS
    value: "1.0"
```

### Production (Conservative)
```yaml
env:
  - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
    value: "50"
  - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
    value: "5"
  - name: RECONCILE_JITTER_MAX_SECONDS
    value: "5.0"
```

### Testing (Fast)
```yaml
env:
  - name: KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS
    value: "1000"
  - name: KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS
    value: "1000"
  - name: RECONCILE_JITTER_MAX_SECONDS
    value: "0.1"
```

## Rollout Plan

### Phase 1: Development Branch ✅
- Current status: In progress on `feat/rate-limiting-async`
- Merge strategy: PR with comprehensive review

### Phase 2: Staging Deployment
- Deploy to test cluster
- Run load tests (100+ realms)
- Monitor metrics for 48 hours

### Phase 3: Canary Production
- Deploy to 1 production cluster
- Monitor for 1 week
- Gradually increase rate limits if stable

### Phase 4: Full Rollout
- Deploy to all production clusters
- Update default Helm chart values
- Announce in release notes

## Open Questions

1. **Circuit breaker removal**: Remove `pybreaker` dependency?
   - Recommendation: Yes, rate limiting provides sufficient protection

2. **Rate limit for timers**: Apply rate limiting to timer-based reconciliation?
   - Recommendation: Yes, timers should also be rate limited

3. **Per-resource type limits**: Different limits for realms vs clients?
   - Recommendation: Start with uniform limits, add later if needed

4. **Metrics cardinality**: Expose per-namespace metrics?
   - Recommendation: Yes, but add cardinality limit (top 100 namespaces)

## References

- Issue: #31
- Related PRs: None yet
- Design discussions: This document
