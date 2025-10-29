# Keycloak State Observability - Design Analysis

**Date**: 2025-10-16
**Status**: Design Discussion
**Priority**: To be determined

## Context

Currently, the operator only exposes metrics about its own operation (reconciliation success/failure, circuit breaker state, etc.). We have no visibility into the actual state of Keycloak instances beyond what's reflected in CR status conditions.

This document analyzes what Keycloak state observability we should expose, from an SRE and security perspective.

## Current State

**What we have:**
- ✅ Operator metrics (reconciliation, circuit breaker, errors)
- ✅ CR status conditions (Ready/Failed/Degraded)
- ✅ ObservedGeneration for GitOps sync detection
- ❌ No visibility into actual Keycloak state
- ❌ No drift detection between CRs and Keycloak reality
- ❌ No operational metrics (users, sessions, usage patterns)

## The Observability Question

Should we expose Keycloak's internal state as metrics? If so, what?

### Approach 1: CRs as Single Source of Truth (Current)

**Philosophy**: "If it's not in Git, it doesn't exist"

The operator enforces desired state. What matters is whether reconciliation succeeds, not what's actually in Keycloak.

**Pros:**
- Clean GitOps model - CRs are the truth
- No drift by design (operator enforces state)
- Security: Don't expose Keycloak internals
- Simple: `kubectl get` tells you everything
- No additional API load on Keycloak

**Cons:**
- **Blind to manual changes** - If someone modifies Keycloak via UI, we don't know
- **No visibility into users** - Runtime data (users, sessions) not in CRs
- **Can't detect external modifications** - Someone bypassing operator entirely
- **Usage metrics missing** - Active sessions, login rates, token grants
- **Capacity planning hard** - No growth trends

### Approach 2: Expose Keycloak State as Metrics

**Philosophy**: "Trust but verify" - Expose actual state for drift detection and operational visibility

**What to expose:**

```prometheus
# Configuration drift detection
keycloak_operator_realm_drift_detected{realm="my-app", namespace="default"} 0|1
keycloak_operator_client_drift_detected{client="my-client", realm="my-app"} 0|1

# Inventory (no sensitive data)
keycloak_realms_total 15
keycloak_clients_total{realm="my-app"} 12
keycloak_users_total{realm="my-app"} 1523
keycloak_active_sessions{realm="my-app"} 45
keycloak_identity_providers_total{realm="my-app"} 3

# Usage patterns (for capacity planning)
keycloak_login_attempts_total{realm="my-app", status="success|failure"}
keycloak_token_grants_total{realm="my-app", client="my-client"}
keycloak_user_registrations_total{realm="my-app"}

# Health indicators
keycloak_database_connection_pool_active{instance="keycloak-0"}
keycloak_admin_api_latency_seconds{operation="create_client"}
```

**Pros:**
- **Drift detection** - Alert when Keycloak state doesn't match CRs
- **Operational visibility** - Know what's actually running
- **Security monitoring** - Detect unauthorized changes
- **Capacity planning** - User growth, session trends
- **Audit support** - Evidence of actual state
- **Troubleshooting** - See the real state when debugging

**Cons:**
- **Complexity** - Need to scrape Keycloak Admin API regularly
- **Security risk** - Exposing tenant counts could be info leak
- **Performance** - Frequent API calls to Keycloak
- **Coupling** - Operator becomes state observer, not just reconciler
- **Cardinality** - Many realms/clients = metric explosion

## Recommended Approach: Hybrid Three-Tier Model

### Tier 1: Always Expose (Low Risk, High Value)

**Default: Enabled**

```prometheus
# Drift detection - CRITICAL for security
keycloak_operator_config_drift_detected{type="realm|client", name="...", namespace="..."}

# Inventory counts - for operational visibility
keycloak_realms_total
keycloak_clients_total{realm="..."}
keycloak_identity_providers_total{realm="..."}

# Health metrics - for reliability
keycloak_admin_api_available{instance="..."}
keycloak_admin_api_latency_seconds{operation="..."}
```

**Rationale:**
- **Drift detection is security critical** - Must know if someone bypasses operator
- **Inventory counts are operationally necessary** - Need to know scale
- **Health metrics are reliability requirements** - Need to know API is working
- **Low cardinality** - Limited number of metrics
- **No privacy concerns** - Just counts, no PII

### Tier 2: Opt-In via Helm Values (Privacy Sensitive)

**Default: Disabled**

```yaml
# values.yaml
monitoring:
  keycloakMetrics:
    enabled: false  # Must explicitly enable
    includeUserCounts: false
    includeSessionMetrics: false
    includeLoginMetrics: false
```

```prometheus
# User counts (may reveal tenant size)
keycloak_users_total{realm="..."}

# Session data (could indicate company size/activity)
keycloak_active_sessions{realm="..."}

# Login patterns (could reveal usage patterns)
keycloak_login_attempts_total{realm="...", status="..."}
```

**Rationale:**
- **Privacy sensitive** - User counts reveal tenant information
- **Operational value varies** - Some need it, others don't
- **Performance impact** - Additional API calls to collect
- **Compliance considerations** - Some regulations may restrict this data

### Tier 3: Never Expose (Security Risk)

**These should NEVER be exposed as metrics:**

```
❌ keycloak_users{realm="...", username="..."}
   → PII, individual user enumeration

❌ keycloak_client_secrets_rotated{client="..."}
   → Security event timing could aid attacks

❌ keycloak_realm_admins{realm="...", user="..."}
   → Privilege escalation target list

❌ keycloak_user_attributes{realm="...", attribute="..."}
   → PII leak, attribute enumeration

❌ keycloak_sessions{realm="...", user="...", ip="..."}
   → Privacy violation, tracking data

❌ keycloak_permissions{user="...", role="..."}
   → Attack surface mapping
```

**Rationale:**
- **PII exposure** - Violates privacy regulations (GDPR, etc.)
- **Security surface** - Gives attackers information
- **Audit nightmare** - Who accessed what metrics?
- **Compliance risk** - Data protection violations

## Implementation Strategy

### Phase 1: Drift Detection (Security Critical)

**Goal**: Detect when Keycloak state diverges from CRs

```python
class RealmReconciler:
    async def check_drift(self, realm_name: str, expected_spec: dict) -> bool:
        """Compare CR spec with actual Keycloak state."""
        actual = await self.admin.get_realm(realm_name)

        # Compare critical fields
        drift_fields = []

        # Check theme drift
        if actual.get("loginTheme") != expected_spec.get("themes", {}).get("loginTheme"):
            drift_fields.append("loginTheme")

        # Check security settings drift
        if actual.get("registrationAllowed") != expected_spec.get("security", {}).get("registrationAllowed"):
            drift_fields.append("registrationAllowed")

        # Check SMTP configuration drift
        expected_smtp = expected_spec.get("smtpServer", {}).get("host")
        actual_smtp = actual.get("smtpServer", {}).get("host")
        if expected_smtp != actual_smtp:
            drift_fields.append("smtpServer")

        if drift_fields:
            logger.warning(
                f"Drift detected in realm {realm_name}: {drift_fields}",
                extra={"realm": realm_name, "drift_fields": drift_fields}
            )
            metrics.config_drift_detected.labels(
                type="realm",
                name=realm_name,
                fields=",".join(drift_fields)
            ).set(1)
            return True

        # No drift detected
        metrics.config_drift_detected.labels(
            type="realm",
            name=realm_name,
            fields=""
        ).set(0)
        return False
```

**Alert rule:**

```yaml
- alert: KeycloakConfigurationDrift
  expr: keycloak_operator_config_drift_detected > 0
  for: 5m
  labels:
    severity: warning
    component: keycloak-operator
  annotations:
    summary: "Keycloak configuration drift detected"
    description: |
      Resource {{ $labels.name }} ({{ $labels.type }}) has configuration drift.
      Fields affected: {{ $labels.fields }}
      Someone may have modified Keycloak directly via the admin console.
    action: "Review changes in Keycloak admin console and re-apply CR to restore desired state"
```

**When to check:**
- After every reconciliation (no extra API calls)
- Optionally: Periodic drift checks (every 5 minutes)

### Phase 2: Operational Metrics (Capacity Planning)

**Goal**: Basic inventory for operational visibility

```python
class BaseReconciler:
    async def update_inventory_metrics(self):
        """Update inventory metrics during reconciliation."""
        # These are already fetched during reconciliation - no extra cost

        # Realm count
        realms = await self.admin.get_realms()
        metrics.realms_total.set(len(realms))

        # Clients per realm
        for realm in realms:
            clients = await self.admin.get_realm_clients(realm.name)
            metrics.clients_per_realm.labels(realm=realm.name).set(len(clients))

            # Identity providers per realm
            idps = await self.admin.get_identity_providers(realm.name)
            metrics.identity_providers_per_realm.labels(realm=realm.name).set(len(idps))
```

**Frequency**: Update during reconciliation (no additional load)

### Phase 3: Advanced Metrics (Opt-In)

**Goal**: Usage patterns for capacity planning (if enabled)

```python
class KeycloakMetricsCollector:
    """Optional metrics collector for usage patterns."""

    def __init__(self, admin_client, config):
        self.admin = admin_client
        self.enabled = config.monitoring.keycloak_metrics.enabled
        self.include_users = config.monitoring.keycloak_metrics.include_user_counts
        self.include_sessions = config.monitoring.keycloak_metrics.include_session_metrics

    async def collect(self):
        """Collect optional metrics if enabled."""
        if not self.enabled:
            return

        realms = await self.admin.get_realms()

        for realm in realms:
            if self.include_users:
                # User count (aggregated only)
                user_count = await self.admin.get_user_count(realm.name)
                metrics.users_total.labels(realm=realm.name).set(user_count)

            if self.include_sessions:
                # Active sessions (aggregated only)
                sessions = await self.admin.get_active_sessions(realm.name)
                metrics.active_sessions.labels(realm=realm.name).set(len(sessions))
```

**Frequency**: Every 60 seconds (configurable)

**Configuration:**

```yaml
monitoring:
  keycloakMetrics:
    enabled: false
    scrapeInterval: 60s
    includeUserCounts: false
    includeSessionMetrics: false
    includeLoginMetrics: false
```

## Security Considerations

### What NOT to Do

1. ❌ **Don't expose user lists**
   ```
   keycloak_users{username="john@example.com", realm="..."}
   ```
   This is PII and enables user enumeration attacks.

2. ❌ **Don't expose client secrets**
   ```
   keycloak_client_secret_last_rotated{client="...", hash="..."}
   ```
   Even hashed/masked, timing info aids attacks.

3. ❌ **Don't expose permission mappings**
   ```
   keycloak_user_roles{user="...", realm="...", role="..."}
   ```
   Maps attack surface for privilege escalation.

4. ❌ **Don't expose fine-grained session data**
   ```
   keycloak_sessions{user="...", ip="...", realm="..."}
   ```
   Privacy violation, tracking data.

5. ❌ **Don't expose individual login events**
   ```
   keycloak_login{username="...", status="...", timestamp="..."}
   ```
   Use Keycloak's event logging instead.

### What TO Do

1. ✅ **Aggregate metrics only**
   - Counts, not individuals
   - `keycloak_users_total{realm="..."}` not per-user

2. ✅ **Drift detection**
   - Security critical capability
   - Detect unauthorized changes

3. ✅ **Health indicators**
   - Operational necessity
   - API availability, latency

4. ✅ **Rate limiting on scrapes**
   - Prevent API overload
   - Configurable intervals

5. ✅ **Opt-in for sensitive metrics**
   - Privacy by default
   - Explicit enablement required

6. ✅ **Audit logging**
   - Log who enables advanced metrics
   - Track metric access patterns

## Performance Considerations

### Metric Collection Cost

**Tier 1 (Always):**
- **Cost**: Zero - collected during reconciliation
- **Frequency**: On reconciliation only
- **Impact**: None

**Tier 2 (Opt-in):**
- **Cost**: 1-2 API calls per realm
- **Frequency**: Every 60 seconds (configurable)
- **Impact**: Moderate - scales with realm count

**Mitigation:**
- Cache results for 60 seconds
- Use batch API calls where possible
- Implement circuit breaker for metrics collection
- Make interval configurable
- Allow disabling per realm with labels

### Cardinality Management

**Problem**: Many realms × many clients = metric explosion

**Solution:**
```yaml
monitoring:
  keycloakMetrics:
    maxRealms: 100  # Skip metrics for realms beyond this
    maxClientsPerRealm: 1000  # Aggregate if more clients
    excludeNamespaces:  # Don't collect for these namespaces
      - test-*
      - dev-*
```

## Compliance & Privacy

### GDPR Considerations

- ✅ **Aggregate user counts**: Compliant (no PII)
- ❌ **Individual user metrics**: Non-compliant (PII)
- ✅ **Session counts**: Compliant (aggregated)
- ❌ **Per-user sessions**: Non-compliant (tracking)

### Data Retention

Prometheus default: 15 days
- ✅ Safe for aggregate metrics
- ⚠️ Consider for session/login patterns

### Access Control

**Who should see these metrics?**
- Tier 1: All operators (via Grafana)
- Tier 2: SRE team only
- Tier 3: Nobody (don't expose)

**Implementation**: Grafana datasource permissions

## Recommended Implementation Priority

### Must Have (P0)
1. **Drift detection** - Security critical
   - Compare CR spec to actual state
   - Alert on divergence
   - Log drift details

2. **Basic inventory** - Operational necessity
   - Realm count
   - Clients per realm
   - Identity providers count

### Should Have (P1)
3. **Health metrics** - Reliability
   - Admin API latency
   - API availability
   - Request rate

### Nice to Have (P2)
4. **Opt-in usage metrics** - Capacity planning
   - User counts (aggregated)
   - Session counts (aggregated)
   - Login rate (aggregated)

### Won't Have
5. **Individual user data** - Security/privacy risk
6. **Permission mappings** - Attack surface
7. **Client secrets** - Security risk

## Next Steps

If we decide to implement this:

1. **Phase 1**: Drift detection only
   - Minimal complexity
   - High security value
   - No performance impact

2. **Phase 2**: Basic inventory metrics
   - Simple implementation
   - Clear operational value
   - Negligible performance impact

3. **Phase 3**: Opt-in advanced metrics
   - Complex implementation
   - Requires careful design
   - Performance considerations

## Open Questions

1. **Drift remediation**: Should operator auto-fix drift or just alert?
   - Auto-fix: More GitOps, but could break manual workflows
   - Alert only: Less disruptive, but drift persists

2. **Metric retention**: Should we have shorter retention for sensitive metrics?
   - Shorter: Better privacy
   - Standard: Consistent with other metrics

3. **Real-time vs periodic**: Should drift detection be real-time or periodic?
   - Real-time: During reconciliation only (less load)
   - Periodic: Every N minutes (catches changes faster)

4. **Multi-tenancy**: In shared Keycloak, should metrics be namespace-aware?
   - Yes: Better isolation
   - No: Simpler implementation

## References

- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [GDPR Guidelines for Metrics](https://gdpr.eu/data-protection/)
- [Kubernetes Metrics Guidelines](https://kubernetes.io/docs/concepts/cluster-administration/system-metrics/)
- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/)

---

**Status**: Awaiting decision on implementation priority and scope.
