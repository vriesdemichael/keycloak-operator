# Drift Detection

The Keycloak Operator includes drift detection to monitor the actual state of Keycloak resources and compare them with Kubernetes Custom Resources (CRs). This helps identify:

- **Orphaned resources**: Resources created by the operator but whose CR has been deleted
- **Configuration drift**: Resources whose actual state differs from the CR specification
- **Unmanaged resources**: Resources in Keycloak not managed by any operator instance

## Features

### Resource Ownership Tracking

Every Keycloak resource (realm, client, etc.) created by the operator is tagged with ownership attributes:

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

These attributes enable:
- Multi-operator deployments (each operator tracks its own resources)
- Orphan detection (identify resources whose CR was deleted)
- Drift detection (verify CR still matches actual state)

### Periodic Drift Scanning

The operator runs periodic background scans to check for drift:

1. **Fetch all resources** from Keycloak
2. **Check ownership** using attributes
3. **Verify CR existence** for operator-managed resources
4. **Compare configuration** (future: detect spec drift)
5. **Emit Prometheus metrics** for monitoring

### Auto-Remediation (Optional)

When enabled, the operator can automatically fix drift:

- **Orphaned resources**: Delete from Keycloak if older than minimum age (default: 24 hours)
- **Configuration drift**: Update Keycloak to match CR spec (future feature)

**Safety mechanisms:**
- Minimum age check (default: 24 hours) prevents accidental deletion of newly created resources
- Re-check CR existence before deletion to avoid race conditions
- Only touches resources with this operator's instance ID

## Configuration

Configure drift detection via Helm values:

```yaml
monitoring:
  driftDetection:
    # Enable drift detection
    enabled: true
    
    # Scan interval in seconds (default: 300 = 5 minutes)
    intervalSeconds: 300
    
    # Auto-remediate detected drift (default: false)
    # WARNING: When enabled, orphaned resources will be automatically deleted
    autoRemediate: false
    
    # Minimum age in hours before deleting orphaned resources (default: 24)
    # Safety mechanism to prevent accidental deletion
    minimumAgeHours: 24
    
    # Scope of drift detection
    scope:
      realms: true
      clients: true
      identityProviders: true  # Future feature
      roles: true               # Future feature
```

### Environment Variables

If you're not using Helm, configure via environment variables:

```bash
DRIFT_DETECTION_ENABLED=true
DRIFT_DETECTION_INTERVAL_SECONDS=300
DRIFT_DETECTION_AUTO_REMEDIATE=false
DRIFT_DETECTION_MINIMUM_AGE_HOURS=24
DRIFT_DETECTION_SCOPE_REALMS=true
DRIFT_DETECTION_SCOPE_CLIENTS=true
DRIFT_DETECTION_SCOPE_IDENTITY_PROVIDERS=true
DRIFT_DETECTION_SCOPE_ROLES=true
```

## Prometheus Metrics

The operator exposes the following metrics for drift detection:

### Drift Detection Metrics

```prometheus
# Number of orphaned resources (created by this operator, CR deleted)
keycloak_operator_orphaned_resources{resource_type, resource_name, operator_instance}

# Number of resources with configuration drift
keycloak_operator_config_drift{resource_type, resource_name, cr_namespace, cr_name}

# Number of unmanaged resources (not created by any operator)
keycloak_unmanaged_resources{resource_type, resource_name}
```

### Remediation Metrics

```prometheus
# Total remediation actions performed
keycloak_operator_remediation_total{resource_type, action, reason}

# Total remediation errors
keycloak_operator_remediation_errors_total{resource_type, action}
```

### Health Metrics

```prometheus
# Duration of drift detection scans
keycloak_operator_drift_check_duration_seconds{resource_type}

# Total drift check errors
keycloak_operator_drift_check_errors_total{resource_type}

# Unix timestamp of last successful drift check
keycloak_operator_drift_check_last_success_timestamp
```

## Example Prometheus Alerts

Create alerts to notify when drift is detected:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: keycloak-operator-drift-alerts
spec:
  groups:
    - name: keycloak-drift
      interval: 30s
      rules:
        # Alert on orphaned resources
        - alert: KeycloakOrphanedResources
          expr: keycloak_operator_orphaned_resources > 0
          for: 30m
          labels:
            severity: warning
            component: keycloak-operator
          annotations:
            summary: "Orphaned Keycloak resources detected"
            description: |
              {{ $value }} orphaned {{ $labels.resource_type }} resource(s) detected.
              Resource: {{ $labels.resource_name }}
              Operator: {{ $labels.operator_instance }}
              
        # Alert on configuration drift
        - alert: KeycloakConfigurationDrift
          expr: keycloak_operator_config_drift > 0
          for: 15m
          labels:
            severity: info
            component: keycloak-operator
          annotations:
            summary: "Keycloak configuration drift detected"
            description: |
              Configuration drift detected for {{ $labels.resource_type }}: {{ $labels.resource_name }}
              CR: {{ $labels.cr_namespace }}/{{ $labels.cr_name }}
              
        # Alert on drift check failures
        - alert: KeycloakDriftCheckFailure
          expr: increase(keycloak_operator_drift_check_errors_total[5m]) > 3
          for: 5m
          labels:
            severity: warning
            component: keycloak-operator
          annotations:
            summary: "Drift detection checks are failing"
            description: |
              Drift detection for {{ $labels.resource_type }} has failed {{ $value }} times in the last 5 minutes.
              
        # Alert if drift checks haven't run recently
        - alert: KeycloakDriftCheckStale
          expr: (time() - keycloak_operator_drift_check_last_success_timestamp) > 900
          for: 5m
          labels:
            severity: warning
            component: keycloak-operator
          annotations:
            summary: "Drift detection checks are not running"
            description: |
              Drift detection has not run successfully in {{ $value | humanizeDuration }}.
```

## Usage Examples

### Scenario 1: Detect Orphaned Realms

1. **Create a realm**:
   ```bash
   kubectl apply -f my-realm.yaml
   ```

2. **Delete the CR** (simulating accidental deletion):
   ```bash
   kubectl delete keycloakrealm my-realm
   ```

3. **Check metrics** (after next drift scan):
   ```bash
   curl http://localhost:8081/metrics | grep orphaned_resources
   # keycloak_operator_orphaned_resources{resource_type="realm",resource_name="my-realm",...} 1
   ```

4. **Manual cleanup** (if auto-remediation is disabled):
   ```bash
   # The realm still exists in Keycloak
   # Delete it manually via Keycloak Admin UI or API
   ```

5. **Auto-cleanup** (if auto-remediation is enabled and age > 24h):
   ```bash
   # Wait 24 hours, then the operator will automatically delete the orphaned realm
   # Check logs:
   kubectl logs -n keycloak-system deployment/keycloak-operator | grep "Successfully deleted orphaned realm"
   ```

### Scenario 2: Multi-Operator Deployments

When running multiple operator instances:

```yaml
# Operator 1 in production namespace
operator:
  instanceId: "keycloak-operator-production"

# Operator 2 in staging namespace  
operator:
  instanceId: "keycloak-operator-staging"
```

Each operator only manages resources it created:
- Production operator ignores resources created by staging operator
- Prevents conflicts and accidental deletions
- Clear ownership boundaries

### Scenario 3: Identify Unmanaged Resources

Find Keycloak resources not managed by any operator:

```bash
# Query metrics
curl http://localhost:8081/metrics | grep unmanaged_resources

# Example output:
# keycloak_unmanaged_resources{resource_type="realm",resource_name="legacy-realm"} 1
# keycloak_unmanaged_resources{resource_type="client",resource_name="manual-client"} 1
```

These are resources that existed before the operator or were created manually.

**Options:**
- Leave them as-is (operator won't touch them)
- Manually add ownership attributes to adopt them (not recommended)
- Create matching CRs to bring them under operator management (recommended)

## Troubleshooting

### Drift detection is not running

**Symptoms:** `keycloak_operator_drift_check_last_success_timestamp` is stale

**Causes:**
1. Drift detection is disabled in Helm values
2. No KeycloakRealm CRs exist (timer trigger requires at least one resource)
3. Operator is not running or crashing

**Solutions:**
```bash
# Check if enabled
helm get values keycloak-operator | grep driftDetection

# Check operator logs
kubectl logs -n keycloak-system deployment/keycloak-operator | grep drift

# Ensure at least one realm CR exists
kubectl get keycloakrealms -A
```

### Orphaned resources not being deleted

**Symptoms:** `keycloak_operator_orphaned_resources` > 0 but resources not deleted

**Causes:**
1. Auto-remediation is disabled (check `autoRemediate: false`)
2. Resource age < minimum age (default 24h)
3. Remediation errors (check error metrics)

**Solutions:**
```bash
# Check auto-remediation setting
helm get values keycloak-operator | grep autoRemediate

# Check resource age (must be > minimumAgeHours)
# Resource created_at is in the attributes

# Check for remediation errors
curl http://localhost:8081/metrics | grep remediation_errors_total

# Check operator logs for errors
kubectl logs -n keycloak-system deployment/keycloak-operator | grep remediation
```

### False orphan detection

**Symptoms:** Resources marked as orphaned but CR exists

**Causes:**
1. CR is in different namespace than expected
2. Ownership attributes don't match actual CR name/namespace
3. Permissions issue (operator can't read CR)

**Solutions:**
```bash
# Verify CR exists and matches ownership attributes
kubectl get keycloakrealm my-realm -n expected-namespace -o yaml

# Check operator RBAC permissions
kubectl auth can-i get keycloakrealms --as=system:serviceaccount:keycloak-system:keycloak-operator-keycloak-system

# Check operator logs for permission errors
kubectl logs -n keycloak-system deployment/keycloak-operator | grep -i "permission\|rbac"
```

## Migration from Existing Resources

### Breaking Change Notice

**⚠️ Resources created before this version will NOT be managed for drift detection.**

Existing realms and clients lack ownership attributes and will be treated as "unmanaged" resources.

### Migration Options

#### Option 1: Recreate Resources (Recommended)

1. Export existing resource configuration
2. Delete the resource from Keycloak
3. Recreate via CR (operator will add ownership attributes)

```bash
# Backup realm config
kubectl get keycloakrealm my-realm -o yaml > my-realm-backup.yaml

# Delete and recreate
kubectl delete keycloakrealm my-realm
kubectl apply -f my-realm-backup.yaml
```

#### Option 2: Manual Attribute Addition (Advanced)

Manually add ownership attributes to existing Keycloak resources via Admin API:

```bash
# Get current realm
GET /admin/realms/{realm-name}

# Add attributes
PATCH /admin/realms/{realm-name}
{
  "attributes": {
    "io.kubernetes.managed-by": "keycloak-operator",
    "io.kubernetes.operator-instance": "keycloak-operator-<namespace>",
    "io.kubernetes.cr-namespace": "<cr-namespace>",
    "io.kubernetes.cr-name": "<cr-name>",
    "io.kubernetes.created-at": "2025-10-28T12:00:00Z"
  }
}
```

⚠️ **Risks:**
- Incorrect attributes can cause drift detection to malfunction
- Easy to make mistakes with namespace/name mapping
- Not recommended unless you know what you're doing

#### Option 3: Leave As Unmanaged (Simplest)

Do nothing. Existing resources will show up as "unmanaged" in metrics but won't be affected by drift detection or auto-remediation.

## Security Considerations

### Ownership Attribute Tampering

**Threat:** Someone manually modifies ownership attributes in Keycloak to evade drift detection

**Mitigation:**
- Keycloak Admin API should be restricted (not publicly accessible)
- Use Keycloak RBAC to limit who can modify realms/clients
- Audit logs should track attribute changes

### Unauthorized Resource Deletion

**Threat:** Auto-remediation deletes resources that shouldn't be deleted

**Mitigation:**
- Auto-remediation is disabled by default
- 24-hour minimum age prevents accidental deletions
- Operator logs all deletions for audit trail
- Monitor `remediation_total` metric for unexpected deletions

### Information Disclosure

**Threat:** Prometheus metrics expose sensitive information about tenants

**Mitigation:**
- Metrics only expose resource names (not secrets, passwords, etc.)
- Unmanaged resources are visible (could reveal what exists)
- Use Prometheus authentication/authorization to restrict metric access
- Consider disabling unmanaged resource metrics if needed

## Future Enhancements

- [ ] **Config drift detection**: Compare actual Keycloak state with CR spec
- [ ] **Identity provider drift detection**: Track IDP configuration changes
- [ ] **Role drift detection**: Monitor role assignments
- [ ] **Drift remediation for config changes**: Auto-update Keycloak when CR changes
- [ ] **Grafana dashboard**: Pre-built dashboard for drift visualization
- [ ] **Webhook notifications**: Send alerts to Slack/Teams when drift detected
- [ ] **Dry-run mode**: Log what would be remediated without actually doing it
- [ ] **Per-resource remediation control**: Annotation to disable auto-remediation for specific resources
