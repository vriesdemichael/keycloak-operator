# Token Management Operations Guide

**Audience**: Platform teams, SREs, operators
**Last Updated**: 2025-01-21

---

## Overview

This guide covers operational procedures for managing the Keycloak operator's automatic token rotation system. It provides runbooks for common scenarios, troubleshooting procedures, and monitoring recommendations.

---

## Table of Contents

- [System Architecture](#system-architecture)
- [Day-to-Day Operations](#day-to-day-operations)
- [Monitoring](#monitoring)
- [Common Procedures](#common-procedures)
- [Troubleshooting](#troubleshooting)
- [Emergency Procedures](#emergency-procedures)
- [Security Incidents](#security-incidents)

---

## System Architecture

### Token Types

The operator manages two types of tokens:

| Token Type | Purpose | Lifespan | Rotation |
|------------|---------|----------|----------|
| **Admission** | Bootstrap new namespaces | 1 year | Manual (platform team) |
| **Operational** | Day-to-day authorization | 90 days | Automatic (operator) |

### Token Flow

```
Platform Team                Operator                    Application Team
     |                          |                              |
     |--admission token-------->|                              |
     |                          |                              |
     |                          |--operational token---------->|
     |                          |   (via Kubernetes secret)    |
     |                          |                              |
     |                          |                              |
     |         (Day 83)         |                              |
     |                          |--new token + old token------>|
     |                          |   (grace period starts)      |
     |                          |                              |
     |         (Day 90)         |                              |
     |                          |--cleanup old token---------->|
     |                          |                              |
```

### Storage Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| **Admission Tokens** | Team namespace secrets | Bootstrap new namespaces |
| **Operational Tokens** | Team namespace secrets | Active authorization |
| **Token Metadata** | Operator ConfigMap | Token lifecycle tracking |
| **Rotation State** | Secret annotations | Grace period tracking |

---

## Day-to-Day Operations

### Daily Checks

**Automated via monitoring (recommended)**. Manual checks if alerts aren't set up:

```bash
# Check for tokens expiring soon
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | \
  jq -r '.data | to_entries[] | select(.value | fromjson | .valid_until < (now + 7*86400 | strftime("%Y-%m-%dT%H:%M:%SZ"))) | .key'

# Check recent rotation events
kubectl get events --all-namespaces \
  --field-selector reason=TokenRotated \
  --sort-by='.lastTimestamp' | tail -10

# Check for rotation failures
kubectl logs -n keycloak-operator-system \
  deployment/keycloak-operator --since=24h | grep -i "rotation.*failed"
```

### Weekly Checks

```bash
# Verify all operational tokens are healthy
for ns in $(kubectl get ns -l team=enabled -o jsonpath='{.items[*].metadata.name}'); do
  echo "Namespace: $ns"
  kubectl get secret -n $ns -l keycloak.mdvr.nl/token-type=operational \
    -o jsonpath='{range .items[*]}{.metadata.name}: version={.metadata.annotations.keycloak\.mdvr\.nl/version}, valid-until={.metadata.annotations.keycloak\.mdvr\.nl/valid-until}{"\n"}{end}'
done

# Check ConfigMap size (should grow slowly over time)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system \
  -o json | jq '.data | length'
```

### Monthly Tasks

1. **Review admission token inventory**
   ```bash
   # List all admission tokens
   kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=admission \
     -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,AGE:.metadata.creationTimestamp
   ```

2. **Audit operational tokens**
   ```bash
   # Generate token audit report
   kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational \
     -o json | jq -r '.items[] |
       "\(.metadata.namespace)|\(.metadata.name)|\(.metadata.annotations["keycloak.mdvr.nl/version"])|\(.metadata.annotations["keycloak.mdvr.nl/valid-until"])"' | \
     column -t -s '|'
   ```

3. **Review rotation metrics**
   ```promql
   # Query Prometheus for rotation statistics
   sum(increase(keycloak_operator_token_rotations_total[30d])) by (namespace)
   ```

---

## Monitoring

### Prometheus Metrics

Deploy these metrics to track token health:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: keycloak-operator-tokens
  namespace: keycloak-operator-system
spec:
  selector:
    matchLabels:
      app: keycloak-operator
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

**Key Metrics**:

| Metric | Type | Description | Alert Threshold |
|--------|------|-------------|-----------------|
| `keycloak_operator_token_rotations_total` | Counter | Successful rotations | N/A (informational) |
| `keycloak_operator_token_bootstraps_total` | Counter | Bootstrap operations | N/A (informational) |
| `keycloak_operator_tokens_expiring_soon` | Gauge | Tokens expiring <7 days | > 0 for >48h |
| `keycloak_operator_active_tokens` | Gauge | Active operational tokens | Sudden drop |
| `keycloak_operator_token_rotation_failures_total` | Counter | Failed rotations | > 0 |

### Recommended Alerts

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: keycloak-token-alerts
  namespace: keycloak-operator-system
spec:
  groups:
    - name: keycloak_tokens
      interval: 5m
      rules:
        # CRITICAL: Token rotation failing
        - alert: KeycloakTokenRotationFailing
          expr: increase(keycloak_operator_token_rotation_failures_total[1h]) > 0
          labels:
            severity: critical
            component: keycloak-operator
          annotations:
            summary: "Keycloak token rotation failed"
            description: "Token rotation has failed in the last hour. Check operator logs immediately."
            runbook: "https://your-docs/keycloak/runbooks#token-rotation-failed"

        # CRITICAL: Token expired without rotation
        - alert: KeycloakTokenExpired
          expr: |
            keycloak_operator_tokens_expiring_soon > 0
            AND
            time() - keycloak_operator_last_rotation_timestamp > 86400 * 8
          for: 1h
          labels:
            severity: critical
            component: keycloak-operator
          annotations:
            summary: "Keycloak token expired without rotation"
            description: "Token has been expiring for >1 hour without rotation. Manual intervention required."
            runbook: "https://your-docs/keycloak/runbooks#token-expired"

        # WARNING: Token expiring soon
        - alert: KeycloakTokenExpiringSoon
          expr: keycloak_operator_tokens_expiring_soon > 0
          for: 48h
          labels:
            severity: warning
            component: keycloak-operator
          annotations:
            summary: "Keycloak token expiring within 7 days"
            description: "{{ $value }} token(s) will expire soon. Verify automatic rotation is working."
            runbook: "https://your-docs/keycloak/runbooks#token-expiring"

        # WARNING: Many tokens in grace period
        - alert: KeycloakManyTokensInGracePeriod
          expr: |
            count(
              label_replace(
                kube_secret_annotations{annotation_keycloak_mdvr_nl_grace_period_ends!=""},
                "has_grace_period", "1", "", ""
              )
            ) > 5
          for: 2h
          labels:
            severity: warning
            component: keycloak-operator
          annotations:
            summary: "Many tokens in grace period"
            description: "{{ $value }} tokens have been in grace period for >2 hours. Check cleanup handler."

        # INFO: Bootstrap activity
        - alert: KeycloakNewBootstrap
          expr: increase(keycloak_operator_token_bootstraps_total[15m]) > 0
          labels:
            severity: info
            component: keycloak-operator
          annotations:
            summary: "New namespace bootstrapped"
            description: "A new namespace was bootstrapped with operational token."
```

### Grafana Dashboards

Create dashboards to visualize token health:

```json
{
  "dashboard": {
    "title": "Keycloak Token Management",
    "panels": [
      {
        "title": "Active Tokens by Namespace",
        "targets": [{
          "expr": "keycloak_operator_active_tokens"
        }]
      },
      {
        "title": "Rotation Rate (30d)",
        "targets": [{
          "expr": "increase(keycloak_operator_token_rotations_total[30d])"
        }]
      },
      {
        "title": "Tokens Expiring Soon",
        "targets": [{
          "expr": "keycloak_operator_tokens_expiring_soon"
        }]
      },
      {
        "title": "Rotation Failures",
        "targets": [{
          "expr": "increase(keycloak_operator_token_rotation_failures_total[24h])"
        }]
      }
    ]
  }
}
```

---

## Common Procedures

### Onboard New Team

**Scenario**: A new team needs to create Keycloak realms.

**Steps**:

1. **Generate admission token**:
   ```bash
   # Generate token
   TEAM_NAME="team-alpha"
   ADMISSION_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

   # Create secret in team namespace
   kubectl create secret generic admission-token-${TEAM_NAME} \
     --from-literal=token="$ADMISSION_TOKEN" \
     --namespace=${TEAM_NAME}

   # Add required labels
   kubectl label secret admission-token-${TEAM_NAME} \
     keycloak.mdvr.nl/token-type=admission \
     keycloak.mdvr.nl/allow-operator-read=true \
     --namespace=${TEAM_NAME}
   ```

2. **Store token metadata**:
   ```bash
   # Calculate token hash
   TOKEN_HASH=$(echo -n "$ADMISSION_TOKEN" | sha256sum | cut -d' ' -f1)

   # Store in ConfigMap
   kubectl get configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system -o json | \
   jq --arg hash "$TOKEN_HASH" \
      --arg namespace "$TEAM_NAME" \
      --arg issued "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg valid "$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)" \
      '.data[$hash] = "{\"namespace\": \"" + $namespace + "\", \"token_type\": \"admission\", \"token_hash\": \"" + $hash + "\", \"issued_at\": \"" + $issued + "\", \"valid_until\": \"" + $valid + "\", \"version\": 1, \"created_by_realm\": null, \"revoked\": false}"' | \
   kubectl apply -f -
   ```

3. **Share with team** (via GitOps/SealedSecrets/manual):
   ```bash
   # Export for GitOps
   kubectl get secret admission-token-${TEAM_NAME} \
     -n ${TEAM_NAME} -o yaml > ${TEAM_NAME}-admission-token.yaml
   ```

4. **Document handoff**:
   - Provide team with realm creation example
   - Explain bootstrap process (first realm triggers operational token)
   - Share monitoring dashboard access

**Verification**:
```bash
# After team creates first realm, verify operational token created
kubectl get secret -n ${TEAM_NAME} -l keycloak.mdvr.nl/token-type=operational

# Check bootstrap recorded in metrics
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics | grep token_bootstraps_total
```

### Force Token Rotation

**Scenario**: Security policy requires immediate rotation (e.g., compliance audit).

**Steps**:

1. **Identify token to rotate**:
   ```bash
   NAMESPACE="team-alpha"
   kubectl get secret -n ${NAMESPACE} -l keycloak.mdvr.nl/token-type=operational
   ```

2. **Trigger rotation by updating valid-until annotation**:
   ```bash
   # Set expiry to now (triggers rotation on next check)
   kubectl annotate secret ${NAMESPACE}-operator-token \
     keycloak.mdvr.nl/valid-until="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     --overwrite \
     -n ${NAMESPACE}
   ```

3. **Wait for rotation handler** (runs hourly) or **restart operator**:
   ```bash
   # Option A: Wait up to 1 hour for automatic rotation
   # Option B: Restart operator to trigger immediate rotation
   kubectl rollout restart deployment keycloak-operator \
     -n keycloak-operator-system
   ```

4. **Verify rotation completed**:
   ```bash
   # Check version incremented
   kubectl get secret ${NAMESPACE}-operator-token \
     -n ${NAMESPACE} \
     -o jsonpath='{.metadata.annotations.keycloak\.mdvr\.nl/version}'

   # Check both tokens present (grace period)
   kubectl get secret ${NAMESPACE}-operator-token \
     -n ${NAMESPACE} -o jsonpath='{.data}' | jq 'keys'
   # Should show: ["token", "token-previous"]
   ```

5. **Monitor for issues**:
   ```bash
   # Watch for authorization failures
   kubectl get events --all-namespaces \
     --field-selector reason=AuthorizationFailed -w
   ```

### Revoke Token (Emergency)

**Scenario**: Token compromised, immediate revocation required.

**Steps**:

1. **Identify compromised token**:
   ```bash
   NAMESPACE="team-compromised"
   TOKEN_SECRET="${NAMESPACE}-operator-token"
   ```

2. **Revoke in metadata**:
   ```bash
   # Get current token value to calculate hash
   TOKEN=$(kubectl get secret ${TOKEN_SECRET} -n ${NAMESPACE} \
     -o jsonpath='{.data.token}' | base64 -d)
   TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)

   # Mark as revoked in ConfigMap
   kubectl get configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system -o json | \
   jq --arg hash "$TOKEN_HASH" \
      '.data[$hash] = (.data[$hash] | fromjson | .revoked = true | .revoked_at = (now | strftime("%Y-%m-%dT%H:%M:%SZ")) | tojson)' | \
   kubectl apply -f -
   ```

3. **Delete secret** (prevents further use):
   ```bash
   kubectl delete secret ${TOKEN_SECRET} -n ${NAMESPACE}
   ```

4. **Verify revocation**:
   ```bash
   # Check realms fail authorization
   kubectl get keycloakrealm -n ${NAMESPACE} \
     -o jsonpath='{range .items[*]}{.metadata.name}: {.status.phase}{"\n"}{end}'
   # Should show: Failed or Degraded
   ```

5. **Re-bootstrap namespace** (if team should regain access):
   ```bash
   # Generate new admission token
   # Follow "Onboard New Team" procedure
   ```

### Cleanup Stale Tokens

**Scenario**: Namespace deleted but token metadata remains.

**Steps**:

1. **Identify stale tokens**:
   ```bash
   # Get all namespaces with operational tokens
   for ns in $(kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational \
     -o jsonpath='{.items[*].metadata.namespace}' | tr ' ' '\n' | sort -u); do
     kubectl get ns $ns &>/dev/null || echo "Stale: $ns"
   done
   ```

2. **Remove from ConfigMap**:
   ```bash
   # List tokens for deleted namespace
   DELETED_NS="old-team"
   kubectl get configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system -o json | \
   jq -r --arg ns "$DELETED_NS" \
     '.data | to_entries[] | select(.value | fromjson | .namespace == $ns) | .key'

   # Remove each token hash
   for hash in $(above command); do
     kubectl get configmap keycloak-operator-token-metadata \
       -n keycloak-operator-system -o json | \
     jq --arg hash "$hash" 'del(.data[$hash])' | \
     kubectl apply -f -
   done
   ```

3. **Verify cleanup**:
   ```bash
   # ConfigMap should not contain deleted namespace
   kubectl get configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system -o json | \
   jq -r '.data | to_entries[] | .value | fromjson | .namespace' | \
   sort -u
   ```

---

## Troubleshooting

### Token Rotation Not Happening

**Symptoms**:
- Tokens past expiry date
- No rotation events in logs
- Metrics show no recent rotations

**Diagnosis**:

```bash
# 1. Check rotation handler is running
kubectl logs -n keycloak-operator-system \
  deployment/keycloak-operator --since=24h | \
  grep -i "rotation.*check\|rotation.*handler"

# 2. Verify ConfigMap is accessible
kubectl auth can-i get configmap \
  --as=system:serviceaccount:keycloak-operator-system:keycloak-operator \
  -n keycloak-operator-system

# 3. Check operator health
kubectl get pods -n keycloak-operator-system \
  -l app=keycloak-operator

# 4. Check for errors in logs
kubectl logs -n keycloak-operator-system \
  deployment/keycloak-operator --since=1h | \
  grep -i "error\|exception\|failed"
```

**Solutions**:

```bash
# Solution 1: Restart operator
kubectl rollout restart deployment keycloak-operator \
  -n keycloak-operator-system

# Solution 2: Verify RBAC permissions
kubectl get clusterrole keycloak-operator -o yaml | \
  grep -A5 "resources.*configmaps\|resources.*secrets"

# Solution 3: Check ConfigMap size (max 1MB)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | jq -r '.data | length'
# If >1000 entries, cleanup stale tokens

# Solution 4: Manual rotation
# Use "Force Token Rotation" procedure above
```

### Realms Failing After Rotation

**Symptoms**:
- Realms show "Authorization failed"
- Events show "Token invalid" or "Token not found"
- Happens after rotation completes

**Diagnosis**:

```bash
# 1. Check if realm is using admission token (wrong)
kubectl get keycloakrealm -n team-alpha my-realm -o yaml | \
  grep -A3 authorizationSecretRef

# 2. Check if operational token exists
kubectl get secret -n team-alpha -l keycloak.mdvr.nl/token-type=operational

# 3. Check token version
kubectl get secret team-alpha-operator-token -n team-alpha \
  -o jsonpath='{.metadata.annotations.keycloak\.mdvr\.nl/version}'

# 4. Check if grace period ended
kubectl get secret team-alpha-operator-token -n team-alpha \
  -o jsonpath='{.data}' | jq 'has("token-previous")'
# Should be false if grace period ended
```

**Solutions**:

```bash
# Solution 1: Update realm to use operational token
kubectl patch keycloakrealm my-realm -n team-alpha --type=merge -p '
spec:
  operatorRef:
    authorizationSecretRef:
      name: team-alpha-operator-token
      key: token
'

# Solution 2: Extend grace period (emergency)
# Manually add token-previous back to secret
OLD_TOKEN="<old-token-value>"
kubectl patch secret team-alpha-operator-token -n team-alpha \
  --type=json \
  -p '[{"op": "add", "path": "/data/token-previous", "value": "'$(echo -n "$OLD_TOKEN" | base64)'"}]'

# Solution 3: Re-bootstrap namespace
# Delete operational token and use admission token
kubectl delete secret team-alpha-operator-token -n team-alpha
# Update first realm to use admission token
# Operator will recreate operational token
```

### ConfigMap Growing Too Large

**Symptoms**:
- ConfigMap approaching 1MB limit
- Operator logs show "ConfigMap too large"
- Token operations failing

**Diagnosis**:

```bash
# Check ConfigMap size
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | \
  jq -r '.data | to_entries | length'

# Identify old/stale tokens
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | \
  jq -r '.data | to_entries[] |
    select(.value | fromjson | .issued_at < (now - 365*86400 | strftime("%Y-%m-%dT%H:%M:%SZ"))) |
    .key + ": " + (.value | fromjson | .namespace)'
```

**Solutions**:

```bash
# Solution 1: Cleanup stale tokens
# Use "Cleanup Stale Tokens" procedure

# Solution 2: Archive old tokens (if needed for audit)
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json > token-metadata-backup-$(date +%Y%m%d).json

# Solution 3: Remove revoked tokens
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | \
jq '.data |= with_entries(select(.value | fromjson | .revoked == false))' | \
kubectl apply -f -
```

### Bootstrap Failing

**Symptoms**:
- First realm fails with "Authorization failed"
- No operational token created
- Bootstrap metric not incrementing

**Diagnosis**:

```bash
NAMESPACE="team-alpha"

# 1. Check admission token exists
kubectl get secret admission-token-${NAMESPACE} -n ${NAMESPACE}

# 2. Check admission token in metadata
TOKEN=$(kubectl get secret admission-token-${NAMESPACE} -n ${NAMESPACE} \
  -o jsonpath='{.data.token}' | base64 -d)
TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)

kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o json | \
jq --arg hash "$TOKEN_HASH" '.data[$hash]'

# 3. Check operator logs for bootstrap
kubectl logs -n keycloak-operator-system \
  deployment/keycloak-operator --since=10m | \
  grep -i "bootstrap\|admission.*${NAMESPACE}"

# 4. Verify secret labels
kubectl get secret admission-token-${NAMESPACE} -n ${NAMESPACE} \
  -o jsonpath='{.metadata.labels}'
```

**Solutions**:

```bash
# Solution 1: Add missing labels
kubectl label secret admission-token-${NAMESPACE} \
  keycloak.mdvr.nl/token-type=admission \
  keycloak.mdvr.nl/allow-operator-read=true \
  --overwrite \
  -n ${NAMESPACE}

# Solution 2: Re-add token to metadata
# Follow "Onboard New Team" procedure

# Solution 3: Check if token already used
# Admission tokens are one-time use per namespace
# If operational token already exists, don't use admission token
kubectl get secret -n ${NAMESPACE} -l keycloak.mdvr.nl/token-type=operational

# Solution 4: Restart operator
kubectl rollout restart deployment keycloak-operator \
  -n keycloak-operator-system
```

---

## Emergency Procedures

### Complete Token System Reset

**⚠️ WARNING**: This procedure revokes all tokens. All realms will fail until re-bootstrapped.

**When to use**: Catastrophic security incident, operator corruption, or disaster recovery.

**Steps**:

1. **Backup current state**:
   ```bash
   # Backup ConfigMap
   kubectl get configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system -o yaml > token-metadata-backup.yaml

   # Backup all operational tokens
   kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational \
     -o yaml > operational-tokens-backup.yaml
   ```

2. **Delete all operational tokens**:
   ```bash
   kubectl delete secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational
   ```

3. **Clear ConfigMap**:
   ```bash
   kubectl patch configmap keycloak-operator-token-metadata \
     -n keycloak-operator-system \
     --type=json \
     -p '[{"op": "replace", "path": "/data", "value": {}}]'
   ```

4. **Verify all realms failed**:
   ```bash
   kubectl get keycloakrealm --all-namespaces \
     -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.status.phase}{"\n"}{end}'
   ```

5. **Re-bootstrap each namespace**:
   ```bash
   # For each affected namespace, create new admission token
   # Follow "Onboard New Team" procedure
   ```

6. **Update all realms**:
   ```bash
   # Each team must update their first realm to use admission token
   # Other realms automatically get new operational token
   ```

### Operator Deployment Failure During Rotation

**Scenario**: Operator crashed/restarted during active token rotation.

**Steps**:

1. **Assess rotation state**:
   ```bash
   # Check for tokens in grace period
   kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational \
     -o json | \
   jq -r '.items[] |
     select(.metadata.annotations["keycloak.mdvr.nl/grace-period-ends"] != null) |
     .metadata.namespace + "/" + .metadata.name + ": " + .metadata.annotations["keycloak.mdvr.nl/grace-period-ends"]'
   ```

2. **Verify operator recovery**:
   ```bash
   # Check operator is healthy
   kubectl get pods -n keycloak-operator-system -l app=keycloak-operator

   # Check rotation handler restarted
   kubectl logs -n keycloak-operator-system \
     deployment/keycloak-operator --since=5m | \
     grep -i "rotation.*handler.*start"
   ```

3. **Validate affected tokens**:
   ```bash
   # Check tokens still have both current and previous
   for secret in $(kubectl get secret --all-namespaces \
     -l keycloak.mdvr.nl/token-type=operational \
     -o jsonpath='{.items[*].metadata.namespace}/{.items[*].metadata.name}'); do
     NS=$(echo $secret | cut -d/ -f1)
     NAME=$(echo $secret | cut -d/ -f2)
     echo -n "$NS/$NAME: "
     kubectl get secret $NAME -n $NS -o jsonpath='{.data}' | jq 'keys'
   done
   ```

4. **Manual cleanup if needed**:
   ```bash
   # If operator didn't resume cleanup, manually remove expired previous tokens
   # Check grace period ended
   NOW=$(date -u +%s)
   GRACE_PERIOD_END=$(kubectl get secret team-alpha-operator-token -n team-alpha \
     -o jsonpath='{.metadata.annotations.keycloak\.mdvr\.nl/grace-period-ends}')
   GRACE_PERIOD_END_TS=$(date -d "$GRACE_PERIOD_END" +%s)

   if [ $NOW -gt $GRACE_PERIOD_END_TS ]; then
     # Remove previous token
     kubectl patch secret team-alpha-operator-token -n team-alpha \
       --type=json \
       -p '[{"op": "remove", "path": "/data/token-previous"}]'
   fi
   ```

---

## Security Incidents

### Suspected Token Compromise

**Indicators**:
- Unexpected realm creations
- Realms created in unauthorized namespaces
- Unusual token access patterns in audit logs

**Immediate Actions**:

1. **Isolate affected namespace**:
   ```bash
   COMPROMISED_NS="team-suspected"

   # Revoke token immediately
   kubectl delete secret ${COMPROMISED_NS}-operator-token \
     -n ${COMPROMISED_NS}

   # Mark as revoked in metadata
   # Follow "Revoke Token (Emergency)" procedure
   ```

2. **Audit token usage**:
   ```bash
   # Check Kubernetes audit logs
   kubectl logs -n kube-system kube-apiserver-* | \
     grep "secrets.*${COMPROMISED_NS}-operator-token"

   # Check realm creation events
   kubectl get events --all-namespaces \
     --field-selector involvedObject.kind=KeycloakRealm | \
     grep ${COMPROMISED_NS}
   ```

3. **Identify impact**:
   ```bash
   # List all realms using compromised token
   kubectl get keycloakrealm --all-namespaces \
     -o json | \
   jq -r --arg ns "$COMPROMISED_NS" \
     '.items[] |
     select(.spec.operatorRef.authorizationSecretRef.name | contains($ns)) |
     .metadata.namespace + "/" + .metadata.name'
   ```

4. **Rotate all tokens** (if widespread compromise):
   ```bash
   # Force rotation on all namespaces
   for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
     kubectl get secret -n $ns -l keycloak.mdvr.nl/token-type=operational &>/dev/null && \
       kubectl annotate secret ${ns}-operator-token \
         keycloak.mdvr.nl/valid-until="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
         --overwrite \
         -n $ns
   done

   # Restart operator to trigger immediate rotation
   kubectl rollout restart deployment keycloak-operator \
     -n keycloak-operator-system
   ```

5. **Document incident**:
   ```bash
   cat > incident-$(date +%Y%m%d-%H%M).txt <<EOF
   Date: $(date -u)
   Incident: Token Compromise
   Affected: ${COMPROMISED_NS}
   Actions Taken:
   - Token revoked
   - Namespace isolated
   - Audit completed
   - $(other actions)
   EOF
   ```

### Mass Token Leak

**Scenario**: Tokens accidentally committed to public repo, logged, or exposed.

**Immediate Actions**:

1. **Revoke all exposed tokens**:
   ```bash
   # If you have list of exposed token hashes
   for hash in $(cat exposed-hashes.txt); do
     kubectl get configmap keycloak-operator-token-metadata \
       -n keycloak-operator-system -o json | \
     jq --arg hash "$hash" \
       '.data[$hash] = (.data[$hash] | fromjson | .revoked = true | tojson)' | \
     kubectl apply -f -
   done
   ```

2. **Rotate all operational tokens**:
   ```bash
   # Force immediate rotation on all namespaces
   # Follow "Complete Token System Reset" if necessary
   ```

3. **Notify affected teams**:
   ```bash
   # Send notifications to team leads
   for ns in $(affected-namespaces); do
     echo "Token for $ns has been revoked due to security incident" | \
       mail -s "SECURITY: Keycloak Token Revoked" ${ns}-team@company.com
   done
   ```

---

## Best Practices

### Regular Maintenance

- ✅ Review token metrics weekly
- ✅ Audit ConfigMap size monthly
- ✅ Test recovery procedures quarterly
- ✅ Update runbooks after incidents
- ✅ Keep operator version current

### Monitoring

- ✅ Set up all recommended alerts
- ✅ Create Grafana dashboards
- ✅ Enable Kubernetes audit logging
- ✅ Monitor ConfigMap size
- ✅ Track rotation success rate

### Security

- ✅ Use SealedSecrets/External Secrets for admission tokens
- ✅ Enable RBAC for secret access
- ✅ Audit token access regularly
- ✅ Rotate admission tokens annually
- ✅ Document all manual token operations

### Automation

- ✅ Automate team onboarding
- ✅ Auto-cleanup stale tokens
- ✅ Alert on anomalies
- ✅ Dashboard for self-service status
- ✅ GitOps for token distribution

---

## Support & Escalation

### Logs to Collect

When opening support tickets:

```bash
# Operator logs
kubectl logs -n keycloak-operator-system \
  deployment/keycloak-operator --tail=1000 > operator-logs.txt

# Token metadata
kubectl get configmap keycloak-operator-token-metadata \
  -n keycloak-operator-system -o yaml > token-metadata.yaml

# Affected token
kubectl get secret <token-name> -n <namespace> -o yaml > affected-token.yaml

# Recent events
kubectl get events --all-namespaces --sort-by='.lastTimestamp' | \
  tail -100 > recent-events.txt

# Metrics snapshot
kubectl exec -n keycloak-operator-system deployment/keycloak-operator -- \
  curl -s localhost:8080/metrics > metrics-snapshot.txt
```

### Escalation Path

1. **Self-service**: Check runbooks and documentation
2. **Team lead**: Escalate to platform team lead
3. **SRE on-call**: Page SRE if production impact
4. **Vendor support**: Contact operator maintainers

---

**Document Version**: 1.0
**Last Reviewed**: 2025-01-21
**Next Review**: 2025-04-21
