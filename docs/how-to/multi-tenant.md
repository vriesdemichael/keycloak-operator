# Multi-Tenant Configuration Guide

Configure the operator for multi-tenant environments where multiple teams manage their own realms and clients independently.

## Architecture

```
Platform Team                    Application Teams
     │                                │
     ├─ Deploys Operator              │
     ├─ Creates Keycloak Instance     │
     ├─ Creates Admission Tokens ─────►
     │                                │
     │                         Creates First Realm
     │                         (admission token)
     │                                │
     │◄──── Operational Token ─────────┤
     │      Auto-generated             │
     │                                │
     │                         Creates More Realms
     │                         (operational token)
     │                                │
     │◄────── Auto-Rotation ───────────┤
            (90-day cycle)
```

---

## Platform Team Setup

### 1. Deploy Shared Keycloak

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: Keycloak
metadata:
  name: keycloak
  namespace: platform
spec:
  replicas: 3
  database:
    type: cnpg
    cluster: keycloak-db
    namespace: platform
  ingress:
    enabled: true
    hostname: keycloak.company.com
```

### 2. Create Namespaces for Teams

```bash
# Create namespaces
kubectl create namespace team-alpha
kubectl create namespace team-beta
kubectl create namespace team-gamma

# Label for organization
kubectl label namespace team-alpha team=alpha env=prod
kubectl label namespace team-beta team=beta env=prod
kubectl label namespace team-gamma team=gamma env=prod
```

### 3. Generate Admission Tokens

```bash
#!/bin/bash
TEAMS=("team-alpha" "team-beta" "team-gamma")

for TEAM in "${TEAMS[@]}"; do
  # Generate token
  TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

  # Create secret
  kubectl create secret generic admission-token-${TEAM} \
    --from-literal=token="$TOKEN" \
    --namespace=${TEAM}

  # Add labels
  kubectl label secret admission-token-${TEAM} \
    vriesdemichael.github.io/token-type=admission \
    vriesdemichael.github.io/allow-operator-read=true \
    --namespace=${TEAM}

  # Store metadata
  TOKEN_HASH=$(echo -n "$TOKEN" | sha256sum | cut -d' ' -f1)
  kubectl patch configmap keycloak-operator-token-metadata \
    --namespace=keycloak-operator-system \
    --type=merge \
    --patch "{
      \"data\": {
        \"$TOKEN_HASH\": \"{\\\"namespace\\\": \\\"${TEAM}\\\", \\\"token_type\\\": \\\"admission\\\", \\\"token_hash\\\": \\\"$TOKEN_HASH\\\", \\\"issued_at\\\": \\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"valid_until\\\": \\\"$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)\\\", \\\"version\\\": 1, \\\"created_by_realm\\\": null, \\\"revoked\\\": false}\"
      }
    }"
done
```

### 4. Configure RBAC per Team

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-manager
  namespace: team-alpha
rules:
  # Manage Keycloak resources
  - apiGroups: ["vriesdemichael.github.io"]
    resources: ["keycloakrealms", "keycloakclients"]
    verbs: ["create", "update", "patch", "delete", "get", "list", "watch"]

  # Read tokens
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["admission-token-team-alpha", "team-alpha-operator-token", "*-realm-auth"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-alpha-keycloak
  namespace: team-alpha
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: keycloak-manager
subjects:
  - kind: ServiceAccount
    name: team-alpha-deployer
    namespace: team-alpha
```

### 5. Distribute Tokens (GitOps)

```bash
# Export for GitOps
kubectl get secret admission-token-team-alpha -n team-alpha -o yaml \
  > gitops/teams/team-alpha/admission-token.yaml

# Or use SealedSecrets
kubeseal -o yaml < admission-token.yaml > admission-token-sealed.yaml
```

---

## Application Team Workflow

### Team Alpha: First Realm (Bootstrap)

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: alpha-prod
  namespace: team-alpha
spec:
  realmName: alpha-prod
  operatorRef:
    namespace: platform
    authorizationSecretRef:
      name: admission-token-team-alpha  # ← One-time admission token
      key: token

  security:
    registrationAllowed: false
    resetPasswordAllowed: true
```

**What happens:**
1. Operator validates admission token
2. Creates realm in Keycloak
3. Generates `team-alpha-operator-token` (operational token)
4. Future realms use operational token
5. Token rotates automatically every 90 days

### Team Alpha: Additional Realms

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
metadata:
  name: alpha-staging
  namespace: team-alpha
spec:
  realmName: alpha-staging
  operatorRef:
    namespace: platform
    authorizationSecretRef:
      name: team-alpha-operator-token  # ← Operational token
      key: token

  security:
    registrationAllowed: false
```

### Team Alpha: Create Client

```yaml
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: alpha-webapp
  namespace: team-alpha
spec:
  clientId: alpha-webapp
  realmRef:
    name: alpha-prod
    namespace: team-alpha
    authorizationSecretRef:
      name: alpha-prod-realm-auth  # ← Auto-generated realm token
      key: token

  settings:
    publicClient: false
    standardFlowEnabled: true
    redirectUris:
      - "https://alpha.company.com/callback"
```

---

## Isolation Patterns

### Namespace Isolation

Each team operates in their own namespace:
- **Team Alpha**: `team-alpha` namespace
- **Team Beta**: `team-beta` namespace
- **Team Gamma**: `team-gamma` namespace

Benefits:
- ✅ RBAC enforced at namespace level
- ✅ Tokens don't leak between teams
- ✅ Resource quotas per team
- ✅ Network policies for isolation

### Realm Isolation

Each team manages multiple realms:
- **Team Alpha**: `alpha-prod`, `alpha-staging`, `alpha-dev`
- **Team Beta**: `beta-prod`, `beta-staging`

Benefits:
- ✅ Environment separation
- ✅ Independent configuration
- ✅ Isolated user bases

### Cross-Namespace Clients (Advanced)

Team can create clients in different namespace:

```yaml
# In team-beta namespace
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
metadata:
  name: beta-to-alpha
  namespace: team-beta
spec:
  clientId: beta-to-alpha
  realmRef:
    name: alpha-prod
    namespace: team-alpha  # ← References team-alpha realm
    authorizationSecretRef:
      name: alpha-prod-realm-auth  # ← Must have access to this secret
```

**Requires:** RBAC allowing team-beta to read `alpha-prod-realm-auth` secret.

---

## Resource Quotas

Limit resource usage per team:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-alpha-quota
  namespace: team-alpha
spec:
  hard:
    keycloakrealms.vriesdemichael.github.io: "5"
    keycloakclients.vriesdemichael.github.io: "50"
    requests.cpu: "4"
    requests.memory: "8Gi"
    limits.cpu: "8"
    limits.memory: "16Gi"
```

---

## Monitoring Per Team

### Metrics by Namespace

```promql
# Realms per team
count(keycloak_realm_info) by (namespace)

# Clients per team
count(keycloak_client_info) by (namespace)

# Token rotation status per team
keycloak_operator_tokens_expiring_soon{namespace=~"team-.*"}
```

### Team-Specific Alerts

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: team-alpha-alerts
  namespace: team-alpha
spec:
  groups:
    - name: team-alpha
      rules:
        - alert: TeamAlphaTokenExpiring
          expr: keycloak_operator_tokens_expiring_soon{namespace="team-alpha"} > 0
          for: 24h
          labels:
            severity: warning
            team: alpha
          annotations:
            summary: "Team Alpha token expiring soon"
```

---

## Token Management

### Platform Team Responsibilities

| Task | Frequency | Command |
|------|-----------|---------|
| Create admission tokens | Once per namespace | `kubectl create secret` |
| Monitor token rotation | Continuous | Prometheus metrics |
| Revoke compromised tokens | As needed | `kubectl patch configmap` |
| Audit token usage | Monthly | Review ConfigMap |

### Application Team Responsibilities

| Task | Frequency | Command |
|------|-----------|---------|
| Create first realm | Once | Use admission token |
| Create additional realms | As needed | Use operational token |
| Monitor realm health | Continuous | `kubectl get keycloakrealm` |
| Update realm config | As needed | `kubectl edit keycloakrealm` |

### Token Lifecycle

```
Day 1:   Platform creates admission token
Day 1:   Team creates first realm → operational token generated
Day 2-82: Team uses operational token for all realms
Day 83:  Operator starts rotation (7-day grace period)
Day 83-90: Both old and new tokens valid
Day 90:  Old token removed, new token active
```

---

## Self-Service Onboarding

### Automated Namespace Provisioning

```bash
#!/bin/bash
# scripts/onboard-team.sh

TEAM_NAME=$1
NAMESPACE="team-${TEAM_NAME}"

# 1. Create namespace
kubectl create namespace ${NAMESPACE}
kubectl label namespace ${NAMESPACE} team=${TEAM_NAME} env=prod

# 2. Generate admission token
TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
kubectl create secret generic admission-token-${NAMESPACE} \
  --from-literal=token="$TOKEN" \
  --namespace=${NAMESPACE}
kubectl label secret admission-token-${NAMESPACE} \
  vriesdemichael.github.io/token-type=admission \
  vriesdemichael.github.io/allow-operator-read=true \
  --namespace=${NAMESPACE}

# 3. Create RBAC
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-manager
  namespace: ${NAMESPACE}
rules:
  - apiGroups: ["vriesdemichael.github.io"]
    resources: ["keycloakrealms", "keycloakclients"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["admission-token-${NAMESPACE}", "${NAMESPACE}-operator-token", "*-realm-auth"]
    verbs: ["get"]
EOF

# 4. Create resource quota
kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ${NAMESPACE}-quota
  namespace: ${NAMESPACE}
spec:
  hard:
    keycloakrealms.vriesdemichael.github.io: "5"
    keycloakclients.vriesdemichael.github.io: "50"
EOF

echo "Team ${TEAM_NAME} onboarded to namespace ${NAMESPACE}"
```

---

## Troubleshooting Multi-Tenant

### Token Confusion

```bash
# Check which token realm is using
kubectl get keycloakrealm <name> -n <namespace> \
  -o jsonpath='{.spec.operatorRef.authorizationSecretRef.name}'

# First realm: admission-token-<namespace> OR <namespace>-operator-token
# Other realms: <namespace>-operator-token
```

### Cross-Namespace Access Denied

```bash
# Verify RBAC allows reading secret
kubectl auth can-i get secret/<secret-name> \
  --as=system:serviceaccount:<namespace>:<serviceaccount> \
  --namespace=<target-namespace>
```

### Token Not Rotating

```bash
# Check operator has access to ConfigMap
kubectl auth can-i update configmap \
  --as=system:serviceaccount:keycloak-operator-system:keycloak-operator \
  --namespace=keycloak-operator-system

# Check token expiry
kubectl get secret <namespace>-operator-token -n <namespace> \
  -o jsonpath='{.metadata.annotations.vriesdemichael\.github\.io/valid-until}'
```

---

## Best Practices

### 1. Namespace Strategy
- One namespace per team/department
- Use labels for organization (`team=alpha`, `env=prod`)
- Apply resource quotas

### 2. Token Distribution
- Use GitOps for admission tokens (SealedSecrets/SOPS)
- Never commit plaintext tokens
- Rotate admission tokens yearly

### 3. RBAC
- Least privilege per team
- Separate service accounts per team
- Audit RBAC quarterly

### 4. Monitoring
- Team-specific dashboards
- Per-namespace alerts
- Token expiry notifications

### 5. Documentation
- Onboarding guide for new teams
- Token management procedures
- Escalation paths

---

## Related Documentation

- [End-to-End Setup Guide](./end-to-end-setup.md)
- [Security Model](../security.md)
- [Troubleshooting Guide](../operations/troubleshooting.md)
