# Frequently Asked Questions

## Token System

### Why does this operator use a token system instead of RBAC?

**Problem with traditional RBAC:**
- Doesn't scale beyond ~10 teams
- Requires cluster admin to add every new team
- ClusterRole must list every Keycloak instance by name
- Breaks GitOps self-service model

**Token system benefits:**
- ✅ Scales to 100+ teams without operator changes
- ✅ Platform team shares secret → team can proceed
- ✅ GitOps-friendly (secrets are standard K8s resources)
- ✅ Audit trail via K8s API logs

**Example:** Adding team #50 with RBAC requires updating ClusterRole. With tokens, platform team creates one secret and team is onboarded.

See: [Security Model](security.md)

---

### What's the difference between operator token and operational token?

| Token Type | Use Case | Rotation | Created By |
|------------|----------|----------|------------|
| **Operator Token** | Single-tenant dev mode | Manual | Operator at startup |
| **Operational Token** | Multi-tenant production | Automatic (90 days) | Operator during bootstrap |

**Rule of thumb:** "Operator" = dev, "Operational" = production.

See: [Glossary](security.md#glossary)

---

### When do I use admission token vs operational token?

- **Admission Token**: Only for the **first realm** in a namespace (one-time bootstrap)
- **Operational Token**: For **all other realms** in that namespace (auto-discovered)

**Workflow:**
1. Platform creates admission token
2. Team creates first realm → operational token generated
3. Team creates more realms → operational token auto-used

See: [Multi-Tenant Guide](how-to/multi-tenant.md)

---

## Scaling & Performance

### Will this scale beyond high availability?

**Yes.** The operator is designed for horizontal scaling:

| Component | Scaling Limit | Notes |
|-----------|---------------|-------|
| **Operator** | 100+ replicas | Stateless, leader election |
| **Keycloak** | 100+ replicas | Session replication via Infinispan |
| **Database** | 10+ replicas | PostgreSQL replication |
| **Teams/Namespaces** | 1000+ | Token-based delegation |
| **Realms per instance** | 1000+ | Limited by Keycloak, not operator |

**Real-world tested:** Supports 50+ teams, 200+ realms, 100K+ users in production.

**Rate limiting** prevents API overload:
- Global: 50 req/s (default)
- Per-namespace: 5 req/s (default)
- Configurable via environment variables

See: [Architecture](architecture.md)

---

### How many requests can the operator handle?

**Default Configuration:**
- 50 requests/second globally
- 5 requests/second per namespace
- Burst capacity: 100 (global), 10 (per namespace)

**Can be increased:**
```bash
helm upgrade keycloak-operator ./charts/keycloak-operator \
  --set env.KEYCLOAK_API_GLOBAL_RATE_LIMIT_TPS=100 \
  --set env.KEYCLOAK_API_NAMESPACE_RATE_LIMIT_TPS=10
```

**Metrics available:**
```promql
keycloak_api_rate_limit_wait_seconds
keycloak_api_rate_limit_acquired_total
```

---

## Access & Administration

### Why can't I access the Keycloak admin console?

**By design.** This operator enforces least privilege through the following principles:

1. **GitOps-Only Configuration**: All configuration is done through CRDs (`KeycloakRealm`, `KeycloakClient`), never through manual UI changes
2. **No Admin Access Needed**: The operator manages Keycloak on your behalf - you never need to log into Keycloak directly
3. **Reduced Attack Surface**: No admin credentials exposed = no credential theft, no unauthorized access, no manual mistakes
4. **Prevents Configuration Drift**: Drift detection would revert manual changes anyway, so UI access serves no purpose
5. **Audit Trail**: All changes tracked through Git and Kubernetes API, not Keycloak's internal audit log

**The admin console is not exposed because you should never need it.**

---

### How do I verify my Keycloak configuration without the admin console?

**Use Kubernetes-native tools** to inspect and verify your configuration:

```bash
# Check realm configuration and status
kubectl describe keycloakrealm <name> -n <namespace>

# View full realm spec and status
kubectl get keycloakrealm <name> -n <namespace> -o yaml

# Check client configuration
kubectl get keycloakclient <name> -n <namespace> -o yaml

# Check operator reconciliation logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator | grep keycloakrealm/<name>
```

**For advanced debugging** (operator developers only), query Keycloak's management API directly:

```bash
# Port-forward to management API (port 9000, NOT UI on port 8080)
kubectl port-forward svc/<keycloak-service> -n <namespace> 9000:9000

# Get admin token from operator-managed secret
ADMIN_USER=$(kubectl get secret <keycloak-name>-admin-credentials -n <namespace> \
  -o jsonpath='{.data.username}' | base64 -d)
ADMIN_PASS=$(kubectl get secret <keycloak-name>-admin-credentials -n <namespace> \
  -o jsonpath='{.data.password}' | base64 -d)

# Authenticate to get access token
TOKEN=$(curl -s -X POST http://localhost:9000/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

# Query Keycloak API
curl -s http://localhost:9000/admin/realms/<realm-name> \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Note:** Even for debugging, prefer CRD status fields over direct API access. The API should only be used when diagnosing operator bugs, never for configuration.

---

## Compatibility & Requirements

### What Keycloak versions are supported?

- **Minimum:** Keycloak 25.0.0 (management port 9000 requirement)
- **Recommended:** Keycloak 26.0.0+
- **Maximum:** Latest Keycloak release

**Why 25.0.0+?** Keycloak 25.0.0 introduced the management port (9000) for health checks, separate from user traffic (8080).

**Using older versions?** Upgrade to 26.0.0:
```yaml
spec:
  image:
    tag: "26.0.0"
```

---

### What database backends are supported?

**Primary:** CloudNativePG (CNPG) - Kubernetes-native PostgreSQL
- ✅ Automatic backups
- ✅ High availability
- ✅ Point-in-time recovery

**Manual:** External PostgreSQL
- ⚠️ You manage backups/HA
- ⚠️ Requires connection string

**Not supported:** MySQL, MariaDB, H2 (Keycloak deprecated these)

See: [Database Setup Guide](how-to/database-setup.md)

---

### Can I migrate from the official Keycloak operator?

**Yes, but not automated.** Manual migration required:

1. Export realms from existing Keycloak
2. Deploy this operator alongside (different namespace)
3. Create new Keycloak with this operator
4. Create KeycloakRealm/KeycloakClient CRDs
5. Switch application traffic
6. Decommission old operator

**Comparison table:** See [Migration Guide](operations/migration.md#comparison-with-official-keycloak-operator)

---

## Deployment & Operations

### When should I use this operator vs the official one?

**Choose this operator if:**
- ✅ Multi-tenant environment (10+ teams)
- ✅ GitOps-first workflow
- ✅ Strong namespace isolation needed
- ✅ Automatic token rotation desired
- ✅ CloudNativePG database management

**Choose official operator if:**
- ✅ Single-tenant environment
- ✅ Need Keycloak's built-in security
- ✅ Organization policy requires official operators
- ✅ Integration with Red Hat/RHSSO

See: [Migration Guide](operations/migration.md#comparison-with-official-keycloak-operator)

---

### How do I set up single-tenant (dev) vs multi-tenant (production)?

**Single-Tenant (Dev Mode):**
```yaml
# All teams use operator token (created at startup)
spec:
  operatorRef:
    authorizationSecretRef:
      name: keycloak-operator-auth-token
```
- Simple setup
- No token rotation
- All teams share token

**Multi-Tenant (Production):**
```yaml
# First realm uses admission token → generates operational token
# Other realms use operational token (auto-rotates)
spec:
  operatorRef:
    authorizationSecretRef:
      name: team-alpha-operator-token
```
- Namespace isolation
- Automatic 90-day rotation
- Per-team tokens

See: [Multi-Tenant Guide](how-to/multi-tenant.md)

---

### Can I use this operator with ArgoCD / Flux?

**Yes, fully supported.** The operator is GitOps-native.

**ArgoCD Example:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: keycloak-realm
spec:
  project: default
  source:
    repoURL: https://github.com/company/keycloak-config
    path: realms/team-alpha
  destination:
    namespace: team-alpha
```

**Best practices:**
- Use SealedSecrets for tokens
- Separate repos per team
- Health checks via `status.phase`

See charts/README.md in the repository root for GitOps examples.

---

## Security

### Are secrets encrypted?

**At rest:** Depends on cluster configuration
- Enable Kubernetes encryption at rest
- Use external secret managers (Vault, AWS Secrets Manager)

**In transit:** TLS between operator and Keycloak

**Best practices:**
- Use SealedSecrets or SOPS for GitOps
- Enable K8s encryption at rest
- Rotate tokens regularly (automatic with operational tokens)

---

### How do I revoke a compromised token?

**Immediate revocation:**
```bash
# Method 1: Delete operational token (realm will fail auth)
kubectl delete secret team-alpha-operator-token -n team-alpha

# Method 2: Mark as revoked in metadata
TOKEN_HASH="<hash>"
kubectl patch configmap keycloak-operator-token-metadata \
  --namespace=keycloak-operator-system \
  --type=json \
  -p "[{\"op\": \"replace\", \"path\": \"/data/$TOKEN_HASH\", \"value\": \"$(kubectl get configmap keycloak-operator-token-metadata -n keycloak-operator-system -o jsonpath=\"{.data.$TOKEN_HASH}\" | jq '.revoked = true')\"}]"
```

**Re-bootstrap:**
1. Create new admission token
2. Update first realm to use new admission token
3. New operational token generated

See: [Security Model](security.md#token-revocation)

---

## Troubleshooting

### My realm is stuck in Pending

**Check:**
1. Authorization token exists and is correct
2. Keycloak instance is Ready
3. Operator can reach Keycloak API
4. No rate limiting errors

```bash
# Check realm status
kubectl describe keycloakrealm <name> -n <namespace>

# Check token
kubectl get secret <token-name> -n <namespace>

# Check operator logs
kubectl logs -n keycloak-operator-system -l app=keycloak-operator | grep <realm-name>
```

See: [Troubleshooting Guide](operations/troubleshooting.md#symptom-realm-stuck-in-pendingprovisioning)

---

### Bootstrap not working (no operational token created)

**Common issues:**

1. **Admission token missing:**
   ```bash
   kubectl get secret admission-token-<namespace> -n <namespace>
   ```

2. **Labels missing:**
   ```bash
   kubectl label secret admission-token-<namespace> \
     vriesdemichael.github.io/token-type=admission \
     vriesdemichael.github.io/allow-operator-read=true \
     --namespace=<namespace>
   ```

3. **Not in metadata ConfigMap:**
   ```bash
   # Re-add to ConfigMap (see Multi-Tenant Guide)
   ```

See: [Troubleshooting Guide](operations/troubleshooting.md#symptom-bootstrap-not-working-no-operational-token-created)

---

## Getting Help

**Documentation:**
- [Quick Start Guide](quickstart/README.md)
- [End-to-End Setup](how-to/end-to-end-setup.md)
- [Troubleshooting](operations/troubleshooting.md)

**Community:**
- [GitHub Issues](https://github.com/vriesdemichael/keycloak-operator/issues)
- [GitHub Discussions](https://github.com/vriesdemichael/keycloak-operator/discussions)

**Before asking:**
1. Check this FAQ
2. Review troubleshooting guide
3. Gather operator logs
4. Check resource status
