# Disaster Recovery

This page covers what you actually lose when things go wrong, the correct order to bring things back, and where to find instructions for specific scenarios.

---

## Your GitOps repository is your primary recovery mechanism

The operator is stateless. Your desired Keycloak state is declared through your `Keycloak`, `KeycloakRealm`, and `KeycloakClient` resources, together with any referenced Kubernetes Secrets and Helm deployment values. When the operator is running and those resources exist in the cluster, it will reconcile them to the desired state without any manual intervention.

If you store those manifests and referenced inputs in a Git repository — which is the intended deployment model — re-applying them is enough to reconstruct the configuration side of Keycloak. You do not need a special operator recovery procedure.

What you need in addition to those declarative resources is a healthy **Keycloak database**. That is it.

---

## What you lose without a database restore

Whether a database restore is worth your operational investment depends on what you use Keycloak for. This table helps you decide:

| What | Survives without DB restore? | Notes |
|------|------------------------------|-------|
| Realm configuration | ✅ Recovered from CRDs | Operator re-creates on reconcile |
| Client configuration | ✅ Recovered from CRDs | Operator re-creates on reconcile |
| IdP / SSO federation settings | ✅ Recovered from CRDs | Re-created from spec |
| Active OAuth sessions | ⚠️ Lost — usually acceptable | Users simply re-authorize |
| Keycloak audit / admin event log | ⚠️ Lost — usually acceptable | Purely historical |
| Operator-managed client secrets | ⚠️ Changed — see below | Operator generates a new secret; consumers need to pick up the new value |
| Manually bound client secrets | ✅ Preserved | Operator reads from your referenced Secret, syncs that value to Keycloak |
| Registered user accounts | ❌ Lost | Passwords, attributes, MFA enrollments |
| User role assignments | ❌ Lost | Must be re-assigned or re-imported |

**The guiding principle:** the more Keycloak is a pass-through to an upstream IdP (Azure AD, Google, GitHub), the less your database matters. If users log in with their corporate SSO and Keycloak holds no local credentials, losing the database and re-applying your CRDs is a full recovery.

The more Keycloak is the identity source — local accounts, password-based login, self-registration — the more critical a timely database backup becomes.

---

## Client secrets and automated rotation

The authoritative source for client secrets is the **Keycloak database**. How recovery affects your consumers depends on whether you restored that database and how the client was configured.

**With a database restore**: Keycloak has the same secret values as before. The operator reads them back from Keycloak and writes them into the credentials Secrets in your namespaces. Values are unchanged. No consumers are affected.

**Without a database restore**: Keycloak creates each client fresh with a new randomly generated secret. The new value is written into the credentials Secrets in your namespaces. Anything that was consuming the old value now has a mismatch until updated.

**With a manually bound secret** (`spec.clientSecret`): the operator always reads the secret value from your referenced Kubernetes Secret and pushes it to Keycloak, regardless of what Keycloak currently has. If Keycloak was re-initialized, the operator will sync your value back into it. The credentials Secret in your namespace reflects your value. No consumers are affected.

### In-cluster applications (without a database restore)

Applications that consume the credentials Secret through environment variables will keep the old value until their pods are restarted. Applications that mount the Secret as a volume usually see the updated files automatically after a short delay, but the application may still need a restart or reload to begin using the new value.

Kubernetes does not automatically restart pods when a Secret changes, so tools such as Stakater Reloader or a Kyverno restart policy are a practical way to automate updates for workloads that need a restart or reload. See the [Secret Management guide](./secret-management.md) for configuration examples.

### Out-of-cluster consumers (without a database restore)

If you copied a client secret value somewhere outside the cluster — a CI/CD secret variable, a `.env` file, a cloud secrets manager — that copy is now wrong. There is no automated path to fix it. You need to export the new value and update every external location by hand:

```bash
kubectl get secret <client-name>-credentials -n <namespace> \
  -o jsonpath='{.data.client-secret}' | base64 -d
```

If you need client secrets available outside the cluster, use a tool like [External Secrets Operator](https://external-secrets.io/) to continuously sync the credentials Secret to your external store. When the value changes, the sync propagates it automatically.

Alternatively, use `spec.clientSecret` to bind the client to a Kubernetes Secret you control. The operator will always push your value to Keycloak, so recovery never generates a new value unexpectedly.

---

## Recovery order

When recovering from a failure that involved data loss:

1. **Restore the Keycloak database first.** Keycloak must be able to connect to a working database before it starts. Starting Keycloak against an empty database will initialize a blank instance.

2. **Bring up Keycloak** (or let the operator deploy it, if you use a managed Keycloak CR).

3. **Ensure the operator is running** and your CRDs are present in the cluster. The operator will reconcile immediately. No manual trigger is needed.

If the operator comes up before the database is ready, Keycloak will report unhealthy and the operator will set the status to `Degraded`. This self-corrects once the database is available — no action required.

---

## Common scenarios

For situations that land you on this page, here is where to find the relevant procedure:

| Scenario | Where to look |
|----------|--------------|
| Keycloak database lost or corrupted | Restore from your database provider's backup (CNPG, managed PostgreSQL, cloud provider snapshot). Then follow the recovery order above. For configuring automated pre-upgrade backups with CNPG, see [Backup & Restore](./backup-restore.md). |
| Operator pod or namespace deleted | Re-deploy via Helm. If only the operator pod or deployment was deleted, there is no data loss and the operator will reconcile on startup. If the namespace was deleted, all namespaced resources in it (including Keycloak CRs and Secrets) were deleted too — after recreating the namespace, re-apply your GitOps manifests and restore Secrets as needed. |
| Entire cluster lost | Restore your database, recreate the cluster, apply your GitOps manifests. The rest follows from the order above. |
| Migrating Keycloak to a different instance or cluster | See the [Migration & Upgrade guide](./migration.md) and [Escape Hatch](./escape-hatch.md). |
| Drift detector marking resources as orphaned | See [Troubleshooting](./troubleshooting.md). |
| Client secret mismatch after recovery | See [Secret Management](./secret-management.md). |
