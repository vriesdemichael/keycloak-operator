# Disaster Recovery

This page covers what you actually lose when things go wrong, the correct order to bring things back, and where to find instructions for specific scenarios.

---

## Your GitOps repository is your primary recovery mechanism

The operator is stateless. Every Keycloak realm, client, and configuration setting is declared in your `KeycloakRealm` and `KeycloakClient` CRDs. When the operator is running and those CRDs exist in the cluster, it will reconcile them to the desired state without any manual intervention.

If you store your CRD manifests in a Git repository — which is the intended deployment model — re-applying them is enough to reconstruct the configuration side of Keycloak. You do not need a special operator recovery procedure.

What you need in addition to your CRD manifests is a healthy **Keycloak database**. That is it.

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

How the operator handles client secrets after a recovery depends on whether the Kubernetes Secret still exists:

**If the Kubernetes Secret survives** (e.g., only Keycloak's database was lost, or you restored from a cluster backup): the operator reads the secret value from the existing Kubernetes Secret and syncs it back to the freshly initialized Keycloak. The value is unchanged. No consumers are affected.

**If the Kubernetes Secret is gone** (e.g., full cluster loss without a cluster backup, and no database restore): the operator creates the client fresh in Keycloak and generates a new secret. That new value is written into a new Kubernetes Secret in your namespace. Anything that was consuming the old value now has a mismatch.

### In-cluster applications

Applications that mount the Kubernetes Secret as a volume or environment variable will have stale values until their pods are restarted. Kubernetes does not automatically restart pods when a Secret changes.

Use [Stakater Reloader](https://github.com/stakater/Reloader) or a [Kyverno restart policy](./secret-management.md#kyverno-restart-policy) to automate this. See the [Secret Management guide](./secret-management.md) for configuration examples.

### Out-of-cluster consumers

If you manually copied a client secret value somewhere outside the cluster — a CI/CD secret variable, a `.env` file, a cloud secrets manager entry — that copy is now wrong and there is no automated path to fix it. You need to export the new value from the Kubernetes Secret and update every external location by hand:

```bash
kubectl get secret <client-name>-credentials -n <namespace> \
  -o jsonpath='{.data.client-secret}' | base64 -d
```

The only way to avoid this problem is to not copy secret values out-of-band in the first place. If you need the secret available outside the cluster, use a tool like [External Secrets Operator](https://external-secrets.io/) to continuously sync the Kubernetes Secret to your external store — so when the secret changes, the sync propagates the new value automatically.

Alternatively, pin the secret to a known value from the start by using `spec.clientSecret` (a reference to a Kubernetes Secret you control) rather than operator-managed generation. When a manually bound secret is used, the operator always reads from your referenced Secret and pushes that value to Keycloak — so you control the value and a recovery never changes it unexpectedly.

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
| Operator pod or namespace deleted | Re-deploy via Helm. No data loss — CRDs survive namespace deletion. Operator reconciles on startup. |
| Entire cluster lost | Restore your database, recreate the cluster, apply your GitOps manifests. The rest follows from the order above. |
| Migrating Keycloak to a different instance or cluster | See the [Migration & Upgrade guide](./migration.md) and [Escape Hatch](./escape-hatch.md). |
| Drift detector marking resources as orphaned | See [Troubleshooting](./troubleshooting.md). |
| Client secret mismatch after recovery | See [Secret Management](./secret-management.md). |
