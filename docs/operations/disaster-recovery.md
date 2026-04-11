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

| What might be lost | Lost without DB restore? | Notes |
|--------------------|--------------------------|-------|
| Realm configuration | **No** — recovered from CRDs | Operator re-creates on reconcile |
| Client configuration | **No** — recovered from CRDs | Operator re-creates on reconcile |
| IdP / SSO federation settings | **No** — recovered from CRDs | Re-created from spec |
| Registered user accounts | **Yes** | Passwords, attributes, MFA enrollments |
| User role assignments | **Yes** | Must be re-assigned or re-imported |
| Active OAuth sessions | **Yes** — but acceptable | Users simply re-authorize |
| Operator-managed client secrets | Partial — see below | Operator regenerates on reconcile; external consumers need to pick up the new value |
| Manually copied client secrets | **Yes** | If you copied a secret out-of-band, it will not match the newly generated one |
| Keycloak audit / admin event log | **Yes** — usually acceptable | Purely historical |

**The guiding principle:** the more Keycloak is a pass-through to an upstream IdP (Azure AD, Google, GitHub), the less your database matters. If users log in with their corporate SSO and Keycloak holds no local credentials, losing the database and re-applying your CRDs is a full recovery.

The more Keycloak is the identity source — local accounts, password-based login, self-registration — the more critical a timely database backup becomes.

---

## Client secrets and automated rotation

When the operator manages a client secret (`manageSecret: true` with rotation enabled), a database loss followed by a re-apply of your CRDs will cause the operator to **regenerate the client secret** and write the new value into the Kubernetes Secret in your namespace. Applications that read the Secret directly from the cluster — the intended pattern — will pick up the new value on their next restart or secret refresh.

The problem arises when a secret has been **manually copied to a location outside the cluster** — for example, into an environment variable in a CI system, a `.env` file on a server, or a secrets store populated by hand. Those external copies will be stale and authentication will fail silently until they are updated.

If you have consumers outside the cluster, see the [Secret Management guide](./secret-management.md) for how to:

- Automate pod restarts when a managed secret changes (Stakater Reloader, Kyverno)
- Configure notifications or pipelines for external consumers on rotation events

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
