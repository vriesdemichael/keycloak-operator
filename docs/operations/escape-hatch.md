# Escape Hatch: Migrating Back to Your Previous Solution

You can evaluate this operator safely. If you decide not to adopt it, this guide explains exactly how to recover your realm configuration, clients, and — most critically — your users, and bring them back to your previous Keycloak setup.

!!! tip "Users are the priority"
    Realm configuration is straightforward to re-import. Users are the harder part:
    their hashed credentials, role assignments, and attributes must transfer intact so
    users do not need to reset their passwords. This guide is written with that constraint first.

---

## Step 0 — Export Everything From This Operator's Keycloak

Before you can migrate anywhere, export your data from the Keycloak instance managed by this operator. Use `kc.sh export` — **not** the web UI export, which strips client secrets and certain credential types.

!!! warning "Scale down before exporting"
    To avoid consistency issues and database lock conflicts, scale the operator-managed
    Keycloak StatefulSet to 0 replicas before running the export Job, then scale it back up
    after copying the files.

    ```bash
    kubectl scale statefulset <keycloak-name>-keycloak -n keycloak-system --replicas=0
    # ... run the export Job ...
    kubectl scale statefulset <keycloak-name>-keycloak -n keycloak-system --replicas=1
    ```

### Export via a Kubernetes Job

```yaml
# escape-hatch-export-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keycloak-export
  namespace: keycloak-system   # adjust to your namespace
spec:
  template:
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.0.0   # match your running version
          command: ["/bin/sh", "-c"]
          args:
            - |
              /opt/keycloak/bin/kc.sh export \
                --dir /tmp/export \
                --users realm_file
              # Keep the pod alive so you can copy the files out
              sleep 3600
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://<db-host>:5432/<db-name>
            - name: KC_DB_USERNAME
              valueFrom:
                secretKeyRef:
                  name: <db-credentials-secret>
                  key: username
            - name: KC_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: <db-credentials-secret>
                  key: password
      restartPolicy: Never
```

```bash
kubectl create -f escape-hatch-export-job.yaml

# Wait for the pod to be Running, then copy the export
POD=$(kubectl get pods -n keycloak-system -l job-name=keycloak-export \
  -o jsonpath='{.items[0].metadata.name}')
kubectl cp keycloak-system/$POD:/tmp/export ./keycloak-export

# Clean up
kubectl delete job keycloak-export -n keycloak-system
```

The `./keycloak-export` directory will contain one JSON file per realm (e.g. `my-realm-realm.json`). Each file includes realm settings, clients with their secrets, and fully hashed user credentials.

!!! info "What `kc.sh export` includes"
    - ✅ Realm configuration (roles, groups, flows, settings)
    - ✅ Clients and their secrets
    - ✅ Users with hashed passwords, attributes, and role assignments
    - ✅ Groups and their memberships
    - ❌ Active sessions (users stay logged in on the *old* instance only)
    - ❌ Offline tokens

---

## Scenario 1 — Back to Standalone Keycloak (Recommended)

This is the cleanest path. Standalone Keycloak accepts the full realm export produced by `kc.sh export` and restores everything including hashed user credentials.

**Users do not need to reset their passwords.**

### Option A: Import at Keycloak Startup

Pass the export directory as a startup argument. Keycloak imports the realm on first boot if it does not already exist.

```bash
# Docker/Podman
docker run \
  -e KC_DB=postgres \
  -e KC_DB_URL=... \
  -e KC_DB_USERNAME=... \
  -e KC_DB_PASSWORD=... \
  -v $(pwd)/keycloak-export:/opt/keycloak/data/import:ro \
  quay.io/keycloak/keycloak:26.0.0 \
  start --import-realm
```

On Kubernetes, mount the export from a PersistentVolumeClaim, an `emptyDir` populated by an initContainer, or object storage, and add `--import-realm` to the Keycloak command. Avoid using a ConfigMap: Kubernetes ConfigMaps have a ~1 MiB size limit and full realm exports (especially with users) can easily exceed it.

### Option B: Import via the Admin REST API (Running Instance)

If your standalone Keycloak instance is already running, use the Admin REST API to import each realm:

```bash
# Get an admin token
TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=<admin-pass>" \
  | jq -r '.access_token')

# Import a realm (creates it if it doesn't exist)
curl -s -X POST \
  "http://localhost:8080/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @keycloak-export/my-realm-realm.json
```

!!! warning "Full-realm POST vs Partial Import"
    `POST /admin/realms` with a full realm export JSON restores **everything** including
    users. The `POST /admin/realms/{realm}/partialImport` endpoint is different — it does
    **not** support full realm creation. Use the full endpoint shown above for this scenario.

---

## Scenario 2 — Back to the Realm Operator

!!! warning "Significant limitations ahead"
    The realm operator has fundamental design constraints that this project was built to overcome. Read this section carefully.

The realm operator manages realm and client configuration via Kubernetes `KeycloakRealm` CRDs, but it:

- **Stores client secrets in plaintext** inside CRD specs — a serious security concern in any GitOps flow
- **Has no native user import mechanism** — users must be handled separately
- **Requires credentials in Kubernetes Secrets** that are referenced from CRDs, increasing the attack surface

Proceed with this path only if you have a hard requirement to use the realm operator.

### Step 1 — Reconstruct Realm and Client CRDs

The realm operator uses its own CRD format. You will need to manually map fields from your `kc.sh` export JSON to `KeycloakRealm` and `KeycloakClient` CRDs.

There is no automated converter. Key mappings:

| Export field | Realm Operator CRD path |
|---|---|
| `realm` | `.spec.realm.realm` |
| `displayName` | `.spec.realm.displayName` |
| `clients[].clientId` | `.spec.realm.clients[].clientId` |
| `clients[].secret` | Referenced via `.spec.realm.clients[].secret.name` (K8s Secret) |

!!! danger "Client secrets in Git"
    The realm operator's `KeycloakRealm` CRD encourages inlining client secrets. If you
    commit these CRDs to Git, you are leaking secrets. Use a Kubernetes Secret and reference
    it, or use ESO/Sealed Secrets before committing.

### Step 2 — Import Users

The realm operator does not import historical users. You have two paths:

**Option A — Keycloak startup import** (cleanest, requires access to the realm operator's Keycloak pod):

Mount your `kc.sh` export JSON and restart with `--import-realm`. This restores password hashes.
Consult your realm operator's documentation for how to pass startup flags to its Keycloak instance.

**Option B — Partial Import API**:

The `keycloak-migrate import-users` command from this project's migration toolkit can also import into any reachable Keycloak instance, not just one managed by this operator:

```bash
# First, extract users.json from a transform run (or extract manually)
keycloak-migrate transform \
  --input keycloak-export/my-realm-realm.json \
  --output-dir ./migration-output

# Then import into the realm operator's Keycloak
keycloak-migrate import-users \
  --input migration-output/my-realm/users.json \
  --server-url http://<realm-operator-keycloak>:8080 \
  --username admin \
  --password <admin-password> \
  --realm my-realm
```

!!! info "Password hashes via Partial Import"
    The Partial Import API preserves hashed credentials when the source export was
    produced by `kc.sh export`. Users will not need to reset passwords.

---

## Scenario 3 — Any Other Target

If your target is not standalone Keycloak or the realm operator (e.g., a SAML proxy, a custom IAM system, or a non-Keycloak SSO), there is no generic import path.

**Recommendation**: Keep running this operator. It is production-ready and well-tested. If you have a specific integration concern, open an issue.

If you must migrate away to a non-Keycloak system, you will need to:

1. Export all users from Keycloak via the Admin REST API (`GET /admin/realms/{realm}/users`) — this does **not** include password hashes
2. Force a password-reset flow on first login to your new system
3. Re-configure all clients manually in the new system

There is no path that preserves password hashes outside of Keycloak-to-Keycloak migration.

---

## Summary

| Target | User passwords preserved? | Effort | Recommended? |
|---|---|---|---|
| Standalone Keycloak (`--import-realm`) | ✅ Yes | Low | ✅ Yes |
| Standalone Keycloak (Admin API) | ✅ Yes | Low | ✅ Yes |
| Realm operator + startup import | ✅ Yes (with care) | Medium | ⚠️ Partial |
| Realm operator + `import-users` | ✅ Yes | Medium | ⚠️ Partial |
| Non-Keycloak target | ❌ No — password reset required | High | ❌ No |

For the export procedure used by all scenarios, see the [Realm Export Guide](../how-to/export-realms.md).
For the `import-users` command options, see the [Migration Toolkit Guide](../how-to/migration-toolkit.md#import-users).
