# Exporting Realms & Users

This guide explains how to export Keycloak configuration and user data for migration into this operator’s Helm-first workflow.

## Read This First

- the recommended deployment target is Helm values rendered by the migration toolkit, not hand-written raw CRDs
- realm and client configuration are desired-state data
- users and other live identity records are stateful data and are imported separately
- supported target Keycloak versions start at `24.x`; see [Keycloak Version Support](../reference/keycloak-version-support.md)

If you are leaving this operator rather than migrating into it, see [Escape Hatch](../operations/escape-hatch.md).

## Prerequisites

Before the first `keycloak-migrate` command, download the toolkit from the GitHub Releases page for this repository:

```bash
# Pick the migration-toolkit release that matches the version you want
gh release download migration-toolkit-v<version> \
  --repo vriesdemichael/keycloak-operator \
  --pattern '*keycloak-migrate*'
```

Or download the binary asset directly from the migration toolkit releases view:

`https://github.com/vriesdemichael/keycloak-operator/releases?q=migration-toolkit`

Also make sure you know the actual Keycloak version you are exporting from. Do not hardcode a stale image tag into export jobs.

## What You Are Exporting

Exports contain two different categories of data:

### Desired-State Configuration

- realm settings
- clients and client configuration
- roles, groups, protocol settings, and related declarative configuration

This is what the migration toolkit transforms into Helm values.

### Stateful Identity Data

- users
- password hashes
- attributes and group membership
- other runtime identity records

This is not reconciled through `KeycloakRealm` or `KeycloakClient` CRs. It is imported through dedicated user-migration workflows.

## Export Scenarios

Choose the scenario that matches your current environment.

### Kubernetes-Based Keycloak

This is the most common case.

1. determine the running Keycloak image version
2. scale down or otherwise gate writes if you need a strongly consistent export
3. run `kc.sh export` from a matching Keycloak image version
4. copy the export out
5. validate the export before moving on

Example version check:

```bash
kubectl get deploy -n <namespace> <keycloak-deployment> \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

Example export job:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keycloak-export
  namespace: keycloak-namespace
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.5.2  # Replace with the exact version your source Keycloak is running
          command: ["/bin/sh", "-c"]
          args:
            - |
              /opt/keycloak/bin/kc.sh export \
                --dir /tmp/export \
                --users realm_file \
                --realm my-realm
              sleep 3600
          env:
            - name: KC_DB
              value: postgres
            - name: KC_DB_URL
              value: jdbc:postgresql://keycloak-db-rw:5432/keycloak
            - name: KC_DB_USERNAME
              valueFrom:
                secretKeyRef:
                  name: keycloak-db-credentials
                  key: username
            - name: KC_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: keycloak-db-credentials
                  key: password
```

Use the exact Keycloak version that matches the source instance you are exporting from.

### Container-Based Keycloak

Run an export container attached to the same database and network as the current deployment.

Prefer secret-backed environment variables instead of typing passwords directly into shell history.

```bash
export KC_DB_PASSWORD="$(pass show keycloak/db-password)"

docker run --rm \
  --network keycloak-network \
  -v $(pwd)/export:/tmp/export \
  -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://postgres-container:5432/keycloak \
  -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD="$KC_DB_PASSWORD" \
  ${KEYCLOAK_IMAGE} \
  export --dir /tmp/export --users realm_file --realm my-realm
```

### VM Or Bare-Metal Keycloak

Stop the service or otherwise gate writes, then run `kc.sh export` locally with the installed Keycloak distribution.

### Legacy WildFly Keycloak

Do not treat very old WildFly-era exports as a direct import path into this operator.

Upgrade into a supported Quarkus-based Keycloak first, then export from there.

## Validate The Export Before Migration

Before destructive follow-up work:

1. confirm the export contains the expected realm JSON files
2. confirm the realm file includes clients and users where expected
3. keep a backup of the original export separate from the transformed output

Example quick check:

```bash
ls -1 ./keycloak-export
jq '.realm, (.clients | length), (.users | length)' ./keycloak-export/my-realm-realm.json
```

## Transform Configuration Into Helm Values

Use the migration toolkit to turn exported configuration into Helm values:

```bash
./keycloak-migrate transform \
  --input ./keycloak-export/my-realm-realm.json \
  --output-dir ./migration-output \
  --operator-namespace keycloak-system \
  --secret-mode eso \
  --eso-store my-vault-store
```

This produces:

- `realm-values.yaml` for the `keycloak-realm` chart
- `clients/<name>/values.yaml` for each `keycloak-client` chart release
- secret material transformed according to the selected secret mode
  - `plain` writes Kubernetes `Secret` manifests
  - `eso` writes `ExternalSecret` manifests that point at your external secret backend
  - `sealed-secrets` writes `SealedSecret` manifests that must still be sealed with your controller key
- `unsupported-features.json`
- `NEXT-STEPS.md`, which summarizes the transformed realm, calls out any unsupported or manual follow-up work, and gives the post-transform checklist you should complete before deployment

See [Migration Toolkit secret modes](./migration-toolkit.md#secret-modes) and [Migration Toolkit unsupported features](./migration-toolkit.md#unsupported-features).

## Deploy Configuration Through Helm

Install the realm first:

```bash
helm install my-realm \
  oci://ghcr.io/vriesdemichael/charts/keycloak-realm \
  -f migration-output/my-realm/realm-values.yaml \
  -n my-namespace \
  --version 0.4.8
```

Then install clients:

```bash
helm install my-app \
  oci://ghcr.io/vriesdemichael/charts/keycloak-client \
  -f migration-output/my-realm/clients/my-app/values.yaml \
  -n my-namespace \
  --version 0.4.5
```

Before installing client charts into other namespaces, make sure the realm’s `clientAuthorizationGrants` includes those namespaces.

## Import Users Separately

The operator manages configuration declaratively. User import is separate.

### Preferred For Full Environment Migration

If you are moving the whole installation and database continuity is acceptable, database migration or restore preserves the most state.

### Repeatable User Import Workflow

Use the toolkit’s `import-users` command:

```bash
./keycloak-migrate import-users \
  --input migration-output/my-realm/users.json \
  --keycloak my-keycloak \
  --namespace keycloak-system \
  --realm my-realm
```

This is the preferred repeatable import path for user data generated by the toolkit.

### Manual Partial Import

If you need a manual workflow for a smaller cutover, you can still use Keycloak’s Partial Import tooling, but it is not the primary GitOps path.

## Post-Import Verification

After deployment and user import:

1. verify the realm reaches a healthy phase
2. verify expected clients exist and generated secrets are present where applicable
3. verify at least one real login or token flow
4. verify imported users can authenticate without forced password reset when hashes were preserved

Useful checks:

```bash
kubectl get keycloakrealm -n my-namespace
kubectl get keycloakclient -n my-namespace
kubectl logs -n keycloak-system -l app.kubernetes.io/name=keycloak-operator --tail=100
```

## See Also

- [Migration Toolkit](./migration-toolkit.md)
- [Migration & Upgrade Guide](../operations/migration.md)
- [Escape Hatch](../operations/escape-hatch.md)
- [Keycloak Version Support](../reference/keycloak-version-support.md)
