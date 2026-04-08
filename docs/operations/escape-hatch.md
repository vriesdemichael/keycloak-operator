# Escape Hatch: Exit Paths And Migration Out

This guide documents practical paths for moving away from this operator if your requirements change. The most reliable path is still Keycloak-to-Keycloak migration, because that is the only route that can preserve the most user data with the least friction.

!!! tip "Users are the priority"
    Realm and client configuration can be recreated. Users are harder: password hashes,
    role assignments, and attributes are the parts you do not want to lose.

## Before You Migrate Anywhere

Export first, validate the export, and only then start destructive work.

Use `kc.sh export`, not the admin console export, because the admin console path drops important data such as client secrets and some credential details.

## Step 1: Determine The Running Keycloak Version

Use the managed `Keycloak` resource to determine the image you should export with:

```bash
kubectl get keycloak <name> -n <namespace> -o jsonpath='{.spec.image}{"\n"}'
```

Avoid hardcoding a stale Keycloak image version into export jobs.

## Step 2: Export Everything From The Managed Keycloak

Use [Exporting Realms & Users](../how-to/export-realms.md) as the primary workflow.

If you need a Kubernetes Job for export, use the same Keycloak major version as the running instance.

!!! warning "Scale down before exporting when consistency matters"
    To avoid consistency issues and database lock conflicts, scale the operator-managed
    Keycloak workload down before running the export Job, then scale it back up after
    copying the files out.

    ```bash
    kubectl scale statefulset <keycloak-name>-keycloak -n keycloak-system --replicas=0
    # run export
    kubectl scale statefulset <keycloak-name>-keycloak -n keycloak-system --replicas=1
    ```

### Export Via Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: keycloak-export
  namespace: keycloak-system
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: keycloak
          image: ${KEYCLOAK_IMAGE}
          command: ["/bin/sh", "-c"]
          args:
            - |
              /opt/keycloak/bin/kc.sh export \
                --dir /tmp/export \
                --users realm_file
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
```

After the pod is running:

```bash
POD=$(kubectl get pods -n keycloak-system -l job-name=keycloak-export \
  -o jsonpath='{.items[0].metadata.name}')
kubectl cp keycloak-system/$POD:/tmp/export ./keycloak-export
kubectl delete job keycloak-export -n keycloak-system
```

`kc.sh export` includes:

- realm configuration
- clients and their secrets
- users with hashed passwords, attributes, and role assignments
- groups and memberships

It does not preserve active sessions or offline tokens in a way that replaces normal live state.

## Recommended Exit Path: Standalone Keycloak Or Another Keycloak Deployment

This is the cleanest path.

### Option A: Import At Startup

```bash
docker run \
  -e KC_DB=postgres \
  -e KC_DB_URL=... \
  -e KC_DB_USERNAME=... \
  -e KC_DB_PASSWORD=... \
  -v $(pwd)/keycloak-export:/opt/keycloak/data/import:ro \
  ${KEYCLOAK_IMAGE} \
  start --import-realm
```

On Kubernetes, mount the export from a PVC, `emptyDir` populated by an initContainer, or object storage. Avoid ConfigMaps for large exports.

### Option B: Admin REST API Import

If the target Keycloak instance is already running, use the admin API to create realms from the full export.

Prefer environment variables or secret-backed shell patterns for admin passwords rather than putting credentials directly into shell history.

## Migration Toolkit Path

Use the toolkit when you want to transform exports into the operator’s Helm-first model or reuse the user-import workflow.

See:

- [Migration Toolkit](../how-to/migration-toolkit.md)
- [Exporting Realms & Users](../how-to/export-realms.md)

The toolkit is especially useful when you need to:

- transform realm exports into chart values
- separate secret material from declarative config
- import users with the supported `import-users` flow

## Realm Operator Path

This path is possible, but it should be treated cautiously.

The old realm-operator approach has weaker secret handling and a less attractive GitOps model. If you must target it, verify the exact target version before relying on any CRD mapping.

Important caveats:

- some workflows still encourage plaintext client secret handling in CRs
- user import is not a first-class feature there
- startup import or Keycloak-native export/import is safer than hand-maintained CR translation where possible

If you must take this route:

1. validate the realm-operator version and CRD behavior
2. verify how it expects client secrets and startup import flags
3. prefer Keycloak-native export/import for users instead of manual reconstruction where possible

## Non-Keycloak Targets

If the target is not Keycloak-compatible, assume password-hash preservation is off the table.

Plan for:

- user export and identity mapping
- manual or scripted client recreation
- password reset or re-enrollment workflows

## Storage Guidance For Large Exports

Avoid putting large export payloads into ConfigMaps.

Prefer:

- PersistentVolumeClaims
- object storage such as S3-compatible buckets
- temporary encrypted local storage during a controlled migration window

## Minimal Exit Checklist

1. export and validate realm data first
2. back up the backing database if you still control it
3. choose a Keycloak-to-Keycloak path whenever possible
4. use the migration toolkit for transformed Helm output or user import workflows
5. only decommission the old deployment after import verification succeeds

## Summary

| Target | User passwords preserved? | Effort | Notes |
| --- | --- | --- | --- |
| Standalone Keycloak with `--import-realm` | Yes | Low | Best overall exit path |
| Another Keycloak deployment via admin API | Usually yes | Low to medium | Validate target behavior first |
| Realm operator | Conditional | Medium | Verify target version and secret handling |
| Non-Keycloak IAM target | No | High | Expect password reset or re-enrollment |

## See Also

- [Migration](./migration.md)
- [Backup & Restore](./backup-restore.md)
- [Exporting Realms & Users](../how-to/export-realms.md)
- [Migration Toolkit](../how-to/migration-toolkit.md)
