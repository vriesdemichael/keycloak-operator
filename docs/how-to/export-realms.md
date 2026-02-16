# Exporting Realms & Users

This guide provides instructions for exporting Keycloak realms, users, and secrets for migration purposes. These exports can be used to migrate existing Keycloak installations to this operator.

## Overview

The migration process generally involves:
1.  **Exporting data** from your existing Keycloak instance.
2.  **Transforming configuration** into Kubernetes Custom Resources (CRDs).
3.  **Importing data** (users, sessions) into the new instance.

### Scope of Export
Standard Keycloak exports include:
*   **Realm Configuration**: Roles, groups, settings.
*   **Clients**: Configurations, redirect URIs.
*   **Users**: Credentials (hashed), attributes, role mappings.
*   **Secrets**: Client secrets and hashed user passwords (encrypted).

## Scenarios

Choose the instruction set that matches your current environment.

### 1. Kubernetes (Clustered Quarkus with Infinispan)

For Keycloak deployed on Kubernetes (Quarkus distribution) with an external database (e.g., CNPG, RDS).

**Prerequisites:**
*   `kubectl` access to the cluster.
*   Database credentials (usually in a Secret).

**Steps:**

1.  **Identify Database Credentials**:
    Locate the secret containing your database credentials.
    ```bash
    kubectl get secret keycloak-db-credentials -o jsonpath='{.data}'
    ```

2.  **Scale Down Keycloak**:
    To ensure data consistency and release database locks, scale the Keycloak StatefulSet to 0.
    ```bash
    kubectl scale statefulset keycloak --replicas=0 -n keycloak-namespace
    ```

3.  **Run Export Job**:
    Deploy a temporary Job to perform the export. Replace environment variables with your specific database configuration.

    ```yaml
    # export-job.yaml
    apiVersion: batch/v1
    kind: Job
    metadata:
      name: keycloak-export
      namespace: keycloak-namespace
    spec:
      template:
        spec:
          containers:
            - name: keycloak
              image: quay.io/keycloak/keycloak:26.0.0  # Use your current version
              command: ["/bin/sh", "-c"]
              args:
                - |
                  /opt/keycloak/bin/kc.sh export --dir /tmp/export --users realm_file --realm my-realm
                  # Keep pod running to allow copying
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
          restartPolicy: Never
    ```
    ```bash
    kubectl apply -f export-job.yaml
    ```

4.  **Copy Exported Data**:
    Once the job is running (check `kubectl get pods`), copy the files to your local machine.
    ```bash
    POD_NAME=$(kubectl get pods -n keycloak-namespace -l job-name=keycloak-export -o jsonpath='{.items[0].metadata.name}')
    kubectl cp keycloak-namespace/$POD_NAME:/tmp/export ./keycloak-export
    ```

5.  **Cleanup**:
    ```bash
    kubectl delete job keycloak-export -n keycloak-namespace
    kubectl scale statefulset keycloak --replicas=3 -n keycloak-namespace
    ```

### 2. Single Node Container (Docker/Podman)

For a single Keycloak container running locally or on a server.

**Steps:**

1.  **Stop the Container**:
    ```bash
    docker stop keycloak-container
    ```

2.  **Run Export**:
    Run a temporary container attached to the same network/volume/database.

    *If using an external database container:*
    ```bash
    docker run --rm \
      --network keycloak-network \
      -v $(pwd)/export:/tmp/export \
      -e KC_DB=postgres \
      -e KC_DB_URL=jdbc:postgresql://postgres-container:5432/keycloak \
      -e KC_DB_USERNAME=keycloak \
      -e KC_DB_PASSWORD=password \
      quay.io/keycloak/keycloak:26.0.0 \
      export --dir /tmp/export --users realm_file --realm my-realm
    ```

    *If using an internal H2 database (not recommended for production):*
    You must mount the data volume of the stopped container.
    ```bash
    docker run --rm \
      -v keycloak-data-volume:/opt/keycloak/data/h2 \
      -v $(pwd)/export:/tmp/export \
      quay.io/keycloak/keycloak:26.0.0 \
      export --dir /tmp/export --users realm_file --realm my-realm
    ```

### 3. Single Node VM (Systemd/Bare Metal)

For Keycloak running directly on a Virtual Machine.

**Steps:**

1.  **Stop Keycloak Service**:
    ```bash
    sudo systemctl stop keycloak
    ```

2.  **Run Export Command**:
    Switch to the Keycloak user and run the export CLI.
    ```bash
    # As root or keycloak user
    cd /opt/keycloak
    bin/kc.sh export --dir /tmp/export --users realm_file --realm my-realm
    ```

3.  **Restart Service**:
    ```bash
    sudo systemctl start keycloak
    ```

### 4. Legacy WildFly Keycloak (Pre-Quarkus)

Older versions of Keycloak (16 and below) running on WildFly require a different approach.

**Strategy: Upgrade then Export**
Directly exporting from WildFly and importing into Quarkus often leads to compatibility issues. The recommended path is:

1.  **Migrate Database**: Perform a database migration to a newer Keycloak version (Quarkus) using the official Keycloak migration guide.
2.  **Export from New Version**: Once the database is upgraded and running with a Quarkus distribution, use **Scenario 1, 2, or 3** above to perform the export.

---

## Importing into Keycloak Operator

This operator follows a **GitOps-first** approach. It manages *configuration* (Realms, Clients) but does not manage *stateful data* (Users, Sessions) via CRDs.

### 1. Transform Configuration with the Migration Toolkit

Use the [Migration Toolkit](./migration-toolkit.md) to automatically transform your export files into Helm chart values:

```bash
keycloak-migrate transform \
  --input ./keycloak-export/my-realm-realm.json \
  --output-dir ./migration-output \
  --operator-namespace keycloak-system \
  --secret-mode eso \
  --eso-store my-vault-store
```

This produces:

- `realm-values.yaml` — Helm values for the `keycloak-realm` chart
- `clients/<name>/values.yaml` — Helm values for each `keycloak-client` chart release
- `secrets.yaml` — Secret manifests (plain, ExternalSecret, or SealedSecret)
- `unsupported-features.json` — Features not yet supported with tracking issue links
- `NEXT-STEPS.md` — Actionable migration checklist

See the [Migration Toolkit Guide](./migration-toolkit.md) for full command reference, secret mode options, and examples.

### 2. Deploy with Helm

```bash
# Deploy realm
helm install my-realm keycloak-realm \
  -f migration-output/my-realm/realm-values.yaml \
  -n my-namespace

# Deploy each client
helm install my-app keycloak-client \
  -f migration-output/my-realm/clients/my-app/values.yaml \
  -n my-namespace
```

### 3. Import Users (Data Migration)

Since the `KeycloakRealm` CRD does not manage users, you must import them separately.

**Option A: Database Migration (Recommended)**
If migrating the entire installation, backup and restore the PostgreSQL database directly using CloudNativePG. This preserves all data, including users, sessions, and history.

*   See [Database Setup Guide](./database-setup.md) for restore instructions.

**Option B: Partial Import (Manual)**
If starting fresh and only migrating specific users:

1.  Deploy Keycloak using the operator.
2.  Log in to the Keycloak Admin Console.
3.  Navigate to **Realm Settings** > **Partial Import**.
4.  Upload the `users.json` file generated by the migration toolkit.
5.  Select **Overwrite** or **Skip** strategy as needed.

!!! note "User passwords are preserved"
    Keycloak exports include password hashes. Users imported via Partial Import retain their existing passwords — no password reset is required.
