# Helm Charts & RBAC Refactor - Implementation Plan

**Date:** October 9, 2025  
**Purpose:** This document provides a detailed, step-by-step plan to execute the architectural refactor for RBAC, Helm chart structure, and authorization as outlined in `TODO/helm-charts-refactor-context.md`.
**Status:** Not Started

---

## High-Level Phases

1.  **Phase 1: CRD Schema Updates** - Modify CRDs and Pydantic models.
2.  **Phase 2: Authorization Infrastructure** - Build token generation and validation logic.
3.  **Phase 3: Handler Updates** - Refactor reconciler logic for new auth flow.
4.  **Phase 4: RBAC Refactor** - Drastically reduce ClusterRole permissions.
5.  **Phase 5: Helm Charts Creation** - Build the three new Helm charts.
6.  **Phase 6: Release Process Updates** - Configure multi-component releases.
7.  **Phase 7: Migration & Documentation** - Update examples and write migration guide.
8.  **Phase 8: End-to-End Testing** - Full validation of the new architecture.

---

## Detailed Implementation Plan

### Phase 1: CRD Schema Updates

*   **Objective:** Update `KeycloakRealm` and `KeycloakClient` CRDs to replace `keycloak_instance_ref` with the new `operatorRef` and `realmRef` authorization structures.
*   **Estimated Time:** 2 hours
*   **Dependencies:** None

#### Step 1.1: Update `KeycloakRealm` CRD

*   **File:** `k8s/crds/keycloakrealm-crd.yaml`
*   **Action:** Remove `keycloak_instance_ref` and add `operatorRef`.

```diff
--- a/k8s/crds/keycloakrealm-crd.yaml
+++ b/k8s/crds/keycloakrealm-crd.yaml
@@ -38,18 +38,25 @@
               login_page_title:
                 type: string
                 description: "HTML title for login pages"
-
-              # Target configuration
-              keycloak_instance_ref:
+ 
+              # Operator reference and authorization
+              operatorRef:
                 type: object
-                description: "Reference to the target Keycloak instance"
+                description: "Reference to the operator managing this realm"
                 properties:
-                  name:
+                  namespace:
                     type: string
-                    description: "Name of the Keycloak instance"
-                  namespace:
+                    description: "Namespace where the operator is running (e.g., keycloak-system)"
+                  authorizationSecretRef:
+                    type: object
+                    description: "Secret containing the token to authorize with the operator"
+                    properties:
+                      name:
+                        type: string
+                        description: "Name of the authorization secret"
+                      key:
+                        type: string
+                        description: "Key within the secret containing the token"
+                        default: "token"
+                    required: ["name"]
+                required:
+                - namespace
+                - authorizationSecretRef
 
               # Security settings
               security:
                 type: object

```

#### Step 1.2: Update `KeycloakClient` CRD

*   **File:** `k8s/crds/keycloakclient-crd.yaml`
*   **Action:** Remove `keycloak_instance_ref` and replace `realm` string with a structured `realmRef`.

```diff
--- a/k8s/crds/keycloakclient-crd.yaml
+++ b/k8s/crds/keycloakclient-crd.yaml
@@ -34,23 +34,28 @@
               description:
                 type: string
                 description: "Client description"
-
-              # Target configuration
-              keycloak_instance_ref:
+ 
+              # Realm reference and authorization
+              realmRef:
                 type: object
-                description: "Reference to the target Keycloak instance"
+                description: "Reference to the parent KeycloakRealm"
                 properties:
                   name:
                     type: string
-                    description: "Name of the Keycloak instance"
+                    description: "Name of the KeycloakRealm CR"
                   namespace:
                     type: string
-                    description: "Namespace of the Keycloak instance"
+                    description: "Namespace of the KeycloakRealm CR"
+                  authorizationSecretRef:
+                    type: object
+                    description: "Secret containing the token to authorize with the realm"
+                    properties:
+                      name:
+                        type: string
+                        description: "Name of the realm's authorization secret"
+                      key:
+                        type: string
+                        description: "Key within the secret containing the token"
+                        default: "token"
+                    required: ["name"]
                 required:
                 - name
-              realm:
-                type: string
-                description: "Target realm name"
-                default: "master"
+                - namespace
+                - authorizationSecretRef
 
               # Client type configuration
               public_client:

```

#### Step 1.3: Update Pydantic Models

*   **Files:**
    *   `src/keycloak_operator/models/common.py`
    *   `src/keycloak_operator/models/realm.py`
    *   `src/keycloak_operator/models/client.py`
*   **Action:** Create new models for `operatorRef` and `realmRef` and update the `KeycloakRealmSpec` and `KeycloakClientSpec` models. Remove the old `KeycloakInstanceRef`.

**1. Create `AuthorizationSecretRef` in `src/keycloak_operator/models/common.py`:**
```python
# src/keycloak_operator/models/common.py

from pydantic import BaseModel, Field

class AuthorizationSecretRef(BaseModel):
    name: str = Field(..., description="Name of the authorization secret")
    key: str = Field("token", description="Key within the secret containing the token")
```

**2. Create `OperatorRef` and update `KeycloakRealmSpec` in `src/keycloak_operator/models/realm.py`:**
```python
# src/keycloak_operator/models/realm.py
# ... imports ...
from keycloak_operator.models.common import AuthorizationSecretRef

class OperatorRef(BaseModel):
    namespace: str = Field(..., description="Namespace where the operator is running")
    authorization_secret_ref: AuthorizationSecretRef = Field(..., alias="authorizationSecretRef")

class KeycloakRealmSpec(BaseModel):
    # ... other fields ...
    
    # REMOVE:
    # keycloak_instance_ref: KeycloakInstanceRef = Field(...)

    # ADD:
    operator_ref: OperatorRef = Field(..., alias="operatorRef", description="Reference to the operator managing this realm")
    
    # ... other fields ...
```

**3. Create `RealmRef` and update `KeycloakClientSpec` in `src/keycloak_operator/models/client.py`:**
```python
# src/keycloak_operator/models/client.py
# ... imports ...
from keycloak_operator.models.common import AuthorizationSecretRef

class RealmRef(BaseModel):
    name: str = Field(..., description="Name of the KeycloakRealm CR")
    namespace: str = Field(..., description="Namespace of the KeycloakRealm CR")
    authorization_secret_ref: AuthorizationSecretRef = Field(..., alias="authorizationSecretRef")

class KeycloakClientSpec(BaseModel):
    # ... other fields ...

    # REMOVE:
    # keycloak_instance_ref: KeycloakInstanceRef = Field(...)
    # realm: str = Field("master", ...)

    # ADD:
    realm_ref: RealmRef = Field(..., alias="realmRef", description="Reference to the parent KeycloakRealm")

    # ... other fields ...
```

**4. Remove `KeycloakInstanceRef` from `src/keycloak_operator/models/common.py` (or wherever it is defined).**

#### Step 1.4: Update Unit Tests for Models

*   **File:** `tests/unit/test_models.py`
*   **Action:** Update or create new tests to validate the new spec models (`KeycloakRealmSpec`, `KeycloakClientSpec`) with example data. Ensure `keycloak_instance_ref` tests are removed.

#### Testing Checkpoint

*   Run `make test-unit`. All model-related tests should pass.
*   Apply the new CRDs to a kind cluster with `kubectl apply -f k8s/crds/`. The command should succeed.
*   Attempt to create a `KeycloakRealm` and `KeycloakClient` with the old `keycloak_instance_ref` spec. The creation should be rejected by the API server.
*   Create a `KeycloakRealm` and `KeycloakClient` with the new `operatorRef` and `realmRef` specs. The resources should be created successfully (the operator will fail to reconcile them, which is expected at this stage).

#### Rollback Strategy

*   Revert the changes to the CRD YAML files and apply them to the cluster.
*   Revert the changes in the Pydantic models.
*   Use `git restore <file>` on all modified files.

---
### Phase 2: Authorization Infrastructure

*   **Objective:** Implement the core logic for generating and validating authorization tokens.
*   **Estimated Time:** 3 hours
*   **Dependencies:** Phase 1

#### Step 2.1: Create Authorization Utility Module

*   **File:** `src/keycloak_operator/utils/auth.py` (new file)
*   **Action:** Create functions for token generation and validation.

```python
# src/keycloak_operator/utils/auth.py
import base64
import logging
import secrets
from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

def generate_token(length: int = 32) -> str:
    """Generates a secure, URL-safe random token."""
    return secrets.token_urlsafe(length)

async def validate_authorization(
    secret_ref: dict[str, str],
    secret_namespace: str,
    expected_token: str,
    k8s_client: client.CoreV1Api,
) -> bool:
    """Validate authorization token from a referenced secret."""
    try:
        secret = await k8s_client.read_namespaced_secret(
            name=secret_ref["name"],
            namespace=secret_namespace,
        )
        token_key = secret_ref.get("key", "token")
        
        if token_key not in secret.data:
            logger.warning(f"Key '{token_key}' not found in secret '{secret_ref['name']}'")
            return False

        encoded_token = secret.data[token_key]
        decoded_token = base64.b64decode(encoded_token).decode("utf-8")
        
        return secrets.compare_digest(decoded_token, expected_token)

    except ApiException as e:
        if e.status == 404:
            logger.warning(f"Authorization secret '{secret_ref['name']}' not found in namespace '{secret_namespace}'")
        else:
            logger.error(f"Cannot read authorization secret '{secret_ref['name']}': {e}")
        return False
    except (base64.binascii.Error, UnicodeDecodeError):
        logger.error(f"Failed to decode token from secret '{secret_ref['name']}'")
        return False
```

#### Step 2.2: Operator Startup Logic

*   **File:** `src/keycloak_operator/operator.py`
*   **Action:** On startup, generate a unique operator token and store it in a secret within the operator's namespace.

```python
# src/keycloak_operator/operator.py

# ... imports ...
from keycloak_operator.utils.auth import generate_token

OPERATOR_NAMESPACE = os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")
OPERATOR_AUTH_SECRET_NAME = "keycloak-operator-auth-token"
OPERATOR_TOKEN = "" # Global variable to hold the token in memory

@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    # ... existing startup logic ...
    
    global OPERATOR_TOKEN
    core_v1 = client.CoreV1Api()

    try:
        # Try to read existing secret
        secret = await core_v1.read_namespaced_secret(name=OPERATOR_AUTH_SECRET_NAME, namespace=OPERATOR_NAMESPACE)
        OPERATOR_TOKEN = base64.b64decode(secret.data["token"]).decode("utf-8")
        logger.info(f"Loaded existing operator token from secret '{OPERATOR_AUTH_SECRET_NAME}'")
    except ApiException as e:
        if e.status == 404:
            # Create secret if it doesn't exist
            logger.info(f"Operator token secret not found. Generating a new one.")
            OPERATOR_TOKEN = generate_token()
            secret_body = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": OPERATOR_AUTH_SECRET_NAME},
                "type": "Opaque",
                "data": {"token": base64.b64encode(OPERATOR_TOKEN.encode()).decode()},
            }
            await core_v1.create_namespaced_secret(namespace=OPERATOR_NAMESPACE, body=secret_body)
            logger.info(f"Created operator token secret '{OPERATOR_AUTH_SECRET_NAME}'")
        else:
            raise kopf.FatalError(f"Failed to read operator token secret: {e}")

```

#### Testing Checkpoint

*   Deploy the operator. Check the operator logs to confirm it generated and stored a token, or loaded an existing one.
*   Check that the `keycloak-operator-auth-token` secret exists in the `keycloak-system` namespace and contains a token.
*   Write unit tests for `generate_token` and `validate_authorization` (mocking the `CoreV1Api` client).

#### Rollback Strategy

*   Revert changes in `operator.py`.
*   Delete the `src/keycloak_operator/utils/auth.py` file.
*   Manually delete the `keycloak-operator-auth-token` secret from the cluster.

---

### Phase 3: Handler Updates

*   **Objective:** Refactor the `KeycloakRealm` and `KeycloakClient` handlers to use the new authorization flow.
*   **Estimated Time:** 4 hours
*   **Dependencies:** Phase 2

#### Step 3.1: Update Realm Handler

*   **File:** `src/keycloak_operator/handlers/realm.py`
*   **Action:**
    1.  Use `operatorRef` to validate the request against the operator's in-memory token.
    2.  Generate a new authorization token for the realm itself.
    3.  Store this realm token in a new secret in the realm's namespace.

```python
# src/keycloak_operator/handlers/realm.py

# ... imports ...
from keycloak_operator.operator import OPERATOR_TOKEN, OPERATOR_NAMESPACE
from keycloak_operator.utils.auth import validate_authorization, generate_token
from keycloak_operator.models.realm import KeycloakRealmSpec

# ...

@kopf.on.create("keycloakrealms", ...)
async def ensure_keycloak_realm(spec: dict, name: str, namespace: str, patch: kopf.Patch, **kwargs):
    # ...
    
    realm_spec = KeycloakRealmSpec(**spec)
    
    # 1. Authorize request against operator token
    core_v1 = client.CoreV1Api()
    is_authorized = await validate_authorization(
        secret_ref=realm_spec.operator_ref.authorization_secret_ref.dict(),
        secret_namespace=realm_spec.operator_ref.namespace,
        expected_token=OPERATOR_TOKEN,
        k8s_client=core_v1,
    )

    if not is_authorized:
        patch.status["phase"] = "Failed"
        patch.status["message"] = "Unauthorized: Invalid or missing operator token."
        raise kopf.PermanentError("Authorization failed.")

    # Check that the operatorRef.namespace matches the operator's actual namespace
    if realm_spec.operator_ref.namespace != OPERATOR_NAMESPACE:
        patch.status["phase"] = "Failed"
        patch.status["message"] = f"operatorRef.namespace must be '{OPERATOR_NAMESPACE}'"
        raise kopf.PermanentError("Invalid operator namespace reference.")

    # ... existing reconciliation logic ...

    # 2. Generate and store realm token
    realm_token = generate_token()
    realm_secret_name = f"{name}-auth-token"
    
    # Store token in memory for client validation (this needs a robust shared cache like Redis for multi-pod operators)
    # For now, we'll rely on reading the secret, but a cache is better for performance.
    
    secret_body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": realm_secret_name,
            "ownerReferences": [ ... ], # Add owner reference to the realm CR
            "labels": {
                "keycloak.mdvr.nl/realm": name,
                "keycloak.mdvr.nl/managed-by": "keycloak-operator",
            }
        },
        "type": "Opaque",
        "data": {"token": base64.b64encode(realm_token.encode()).decode()},
    }
    
    try:
        await core_v1.create_namespaced_secret(namespace=namespace, body=secret_body)
        patch.status["authorizationSecretName"] = realm_secret_name
    except ApiException as e:
        if e.status != 409: # Ignore if already exists
            raise kopf.TemporaryError(f"Failed to create realm auth secret: {e}")

    # ... continue reconciliation ...
```

#### Step 3.2: Update Client Handler

*   **File:** `src/keycloak_operator/handlers/client.py`
*   **Action:**
    1.  Use `realmRef` to find the realm's auth secret.
    2.  Read the expected token from the realm's secret.
    3.  Validate the client's request.
    4.  Determine the Keycloak instance from the realm's `operatorRef`.

```python
# src/keycloak_operator/handlers/client.py

# ... imports ...
from keycloak_operator.utils.auth import validate_authorization
from keycloak_operator.models.client import KeycloakClientSpec

# ...

@kopf.on.create("keycloakclients", ...)
async def ensure_keycloak_client(spec: dict, name: str, namespace: str, patch: kopf.Patch, **kwargs):
    # ...
    
    client_spec = KeycloakClientSpec(**spec)
    realm_ref = client_spec.realm_ref
    
    # 1. Get expected token from the realm's auth secret
    core_v1 = client.CoreV1Api()
    api_client = client.ApiClient()
    custom_objects_api = client.CustomObjectsApi(api_client)

    try:
        # Fetch the parent KeycloakRealm CR to find its auth secret
        realm_cr = await custom_objects_api.get_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            name=realm_ref.name,
            namespace=realm_ref.namespace,
            plural="keycloakrealms",
        )
        
        # This assumes the realm handler has stored the token and secret name in its status
        realm_auth_secret_name = realm_cr.get("status", {}).get("authorizationSecretName")
        if not realm_auth_secret_name:
            raise kopf.TemporaryError("Parent realm has not yet generated its auth token.")

        realm_secret = await core_v1.read_namespaced_secret(name=realm_auth_secret_name, namespace=realm_ref.namespace)
        expected_token = base64.b64decode(realm_secret.data["token"]).decode("utf-8")

    except ApiException as e:
        raise kopf.TemporaryError(f"Failed to get parent realm's authorization token: {e}")

    # 2. Validate the client's authorization
    is_authorized = await validate_authorization(
        secret_ref=realm_ref.authorization_secret_ref.dict(),
        secret_namespace=namespace, # The client CR must provide the secret in its own namespace
        expected_token=expected_token,
        k8s_client=core_v1,
    )

    if not is_authorized:
        patch.status["phase"] = "Failed"
        patch.status["message"] = "Unauthorized: Invalid or missing realm token."
        raise kopf.PermanentError("Authorization with realm failed.")

    # 3. Get Keycloak instance from parent realm's spec
    operator_namespace = realm_cr["spec"]["operatorRef"]["namespace"]
    
    # Now, proceed with reconciliation using the operator_namespace to find the Keycloak instance
    # ...
```
*   **Note:** This design requires the user to copy the realm's auth token secret into the client's namespace. This is consistent with the "user responsibility" decision.

#### Step 3.3: Update Keycloak Handler

*   **File:** `src/keycloak_operator/handlers/keycloak.py`
*   **Action:** Add a check to ensure `Keycloak` CRs can only be created in the operator's own namespace.

```python
# src/keycloak_operator/handlers/keycloak.py
# ...
from keycloak_operator.operator import OPERATOR_NAMESPACE

@kopf.on.create("keycloaks", ...)
async def create_keycloak_instance(namespace: str, name: str, patch: kopf.Patch, **_):
    if namespace != OPERATOR_NAMESPACE:
        message = f"Keycloak instances can only be created in the operator namespace ('{OPERATOR_NAMESPACE}')"
        patch.status["phase"] = "Failed"
        patch.status["message"] = message
        raise kopf.PermanentError(message)
    
    # ... existing logic ...
```

#### Testing Checkpoint

*   Update unit tests for all three handlers, mocking the authorization flow.
*   **Integration Test:**
    1.  Deploy the operator.
    2.  Create a `KeycloakRealm` with a valid `operatorRef`. Verify it reconciles and creates an auth secret.
    3.  Create a `KeycloakRealm` with an invalid token secret. Verify it fails with an "Unauthorized" error.
    4.  Copy the realm's auth secret to a different namespace.
    5.  Create a `KeycloakClient` in that namespace with a valid `realmRef`. Verify it reconciles successfully.
    6.  Create a `KeycloakClient` with an invalid token. Verify it fails.
    7.  Attempt to create a `Keycloak` CR outside the `keycloak-system` namespace. Verify it is permanently rejected.

#### Rollback Strategy

*   Revert the logic in all three handlers to use `keycloak_instance_ref`.
*   This requires reverting Phase 1 and 2 as well.

---

### Phase 4: RBAC Refactor

*   **Objective:** Replace the overly permissive `ClusterRole` with a minimal one, and a `Role` scoped to the operator's namespace.
*   **Estimated Time:** 2 hours
*   **Dependencies:** Phase 3

#### Step 4.1: Create New Minimal `ClusterRole`

*   **File:** `k8s/rbac/cluster-role.yaml`
*   **Action:** Replace the entire file content with the new minimal set of permissions.

```yaml
# k8s/rbac/cluster-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: keycloak-operator
rules:
# 1. Read-only access to our CRDs across all namespaces.
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms", "keycloakclients"]
  verbs: ["get", "list", "watch"]

# 2. Permission to update status and finalizers on our CRDs (required by Kopf).
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms/status", "keycloakclients/status"]
  verbs: ["get", "update", "patch"]
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloakrealms/finalizers", "keycloakclients/finalizers"]
  verbs: ["update"]

# 3. Permission to read secrets for authorization checks.
# This is cluster-wide, but the operator logic only reads secrets referenced in CRs.
# User edit: When you get here please ask me about it. The cluster role should NOT be able to see secrets in other namespaces unless the role is added from the helm chart for the client or realm. The commented out parts should NOT be implemented blindly.
# - apiGroups: [""]
#   resources: ["secrets"]
#   verbs: ["get"]

# 4. Permission to manage secrets in other namespaces (for client credentials and realm auth tokens).
# This is the most sensitive permission remaining.
# - apiGroups: [""]
#   resources: ["secrets"]
#   verbs: ["create", "update", "patch", "delete"]

# 5. Event creation for logging.
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]

# 6. Leader election.
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
```

#### Step 4.2: Create New `Role` for Operator Namespace

*   **File:** `k8s/rbac/operator-role.yaml` (new file)
*   **Action:** Create a `Role` that grants the operator full control over resources *only within its own namespace*.

```yaml
# k8s/rbac/operator-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: keycloak-operator-manager
  namespace: keycloak-system # This role is bound in the operator's namespace
rules:
# Full management of Keycloak CRs in this namespace
- apiGroups: ["keycloak.mdvr.nl"]
  resources: ["keycloaks", "keycloaks/status", "keycloaks/finalizers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Management of Keycloak workloads (Deployments, StatefulSets)
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

# Management of associated resources
- apiGroups: [""]
  resources: ["services", "configmaps", "secrets", "persistentvolumeclaims"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

#### Step 4.3: Create `RoleBinding`

*   **File:** `k8s/rbac/operator-role-binding.yaml` (new file)
*   **Action:** Bind the new `Role` to the operator's `ServiceAccount`.

```yaml
# k8s/rbac/operator-role-binding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: keycloak-operator-manager-binding
  namespace: keycloak-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: keycloak-operator-manager
subjects:
- kind: ServiceAccount
  name: keycloak-operator
  namespace: keycloak-system
```

#### Step 4.4: Update `install-rbac.yaml`

*   **File:** `k8s/rbac/install-rbac.yaml`
*   **Action:** Make sure this manifest applies the `ClusterRole`, `ClusterRoleBinding`, `Role`, and `RoleBinding`.

#### Testing Checkpoint

*   Deploy the operator with the new RBAC rules.
*   **Success Case:** Verify that the operator can still manage a full lifecycle: `Keycloak` -> `KeycloakRealm` -> `KeycloakClient`.
*   **Failure Case:** Manually edit the `operator-role.yaml` to remove permissions for `deployments`. Redeploy. The operator should now fail to create the Keycloak `Deployment` and log permission errors. Revert the change.
*   Run `kubectl auth can-i create deployments --as=system:serviceaccount:keycloak-system:keycloak-operator -n default`. This command should fail (return "no").
*   Run `kubectl auth can-i create deployments --as=system:serviceaccount:keycloak-system:keycloak-operator -n keycloak-system`. This command should succeed (return "yes").

#### Rollback Strategy

*   Restore the old `cluster-role.yaml` and apply it.
*   Delete the new `operator-role.yaml` and `operator-role-binding.yaml` files.

---

### Phase 5: Helm Charts Creation

*   **Objective:** Create the three new Helm charts in a monorepo structure for deploying the operator, realms, and clients independently.
*   **Estimated Time:** 6 hours
*   **Dependencies:** Phase 4

#### Step 5.1: Create Directory Structure

*   **Action:** Create the `charts/` directory at the root of the repository.
*   **Command:** `mkdir -p charts/keycloak-operator charts/keycloak-realm charts/keycloak-client`

#### Step 5.2: Create `keycloak-operator` Chart (Chart 1)

*   **Location:** `charts/keycloak-operator/`
*   **Action:** Create the chart for the platform team to install the operator and the Keycloak instance itself.
    1.  **`Chart.yaml`:** Define metadata for the operator chart.
    2.  **`values.yaml`:** Expose values for operator image version, Keycloak instance settings (version, replicas), etc.
    3.  **`templates/`:**
        *   `_helpers.tpl`: Standard Helm helper templates.
        *   `00_namespace.yaml`: Create the `keycloak-system` namespace.
        *   `01_crds.yaml`: A template that includes all CRDs from `k8s/crds/`. Use a `crd-install` hook.
        *   `02_rbac.yaml`: The `ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`, `Role`, and `RoleBinding`.
        *   `03_operator_deployment.yaml`: The operator `Deployment` from `k8s/operator-deployment.yaml`.
        *   `04_keycloak_cr.yaml`: A `Keycloak` custom resource, allowing users to configure the Keycloak instance via `values.yaml`.
    4.  **`templates/NOTES.txt`:** Provide instructions on how to retrieve the operator's authorization token secret, which is required by the realm chart.

#### Step 5.3: Create `keycloak-realm` Chart (Chart 2)

*   **Location:** `charts/keycloak-realm/`
*   **Action:** Create the chart for development teams to deploy realms.
    1.  **`Chart.yaml`:** Define metadata.
    2.  **`values.yaml`:** Expose values for the realm name, display name, and importantly, the `operatorRef` details (`namespace`, `authorizationSecretRef.name`).
    3.  **`templates/`:**
        *   `realm.yaml`: The `KeycloakRealm` CR. It will be configured using the values from `values.yaml`.
    4.  **`templates/NOTES.txt`:** Explain that the output of this chart will be a secret (`<release-name>-auth-token`) that client charts will need.

#### Step 5.4: Create `keycloak-client` Chart (Chart 3)

*   **Location:** `charts/keycloak-client/`
*   **Action:** Create the chart for development teams to deploy clients.
    1.  **`Chart.yaml`:** Define metadata.
    2.  **`values.yaml`:** Expose values for `client_id`, `redirect_uris`, etc., and the `realmRef` details (`name`, `namespace`, `authorizationSecretRef.name`).
    3.  **`templates/`:**
        *   `client.yaml`: The `KeycloakClient` CR, configured from `values.yaml`.

#### Testing Checkpoint

*   Run `helm lint` on all three charts.
*   Run `helm template` to inspect the generated YAML for each chart.
*   **Installation Test:**
    1.  `helm install operator ./charts/keycloak-operator -n keycloak-system`
    2.  Retrieve the operator auth token as described in `NOTES.txt`.
    3.  Create a `values.yaml` for the realm chart, providing the operator token details.
    4.  `helm install my-realm ./charts/keycloak-realm -f values.yaml -n team-a`
    5.  Retrieve the realm auth token.
    6.  Create a `values.yaml` for the client chart, providing the realm token details.
    7.  `helm install my-client ./charts/keycloak-client -f values.yaml -n team-a`
    8.  Verify all resources are created and reconciled successfully.

#### Rollback Strategy

*   Delete the `charts/` directory.
*   Continue using manual `kubectl apply` of the manifests in `k8s/`.

---

### Phase 6: Release Process Updates

*   **Objective:** Update the `release-please` workflow to handle multi-component releases for the operator and the new Helm charts.
*   **Estimated Time:** 3 hours
*   **Dependencies:** Phase 5

#### Step 6.1: Update `RELEASES.md`

*   **File:** `RELEASES.md`
*   **Action:** Document the new release components for the Helm charts.

```diff
--- a/RELEASES.md
+++ b/RELEASES.md
@@ -10,10 +10,19 @@
 - **Release Tags**: `v1.2.3` (no component prefix)
 - **Triggered by**: Any conventional commit without a chart scope.
 
-### 2. Helm Chart (Future)
-- **Path**: `charts/keycloak-operator/`
-- **Artifact**: Helm chart package
-- **Release Tags**: `chart-v0.5.0` (includes component prefix)
-- **Triggered by**: Conventional commits with `(chart)` scope
+### 2. Helm Charts
+- **Paths**: `charts/keycloak-operator`, `charts/keycloak-realm`, `charts/keycloak-client`
+- **Artifacts**: Helm chart packages
+- **Release Tags**: `chart-operator-vX.Y.Z`, `chart-realm-vX.Y.Z`, `chart-client-vX.Y.Z`
+- **Triggered by**: Conventional commits with `(chart-operator)`, `(chart-realm)`, or `(chart-client)` scopes.
 
 ### Operator Releases
 Use standard conventional commits or `(operator)` scope:
@@ -22,9 +31,10 @@
 refactor!: remove deprecated admin_access field
 feat(operator): implement external secrets integration
 ```
-
-### Helm Chart Releases
-Use `(chart)` scope explicitly:
+ 
+### Helm Chart Releases
+Use specific chart scopes:
 ```bash
-feat(chart): add values for custom probes
-fix(chart): correct RBAC permissions
-docs(chart): update README with examples
+feat(chart-operator): add values for custom probes
+fix(chart-realm): update realm spec in template
+docs(chart-client): update README with examples
 ```

```

#### Step 6.2: Update `release-please-config.json`

*   **File:** `release-please-config.json` (or similar configuration for `release-please`)
*   **Action:** Define the paths and component names for each of the four release artifacts (operator + 3 charts).

```json
{
  "packages": {
    ".": {
      "component": "operator",
      "release-type": "python"
    },
    "charts/keycloak-operator": {
      "component": "chart-operator",
      "release-type": "helm"
    },
    "charts/keycloak-realm": {
      "component": "chart-realm",
      "release-type": "helm"
    },
    "charts/keycloak-client": {
      "component": "chart-client",
      "release-type": "helm"
    }
  }
}
```

#### Step 6.3: Update `.github/workflows/release-please.yml`

*   **File:** `.github/workflows/release-please.yml`
*   **Action:** Ensure the workflow is configured to handle the multi-component setup and can publish Helm charts (e.g., to GHCR OCI registry). This may require adding steps for `helm package` and `helm push`.

#### Testing Checkpoint

*   Make a commit with `feat(chart-operator): initial commit` and push to a test branch.
*   Create a pull request. Verify that the `release-please` bot comments on the PR with a pending release for the `chart-operator` component only.
*   Merge the PR and verify that a release PR is created correctly.

#### Rollback Strategy

*   Revert the changes to the release configuration files.

---

### Phase 7: Migration & Documentation

*   **Objective:** Update all documentation, examples, and provide a clear migration path for existing users.
*   **Estimated Time:** 4 hours
*   **Dependencies:** Phase 5

#### Step 7.1: Create Migration Guide

*   **File:** `docs/migration-v2.md` (new file)
*   **Action:** Write a guide explaining how to move from the manual, single-CRD-style deployment to the new Helm-based, auth-delegation model. Include `before` and `after` YAML examples.

#### Step 7.2: Update All Examples

*   **Directory:** `examples/`
*   **Action:** Replace all existing examples with new ones that reflect the Helm chart structure. Instead of raw YAML files, provide `values.yaml` examples for each chart.

#### Step 7.3: Update `README.md`

*   **File:** `README.md`
*   **Action:** Overhaul the "Getting Started" and "Architecture" sections to describe the new Helm-based workflow and the operator -> realm -> client authorization chain.

#### Step 7.4: Update `CLAUDE.md` and Developer Docs

*   **Files:** `CLAUDE.md`, `docs/development.md`
*   **Action:** Update any sections that describe the old architecture, handler logic, or RBAC model.

#### Testing Checkpoint

*   Have a colleague (or another AI) review the documentation for clarity and accuracy.
*   Follow the new `README.md` guide from scratch on a fresh cluster to ensure it's correct.

#### Rollback Strategy

*   Revert documentation changes via `git`.

---

### Phase 8: End-to-End Testing

*   **Objective:** Update the entire test suite to validate the new architecture, including authorization and permission boundaries.
*   **Estimated Time:** 8 hours
*   **Dependencies:** All previous phases.

#### Step 8.1: Update Integration Tests

*   **Directory:** `tests/integration/`
*   **Action:** This is the most critical testing phase.
    *   Refactor existing tests (`test_realm_*.py`, `test_service_account_roles.py`, etc.) to use the new authorization flow. This will involve creating secrets with tokens as part of the test setup.
    *   Create a new test file, `test_authorization.py`, with tests for:
        *   Realm creation succeeds with a valid operator token.
        *   Realm creation fails with an invalid operator token.
        *   Client creation succeeds with a valid realm token.
        *   Client creation fails with an invalid realm token.
        *   Client creation fails if the realm's auth secret is not accessible.
    *   Create a new test file, `test_rbac_permissions.py`, that uses `SelfSubjectAccessReview` to programmatically verify the operator's permissions, confirming it *cannot* manage `Deployments` outside its own namespace.

#### Step 8.2: Update Unit Tests

*   **Directory:** `tests/unit/`
*   **Action:** Update unit tests for handlers to mock the new authorization logic and spec models.

#### Testing Checkpoint

*   Run the full test suite with `make test`. All unit and integration tests must pass.

#### Rollback Strategy

*   This is the final phase; rollback involves reverting the entire project. At this point, the team should commit to fixing tests forward rather than rolling back.