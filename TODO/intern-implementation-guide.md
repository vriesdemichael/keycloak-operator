# Keycloak Operator - Intern Implementation Guide

**Welcome!** This guide will help you implement missing functionality in the Keycloak operator. It's designed for developers who are eager to learn but may not be familiar with the codebase yet.

## Table of Contents
- [Getting Started](#getting-started)
- [Understanding the Codebase](#understanding-the-codebase)
- [Priority 1: Service Account Role Mappings](#priority-1-service-account-role-mappings)
- [Priority 2: Password Policy Configuration](#priority-2-password-policy-configuration)
- [Priority 3: SMTP Configuration](#priority-3-smtp-configuration)
- [Priority 4: Authorization Services](#priority-4-authorization-services)
- [Additional Enhancements](#additional-enhancements)
- [General Testing Guide](#general-testing-guide)
- [General Documentation Guide](#general-documentation-guide)

---

## Getting Started

### Prerequisites
1. **Set up your development environment:**
   ```bash
   # Install dependencies
   make dev-setup

   # Run tests to verify everything works
   make test
   ```

2. **Understand the GitOps philosophy:**
   - Everything must be declarative (no manual UI actions)
   - All configuration through Kubernetes resources
   - RBAC-based security (least privilege principle)
   - No secrets in CRD specs (use K8s secrets)

3. **Read these files first:**
   - `CLAUDE.md` - Project requirements and principles
   - `README.md` - User-facing documentation
   - `keycloak-api-spec.yaml` - Official Keycloak Admin REST API specification

### Development Workflow
For each feature you implement:

1. **CRD Changes** → Update the Custom Resource Definition
2. **Model Changes** → Update Pydantic models for validation
3. **Reconciler Logic** → Implement the actual functionality
4. **Unit Tests** → Test with mocked dependencies
5. **Integration Tests** → Test with real Kubernetes cluster
6. **Documentation** → Update README.md with examples
7. **Run Full Test Suite** → `make test` (quality + unit + integration)

---

## Understanding the Codebase

### Project Structure
```
keycloak-operator/
├── k8s/
│   ├── crds/                    # Custom Resource Definitions (CRDs)
│   │   ├── keycloak-crd.yaml
│   │   ├── keycloakrealm-crd.yaml
│   │   └── keycloakclient-crd.yaml
│   └── rbac/                    # RBAC configurations
├── src/keycloak_operator/
│   ├── handlers/                # Kopf event handlers (entry points)
│   │   ├── client.py           # KeycloakClient handlers
│   │   ├── realm.py            # KeycloakRealm handlers
│   │   └── keycloak.py         # Keycloak instance handlers
│   ├── services/                # Business logic (reconcilers)
│   │   ├── client_reconciler.py
│   │   ├── realm_reconciler.py
│   │   └── keycloak_reconciler.py
│   ├── models/                  # Pydantic data models
│   │   ├── client.py
│   │   ├── realm.py
│   │   └── keycloak.py
│   ├── utils/
│   │   ├── keycloak_admin.py   # Keycloak Admin API client
│   │   └── kubernetes.py       # Kubernetes utilities
│   └── errors/                  # Custom exceptions
├── tests/
│   ├── unit/                    # Fast tests with mocks
│   └── integration/             # Real cluster tests
└── keycloak-api-spec.yaml       # Official Keycloak API reference
```

### Key Concepts

**Handler → Reconciler → Admin API Pattern:**
```python
# Handler (kopf decorator, entry point)
@kopf.on.create("keycloakclients")
async def ensure_keycloak_client(spec, name, namespace, status, **kwargs):
    reconciler = KeycloakClientReconciler()
    return await reconciler.reconcile(spec, name, namespace, status)

# Reconciler (business logic)
class KeycloakClientReconciler(BaseReconciler):
    async def do_reconcile(self, spec, name, namespace, status, **kwargs):
        # 1. Validate spec
        # 2. Call Keycloak Admin API
        # 3. Create K8s resources (secrets, etc.)
        # 4. Return status

# Admin API (Keycloak REST client)
class KeycloakAdminClient:
    def create_client(self, realm_name, client_config):
        # Make HTTP request to Keycloak API
```

**Data Flow:**
1. User creates K8s resource (e.g., `KeycloakClient`)
2. Kopf detects event → calls handler
3. Handler validates spec using Pydantic model
4. Handler calls reconciler service
5. Reconciler calls Keycloak Admin API
6. Reconciler creates K8s secrets if needed
7. Reconciler updates resource status

---

## Priority 1: Service Account Role Mappings

### Problem Statement
When `service_accounts_enabled: true` is set on a KeycloakClient, Keycloak creates a special "service account user" for that client. This user needs roles assigned to it for the service account to be useful (e.g., to call other APIs).

**Current State:** Service accounts can be enabled, but roles must be manually assigned via the Keycloak UI.

**Desired State:** Roles should be declaratively assigned in the CRD spec.

**GitOps Impact:** HIGH - This breaks GitOps workflow and requires manual intervention.

---

### Step 1: Update the CRD Schema ✅

> Completed on 2025-10-01 by adding `service_account_roles` to `k8s/crds/keycloakclient-crd.yaml`.

**File:** `k8s/crds/keycloakclient-crd.yaml`

**Location:** Add this under `spec.properties` (around line 200, after `client_roles`)

```yaml
# Add this new field
service_account_roles:
  type: object
  description: "Role mappings for the client's service account user"
  properties:
    realm_roles:
      type: array
      description: "Realm-level roles to assign to the service account"
      items:
        type: string
      example: ["offline_access", "uma_authorization"]
    client_roles:
      type: object
      description: "Client-level roles to assign to the service account"
      additionalProperties:
        type: array
        items:
          type: string
      example:
        api-server: ["read:data", "write:data"]
        admin-console: ["view-users"]
```

**Why this structure?**
- `realm_roles`: Array of role names (e.g., `["offline_access"]`)
- `client_roles`: Map of client ID → array of role names (e.g., `{"other-api": ["read:data"]}`)

**Apply the CRD:**
```bash
kubectl apply -f k8s/crds/keycloakclient-crd.yaml
```

---

### Step 2: Update the Pydantic Model ✅

> Completed on 2025-10-01 by adding `ServiceAccountRoles` and `service_account_roles` default to the client models.

**File:** `src/keycloak_operator/models/client.py`

**Location:** Add after `KeycloakClientSettings` class (around line 105)

```python
class ServiceAccountRoles(BaseModel):
    """Role mappings for service account users."""

    realm_roles: list[str] = Field(
        default_factory=list,
        description="Realm-level roles to assign to the service account"
    )
    client_roles: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Client-level roles to assign to the service account (client_id -> role names)"
    )
```

**Then update `KeycloakClientSpec`** (around line 106):

Find this section:
```python
class KeycloakClientSpec(BaseModel):
    # ... existing fields ...

    # Client settings
    settings: KeycloakClientSettings = Field(...)
```

Add after `settings`:
```python
    # Service account configuration
    service_account_roles: ServiceAccountRoles = Field(
        default_factory=ServiceAccountRoles,
        description="Role mappings for the client's service account user"
    )
```

**Test the model:**
```bash
# Run unit tests to verify model validation
uv run pytest tests/unit/models/test_client.py -v
```

---

### Step 3: Implement Keycloak Admin API Methods ✅

> Completed on 2025-10-01 by adding service account user retrieval and role assignment helpers to `keycloak_admin.py`.

**File:** `src/keycloak_operator/utils/keycloak_admin.py`

**Location:** Add these methods to the `KeycloakAdminClient` class (around line 400+)

**First, understand the API by checking the spec:**
```bash
# Search for service account endpoints in the API spec
grep -A 10 "service-account-user" keycloak-api-spec.yaml
```

You'll find:
- `GET /admin/realms/{realm}/clients/{id}/service-account-user` - Get service account user
- Role mapping endpoints are under `/admin/realms/{realm}/users/{userId}/role-mappings`

**Implement the methods:**

```python
def get_service_account_user(
    self, client_uuid: str, realm_name: str = "master"
) -> dict[str, Any]:
    """
    Get the service account user for a client.

    Based on OpenAPI spec: GET /admin/realms/{realm}/clients/{id}/service-account-user

    Args:
        client_uuid: Client UUID in Keycloak
        realm_name: Target realm name

    Returns:
        Service account user representation

    Raises:
        KeycloakAdminError: If client doesn't have service accounts enabled
    """
    self._ensure_authenticated()

    url = f"{self.server_url}/admin/realms/{realm_name}/clients/{client_uuid}/service-account-user"

    response = self.session.get(url, timeout=self.timeout)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        raise KeycloakAdminError(
            f"Service account user not found for client {client_uuid}. "
            "Ensure service_accounts_enabled is true.",
            status_code=404
        )
    else:
        raise KeycloakAdminError(
            f"Failed to get service account user: {response.text}",
            status_code=response.status_code
        )


def assign_realm_roles_to_user(
    self, user_id: str, role_names: list[str], realm_name: str = "master"
) -> None:
    """
    Assign realm-level roles to a user.

    Based on OpenAPI spec: POST /admin/realms/{realm}/users/{id}/role-mappings/realm

    Args:
        user_id: User UUID
        role_names: List of role names to assign
        realm_name: Target realm name

    Raises:
        KeycloakAdminError: If role assignment fails
    """
    self._ensure_authenticated()

    # First, get the role representations by name
    roles = []
    for role_name in role_names:
        role = self.get_realm_role(role_name, realm_name)
        if not role:
            logger.warning(f"Realm role '{role_name}' not found in realm '{realm_name}', skipping")
            continue
        roles.append(role)

    if not roles:
        logger.info("No valid realm roles to assign")
        return

    url = f"{self.server_url}/admin/realms/{realm_name}/users/{user_id}/role-mappings/realm"

    response = self.session.post(url, json=roles, timeout=self.timeout)

    if response.status_code not in [204, 200]:
        raise KeycloakAdminError(
            f"Failed to assign realm roles to user: {response.text}",
            status_code=response.status_code
        )

    logger.info(f"Successfully assigned {len(roles)} realm roles to user {user_id}")


def assign_client_roles_to_user(
    self, user_id: str, client_uuid: str, role_names: list[str], realm_name: str = "master"
) -> None:
    """
    Assign client-level roles to a user.

    Based on OpenAPI spec: POST /admin/realms/{realm}/users/{id}/role-mappings/clients/{client}

    Args:
        user_id: User UUID
        client_uuid: Client UUID (not client_id!)
        role_names: List of role names to assign
        realm_name: Target realm name

    Raises:
        KeycloakAdminError: If role assignment fails
    """
    self._ensure_authenticated()

    # First, get the role representations by name
    roles = []
    for role_name in role_names:
        role = self.get_client_role(client_uuid, role_name, realm_name)
        if not role:
            logger.warning(
                f"Client role '{role_name}' not found for client {client_uuid}, skipping"
            )
            continue
        roles.append(role)

    if not roles:
        logger.info("No valid client roles to assign")
        return

    url = f"{self.server_url}/admin/realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_uuid}"

    response = self.session.post(url, json=roles, timeout=self.timeout)

    if response.status_code not in [204, 200]:
        raise KeycloakAdminError(
            f"Failed to assign client roles to user: {response.text}",
            status_code=response.status_code
        )

    logger.info(f"Successfully assigned {len(roles)} client roles to user {user_id}")


def get_realm_role(self, role_name: str, realm_name: str = "master") -> dict[str, Any] | None:
    """
    Get a realm role by name.

    Based on OpenAPI spec: GET /admin/realms/{realm}/roles/{role-name}

    Args:
        role_name: Role name
        realm_name: Target realm name

    Returns:
        Role representation or None if not found
    """
    self._ensure_authenticated()

    url = f"{self.server_url}/admin/realms/{realm_name}/roles/{role_name}"

    response = self.session.get(url, timeout=self.timeout)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        raise KeycloakAdminError(
            f"Failed to get realm role: {response.text}",
            status_code=response.status_code
        )


def get_client_role(
    self, client_uuid: str, role_name: str, realm_name: str = "master"
) -> dict[str, Any] | None:
    """
    Get a client role by name.

    Based on OpenAPI spec: GET /admin/realms/{realm}/clients/{id}/roles/{role-name}

    Args:
        client_uuid: Client UUID
        role_name: Role name
        realm_name: Target realm name

    Returns:
        Role representation or None if not found
    """
    self._ensure_authenticated()

    url = f"{self.server_url}/admin/realms/{realm_name}/clients/{client_uuid}/roles/{role_name}"

    response = self.session.get(url, timeout=self.timeout)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        raise KeycloakAdminError(
            f"Failed to get client role: {response.text}",
            status_code=response.status_code
        )
```

**Key Points:**
- Always reference the Keycloak API spec when implementing methods
- Use proper error handling (404 for not found, raise for other errors)
- Log important actions for debugging
- Role assignments require role UUIDs, not just names (hence the `get_*_role` methods)

---

### Step 4: Implement Reconciler Logic ✅

> Completed on 2025-10-01 by introducing service account role management in `client_reconciler.py` with error handling and admin client integration.

**File:** `src/keycloak_operator/services/client_reconciler.py`

**Location:** Add a new method after `manage_client_roles` (around line 300)

```python
async def manage_service_account_roles(
    self,
    spec: KeycloakClientSpec,
    client_uuid: str,
    name: str,
    namespace: str,
) -> None:
    """
    Manage role mappings for the client's service account user.

    This method:
    1. Gets the service account user for the client
    2. Assigns realm-level roles
    3. Assigns client-level roles

    Args:
        spec: Keycloak client specification
        client_uuid: Client UUID in Keycloak
        name: Resource name
        namespace: Resource namespace

    Raises:
        ReconciliationError: If service account roles cannot be managed
    """
    # Only proceed if service accounts are enabled
    if not spec.settings.service_accounts_enabled:
        self.logger.debug(f"Service accounts not enabled for client {spec.client_id}, skipping role assignment")
        return

    # Check if there are any roles to assign
    if not spec.service_account_roles.realm_roles and not spec.service_account_roles.client_roles:
        self.logger.debug(f"No service account roles specified for client {spec.client_id}")
        return

    self.logger.info(f"Managing service account roles for client {spec.client_id}")

    try:
        # Get admin client
        keycloak_ref = spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = self.keycloak_admin_factory(keycloak_ref.name, target_namespace)

        realm_name = spec.realm or "master"

        # Get the service account user
        self.logger.info(f"Fetching service account user for client {spec.client_id}")
        service_account_user = admin_client.get_service_account_user(client_uuid, realm_name)
        user_id = service_account_user.get("id")

        if not user_id:
            raise ReconciliationError(
                f"Service account user missing 'id' field for client {spec.client_id}"
            )

        self.logger.info(f"Service account user ID: {user_id}")

        # Assign realm roles
        if spec.service_account_roles.realm_roles:
            self.logger.info(
                f"Assigning {len(spec.service_account_roles.realm_roles)} realm roles to service account"
            )
            admin_client.assign_realm_roles_to_user(
                user_id=user_id,
                role_names=spec.service_account_roles.realm_roles,
                realm_name=realm_name
            )

        # Assign client roles
        if spec.service_account_roles.client_roles:
            for target_client_id, role_names in spec.service_account_roles.client_roles.items():
                self.logger.info(
                    f"Assigning {len(role_names)} roles from client '{target_client_id}' to service account"
                )

                # Get the target client UUID by client_id
                target_client = admin_client.get_client_by_name(target_client_id, realm_name)
                if not target_client:
                    self.logger.warning(
                        f"Target client '{target_client_id}' not found in realm '{realm_name}', "
                        "skipping its roles"
                    )
                    continue

                target_client_uuid = target_client.get("id")
                if not target_client_uuid:
                    self.logger.warning(
                        f"Target client '{target_client_id}' missing UUID, skipping"
                    )
                    continue

                # Assign the roles
                admin_client.assign_client_roles_to_user(
                    user_id=user_id,
                    client_uuid=target_client_uuid,
                    role_names=role_names,
                    realm_name=realm_name
                )

        self.logger.info(f"Successfully configured service account roles for client {spec.client_id}")

    except Exception as e:
        self.logger.error(f"Failed to manage service account roles: {e}")
        raise ReconciliationError(f"Service account role management failed: {e}") from e
```

**Now update the `do_reconcile` method** to call this new method:

Find this section (around line 94):
```python
# Manage client roles
if client_spec.client_roles:
    await self.manage_client_roles(client_spec, client_uuid, name, namespace)
```

Add after it:
```python
# Manage service account roles
if client_spec.settings.service_accounts_enabled:
    await self.manage_service_account_roles(client_spec, client_uuid, name, namespace)
```

**Important:** You'll need to add the `ReconciliationError` import at the top:
```python
from ..errors import ValidationError, ReconciliationError
```

If `ReconciliationError` doesn't exist, create it in `src/keycloak_operator/errors/operator_errors.py`:
```python
class ReconciliationError(Exception):
    """Raised when reconciliation fails."""
    pass
```

---

### Step 5: Write Unit Tests

> Completed on 2025-10-01 by adding coverage in `tests/unit/services/test_client_reconciler.py` for service account role management, including happy paths, skipped execution, and error handling.

**File:** `tests/unit/services/test_client_reconciler.py` (create if doesn't exist)

**Example test structure:**

```python
"""Unit tests for KeycloakClient reconciler."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from keycloak_operator.models.client import KeycloakClientSpec, ServiceAccountRoles
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.fixture
def mock_admin_client():
    """Mock Keycloak admin client."""
    client = MagicMock()
    client.get_service_account_user.return_value = {
        "id": "service-account-user-uuid",
        "username": "service-account-test-client"
    }
    client.get_realm_role.return_value = {
        "id": "role-uuid",
        "name": "offline_access"
    }
    client.get_client_by_name.return_value = {
        "id": "target-client-uuid",
        "clientId": "api-server"
    }
    client.get_client_role.return_value = {
        "id": "client-role-uuid",
        "name": "read:data"
    }
    return client


@pytest.mark.asyncio
async def test_manage_service_account_roles_realm_roles(mock_admin_client):
    """Test assigning realm roles to service account."""
    # Arrange
    reconciler = KeycloakClientReconciler(
        keycloak_admin_factory=lambda name, ns: mock_admin_client
    )

    spec = KeycloakClientSpec(
        client_id="test-client",
        keycloak_instance_ref={"name": "my-keycloak"},
        settings={"service_accounts_enabled": True},
        service_account_roles=ServiceAccountRoles(
            realm_roles=["offline_access", "uma_authorization"]
        )
    )

    # Act
    await reconciler.manage_service_account_roles(
        spec=spec,
        client_uuid="client-uuid",
        name="test-client",
        namespace="default"
    )

    # Assert
    mock_admin_client.get_service_account_user.assert_called_once_with(
        "client-uuid", "master"
    )
    mock_admin_client.assign_realm_roles_to_user.assert_called_once_with(
        user_id="service-account-user-uuid",
        role_names=["offline_access", "uma_authorization"],
        realm_name="master"
    )


@pytest.mark.asyncio
async def test_manage_service_account_roles_client_roles(mock_admin_client):
    """Test assigning client roles to service account."""
    # Arrange
    reconciler = KeycloakClientReconciler(
        keycloak_admin_factory=lambda name, ns: mock_admin_client
    )

    spec = KeycloakClientSpec(
        client_id="test-client",
        keycloak_instance_ref={"name": "my-keycloak"},
        settings={"service_accounts_enabled": True},
        service_account_roles=ServiceAccountRoles(
            client_roles={
                "api-server": ["read:data", "write:data"]
            }
        )
    )

    # Act
    await reconciler.manage_service_account_roles(
        spec=spec,
        client_uuid="client-uuid",
        name="test-client",
        namespace="default"
    )

    # Assert
    mock_admin_client.get_client_by_name.assert_called_with("api-server", "master")
    mock_admin_client.assign_client_roles_to_user.assert_called_once()


@pytest.mark.asyncio
async def test_service_account_roles_skipped_when_disabled(mock_admin_client):
    """Test that role assignment is skipped when service accounts are disabled."""
    # Arrange
    reconciler = KeycloakClientReconciler(
        keycloak_admin_factory=lambda name, ns: mock_admin_client
    )

    spec = KeycloakClientSpec(
        client_id="test-client",
        keycloak_instance_ref={"name": "my-keycloak"},
        settings={"service_accounts_enabled": False},
        service_account_roles=ServiceAccountRoles(
            realm_roles=["offline_access"]
        )
    )

    # Act
    await reconciler.manage_service_account_roles(
        spec=spec,
        client_uuid="client-uuid",
        name="test-client",
        namespace="default"
    )

    # Assert
    mock_admin_client.get_service_account_user.assert_not_called()
```

**Run the tests:**
```bash
uv run pytest tests/unit/services/test_client_reconciler.py -v
```

**Key testing concepts:**
- Use `@pytest.mark.asyncio` for async tests
- Mock external dependencies (Keycloak API, Kubernetes API)
- Use `MagicMock` for synchronous code, `AsyncMock` for async code
- Test both success and failure scenarios
- Verify method calls with `assert_called_once_with()`

---

### Step 6: Write Integration Tests

> Completed on 2025-10-01 by introducing `tests/integration/test_service_account_roles.py`, which provisions Keycloak resources, assigns a custom realm role, and validates the service account mapping end-to-end.

**File:** `tests/integration/test_service_account_roles.py` (create new file)

**Example integration test:**

```python
"""Integration tests for service account role mappings."""

import pytest
from kubernetes import client


@pytest.mark.integration
async def test_service_account_with_realm_roles(
    k8s_custom_objects,
    test_namespace,
    keycloak_instance_ready
):
    """
    Test creating a client with service accounts and realm roles.

    This test:
    1. Creates a KeycloakRealm with custom roles
    2. Creates a KeycloakClient with service accounts enabled
    3. Assigns realm roles to the service account
    4. Verifies the roles are assigned in Keycloak
    """
    realm_name = "test-realm"
    client_id = "test-service-account-client"

    # Create realm with custom roles
    realm_manifest = {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace
        },
        "spec": {
            "realm_name": realm_name,
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": test_namespace
            },
            "roles": [
                {"name": "api-user"},
                {"name": "api-admin"}
            ]
        }
    }

    k8s_custom_objects.create_namespaced_custom_object(
        group="keycloak.mdvr.nl",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_manifest
    )

    # Wait for realm to be ready
    await wait_for_resource_ready(
        k8s_custom_objects,
        "keycloakrealms",
        realm_name,
        test_namespace,
        timeout=120
    )

    # Create client with service account and role mappings
    client_manifest = {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakClient",
        "metadata": {
            "name": client_id,
            "namespace": test_namespace
        },
        "spec": {
            "client_id": client_id,
            "realm": realm_name,
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": test_namespace
            },
            "settings": {
                "service_accounts_enabled": True
            },
            "service_account_roles": {
                "realm_roles": ["api-user", "offline_access"]
            }
        }
    }

    k8s_custom_objects.create_namespaced_custom_object(
        group="keycloak.mdvr.nl",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        body=client_manifest
    )

    # Wait for client to be ready
    await wait_for_resource_ready(
        k8s_custom_objects,
        "keycloakclients",
        client_id,
        test_namespace,
        timeout=120
    )

    # Verify status
    client_resource = k8s_custom_objects.get_namespaced_custom_object(
        group="keycloak.mdvr.nl",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        name=client_id
    )

    assert client_resource["status"]["phase"] == "Ready"
    assert client_resource["status"]["client_uuid"]

    # TODO: Add verification that roles are actually assigned in Keycloak
    # This would require connecting to Keycloak and checking the service account user


async def wait_for_resource_ready(
    k8s_custom_objects,
    plural: str,
    name: str,
    namespace: str,
    timeout: int = 120
):
    """Wait for a custom resource to reach Ready phase."""
    import asyncio

    for _ in range(timeout):
        try:
            resource = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural=plural,
                name=name
            )

            if resource.get("status", {}).get("phase") == "Ready":
                return

        except Exception:
            pass

        await asyncio.sleep(1)

    raise TimeoutError(f"Resource {plural}/{name} did not become ready in {timeout}s")
```

**Run integration tests:**
```bash
# This will create a Kind cluster, deploy operator, and run tests
make test-integration
```

**Integration test tips:**
- Tests run against a real Kubernetes cluster
- Use fixtures from `tests/integration/conftest.py`
- Be patient - integration tests take time
- Always clean up resources (use fixtures with cleanup)
- Test end-to-end workflows, not just individual components

---

### Step 7: Update Documentation

> Completed on 2025-10-01 by updating `README.md` with a service account role mapping example and highlighting the feature in the overview list.

**File:** `README.md`

**Location:** Find the "KeycloakClient Configuration" section and add example

**Add this example after the basic client example:**

```markdown
#### Service Account with Role Mappings

For machine-to-machine authentication with specific permissions:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: api-gateway-service
  namespace: production
spec:
  client_id: api-gateway
  realm: production-realm
  keycloak_instance_ref:
    name: prod-keycloak
    namespace: identity-system

  settings:
    service_accounts_enabled: true
    standard_flow_enabled: false  # Service accounts don't need user login

  # Assign roles to the service account
  service_account_roles:
    # Realm-level roles
    realm_roles:
      - offline_access
      - uma_authorization

    # Client-level roles (access other APIs)
    client_roles:
      user-api:
        - read:users
        - write:users
      payment-api:
        - process:payments
```

**Key Features:**
- Service account credentials are stored in `api-gateway-service-credentials` secret
- Roles are automatically assigned during client creation
- Use the `client-secret` from the secret to authenticate as the service account
- The service account can then call other APIs with the assigned permissions
```

**Also update the features list at the top:**

Find the features section and add:
```markdown
- **Service Account Management** - Automatic role assignment for machine-to-machine authentication
```

---

### Step 8: Test the Complete Feature

**Manual testing workflow:**

1. **Start local cluster:**
   ```bash
   make dev-setup
   ```

2. **Deploy operator:**
   ```bash
   make deploy
   ```

3. **Create test resources:**

   ```yaml
   # test-realm.yaml
   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakRealm
   metadata:
     name: test-realm
     namespace: default
   spec:
     realm_name: test
     keycloak_instance_ref:
       name: test-keycloak
       namespace: default
     roles:
       - name: api-user
       - name: api-admin

   ---
   # test-client.yaml
   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakClient
   metadata:
     name: test-service
     namespace: default
   spec:
     client_id: test-service
     realm: test
     keycloak_instance_ref:
       name: test-keycloak
       namespace: default
     settings:
       service_accounts_enabled: true
     service_account_roles:
       realm_roles:
         - api-user
         - offline_access
   ```

4. **Apply and verify:**
   ```bash
   kubectl apply -f test-realm.yaml
   kubectl apply -f test-client.yaml

   # Watch for status
   kubectl get keycloakclients test-service -o yaml

   # Check operator logs
   make operator-logs
   ```

5. **Verify in Keycloak UI:**
   - Port-forward to Keycloak
   - Login to admin console
   - Navigate to Clients → test-service → Service Account Roles
   - Verify roles are assigned

6. **Run full test suite:**
   ```bash
   make test
   ```

---

### Step 9: Checklist Before Submitting

- [ ] CRD updated (`k8s/crds/keycloakclient-crd.yaml`)
- [ ] Pydantic model updated (`src/keycloak_operator/models/client.py`)
- [ ] Keycloak Admin API methods implemented (`utils/keycloak_admin.py`)
- [ ] Reconciler logic implemented (`services/client_reconciler.py`)
- [ ] Unit tests written and passing (`tests/unit/`)
- [ ] Integration tests written and passing (`tests/integration/`)
- [ ] README.md updated with examples
- [ ] Full test suite passes: `make test`
- [ ] Code quality passes: `make quality`
- [ ] Manual testing completed
- [ ] No manual steps required (GitOps compliant)

---

## Priority 2: Password Policy Configuration

### Problem Statement
Keycloak realms have password policies that control password requirements (length, special characters, history, etc.). Currently, these must be configured manually via the Keycloak UI.

**Current State:** Password policies use Keycloak defaults.

**Desired State:** Password policies should be declaratively configured in KeycloakRealm CRD.

**GitOps Impact:** MEDIUM - Can work with defaults, but limits security customization.

---

### Step 1: Understand Password Policies

Keycloak password policies are defined as a single string with space-separated directives:

```
length(12) and digits(1) and specialChars(1) and upperCase(1) and lowerCase(1) and notUsername() and passwordHistory(3)
```

**Common policy directives:**
- `length(N)` - Minimum length
- `digits(N)` - Minimum number of digits
- `specialChars(N)` - Minimum special characters
- `upperCase(N)` - Minimum uppercase letters
- `lowerCase(N)` - Minimum lowercase letters
- `notUsername()` - Password cannot be same as username
- `passwordHistory(N)` - Cannot reuse last N passwords
- `hashAlgorithm(algo)` - Password hash algorithm
- `hashIterations(N)` - PBKDF2 iterations

**Check the API spec:**
```bash
grep -A 20 "passwordPolicy" keycloak-api-spec.yaml
```

You'll find it's a string field on `RealmRepresentation`.

---

### Step 2: Update KeycloakRealm CRD

**File:** `k8s/crds/keycloakrealm-crd.yaml`

**Location:** Add under `spec.properties.security` (around line 150)

```yaml
security:
  type: object
  properties:
    # ... existing fields ...

    # Add this new field
    password_policy:
      type: string
      description: |
        Password policy configuration as a space-separated string of policy directives.

        Examples:
        - "length(12) and digits(1) and specialChars(1)"
        - "length(8) and upperCase(1) and lowerCase(1) and notUsername()"

        Common directives:
        - length(N): Minimum password length
        - digits(N): Minimum number of digits
        - specialChars(N): Minimum special characters
        - upperCase(N): Minimum uppercase letters
        - lowerCase(N): Minimum lowercase letters
        - notUsername(): Password cannot be username
        - passwordHistory(N): Cannot reuse last N passwords
        - hashAlgorithm(algorithm): pbkdf2-sha256, pbkdf2-sha512, etc.
        - hashIterations(N): Number of hash iterations (default 27500)
      example: "length(12) and digits(1) and specialChars(1) and upperCase(1) and lowerCase(1) and notUsername()"
```

**Apply the CRD:**
```bash
kubectl apply -f k8s/crds/keycloakrealm-crd.yaml
```

---

### Step 3: Update Pydantic Model

**File:** `src/keycloak_operator/models/realm.py`

**Find the `KeycloakRealmSecurity` class** (should be around line 50-100):

```python
class KeycloakRealmSecurity(BaseModel):
    """Security settings for a realm."""

    # ... existing fields ...

    # Add this field
    password_policy: str | None = Field(
        None,
        description=(
            "Password policy as space-separated directives. "
            "Example: 'length(12) and digits(1) and specialChars(1)'"
        )
    )

    @field_validator("password_policy")
    @classmethod
    def validate_password_policy(cls, v: str | None) -> str | None:
        """Validate password policy string format."""
        if v is None:
            return None

        # Basic validation - check for common directives
        valid_directives = [
            "length", "digits", "specialChars", "upperCase", "lowerCase",
            "notUsername", "passwordHistory", "hashAlgorithm", "hashIterations",
            "forceExpiredPasswordChange", "regexPattern", "notEmail"
        ]

        # Simple check: at least one valid directive
        has_valid_directive = any(directive in v for directive in valid_directives)

        if not has_valid_directive:
            raise ValueError(
                f"Password policy must contain at least one valid directive. "
                f"Valid directives: {', '.join(valid_directives)}"
            )

        return v
```

---

### Step 4: Update Keycloak Admin Client

**File:** `src/keycloak_operator/utils/keycloak_admin.py`

Password policy is part of the realm configuration, so it's already handled by the existing `update_realm()` method. Just ensure the `passwordPolicy` field is included when building the realm config.

**No changes needed to `keycloak_admin.py`** - the realm update method already handles all realm fields.

---

### Step 5: Update Realm Reconciler

**File:** `src/keycloak_operator/services/realm_reconciler.py`

**Find the method that builds the realm configuration** (look for `to_keycloak_config` or similar):

You need to ensure that when converting the Pydantic model to Keycloak's API format, the `password_policy` field is mapped correctly.

**Example - find the realm config building section:**

```python
def _build_realm_config(self, spec: KeycloakRealmSpec) -> dict[str, Any]:
    """Build Keycloak realm configuration from spec."""
    config = {
        "realm": spec.realm_name,
        "enabled": spec.enabled,
        # ... other fields ...
    }

    # Add security settings
    if spec.security:
        if spec.security.brute_force_protected is not None:
            config["bruteForceProtected"] = spec.security.brute_force_protected

        # Add password policy
        if spec.security.password_policy:
            config["passwordPolicy"] = spec.security.password_policy

    return config
```

**Key point:** Keycloak API uses `passwordPolicy` (camelCase), our CRD uses `password_policy` (snake_case).

---

### Step 6: Write Unit Tests

**File:** `tests/unit/models/test_realm.py`

```python
"""Unit tests for KeycloakRealm models."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.realm import KeycloakRealmSecurity


def test_password_policy_valid():
    """Test valid password policy configurations."""
    valid_policies = [
        "length(12)",
        "length(12) and digits(1)",
        "length(8) and specialChars(1) and upperCase(1)",
        "length(16) and digits(2) and specialChars(2) and notUsername() and passwordHistory(5)"
    ]

    for policy in valid_policies:
        security = KeycloakRealmSecurity(password_policy=policy)
        assert security.password_policy == policy


def test_password_policy_none():
    """Test that password_policy can be None."""
    security = KeycloakRealmSecurity(password_policy=None)
    assert security.password_policy is None


def test_password_policy_empty_string():
    """Test that empty password policy is rejected."""
    with pytest.raises(ValidationError):
        KeycloakRealmSecurity(password_policy="")


def test_password_policy_invalid():
    """Test that invalid password policy is rejected."""
    invalid_policies = [
        "invalid_directive",
        "random text",
        "123456"
    ]

    for policy in invalid_policies:
        with pytest.raises(ValidationError) as exc_info:
            KeycloakRealmSecurity(password_policy=policy)
        assert "valid directive" in str(exc_info.value).lower()
```

---

### Step 7: Write Integration Tests

**File:** `tests/integration/test_realm_password_policy.py`

```python
"""Integration tests for realm password policies."""

import pytest


@pytest.mark.integration
async def test_realm_with_password_policy(
    k8s_custom_objects,
    test_namespace,
    keycloak_instance_ready
):
    """Test creating a realm with custom password policy."""
    realm_name = "policy-test-realm"

    realm_manifest = {
        "apiVersion": "keycloak.mdvr.nl/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": realm_name,
            "namespace": test_namespace
        },
        "spec": {
            "realm_name": realm_name,
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": test_namespace
            },
            "security": {
                "password_policy": "length(12) and digits(1) and specialChars(1) and upperCase(1)"
            }
        }
    }

    # Create realm
    k8s_custom_objects.create_namespaced_custom_object(
        group="keycloak.mdvr.nl",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_manifest
    )

    # Wait for ready
    await wait_for_resource_ready(
        k8s_custom_objects,
        "keycloakrealms",
        realm_name,
        test_namespace,
        timeout=120
    )

    # Verify status
    realm_resource = k8s_custom_objects.get_namespaced_custom_object(
        group="keycloak.mdvr.nl",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_name
    )

    assert realm_resource["status"]["phase"] == "Ready"

    # TODO: Verify policy is actually set in Keycloak
    # Would require connecting to Keycloak and fetching realm config
```

---

### Step 8: Update Documentation

**File:** `README.md`

**Location:** Add to KeycloakRealm examples section

```markdown
#### Realm with Custom Password Policy

Enforce password complexity requirements:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: secure-realm
  namespace: identity-system
spec:
  realm_name: production
  keycloak_instance_ref:
    name: prod-keycloak
    namespace: identity-system

  security:
    # Custom password policy (space-separated directives)
    password_policy: >-
      length(12) and
      digits(1) and
      specialChars(1) and
      upperCase(1) and
      lowerCase(1) and
      notUsername() and
      passwordHistory(3)

    # Brute force protection
    brute_force_protected: true
```

**Available password policy directives:**
- `length(N)` - Minimum password length
- `digits(N)` - Minimum number of digits
- `specialChars(N)` - Minimum special characters
- `upperCase(N)` - Minimum uppercase letters
- `lowerCase(N)` - Minimum lowercase letters
- `notUsername()` - Password cannot match username
- `passwordHistory(N)` - Cannot reuse last N passwords
- `hashAlgorithm(algorithm)` - Hash algorithm (pbkdf2-sha256, pbkdf2-sha512, etc.)
- `hashIterations(N)` - Number of PBKDF2 iterations (default: 27500)

For more directives, see [Keycloak Password Policy Documentation](https://www.keycloak.org/docs/latest/server_admin/#password-policies).
```

---

### Step 9: Test and Verify

```bash
# Run all tests
make test

# Manual testing
kubectl apply -f examples/realm-with-password-policy.yaml
kubectl get keycloakrealms secure-realm -o yaml

# Check operator logs
make operator-logs
```

---

## Priority 3: SMTP Configuration

### Problem Statement
Keycloak requires SMTP configuration to send emails (password reset, email verification, etc.). Currently, this must be configured manually via the Keycloak UI.

**Challenge:** Testing SMTP configuration requires a working SMTP server, which complicates testing.

**Recommendation:** Implement the feature, but defer full testing until you have SMTP infrastructure (or use a test service like Mailhog).

---

### Step 1: Update KeycloakRealm CRD

**File:** `k8s/crds/keycloakrealm-crd.yaml`

**Location:** Add under `spec.properties` (top level, around line 100)

```yaml
# Add this new section
smtp_server:
  type: object
  description: "SMTP server configuration for sending emails"
  properties:
    host:
      type: string
      description: "SMTP server hostname"
      example: "smtp.sendgrid.net"
    port:
      type: integer
      description: "SMTP server port"
      default: 587
      minimum: 1
      maximum: 65535
    from:
      type: string
      description: "From email address"
      format: email
      example: "noreply@company.com"
    from_display_name:
      type: string
      description: "Display name for from address"
      example: "Company Identity Service"
    ssl:
      type: boolean
      description: "Use SSL connection"
      default: false
    starttls:
      type: boolean
      description: "Use STARTTLS"
      default: true
    auth:
      type: boolean
      description: "Enable SMTP authentication"
      default: true
    username:
      type: string
      description: "SMTP username (if auth is enabled)"
    password_secret:
      type: object
      description: "Reference to Kubernetes secret containing SMTP password"
      properties:
        name:
          type: string
          description: "Secret name"
        key:
          type: string
          description: "Key within secret containing password"
          default: "password"
      required:
      - name
    envelope_from:
      type: string
      description: "Envelope from address (optional, for different return path)"
      format: email
  required:
  - host
  - from
```

**Security Note:** Password comes from a Kubernetes secret, not inline in the CRD!

---

### Step 2: Update Pydantic Model

**File:** `src/keycloak_operator/models/realm.py`

```python
class SMTPPasswordSecret(BaseModel):
    """Reference to Kubernetes secret containing SMTP password."""

    name: str = Field(..., description="Secret name")
    key: str = Field(default="password", description="Key within secret")


class SMTPServerConfig(BaseModel):
    """SMTP server configuration for email sending."""

    host: str = Field(..., description="SMTP server hostname")
    port: int = Field(default=587, ge=1, le=65535, description="SMTP server port")
    from_: str = Field(..., alias="from", description="From email address")
    from_display_name: str | None = Field(None, description="Display name for from address")
    ssl: bool = Field(default=False, description="Use SSL connection")
    starttls: bool = Field(default=True, description="Use STARTTLS")
    auth: bool = Field(default=True, description="Enable SMTP authentication")
    username: str | None = Field(None, description="SMTP username")
    password_secret: SMTPPasswordSecret | None = Field(
        None,
        description="Reference to Kubernetes secret containing SMTP password"
    )
    envelope_from: str | None = Field(None, description="Envelope from address")

    @field_validator("from_")
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Basic email validation."""
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v


# Then add to KeycloakRealmSpec:
class KeycloakRealmSpec(BaseModel):
    # ... existing fields ...

    smtp_server: SMTPServerConfig | None = Field(
        None,
        description="SMTP server configuration for email sending"
    )
```

---

### Step 3: Update Reconciler to Fetch Password

**File:** `src/keycloak_operator/services/realm_reconciler.py`

```python
async def _build_smtp_config(
    self,
    smtp_spec: SMTPServerConfig,
    namespace: str
) -> dict[str, str]:
    """
    Build SMTP configuration for Keycloak, fetching password from K8s secret.

    Args:
        smtp_spec: SMTP configuration from spec
        namespace: Namespace to fetch secret from

    Returns:
        SMTP configuration dictionary for Keycloak API
    """
    config = {
        "host": smtp_spec.host,
        "port": str(smtp_spec.port),
        "from": smtp_spec.from_,
        "ssl": str(smtp_spec.ssl).lower(),
        "starttls": str(smtp_spec.starttls).lower(),
        "auth": str(smtp_spec.auth).lower(),
    }

    if smtp_spec.from_display_name:
        config["fromDisplayName"] = smtp_spec.from_display_name

    if smtp_spec.envelope_from:
        config["envelopeFrom"] = smtp_spec.envelope_from

    # Add authentication if enabled
    if smtp_spec.auth and smtp_spec.username and smtp_spec.password_secret:
        config["user"] = smtp_spec.username

        # Fetch password from Kubernetes secret
        try:
            core_api = client.CoreV1Api(self.k8s_client)
            secret = core_api.read_namespaced_secret(
                name=smtp_spec.password_secret.name,
                namespace=namespace
            )

            if not secret.data:
                raise ReconciliationError(
                    f"SMTP password secret '{smtp_spec.password_secret.name}' has no data"
                )

            key = smtp_spec.password_secret.key
            if key not in secret.data:
                raise ReconciliationError(
                    f"SMTP password secret '{smtp_spec.password_secret.name}' "
                    f"missing key '{key}'"
                )

            # Decode base64 password
            import base64
            password = base64.b64decode(secret.data[key]).decode('utf-8')
            config["password"] = password

        except ApiException as e:
            if e.status == 404:
                raise ReconciliationError(
                    f"SMTP password secret '{smtp_spec.password_secret.name}' not found "
                    f"in namespace '{namespace}'"
                ) from e
            raise

    return config


# Then in the main reconcile method, add SMTP config to realm:
def _build_realm_config(self, spec: KeycloakRealmSpec, namespace: str) -> dict[str, Any]:
    """Build Keycloak realm configuration."""
    config = {
        "realm": spec.realm_name,
        # ... other fields ...
    }

    # Add SMTP configuration
    if spec.smtp_server:
        config["smtpServer"] = await self._build_smtp_config(
            spec.smtp_server,
            namespace
        )

    return config
```

**Security Note:** The password is fetched at reconciliation time, never stored in the CRD status.

---

### Step 4: Testing Strategy (Without Real SMTP)

**Option 1: Use Mailhog (Fake SMTP Server)**

Deploy Mailhog in your test cluster:

```yaml
# mailhog-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mailhog
spec:
  selector:
    matchLabels:
      app: mailhog
  template:
    metadata:
      labels:
        app: mailhog
    spec:
      containers:
      - name: mailhog
        image: mailhog/mailhog:latest
        ports:
        - containerPort: 1025  # SMTP
        - containerPort: 8025  # Web UI
---
apiVersion: v1
kind: Service
metadata:
  name: mailhog
spec:
  selector:
    app: mailhog
  ports:
  - name: smtp
    port: 1025
  - name: http
    port: 8025
```

Then test with:
```yaml
smtp_server:
  host: mailhog.default.svc.cluster.local
  port: 1025
  from: test@example.com
  auth: false
```

**Option 2: Mock SMTP in Unit Tests**

```python
@pytest.mark.asyncio
async def test_smtp_configuration(mock_k8s_client):
    """Test SMTP configuration with mocked secret."""
    # Mock secret fetch
    mock_secret = MagicMock()
    mock_secret.data = {
        "password": base64.b64encode(b"test-password").decode('utf-8')
    }

    mock_core_api = MagicMock()
    mock_core_api.read_namespaced_secret.return_value = mock_secret

    # Test SMTP config building
    smtp_spec = SMTPServerConfig(
        host="smtp.example.com",
        from_="noreply@example.com",
        username="apikey",
        password_secret=SMTPPasswordSecret(name="smtp-creds")
    )

    reconciler = KeycloakRealmReconciler()
    config = await reconciler._build_smtp_config(smtp_spec, "default")

    assert config["host"] == "smtp.example.com"
    assert config["user"] == "apikey"
    assert config["password"] == "test-password"
```

**Option 3: Integration Test with Skip Decorator**

```python
@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv("SMTP_TEST_ENABLED"),
    reason="SMTP testing requires SMTP_TEST_ENABLED=true"
)
async def test_realm_with_smtp():
    """Integration test for SMTP configuration."""
    # Only runs if explicitly enabled
    pass
```

---

### Step 5: Documentation

**File:** `README.md`

```markdown
#### Realm with Email Configuration

Enable password reset and email verification:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: email-enabled-realm
  namespace: identity-system
spec:
  realm_name: production
  keycloak_instance_ref:
    name: prod-keycloak
    namespace: identity-system

  # SMTP configuration for email sending
  smtp_server:
    host: smtp.sendgrid.net
    port: 587
    from: noreply@company.com
    from_display_name: "Company Identity Service"
    starttls: true
    auth: true
    username: apikey
    password_secret:
      name: smtp-credentials  # Kubernetes secret
      key: password

---
# SMTP credentials secret
apiVersion: v1
kind: Secret
metadata:
  name: smtp-credentials
  namespace: identity-system
type: Opaque
stringData:
  password: "SG.your-sendgrid-api-key"
```

**Supported SMTP Providers:**
- SendGrid
- Amazon SES
- Mailgun
- Office 365 / Outlook
- Gmail (app passwords)
- Custom SMTP servers
```

---

### Testing Guidance for Interns

**Without SMTP Infrastructure:**
1. Implement the feature completely
2. Write unit tests with mocked secrets
3. Skip integration tests (use `@pytest.mark.skip`)
4. Document the feature with examples
5. Mark as "untested in production" in PR

**With SMTP Infrastructure:**
1. Deploy Mailhog to test cluster
2. Create integration test with Mailhog
3. Verify emails appear in Mailhog UI
4. Test password reset flow end-to-end

---

## Priority 4: Authorization Services (Long-Term)

### Problem Statement
Keycloak Authorization Services provide fine-grained permissions (UMA 2.0) for APIs. This is a complex feature that allows defining resources, scopes, policies, and permissions.

**Complexity:** HIGH - This is a multi-month project requiring deep Keycloak understanding.

**Recommendation:** Break into phases, start with research.

---

### Phase 1: Research and Design (2-3 weeks)

**Tasks:**
1. **Study the Keycloak Authorization Services:**
   - Read official docs: https://www.keycloak.org/docs/latest/authorization_services/
   - Understand resources, scopes, policies, permissions
   - Try creating authorization config manually in Keycloak UI

2. **Analyze the API specification:**
   ```bash
   # Find authorization endpoints
   grep -A 20 "authz/resource-server" keycloak-api-spec.yaml
   ```

   Key endpoints:
   - `/admin/realms/{realm}/clients/{id}/authz/resource-server` - Enable/configure
   - `/admin/realms/{realm}/clients/{id}/authz/resource-server/resource` - Manage resources
   - `/admin/realms/{realm}/clients/{id}/authz/resource-server/policy` - Manage policies
   - `/admin/realms/{realm}/clients/{id}/authz/resource-server/permission` - Manage permissions

3. **Design CRD options:**

   **Option A: Embed in KeycloakClient**
   ```yaml
   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakClient
   spec:
     client_id: api-server
     authorization_services:
       enabled: true
       resources:
         - name: "document"
           scopes: ["read", "write", "delete"]
       policies:
         - name: "admin-only"
           type: "role"
           logic: "POSITIVE"
           config:
             roles: ["admin"]
       permissions:
         - name: "document-admin-permission"
           type: "resource"
           resources: ["document"]
           policies: ["admin-only"]
   ```

   **Option B: Separate CRDs**
   ```yaml
   # Separate resources for better modularity
   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakAuthorizationResource

   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakAuthorizationPolicy

   apiVersion: keycloak.mdvr.nl/v1
   kind: KeycloakAuthorizationPermission
   ```

4. **Write design document:**
   Create `TODO/authorization-services-design.md` with:
   - Use cases and examples
   - Proposed CRD structure
   - Implementation phases
   - Testing strategy
   - Migration path for existing deployments

---

### Phase 2: Minimal Implementation (4-6 weeks)

**Goal:** Enable authorization services with basic resources and policies

**Tasks:**
1. Add `authorization_services_enabled` boolean to KeycloakClient
2. Implement enabling authorization services on client
3. Add basic resource management
4. Add simple policy types (role-based, time-based)
5. Write comprehensive tests

---

### Phase 3: Advanced Features (4-6 weeks)

**Tasks:**
1. Complex policy types (JavaScript, aggregated, etc.)
2. Permission management
3. Scope management
4. Policy evaluation APIs
5. Performance optimization

---

### Guidance for Interns

**If you're interested in this feature:**
1. Start with Phase 1 research
2. Create a prototype in a fork
3. Share design document for feedback
4. Don't commit to full implementation without approval
5. This is advanced - ask for help often

**Resources:**
- Keycloak Authorization Services docs
- Keycloak Admin API spec
- UMA 2.0 specification
- Example implementations in other operators

---

## Additional Enhancements

### Quick Wins (1-2 days each)

#### 1. Client Secret Rotation Status
Add `secretRotatedAt` to KeycloakClient status to track when secrets were last regenerated.

#### 2. Realm Export Status
Add `lastExported` to KeycloakRealm status for backup tracking.

#### 3. Health Check Intervals
Make health check intervals configurable per resource.

#### 4. Better Error Messages
Improve error messages with specific resolution steps.

#### 5. Status Conditions
Add Kubernetes-style status conditions for better observability.

---

## General Testing Guide

### Unit Testing Patterns

**1. Test Pydantic Models:**
```python
def test_model_validation():
    """Test that model validates correctly."""
    valid_data = {...}
    model = MyModel(**valid_data)
    assert model.field == expected_value

def test_model_validation_fails():
    """Test that invalid data raises ValidationError."""
    invalid_data = {...}
    with pytest.raises(ValidationError):
        MyModel(**invalid_data)
```

**2. Test Reconciler Logic:**
```python
@pytest.mark.asyncio
async def test_reconciler_creates_resource(mock_admin_client, mock_k8s_client):
    """Test that reconciler creates resources correctly."""
    reconciler = MyReconciler(
        k8s_client=mock_k8s_client,
        keycloak_admin_factory=lambda name, ns: mock_admin_client
    )

    result = await reconciler.reconcile(spec, name, namespace, status)

    # Assert API calls were made
    mock_admin_client.create_something.assert_called_once()

    # Assert status is correct
    assert result["phase"] == "Ready"
```

**3. Test Error Handling:**
```python
@pytest.mark.asyncio
async def test_reconciler_handles_error(mock_admin_client):
    """Test that errors are handled gracefully."""
    mock_admin_client.create_something.side_effect = KeycloakAdminError("API Error")

    reconciler = MyReconciler(keycloak_admin_factory=lambda name, ns: mock_admin_client)

    with pytest.raises(ReconciliationError):
        await reconciler.reconcile(spec, name, namespace, status)
```

### Integration Testing Patterns

**1. Resource Lifecycle:**
```python
@pytest.mark.integration
async def test_resource_creation_lifecycle(k8s_custom_objects, test_namespace):
    """Test complete resource lifecycle."""
    # Create resource
    resource = {...}
    k8s_custom_objects.create_namespaced_custom_object(...)

    # Wait for ready
    await wait_for_ready(...)

    # Verify status
    result = k8s_custom_objects.get_namespaced_custom_object(...)
    assert result["status"]["phase"] == "Ready"

    # Update resource
    patch = {"spec": {"field": "new_value"}}
    k8s_custom_objects.patch_namespaced_custom_object(...)

    # Verify update
    await wait_for_ready(...)

    # Delete resource
    k8s_custom_objects.delete_namespaced_custom_object(...)

    # Verify deletion
    await wait_for_deletion(...)
```

**2. Cross-Namespace Testing:**
```python
@pytest.mark.integration
async def test_cross_namespace_client(k8s_custom_objects, test_namespace):
    """Test client creation in different namespace from Keycloak."""
    # Create Keycloak in namespace A
    keycloak_ns = f"{test_namespace}-keycloak"
    client_ns = f"{test_namespace}-client"

    # Create namespaces
    create_namespace(keycloak_ns)
    create_namespace(client_ns)

    # Create Keycloak instance
    create_keycloak(keycloak_ns)

    # Create client referencing cross-namespace Keycloak
    create_client(
        namespace=client_ns,
        keycloak_ref={"name": "my-keycloak", "namespace": keycloak_ns}
    )

    # Verify RBAC allows this
    await wait_for_ready(...)
```

### Running Tests

```bash
# Fast unit tests during development
make test-unit

# Full test suite before committing
make test

# Watch mode for continuous testing
make test-watch

# Only integration tests
make test-integration

# Specific test file
uv run pytest tests/unit/models/test_client.py -v

# Specific test function
uv run pytest tests/unit/models/test_client.py::test_service_account_roles -v

# With coverage
uv run pytest --cov=keycloak_operator tests/

# See test output even on success
uv run pytest -v -s
```

---

## General Documentation Guide

### What to Document

**1. README.md Updates:**
- Add new features to feature list
- Add configuration examples with YAML
- Update quick start if needed
- Add troubleshooting tips

**2. API Documentation:**
- Update CRD field descriptions
- Add examples in CRD comments
- Document validation rules

**3. Code Comments:**
- Docstrings for all public methods
- Reference Keycloak API endpoints in docstrings
- Explain "why" not just "what"

### Documentation Standards

**1. YAML Examples:**
```yaml
# Always include:
# - Complete working example
# - Comments explaining each field
# - Realistic values (not foo/bar)

apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakClient
metadata:
  name: api-gateway  # Use descriptive names
  namespace: production
spec:
  client_id: api-gateway
  # Reference to Keycloak instance
  keycloak_instance_ref:
    name: prod-keycloak
    namespace: identity-system
  # ... more fields with comments
```

**2. Method Docstrings:**
```python
def create_something(self, param1: str, param2: int) -> dict[str, Any]:
    """
    Create a something in Keycloak.

    Based on OpenAPI spec: POST /admin/realms/{realm}/something

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Created resource representation

    Raises:
        KeycloakAdminError: If creation fails

    Example:
        >>> client.create_something("name", 42)
        {"id": "uuid", "name": "name"}
    """
```

**3. README Structure:**
```markdown
## Feature Name

Brief description of what this feature does.

### Use Cases
- When to use this feature
- What problems it solves

### Configuration

```yaml
# Example YAML
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field_name` | string | Yes | What this field does |

### Examples

#### Simple Example
```yaml
# Minimal configuration
```

#### Advanced Example
```yaml
# All options
```

### Troubleshooting

**Problem:** Common issue
**Solution:** How to fix it
```

---

## Getting Help

**When you're stuck:**

1. **Read the existing code:**
   - Find similar functionality (e.g., study `client_reconciler.py` for patterns)
   - Look at tests for examples

2. **Check the Keycloak API spec:**
   - `keycloak-api-spec.yaml` is your source of truth
   - Search for endpoints with `grep`

3. **Run tests frequently:**
   - `make test-unit` after each change
   - Catch issues early

4. **Use the operator logs:**
   - `make operator-logs` shows what's happening
   - Add more logging if needed

5. **Ask for help:**
   - Share your branch and describe what you've tried
   - Ask specific questions with code examples

**Good Questions:**
- "I'm implementing X and trying Y, but getting error Z. Here's my code..."
- "I see this pattern in file A, should I follow it for feature B?"
- "The test is failing with this output, what does it mean?"

**Less Helpful:**
- "It doesn't work"
- "How do I implement X?" (without showing any attempt)

---

## Checklist for Each Feature

- [ ] Research: Understand the Keycloak feature and API
- [ ] CRD: Update Custom Resource Definition
- [ ] Model: Update Pydantic models with validation
- [ ] Admin API: Implement Keycloak API methods
- [ ] Reconciler: Implement business logic
- [ ] Unit Tests: Test with mocks
- [ ] Integration Tests: Test with real cluster
- [ ] Documentation: Update README with examples
- [ ] Quality: Run `make quality` to fix linting
- [ ] Test: Run `make test` - all tests pass
- [ ] Manual Test: Deploy to local cluster and verify
- [ ] GitOps Check: No manual steps required

---

## Final Notes

**Remember:**
- GitOps means everything is declarative
- Least privilege means proper RBAC always
- Test thoroughly before considering done
- Document for the user, not just for developers
- Ask questions early and often

**You got this!** Take your time, follow the patterns, and don't hesitate to ask for help.

Good luck! 🚀
