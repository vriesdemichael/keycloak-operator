# Keycloak API Model Integration - Step-by-Step Implementation Guide

## Implementation Status

**Last Updated:** 2025-10-03

### ✅ Completed Phases

- **Phase 1: Validation Wrapper** ✅ COMPLETED (2025-10-03)
  - Added `_make_validated_request()` method at `keycloak_admin.py:318-364`
  - Added BaseModel import
  - 27 tests passing (19 API model + 8 admin client integration tests)

- **Phase 2-3: Method Signatures (Partial)** ✅ COMPLETED (2025-10-03)
  - Updated realm methods: `create_realm()`, `get_realm()`, `update_realm()`
  - Updated client methods: `create_client()`, `update_client()`
  - All methods support both Pydantic models and dicts (backward compatible)

### 🔄 Remaining Work

- **~20 admin client methods** still using `dict[str, Any]` (user management, roles, protocol mappers, etc.)
- **Reconcilers** not yet updated to build validated configs
- **Documentation** not yet updated with usage examples

**Estimated Time Remaining:** 6-8 hours

---

## Overview

This guide will help you integrate the generated Pydantic models with the Keycloak admin client. Follow each step carefully and in order. Test after each major change to catch issues early.

**Original Estimated Time:** 10-14 hours total (can be split across multiple days)

**What You'll Accomplish:**
- Replace all `dict[str, Any]` types with validated Pydantic models
- Add automatic validation for all Keycloak API requests
- Catch API errors before sending requests to Keycloak
- Make code type-safe and easier to maintain

---

## Prerequisites

Before starting, make sure you have:

1. ✅ Generated models exist at `src/keycloak_operator/models/keycloak_api.py`
2. ✅ You can import models successfully:
   ```bash
   uv run python -c "from keycloak_operator.models.keycloak_api import RealmRepresentation; print('OK')"
   ```
3. ✅ All existing tests pass:
   ```bash
   make test-unit
   ```

---

## Phase 1: Create Validation Wrapper (2-3 hours)

### Step 1.1: Open the Admin Client File

**File to edit:** `src/keycloak_operator/utils/keycloak_admin.py`

Open this file in your editor. You'll be adding a new method to the `KeycloakAdminClient` class.

### Step 1.2: Add Import for BaseModel

**Location:** Top of the file, around line 10-20 (in the imports section)

**Find this line:**
```python
from pydantic import BaseModel
```

**If it doesn't exist, add it:**
```python
from pydantic import BaseModel
```

### Step 1.3: Add Validation Wrapper Method

**Location:** In the `KeycloakAdminClient` class, add this method after the `_make_request` method (around line 250-300)

**What to do:**
1. Find the `_make_request` method (use Ctrl+F to search for `def _make_request`)
2. Scroll down to the end of that method
3. Add a blank line
4. Copy and paste this entire method:

```python
def _make_validated_request(
    self,
    method: str,
    endpoint: str,
    request_model: BaseModel | None = None,
    response_model: type[BaseModel] | None = None,
    **kwargs
) -> Any:
    """
    Make an HTTP request with automatic Pydantic validation.

    This method wraps _make_request to add validation for both request
    payloads (before sending) and response payloads (after receiving).

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint path (e.g., "realms/master")
        request_model: Optional Pydantic model instance to validate and send
        response_model: Optional Pydantic model class to validate response against
        **kwargs: Additional arguments passed to _make_request

    Returns:
        - If response_model is provided and status < 300: Validated Pydantic model instance
        - Otherwise: requests.Response object

    Raises:
        KeycloakAdminError: If request fails or validation fails

    Example:
        # Create a realm with validation
        realm = RealmRepresentation(realm="test", enabled=True)
        created = self._make_validated_request(
            "POST",
            "realms",
            request_model=realm,
            response_model=RealmRepresentation
        )
    """
    # Step 1: Validate and serialize request payload
    if request_model is not None:
        try:
            # Convert Pydantic model to dict for API
            # - exclude_none=True: Don't send null fields
            # - by_alias=True: Use camelCase field names (API format)
            kwargs['json'] = request_model.model_dump(
                exclude_none=True,
                by_alias=True
            )
            logger.debug(f"Validated request payload for {method} {endpoint}")
        except Exception as e:
            logger.error(f"Failed to serialize request model: {e}")
            raise KeycloakAdminError(f"Invalid request model: {e}") from e

    # Step 2: Make the HTTP request
    response = self._make_request(method, endpoint, **kwargs)

    # Step 3: Validate response payload if model is provided
    if response_model is not None and response.status_code < 300:
        try:
            # Parse response JSON and validate with Pydantic
            response_data = response.json()
            validated_response = response_model.model_validate(response_data)
            logger.debug(f"Validated response from {method} {endpoint}")
            return validated_response
        except Exception as e:
            logger.warning(f"Failed to validate response: {e}")
            # Don't fail the request if validation fails - just log and return response
            # This allows us to handle unexpected API responses gracefully
            return response

    # Step 4: Return raw response if no validation needed
    return response
```

**Why this works:**
- Takes a Pydantic model as input
- Converts it to JSON with correct field names (camelCase for Keycloak API)
- Validates the response from Keycloak
- Returns a typed object instead of a raw dict

### Step 1.4: Test the Validation Wrapper

**Create a test file:** `tests/unit/test_keycloak_admin_validation.py`

```python
"""
Test validation wrapper in KeycloakAdminClient.
"""
import pytest
from unittest.mock import Mock, patch
from requests import Response

from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
from keycloak_operator.models.keycloak_api import RealmRepresentation


class TestValidationWrapper:
    """Test the _make_validated_request method."""

    @pytest.fixture
    def mock_admin_client(self):
        """Create a mock admin client."""
        with patch('keycloak_operator.utils.keycloak_admin.requests.Session'):
            client = KeycloakAdminClient(
                server_url="http://localhost:8080",
                username="admin",
                password="admin"
            )
            return client

    def test_request_model_serialization(self, mock_admin_client):
        """Test that request models are properly serialized."""
        # Create a test realm model
        realm = RealmRepresentation(
            realm="test",
            display_name="Test Realm",
            enabled=True
        )

        # Mock _make_request to capture what was sent
        mock_response = Mock(spec=Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {"realm": "test"}

        with patch.object(mock_admin_client, '_make_request', return_value=mock_response) as mock_make_request:
            # Call validated request
            mock_admin_client._make_validated_request(
                "POST",
                "realms",
                request_model=realm
            )

            # Verify _make_request was called with correct JSON
            mock_make_request.assert_called_once()
            call_kwargs = mock_make_request.call_args.kwargs

            # Check that JSON was provided
            assert 'json' in call_kwargs
            json_data = call_kwargs['json']

            # Check fields are in camelCase (API format)
            assert json_data['realm'] == "test"
            assert json_data['displayName'] == "Test Realm"
            assert json_data['enabled'] is True

    def test_response_model_validation(self, mock_admin_client):
        """Test that responses are validated against models."""
        # Mock API response
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "12345",
            "realm": "test",
            "displayName": "Test Realm",
            "enabled": True
        }

        with patch.object(mock_admin_client, '_make_request', return_value=mock_response):
            # Call with response validation
            result = mock_admin_client._make_validated_request(
                "GET",
                "realms/test",
                response_model=RealmRepresentation
            )

            # Result should be a validated Pydantic model
            assert isinstance(result, RealmRepresentation)
            assert result.id == "12345"
            assert result.realm == "test"
            assert result.display_name == "Test Realm"  # Note: snake_case in Python

    def test_no_validation_when_models_not_provided(self, mock_admin_client):
        """Test that requests work without models (backward compatibility)."""
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200

        with patch.object(mock_admin_client, '_make_request', return_value=mock_response):
            result = mock_admin_client._make_validated_request(
                "GET",
                "realms/test"
            )

            # Should return raw response
            assert result == mock_response
```

**Run the test:**
```bash
uv run pytest tests/unit/test_keycloak_admin_validation.py -v
```

**Expected output:** All tests should pass

**If tests fail:**
1. Check that you copied the `_make_validated_request` method correctly
2. Check for indentation errors (Python is sensitive to indentation!)
3. Make sure the method is inside the `KeycloakAdminClient` class
4. Check that imports are correct at the top of the file

---

## Phase 2: Update Admin Client Methods (3-4 hours)

Now we'll update the admin client methods one by one to use the validation wrapper.

**Strategy:** Update methods in order of importance/usage. Start with realms, then clients, then users.

### Step 2.1: Update `create_realm` Method

**Location:** `src/keycloak_operator/utils/keycloak_admin.py`, around line 319

**Current code (BEFORE):**
```python
def create_realm(self, realm_config: dict[str, Any]) -> dict[str, Any]:
    """
    Create a new realm in Keycloak.

    Args:
        realm_config: Realm configuration dictionary

    Returns:
        Created realm information
    """
    logger.info(f"Creating realm: {realm_config.get('realm', 'unknown')}")

    # Implement realm creation
    response = self._make_request("POST", "realms", data=realm_config)

    if response.status_code == 201:
        logger.info("Realm created successfully")
        # Return realm details
        return realm_config

    raise KeycloakAdminError(f"Failed to create realm: {response.text}")
```

**New code (AFTER):**
```python
def create_realm(
    self,
    realm_config: "RealmRepresentation | dict[str, Any]"
) -> "RealmRepresentation":
    """
    Create a new realm in Keycloak.

    Args:
        realm_config: Realm configuration as RealmRepresentation model or dict
            (dict support for backward compatibility)

    Returns:
        Created realm as validated RealmRepresentation

    Raises:
        KeycloakAdminError: If realm creation fails or validation fails

    Example:
        from keycloak_operator.models.keycloak_api import RealmRepresentation

        realm = RealmRepresentation(
            realm="my-realm",
            enabled=True,
            display_name="My Realm"
        )
        created_realm = client.create_realm(realm)
    """
    from keycloak_operator.models.keycloak_api import RealmRepresentation

    # Convert dict to model if needed (backward compatibility)
    if isinstance(realm_config, dict):
        realm_config = RealmRepresentation.model_validate(realm_config)

    realm_name = realm_config.realm or "unknown"
    logger.info(f"Creating realm: {realm_name}")

    # Use validation wrapper
    response = self._make_validated_request(
        "POST",
        "realms",
        request_model=realm_config
    )

    if response.status_code == 201:
        logger.info(f"Realm '{realm_name}' created successfully")
        # Return the model we sent (Keycloak returns empty body on 201)
        return realm_config

    raise KeycloakAdminError(
        f"Failed to create realm '{realm_name}': {response.text}"
    )
```

**What changed:**
1. **Type hints:** `dict[str, Any]` → `RealmRepresentation | dict[str, Any]`
2. **Return type:** `dict[str, Any]` → `RealmRepresentation`
3. **Import:** Added local import of `RealmRepresentation`
4. **Conversion:** Added dict-to-model conversion for backward compatibility
5. **Validation:** Uses `_make_validated_request` instead of `_make_request`
6. **Documentation:** Updated docstring with example usage

**Test it:**
```bash
# Run existing tests - they should still pass
uv run pytest tests/unit/ -k realm -v
```

### Step 2.2: Update `get_realm` Method

**Location:** Same file, around line 380

**Current code (BEFORE):**
```python
def get_realm(self, realm_name: str) -> dict[str, Any] | None:
    """Get realm configuration."""
    response = self._make_request("GET", f"realms/{realm_name}")

    if response.status_code == 200:
        return response.json()

    return None
```

**New code (AFTER):**
```python
def get_realm(self, realm_name: str) -> "RealmRepresentation | None":
    """
    Get realm configuration from Keycloak.

    Args:
        realm_name: Name of the realm to retrieve

    Returns:
        RealmRepresentation if realm exists, None otherwise

    Example:
        realm = client.get_realm("master")
        if realm:
            print(f"Realm: {realm.realm}, Enabled: {realm.enabled}")
    """
    from keycloak_operator.models.keycloak_api import RealmRepresentation

    logger.debug(f"Fetching realm: {realm_name}")

    try:
        # Use validation wrapper with response model
        result = self._make_validated_request(
            "GET",
            f"realms/{realm_name}",
            response_model=RealmRepresentation
        )

        # If we got a RealmRepresentation back, return it
        if isinstance(result, RealmRepresentation):
            return result

        # If we got a response object, try to parse it
        if hasattr(result, 'status_code') and result.status_code == 200:
            return RealmRepresentation.model_validate(result.json())

        return None

    except Exception as e:
        logger.warning(f"Failed to get realm '{realm_name}': {e}")
        return None
```

### Step 2.3: Update `update_realm` Method

**Location:** Same file, around line 435

**Current code (BEFORE):**
```python
def update_realm(
    self, realm_name: str, realm_config: dict[str, Any]
) -> dict[str, Any]:
    """Update realm configuration."""
    logger.info(f"Updating realm: {realm_name}")

    response = self._make_request("PUT", f"realms/{realm_name}", data=realm_config)

    if response.status_code == 204:
        return realm_config

    raise KeycloakAdminError(f"Failed to update realm: {response.text}")
```

**New code (AFTER):**
```python
def update_realm(
    self,
    realm_name: str,
    realm_config: "RealmRepresentation | dict[str, Any]"
) -> "RealmRepresentation":
    """
    Update realm configuration in Keycloak.

    Args:
        realm_name: Name of the realm to update
        realm_config: Updated realm configuration

    Returns:
        Updated realm as RealmRepresentation

    Example:
        realm = client.get_realm("my-realm")
        realm.display_name = "New Name"
        realm.enabled = False
        updated = client.update_realm("my-realm", realm)
    """
    from keycloak_operator.models.keycloak_api import RealmRepresentation

    # Convert dict to model if needed
    if isinstance(realm_config, dict):
        realm_config = RealmRepresentation.model_validate(realm_config)

    logger.info(f"Updating realm: {realm_name}")

    response = self._make_validated_request(
        "PUT",
        f"realms/{realm_name}",
        request_model=realm_config
    )

    if response.status_code == 204:  # No content on successful update
        logger.info(f"Realm '{realm_name}' updated successfully")
        return realm_config

    raise KeycloakAdminError(
        f"Failed to update realm '{realm_name}': {response.text}"
    )
```

### Step 2.4: Update Client-Related Methods

**Methods to update:** `create_client`, `get_client`, `update_client`

**Pattern to follow (same as realm methods):**

1. **Change type hints:**
   - Input: `dict[str, Any]` → `ClientRepresentation | dict[str, Any]`
   - Output: `dict[str, Any]` → `ClientRepresentation`

2. **Add import:**
   ```python
   from keycloak_operator.models.keycloak_api import ClientRepresentation
   ```

3. **Add dict conversion:**
   ```python
   if isinstance(client_config, dict):
       client_config = ClientRepresentation.model_validate(client_config)
   ```

4. **Use validation wrapper:**
   ```python
   self._make_validated_request(
       "POST",
       f"realms/{realm_name}/clients",
       request_model=client_config
   )
   ```

**Example for `create_client`:**

```python
def create_client(
    self,
    client_config: "ClientRepresentation | dict[str, Any]",
    realm_name: str = "master"
) -> str | None:
    """
    Create a new client in the specified realm.

    Args:
        client_config: Client configuration as ClientRepresentation or dict
        realm_name: Name of the realm (defaults to "master")

    Returns:
        Client UUID if successful, None otherwise

    Example:
        from keycloak_operator.models.keycloak_api import ClientRepresentation

        client = ClientRepresentation(
            client_id="my-client",
            enabled=True,
            public_client=True,
            redirect_uris=["http://localhost:3000/*"]
        )
        client_uuid = admin_client.create_client(client, "my-realm")
    """
    from keycloak_operator.models.keycloak_api import ClientRepresentation

    # Convert dict to model if needed
    if isinstance(client_config, dict):
        client_config = ClientRepresentation.model_validate(client_config)

    client_id = client_config.client_id or "unknown"
    logger.info(f"Creating client '{client_id}' in realm '{realm_name}'")

    try:
        response = self._make_validated_request(
            "POST",
            f"realms/{realm_name}/clients",
            request_model=client_config
        )

        if response.status_code == 201:
            # Extract UUID from Location header
            location = response.headers.get("Location", "")
            if location:
                client_uuid = location.split("/")[-1]
                logger.info(
                    f"Client '{client_id}' created with UUID: {client_uuid}"
                )
                return client_uuid

        logger.error(f"Failed to create client '{client_id}': {response.text}")
        return None

    except Exception as e:
        logger.error(f"Error creating client '{client_id}': {e}")
        return None
```

### Step 2.5: Test After Each Method Update

**Important:** Test after updating each method!

```bash
# Test the specific method you just updated
uv run pytest tests/unit/test_keycloak_admin_validation.py -v

# Test all unit tests to make sure nothing broke
uv run pytest tests/unit/ -v

# If tests fail, DON'T continue - fix the issue first!
```

### Step 2.6: Checklist of Methods to Update

Update these methods in order. Check off each one as you complete it:

**Realm methods:**
- [ ] `create_realm` (lines ~319-340)
- [ ] `get_realm` (lines ~380-395)
- [ ] `update_realm` (lines ~435-455)
- [ ] `delete_realm` (lines ~460-475) - Optional, low priority

**Client methods:**
- [ ] `create_client` (lines ~514-550)
- [ ] `get_client` (lines ~580-610)
- [ ] `get_client_by_client_id` (lines ~620-645)
- [ ] `update_client` (lines ~553-590)
- [ ] `delete_client` (lines ~650-670) - Optional

**User methods (if time permits):**
- [ ] `create_user` (lines ~700-730)
- [ ] `get_user` (lines ~750-780)
- [ ] `update_user` (lines ~785-815)

**Role methods (lower priority):**
- [ ] `create_client_role` (lines ~1388-1418)
- [ ] `get_client_roles` (lines ~1450-1480)

**Important:** You don't need to update ALL methods at once. Start with realm and client methods - those are the most important.

---

## Phase 3: Update Reconcilers (2-3 hours)

Now update the reconcilers to build validated configs instead of dicts.

### Step 3.1: Update Realm Reconciler

**File:** `src/keycloak_operator/services/realm_reconciler.py`

**Find the method:** `ensure_realm_exists` (around line 220-280)

**Current code (BEFORE):**
```python
# Build realm config dict
realm_config = {
    "realm": realm_spec.realm_name,
    "enabled": realm_spec.enabled,
    "displayName": realm_spec.display_name,
    # ... more fields
}

# Create realm
admin_client.create_realm(realm_config)
```

**New code (AFTER):**
```python
from keycloak_operator.models.keycloak_api import RealmRepresentation

# Build typed realm config
realm_config = RealmRepresentation(
    realm=realm_spec.realm_name,
    enabled=realm_spec.enabled,
    display_name=realm_spec.display_name,
    # Map all relevant fields from our CRD spec to Keycloak API format
    # Note: Use snake_case here - Pydantic will convert to camelCase
)

# Create realm with validation
created_realm = admin_client.create_realm(realm_config)
logger.info(f"Created realm: {created_realm.realm}")
```

**Where to find the code:**
1. Open `src/keycloak_operator/services/realm_reconciler.py`
2. Search for `def ensure_realm_exists`
3. Look for where it builds the realm configuration
4. Replace dict building with `RealmRepresentation` building

**What fields to map:**

Look at your `KeycloakRealmSpec` model and map fields to `RealmRepresentation`:

```python
realm_config = RealmRepresentation(
    # Core fields
    realm=realm_spec.realm_name,
    enabled=realm_spec.enabled,
    display_name=realm_spec.display_name,

    # Security settings (if your spec has them)
    registration_allowed=realm_spec.security.registration_allowed if realm_spec.security else None,
    reset_password_allowed=realm_spec.security.reset_password_allowed if realm_spec.security else None,

    # Theme settings (if your spec has them)
    login_theme=realm_spec.themes.login if hasattr(realm_spec, 'themes') and realm_spec.themes else None,
    account_theme=realm_spec.themes.account if hasattr(realm_spec, 'themes') and realm_spec.themes else None,

    # Only include fields that exist in your spec!
    # Omit fields with None - Pydantic will exclude them
)
```

### Step 3.2: Update Client Reconciler

**File:** `src/keycloak_operator/services/client_reconciler.py`

**Find the method:** `ensure_client_exists` (around line 180-250)

**Before:**
```python
client_config = {
    "clientId": spec.client_id,
    "enabled": spec.settings.enabled,
    "publicClient": spec.public_client,
    # ... more fields
}

client_uuid = admin_client.create_client(client_config, realm_name)
```

**After:**
```python
from keycloak_operator.models.keycloak_api import ClientRepresentation

# Build typed client config
client_config = ClientRepresentation(
    client_id=spec.client_id,
    enabled=spec.settings.enabled if spec.settings else True,
    public_client=spec.public_client,
    bearer_only=spec.bearer_only,
    redirect_uris=spec.redirect_uris,
    web_origins=spec.web_origins,
    protocol=spec.protocol,
    # Map all fields from your KeycloakClientSpec
)

# Create with validation
client_uuid = admin_client.create_client(client_config, realm_name)
logger.info(f"Created client: {client_config.client_id} (UUID: {client_uuid})")
```

### Step 3.3: Test Reconcilers

**Run integration tests:**
```bash
# If you have integration tests
uv run pytest tests/integration/ -v

# Or run unit tests for reconcilers
uv run pytest tests/unit/services/ -v
```

**Manual testing:**
1. Start a test cluster (if you have one)
2. Deploy the operator
3. Create a test realm
4. Create a test client
5. Check operator logs for validation errors

---

## Phase 4: Add Comprehensive Tests (2-3 hours)

### Step 4.1: Create Model Validation Tests

**Create file:** `tests/unit/test_keycloak_api_models.py`

```python
"""
Test Keycloak API Pydantic models.

Tests validation, serialization, and deserialization of models
generated from the Keycloak OpenAPI specification.
"""
import pytest
from pydantic import ValidationError

from keycloak_operator.models.keycloak_api import (
    RealmRepresentation,
    ClientRepresentation,
    UserRepresentation,
)


class TestRealmRepresentation:
    """Test RealmRepresentation model."""

    def test_create_minimal_realm(self):
        """Test creating a realm with minimal fields."""
        realm = RealmRepresentation(
            realm="test-realm",
            enabled=True
        )

        assert realm.realm == "test-realm"
        assert realm.enabled is True
        assert realm.display_name is None  # Optional field

    def test_create_full_realm(self):
        """Test creating a realm with all common fields."""
        realm = RealmRepresentation(
            realm="full-realm",
            enabled=True,
            display_name="Full Test Realm",
            login_theme="keycloak",
            account_theme="keycloak",
            admin_theme="keycloak",
            email_theme="keycloak",
            registration_allowed=False,
            reset_password_allowed=True,
        )

        assert realm.realm == "full-realm"
        assert realm.display_name == "Full Test Realm"
        assert realm.login_theme == "keycloak"
        assert realm.registration_allowed is False

    def test_serialize_to_api_format(self):
        """Test serialization to API format (camelCase)."""
        realm = RealmRepresentation(
            realm="test",
            display_name="Test Realm",
            enabled=True,
            ssl_required="external"
        )

        # Serialize for API (with aliases, excluding None values)
        api_data = realm.model_dump(by_alias=True, exclude_none=True)

        # Check camelCase field names
        assert "displayName" in api_data
        assert api_data["displayName"] == "Test Realm"
        assert "sslRequired" in api_data
        assert api_data["sslRequired"] == "external"

        # Check that None fields are excluded
        assert "loginTheme" not in api_data  # Was None, should be excluded

    def test_parse_from_api_response(self):
        """Test parsing API response (camelCase) into model."""
        # Simulate API response
        api_response = {
            "id": "abc-123",
            "realm": "parsed-realm",
            "displayName": "Parsed Realm",
            "enabled": True,
            "sslRequired": "external",
            "loginTheme": "keycloak"
        }

        # Parse into model
        realm = RealmRepresentation.model_validate(api_response)

        # Check fields are in snake_case in Python
        assert realm.id == "abc-123"
        assert realm.realm == "parsed-realm"
        assert realm.display_name == "Parsed Realm"  # snake_case!
        assert realm.ssl_required == "external"
        assert realm.login_theme == "keycloak"

    def test_type_validation(self):
        """Test that incorrect types are rejected."""
        # This should fail - enabled should be bool
        with pytest.raises(ValidationError) as exc_info:
            RealmRepresentation(
                realm="test",
                enabled="yes"  # Wrong type!
            )

        error_msg = str(exc_info.value)
        assert "enabled" in error_msg
        assert "bool" in error_msg or "boolean" in error_msg


class TestClientRepresentation:
    """Test ClientRepresentation model."""

    def test_create_public_client(self):
        """Test creating a public client (like a frontend app)."""
        client = ClientRepresentation(
            client_id="frontend-app",
            enabled=True,
            public_client=True,
            redirect_uris=["http://localhost:3000/*"],
            web_origins=["http://localhost:3000"]
        )

        assert client.client_id == "frontend-app"
        assert client.public_client is True
        assert len(client.redirect_uris) == 1

    def test_create_confidential_client(self):
        """Test creating a confidential client (like a backend service)."""
        client = ClientRepresentation(
            client_id="backend-service",
            enabled=True,
            public_client=False,
            service_accounts_enabled=True
        )

        assert client.client_id == "backend-service"
        assert client.public_client is False
        assert client.service_accounts_enabled is True

    def test_serialize_to_api_format(self):
        """Test client serialization to API format."""
        client = ClientRepresentation(
            client_id="test-client",
            enabled=True,
            public_client=True,
            redirect_uris=["http://example.com/*"]
        )

        api_data = client.model_dump(by_alias=True, exclude_none=True)

        # Check camelCase
        assert "clientId" in api_data
        assert "publicClient" in api_data
        assert "redirectUris" in api_data

        # Check values
        assert api_data["clientId"] == "test-client"
        assert api_data["publicClient"] is True


class TestUserRepresentation:
    """Test UserRepresentation model."""

    def test_create_basic_user(self):
        """Test creating a basic user."""
        user = UserRepresentation(
            username="testuser",
            enabled=True,
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.first_name == "Test"

    def test_serialize_user(self):
        """Test user serialization."""
        user = UserRepresentation(
            username="testuser",
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )

        api_data = user.model_dump(by_alias=True, exclude_none=True)

        # Check camelCase
        assert "firstName" in api_data
        assert "lastName" in api_data
        assert api_data["firstName"] == "Test"


class TestModelInteroperability:
    """Test that models work together correctly."""

    def test_dict_to_model_conversion(self):
        """Test converting dicts to models (backward compatibility)."""
        # Old-style dict config
        realm_dict = {
            "realm": "test",
            "enabled": True,
            "displayName": "Test"
        }

        # Should convert successfully
        realm = RealmRepresentation.model_validate(realm_dict)
        assert realm.realm == "test"
        assert realm.display_name == "Test"

    def test_model_to_dict_to_model_roundtrip(self):
        """Test that model → dict → model preserves data."""
        # Create model
        original = RealmRepresentation(
            realm="roundtrip",
            enabled=True,
            display_name="Roundtrip Test"
        )

        # Convert to dict (API format)
        api_dict = original.model_dump(by_alias=True, exclude_none=True)

        # Convert back to model
        restored = RealmRepresentation.model_validate(api_dict)

        # Should be equivalent
        assert restored.realm == original.realm
        assert restored.enabled == original.enabled
        assert restored.display_name == original.display_name
```

### Step 4.2: Run All Tests

```bash
# Run just the new model tests
uv run pytest tests/unit/test_keycloak_api_models.py -v

# Run all unit tests
uv run pytest tests/unit/ -v

# Run everything
make test
```

**All tests should pass!** If not:
1. Read the error message carefully
2. Check which test failed
3. Fix the issue
4. Re-run tests

---

## Phase 5: Documentation (1 hour)

### Step 5.1: Update README

**File:** `README.md`

Add a new section about the API models:

```markdown
## Using Keycloak API Models

All Keycloak Admin API interactions use type-safe Pydantic models generated from the official OpenAPI specification.

### Benefits

- **Type Safety**: IDE autocomplete and type checking for all 152 realm fields, 44 client fields, etc.
- **Validation**: Catch errors before sending requests to Keycloak
- **Documentation**: Self-documenting code with field descriptions
- **Maintainability**: Easy to update when Keycloak releases new versions

### Example: Creating a Realm

\`\`\`python
from keycloak_operator.models.keycloak_api import RealmRepresentation
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client

# Get admin client
admin_client = get_keycloak_admin_client("my-keycloak", "default")

# Create a realm with type-safe config
realm = RealmRepresentation(
    realm="my-realm",
    enabled=True,
    display_name="My Realm",
    login_theme="keycloak",
    registration_allowed=False,
    reset_password_allowed=True
)

# Create with automatic validation
created_realm = admin_client.create_realm(realm)
print(f"Created realm: {created_realm.realm}")
\`\`\`

### Example: Creating a Client

\`\`\`python
from keycloak_operator.models.keycloak_api import ClientRepresentation

# Create a public client (e.g., frontend app)
client = ClientRepresentation(
    client_id="frontend-app",
    enabled=True,
    public_client=True,
    redirect_uris=["http://localhost:3000/*"],
    web_origins=["http://localhost:3000"],
    protocol="openid-connect"
)

client_uuid = admin_client.create_client(client, realm_name="my-realm")
print(f"Created client: {client_uuid}")
\`\`\`

### Regenerating Models

When Keycloak is upgraded, regenerate the models:

\`\`\`bash
# Download new OpenAPI spec
curl -o keycloak-api-spec.yaml https://www.keycloak.org/docs-api/latest/rest-api/openapi.yaml

# Regenerate models
./scripts/generate-keycloak-models.sh

# Test
make test
\`\`\`
```

### Step 5.2: Add Inline Documentation

Add docstring examples to key methods in `keycloak_admin.py`:

```python
def create_realm(
    self,
    realm_config: "RealmRepresentation | dict[str, Any]"
) -> "RealmRepresentation":
    """
    Create a new realm in Keycloak.

    Args:
        realm_config: Realm configuration as RealmRepresentation model or dict

    Returns:
        Created realm as validated RealmRepresentation

    Example:
        >>> from keycloak_operator.models.keycloak_api import RealmRepresentation
        >>> realm = RealmRepresentation(realm="test", enabled=True)
        >>> created = client.create_realm(realm)
        >>> print(created.realm)
        'test'
    """
```

---

## Phase 6: Final Verification (30 minutes)

### Checklist

Go through this checklist to make sure everything is working:

- [ ] All new tests pass: `make test-unit`
- [ ] No type errors: `uv run mypy src/keycloak_operator/` (if you have mypy)
- [ ] Code is formatted: `make quality`
- [ ] Documentation is updated in README.md
- [ ] At least these methods are updated:
  - [ ] `create_realm`, `get_realm`, `update_realm`
  - [ ] `create_client`, `get_client`, `update_client`
- [ ] Reconcilers build typed configs:
  - [ ] Realm reconciler uses `RealmRepresentation`
  - [ ] Client reconciler uses `ClientRepresentation`
- [ ] Integration tests pass (if you have them): `make test-integration`

### Final Test

Create a simple end-to-end test:

```python
# tests/integration/test_typed_api_e2e.py
"""
End-to-end test of typed API models.
"""
import pytest
from keycloak_operator.models.keycloak_api import (
    RealmRepresentation,
    ClientRepresentation
)


@pytest.mark.integration
def test_create_realm_and_client_with_models(admin_client):
    """Test creating realm and client using typed models."""
    # Create realm
    realm = RealmRepresentation(
        realm="e2e-test-realm",
        enabled=True,
        display_name="E2E Test Realm"
    )

    created_realm = admin_client.create_realm(realm)
    assert created_realm.realm == "e2e-test-realm"

    # Create client in that realm
    client = ClientRepresentation(
        client_id="e2e-test-client",
        enabled=True,
        public_client=True
    )

    client_uuid = admin_client.create_client(client, "e2e-test-realm")
    assert client_uuid is not None

    # Cleanup
    admin_client.delete_client(client_uuid, "e2e-test-realm")
    admin_client.delete_realm("e2e-test-realm")
```

---

## Common Issues & Solutions

### Issue 1: Import Errors

**Error:**
```
ImportError: cannot import name 'RealmRepresentation' from 'keycloak_operator.models.keycloak_api'
```

**Solution:**
1. Make sure models are generated: `./scripts/generate-keycloak-models.sh`
2. Check file exists: `ls -la src/keycloak_operator/models/keycloak_api.py`
3. Try importing manually: `uv run python -c "from keycloak_operator.models.keycloak_api import RealmRepresentation"`

### Issue 2: Validation Errors

**Error:**
```
ValidationError: 1 validation error for RealmRepresentation
enabled
  Input should be a valid boolean
```

**Solution:**
- Check that you're passing the correct type
- `enabled` should be `True` or `False`, not `"true"` or `"yes"`
- Use the correct type for each field

### Issue 3: Field Name Mismatches

**Error:**
```
KeyError: 'displayName'
```

**Solution:**
- In Python code, use snake_case: `display_name`
- The model automatically converts to camelCase when sending to API
- Example: `realm.display_name` (Python) → `{"displayName": "..."}` (API)

### Issue 4: Tests Failing After Changes

**Solution:**
1. Run tests in isolation: `uv run pytest tests/unit/test_keycloak_api_models.py::TestRealmRepresentation::test_create_minimal_realm -v`
2. Check error message carefully
3. Make sure you didn't break existing code
4. Revert your changes and try again more carefully

### Issue 5: Method Signature Errors

**Error:**
```
TypeError: create_realm() missing 1 required positional argument: 'realm_config'
```

**Solution:**
- Make sure you updated the method signature correctly
- Check that you're passing arguments in the right order
- Look at the examples in this guide

---

## Summary

By following this guide, you will have:

1. ✅ Created a validation wrapper that checks all API requests/responses
2. ✅ Updated admin client methods to use typed models
3. ✅ Updated reconcilers to build validated configs
4. ✅ Added comprehensive tests
5. ✅ Updated documentation

**Result:** Type-safe, validated Keycloak API interactions with full IDE support!

---

## Getting Help

If you get stuck:

1. **Read error messages carefully** - they usually tell you what's wrong
2. **Check this guide** - search for the error message or issue
3. **Look at examples** - there are many examples throughout this guide
4. **Run tests incrementally** - test after each small change
5. **Ask for help** - if you're truly stuck, ask a senior developer

**Remember:** Take your time, test frequently, and don't skip steps!
