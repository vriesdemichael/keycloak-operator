# SMTP Configuration Implementation Plan

**Status:** ✅ COMPLETED
**Priority:** High (User requested)
**Created:** 2025-10-05
**Completed:** 2025-10-05
**Commit:** `db554e6` - `feat: implement secure SMTP configuration for KeycloakRealm`

## Overview
Implement secure SMTP configuration for KeycloakRealm with Kubernetes secret support, validation, testing, and documentation.

**Current State:**
- ✅ CRD already has SMTP schema defined (host, port, auth, etc.)
- ✅ Model already passes `smtp_server` to Keycloak API
- ❌ Password stored in plain text in CRD spec (security issue)
- ❌ No validation of required fields
- ❌ No integration tests
- ❌ No documentation

## Phase 1: Model Changes (Security + Validation)

**File:** `src/keycloak_operator/models/realm.py`

### 1.1 Create Structured SMTP Model

```python
class KeycloakSMTPPasswordSecret(BaseModel):
    """Reference to Kubernetes secret containing SMTP password."""
    name: str = Field(..., description="Secret name")
    key: str = Field(default="password", description="Key in secret data")

class KeycloakSMTPConfig(BaseModel):
    """SMTP server configuration with validation."""
    host: str = Field(..., description="SMTP server host")
    port: int = Field(..., description="SMTP server port", ge=1, le=65535)
    from_address: str = Field(..., alias="from", description="From email address")
    from_display_name: str | None = Field(None, description="From display name")
    reply_to: str | None = Field(None, description="Reply-to address")
    envelope_from: str | None = Field(None, description="Envelope from address")
    ssl: bool = Field(False, description="Use SSL")
    starttls: bool = Field(False, description="Use STARTTLS")
    auth: bool = Field(False, description="Require authentication")
    user: str | None = Field(None, description="SMTP username")
    password: str | None = Field(None, description="SMTP password (use password_secret instead)")
    password_secret: KeycloakSMTPPasswordSecret | None = Field(None, description="Secret reference for password")

    @model_validator(mode="after")
    def validate_auth_requirements(self):
        """Ensure auth settings are consistent."""
        if self.auth and not self.user:
            raise ValueError("SMTP user required when auth=true")
        if self.auth and not self.password and not self.password_secret:
            raise ValueError("SMTP password or password_secret required when auth=true")
        if self.password and self.password_secret:
            raise ValueError("Cannot specify both password and password_secret")
        return self
```

### 1.2 Update KeycloakRealmSpec

Replace `smtp_server: dict[str, str] | None` with `smtp_server: KeycloakSMTPConfig | None`

### 1.3 Update to_keycloak_config()

**IMPORTANT:** Do NOT include password in returned dict - it will be injected by reconciler after fetching from secret.

```python
if self.smtp_server:
    smtp_config = self.smtp_server.model_dump(by_alias=True, exclude_none=True, exclude={"password_secret", "password"})
    config["smtpServer"] = smtp_config
```

## Phase 2: Reconciler Changes (Secret Handling)

**File:** `src/keycloak_operator/services/realm_reconciler.py`

### 2.1 Add SMTP Secret Fetch Method

```python
async def _fetch_smtp_password(
    self, namespace: str, secret_ref: KeycloakSMTPPasswordSecret
) -> str:
    """Fetch SMTP password from Kubernetes secret."""
    try:
        from kubernetes import client
        core_api = client.CoreV1Api()
        secret = core_api.read_namespaced_secret(
            name=secret_ref.name,
            namespace=namespace
        )
        if secret_ref.key not in secret.data:
            raise ValueError(f"Key '{secret_ref.key}' not found in secret '{secret_ref.name}'")

        import base64
        return base64.b64decode(secret.data[secret_ref.key]).decode()
    except Exception as e:
        raise ValueError(f"Failed to fetch SMTP password from secret '{secret_ref.name}': {e}")
```

### 2.2 Update ensure_realm_exists()

After calling `spec.to_keycloak_config()`, merge SMTP password:

```python
realm_config = spec.to_keycloak_config()

# Inject SMTP password from secret if configured
if spec.smtp_server and spec.smtp_server.password_secret:
    password = await self._fetch_smtp_password(namespace, spec.smtp_server.password_secret)
    if "smtpServer" not in realm_config:
        realm_config["smtpServer"] = {}
    realm_config["smtpServer"]["password"] = password
elif spec.smtp_server and spec.smtp_server.password:
    # Direct password (discouraged but supported)
    if "smtpServer" not in realm_config:
        realm_config["smtpServer"] = {}
    realm_config["smtpServer"]["password"] = spec.smtp_server.password

# Continue with existing realm creation/update logic
```

## Phase 3: CRD Schema Changes

**File:** `k8s/crds/keycloakrealm-crd.yaml`

### 3.1 Add smtp_password_secret Field

Insert after line 232 (after `password` field):

```yaml
password_secret:
  type: object
  description: "Reference to Kubernetes secret containing SMTP password (recommended over password)"
  properties:
    name:
      type: string
      description: "Secret name"
    key:
      type: string
      description: "Key in secret data"
      default: "password"
  required:
  - name
```

### 3.2 Update Descriptions

- Line 231 `password`: Add "(use password_secret instead for better security)"
- Line 192 `smtp_server`: Add "Use password_secret for secure credential storage"

## Phase 4: Testing Strategy

### 4.1 Unit Tests

**File:** `tests/unit/test_realm_smtp.py` (NEW)

Tests:
- ✓ SMTP config validation (required fields)
- ✓ Auth validation (user+password required when auth=true)
- ✓ Mutual exclusion (password vs password_secret)
- ✓ Secret reference structure validation
- ✓ to_keycloak_config() excludes password field
- ✓ CamelCase field conversion (from_address → from)

### 4.2 Integration Tests

**File:** `tests/integration/test_realm_smtp_integration.py` (NEW)

Setup: Use `shared_keycloak_instance` fixture

Tests:
1. Create realm with SMTP config using secret reference
2. Verify realm is created successfully (phase=Ready)
3. Verify SMTP config is applied in Keycloak (fetch realm config via API)
4. Test error handling for missing secret
5. Test error handling for secret with missing key

## Phase 5: Documentation

### 5.1 README.md Updates

Add SMTP configuration section with example:

```yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: my-realm
spec:
  realm_name: my-realm
  keycloak_instance_ref:
    name: my-keycloak
  smtp_server:
    host: smtp.gmail.com
    port: 587
    from: noreply@example.com
    from_display_name: "My Application"
    starttls: true
    auth: true
    user: noreply@example.com
    password_secret:
      name: smtp-credentials
      key: password
---
apiVersion: v1
kind: Secret
metadata:
  name: smtp-credentials
type: Opaque
stringData:
  password: "my-smtp-password"
```

### 5.2 Security Best Practices Section

Document:
- ✓ Always use `password_secret` instead of `password`
- ✓ Seal secrets with SealedSecrets or External Secrets Operator for GitOps
- ✓ Use RBAC to restrict secret access
- ✓ Rotate SMTP credentials regularly

## Implementation Order

1. **Model changes** → Run unit tests
2. **Unit tests for SMTP validation** → Verify all validation logic works
3. **Reconciler changes** → Run quality checks
4. **CRD schema updates** → Apply CRD to dev cluster
5. **Integration tests** → Verify end-to-end flow
6. **Documentation** → Update README.md
7. **Quality check** → `make quality && make test`

## Testing Checkpoints

- [ ] Unit tests pass for SMTP validation
- [ ] Unit tests pass for secret reference structure
- [ ] Integration test creates realm with SMTP config
- [ ] Integration test handles missing secret gracefully
- [ ] All existing tests still pass (149/149)
- [ ] Quality checks pass (ruff + mypy)

## Breaking Changes

**None** - This is purely additive:
- New optional field `smtp_password_secret`
- Existing `password` field still works (backward compatible)
- No existing functionality changes

## Estimated Effort

- Model changes: 30 minutes
- Reconciler changes: 30 minutes
- CRD updates: 15 minutes
- Unit tests: 45 minutes
- Integration tests: 60 minutes
- Documentation: 30 minutes
- **Total: ~3.5 hours**

## Dependencies

- None - can be implemented immediately

## Related Files

- `src/keycloak_operator/models/realm.py` - Model definitions
- `src/keycloak_operator/services/realm_reconciler.py` - Reconciliation logic
- `k8s/crds/keycloakrealm-crd.yaml` - CRD schema
- `keycloak-api-spec.yaml:12601-12604` - Keycloak API spec for smtpServer
- `tests/fixtures/realm-test.yaml:31-43` - Example SMTP config

## Notes

- The model already has basic SMTP passthrough (line 480 in realm.py)
- Keycloak expects `smtpServer` as `dict[str, string]` (from API spec)
- Existing pattern for secret fetching in `kubernetes.py:1300-1319`
- No breaking changes - fully backward compatible
