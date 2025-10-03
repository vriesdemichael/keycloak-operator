# CRD-Pydantic Schema Mismatches - Test Results

## Status Update

**Last Verified:** 2025-10-03
**Test Location:** `tests/unit/test_crd_pydantic_schema_match.py`
**User Impact:** These mismatches confirmed to cause bugs (user quote: *"wieow, that explains many errors"*)

**Current Test Status:**
- ✅ KeycloakClient: PASSED (0 mismatches - perfectly aligned!)
- ❌ Keycloak: FAILED (17 mismatches)
- ❌ KeycloakRealm: FAILED (20 mismatches)

**Total Mismatches:** 37 issues to resolve

---

## Overview

Created automated test `tests/unit/test_crd_pydantic_schema_match.py` to validate that CRD definitions match Pydantic models.

**Test Results:**
- ✅ KeycloakClient: PASSED (no mismatches)
- ❌ Keycloak: FAILED (17 mismatches)
- ❌ KeycloakRealm: FAILED (20 mismatches)

## Keycloak CRD vs KeycloakSpec Model

### Fields in CRD but MISSING from Model (3 critical issues)

1. **`admin_access`** (object)
   - CRD Description: Admin access configuration. Password is auto-generated and stored in {name}-admin-credentials secret.
   - Action: Model has `admin` field instead - field name mismatch
   - Fix: Rename model field from `admin` to `admin_access` OR update CRD to use `admin`

2. **`env`** (object)
   - CRD Description: Environment variables
   - Action: Model has `environment_variables` instead - field name mismatch
   - Fix: Rename model field from `environment_variables` to `env` OR update CRD to use `environment_variables`

3. **`config`** (object)
   - CRD Description: Additional Keycloak configuration
   - Action: Model has `keycloak_options` instead - field name mismatch
   - Fix: Rename model field from `keycloak_options` to `config` OR update CRD to use `keycloak_options`

### Fields in Model but MISSING from CRD (14 warnings)

These are likely planned features not yet exposed in CRD:

1. `persistence` (object) - Persistence configuration
2. `jvm_options` (array) - JVM options
3. `startup_probe` (object) - Startup probe configuration
4. `liveness_probe` (object) - Liveness probe configuration
5. `readiness_probe` (object) - Readiness probe configuration
6. `pod_security_context` (object) - Pod security context
7. `security_context` (object) - Container security context
8. `service_account` (string) - Service account name
9. `monitoring_enabled` (boolean) - Enable monitoring
10. `backup_enabled` (boolean) - Enable backups
11. `backup_schedule` (string) - Backup schedule

**Action:** Either add these to CRD or add them to IGNORE_FIELDS if they're intentionally model-only.

---

## KeycloakRealm CRD vs KeycloakRealmSpec Model

### Fields in CRD but MISSING from Model (8 critical issues)

1. **`description`** (string)
   - CRD Description: Realm description
   - Fix: Add `description: str | None = Field(None, description="Realm description")` to KeycloakRealmSpec

2. **`tokens`** (object)
   - CRD Description: Token and session configuration
   - Action: Model has `token_settings` instead - field name mismatch
   - Fix: Rename model field from `token_settings` to `tokens` OR update CRD to use `token_settings`

3. **`internationalization`** (object)
   - CRD Description: Internationalization settings
   - Action: Model has `localization` instead - field name mismatch
   - Fix: Rename model field from `localization` to `internationalization` OR update CRD to use `localization`

4. **`user_federation_providers`** (array)
   - CRD Description: User federation provider configurations
   - Action: Model has `user_federation` instead - field name mismatch
   - Fix: Rename model field from `user_federation` to `user_federation_providers` OR update CRD

5. **`client_scopes`** (array)
   - CRD Description: Client scope definitions
   - Fix: Add this field to KeycloakRealmSpec model

6. **`roles`** (object)
   - CRD Description: Realm and client role definitions
   - Fix: Add this field to KeycloakRealmSpec model

7. **`groups`** (array)
   - CRD Description: Group definitions
   - Fix: Add this field to KeycloakRealmSpec model

8. **`events_config`** (object)
   - CRD Description: Event logging configuration
   - Action: Model has multiple event-related fields (`events_enabled`, `events_listeners`, etc.) - structure mismatch
   - Fix: Consolidate event fields into `events_config` object in model OR update CRD structure

### Fields in Model but MISSING from CRD (12 warnings)

1. `display_name_html` (string)
2. `email_theme` (string)
3. `smtp_server` (object)
4. `events_enabled` (boolean)
5. `events_listeners` (array)
6. `admin_events_enabled` (boolean)
7. `admin_events_details_enabled` (boolean)
8. `deletion_protection` (boolean)
9. `backup_on_delete` (boolean)

**Action:** Add these to CRD or mark as model-only features.

---

## KeycloakClient CRD vs KeycloakClientSpec Model

✅ **PASSED** - No mismatches found!

The KeycloakClient CRD and KeycloakClientSpec model are perfectly aligned.

---

## Recommended Actions

### Immediate Fixes (High Priority)

These are clear field name mismatches that need to be resolved:

**Keycloak:**
1. Standardize field names:
   - `admin` vs `admin_access`
   - `env` vs `environment_variables`
   - `config` vs `keycloak_options`

**KeycloakRealm:**
1. Add missing `description` field to model
2. Standardize field names:
   - `tokens` vs `token_settings`
   - `internationalization` vs `localization`
   - `user_federation_providers` vs `user_federation`
3. Add missing fields: `client_scopes`, `roles`, `groups`
4. Consolidate event configuration structure

### Medium Priority

Add missing CRD definitions for model-only fields that should be exposed to users:
- Keycloak: `persistence`, `probes`, `security_context`, etc.
- KeycloakRealm: `email_theme`, `smtp_server`, event settings

### Low Priority

Document fields that are intentionally model-only and add them to test's IGNORE_FIELDS.

---

## Test Implementation Details

**File:** `tests/unit/test_crd_pydantic_schema_match.py`

**Features:**
- Loads CRD YAML and extracts OpenAPI schemas
- Generates schemas from Pydantic models
- Compares field presence, types, enums, and nested structures
- Provides detailed mismatch reports with fix suggestions
- Runs in ~2 seconds as part of unit test suite

**Usage:**
```bash
# Run just the schema matching tests
pytest tests/unit/test_crd_pydantic_schema_match.py -v

# Run all unit tests
make test-unit

# Run full test suite
make test
```

**Benefits:**
- Catches field mismatches immediately during development
- Prevents bugs like the `password_secret` issue we found
- Documents the expected alignment between CRDs and models
- Runs automatically in CI/CD

---

## Next Steps

1. **Decision:** Choose whether to align field names in CRD → Model or Model → CRD direction
   - Recommendation: Keep CRD stable (user-facing API) and update Models to match

2. **Fix Critical Mismatches:** Resolve the field name mismatches listed above

3. **Add Missing Fields:** Add fields that exist in CRD but not in models

4. **Update IGNORE_FIELDS:** For fields that are intentionally different, document them in the test

5. **Re-run Tests:** Verify all tests pass after fixes

6. **CI Integration:** Ensure these tests run on every commit/PR

---

## Example Fix for Field Name Mismatch

**Problem:** CRD has `admin_access`, Model has `admin`

**Option 1 - Update Model (Recommended):**
```python
# In src/keycloak_operator/models/keycloak.py
class KeycloakSpec(BaseModel):
    # BEFORE:
    # admin: KeycloakAdminConfig = Field(...)

    # AFTER:
    admin_access: KeycloakAdminConfig = Field(
        default_factory=KeycloakAdminConfig,
        description="Admin access configuration",
        alias="admin",  # Support old name for backward compatibility
    )
```

**Option 2 - Update CRD:**
```yaml
# In k8s/crds/keycloak-crd.yaml
# BEFORE:
# admin_access:
#   type: object

# AFTER:
admin:
  type: object
  description: "Admin access configuration"
```

Choose Option 1 to keep the user-facing CRD API stable.
