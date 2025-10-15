# Authorization Secret Mechanism - Implementation Plan

## Current Status Analysis

### ✅ What's Already Implemented

1. **Token Generation & Storage**
   - `operator.py`: Generates operator token on startup and stores in `keycloak-operator-auth-token` secret
   - `realm_reconciler.py`: `ensure_realm_authorization_secret()` generates realm tokens
   - `utils/auth.py`: Complete `generate_token()` and `validate_authorization()` functions

2. **Pydantic Models**
   - `models/common.py`: `AuthorizationSecretRef` model (name, key)
   - `models/realm.py`: `OperatorRef.authorization_secret_ref` field
   - `models/client.py`: `RealmRef.authorization_secret_ref` field

3. **CRD Definitions**
   - `keycloakrealm-crd.yaml`: `operatorRef.authorizationSecretRef` schema
   - `keycloakclient-crd.yaml`: `realmRef.authorizationSecretRef` schema

4. **Validation Logic**
   - `realm_reconciler.py`: Validates operator token before realm reconciliation
   - `client_reconciler.py`: Validates realm token before client reconciliation
   - Proper error handling with TemporaryError for missing secrets

5. **Test Coverage**
   - `test_authorization_delegation.py`: End-to-end authorization flow tests
   - `test_auth.py`: Unit tests for validation functions
   - Integration test fixtures in `conftest.py`

### ⚠️ What's Partially Implemented

1. **Helm Chart Values** 
   - Both `keycloak-realm/values.yaml` and `keycloak-client/values.yaml` have authorization fields
   - **BUT**: Comments say "This feature is not yet implemented - leave empty"
   - Fields have empty default values (`name: ""`)

2. **Chart Templates**
   - Need to verify that templates correctly render authorizationSecretRef when provided
   - Need to ensure conditional rendering (skip if empty)

3. **Status Reporting**
   - Realm status reports `authorizationSecretName` ✅
   - But need to verify status is exposed in CRD status schema

### ❌ What Needs to Be Implemented

1. **Make Authorization REQUIRED**
   - Currently marked as optional ("optional for now")
   - Need to enforce that `authorizationSecretRef` is required in spec
   - Update validation to reject resources without authorization

2. **Helm Chart Updates**
   - Remove "not yet implemented" comments
   - Make authorization fields required in values.yaml
   - Add validation in templates
   - Update examples to show proper usage

3. **JSON Schema Generation**
   - Create JSON schemas from CRDs for chart values validation
   - Add schema validation to helm templates

4. **Documentation**
   - Update chart READMEs with authorization requirements
   - Add examples showing secret creation and reference
   - Document the authorization flow

5. **Integration Tests**
   - Update test fixtures to ALWAYS use authorization
   - Add negative tests for missing/invalid authorization
   - Test authorization with helm chart deployments

## Implementation Steps

### Step 1: Update Pydantic Models (Make Authorization Required)

**Files to modify:**
- `src/keycloak_operator/models/realm.py`
  - Change `authorization_secret_ref: AuthorizationSecretRef | None` to `authorization_secret_ref: AuthorizationSecretRef`
  - Remove default `None` value
  - Update docstring to remove "optional for now"

- `src/keycloak_operator/models/client.py`
  - Same changes for `RealmRef.authorization_secret_ref`

### Step 2: Update CRD Definitions

**Files to modify:**
- `k8s/crds/keycloakrealm-crd.yaml`
  - Add `required: [authorizationSecretRef]` to operatorRef
  - Update description to indicate it's mandatory

- `k8s/crds/keycloakclient-crd.yaml`
  - Add `required: [authorizationSecretRef]` to realmRef
  - Update description to indicate it's mandatory

### Step 3: Generate JSON Schemas for Helm Charts

**New files to create:**
- `charts/keycloak-realm/values.schema.json`
- `charts/keycloak-client/values.schema.json`

**Tool to use:**
- Install and use `openapi2jsonschema` or write custom script to extract from CRD

### Step 4: Update Helm Chart Values

**Files to modify:**
- `charts/keycloak-realm/values.yaml`
  - Remove "This feature is not yet implemented" comment
  - Update description to indicate requirement
  - Keep default empty but note it must be provided

- `charts/keycloak-client/values.yaml`
  - Same changes

### Step 5: Update Helm Chart Templates

**Files to verify/modify:**
- `charts/keycloak-realm/templates/keycloakrealm.yaml`
  - Ensure authorizationSecretRef is rendered correctly
  - Add validation: fail if not provided or empty

- `charts/keycloak-client/templates/keycloakclient.yaml`
  - Same validation

### Step 6: Update Chart README & Examples

**Files to modify:**
- `charts/keycloak-realm/README.md`
  - Document authorization requirement
  - Add example showing secret creation
  - Show how to reference operator secret

- `charts/keycloak-client/README.md`
  - Document realm authorization requirement
  - Add example showing realm secret reference

- `charts/examples/`
  - Update all example values files with proper authorization

### Step 7: Update Integration Tests

**Files to modify:**
- `tests/integration/conftest.py`
  - Ensure all fixtures include authorization by default
  - Update `sample_realm_spec()` and `sample_client_spec()`

- `tests/integration/test_helm_charts.py`
  - NEW FILE: Add tests for helm chart deployments with authorization
  - Test that charts fail without authorization
  - Test that charts succeed with valid authorization

### Step 8: Update Documentation

**Files to modify:**
- `docs/authorization.md` (create if doesn't exist)
  - Explain the authorization architecture
  - Document the token delegation flow
  - Provide examples

- `CLAUDE.md`
  - Update to reflect authorization as required feature

## Validation Checklist

After implementation, verify:

- [ ] Realm creation fails without operator authorization secret ref
- [ ] Client creation fails without realm authorization secret ref
- [ ] Helm charts fail validation without authorization fields
- [ ] All integration tests pass with authorization required
- [ ] Documentation clearly explains authorization requirements
- [ ] Examples include proper authorization setup
- [ ] JSON schemas validate chart values correctly

## Migration Considerations

Since this makes a breaking change (making optional field required):

1. **Version Bump**: This should be a minor version bump (e.g., 0.x.0)
2. **Migration Guide**: Document how existing deployments need to update
3. **Backward Compatibility**: Consider adding a deprecation period with warnings

## Timeline Estimate

- Step 1-2: Pydantic models & CRDs - 30 minutes
- Step 3: JSON schema generation - 1 hour  
- Step 4-5: Helm chart updates - 1 hour
- Step 6: Documentation - 1 hour
- Step 7: Integration tests - 1-2 hours
- Step 8: Final documentation - 30 minutes

**Total: ~5-6 hours**

## Risk Assessment

**Low Risk:**
- Model and CRD changes are straightforward
- Validation logic already exists
- Tests already cover the flow

**Medium Risk:**
- Helm chart template validation might need debugging
- JSON schema generation might require custom tooling
- Integration tests might need cluster resets to clear cached CRDs

**High Risk:**
- Breaking change for existing users (mitigated by early stage of project)
