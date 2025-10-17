# RBAC Implementation - Code Integration TODO

## Summary of Changes Made

### ✅ Completed

1. **Helm Charts - RBAC Structure**
   - Split `keycloak-operator` ClusterRole into:
     - `keycloak-operator-core`: Minimal cluster-wide permissions
     - `keycloak-operator-manager`: Full permissions in operator namespace (Role, not ClusterRole)
     - `keycloak-operator-namespace-access`: Template ClusterRole for team opt-in
   - Added RoleBinding templates to `keycloak-realm` and `keycloak-client` charts
   - Updated values.yaml with RBAC configuration options
   - Updated NOTES.txt with RBAC instructions

2. **Python - RBAC Utilities**
   - Created `src/keycloak_operator/utils/rbac.py` with:
     - `check_namespace_access()`: SubjectAccessReview for namespace permission checking
     - `validate_secret_label()`: Validates secrets have required label
     - `get_secret_with_validation()`: Complete validation workflow for secret reading
   - Added `ALLOW_OPERATOR_READ_LABEL` constant to `constants.py`
   - Added error message templates for RBAC failures

3. **Documentation**
   - Created comprehensive `docs/rbac-implementation.md`
   - Created `scripts/test-rbac-integration.sh` for testing

4. **Quality Checks**
   - All code passes ruff formatting
   - All code passes ruff linting
   - All code passes ty type checking

### 🚧 Still TODO - Handler Integration

The RBAC validation functions have been created but NOT yet integrated into the actual reconciliation handlers. The following handlers need to be updated:

#### 1. Realm Handler (`src/keycloak_operator/handlers/realm.py`)

**Current behavior**: Directly reads secrets without validation

**Needs**:
- Import RBAC functions from `keycloak_operator.utils.rbac`
- Get operator namespace from environment or config
- Before reading any secret:
  1. Check namespace access with `check_namespace_access()`
  2. Validate secret label with `validate_secret_label()`
  3. Or use `get_secret_with_validation()` for complete workflow
- Update status with appropriate error messages if validation fails

**Secrets to validate**:
- SMTP password secret (`spec.smtpServer.passwordSecret`)
- Any other secrets referenced in the realm spec

**Example integration point**:
```python
from keycloak_operator.utils.rbac import get_secret_with_validation

# In ensure_keycloak_realm handler:
if spec.get("smtpServer", {}).get("passwordSecret"):
    secret_ref = spec["smtpServer"]["passwordSecret"]
    password, error = await get_secret_with_validation(
        api=api,
        secret_name=secret_ref["name"],
        namespace=namespace,
        operator_namespace=os.getenv("OPERATOR_NAMESPACE", "keycloak-system"),
        key=secret_ref.get("key", "password")
    )
    
    if error:
        # Update status with error
        status_wrapper.phase = PHASE_FAILED
        status_wrapper.message = error
        return
```

#### 2. Client Handler (`src/keycloak_operator/handlers/client.py`)

**Current behavior**: Directly reads secrets without validation

**Needs**:
- Same as realm handler
- Validate realm authorization secret

**Secrets to validate**:
- Realm authorization secret (`spec.realmRef.authorizationSecretRef`)
- Any other secrets referenced in the client spec

#### 3. Keycloak Handler (`src/keycloak_operator/handlers/keycloak.py`)

**Current behavior**: Reads admin and database password secrets

**Needs**:
- Validate admin password secret
- Validate database password secret
- **Note**: Since Keycloak instances run in the operator namespace, these secrets should also be in the operator namespace, so namespace validation can be skipped OR should pass since operator has full Role permissions there

**Secrets to validate**:
- Admin password secret (`spec.admin.passwordSecret`)
- Database password secret (`spec.database.passwordSecret`)

### Implementation Strategy

1. **Start with Realm Handler** - It's the most critical path for cross-namespace RBAC
2. **Then Client Handler** - Similar pattern to realm
3. **Finally Keycloak Handler** - Less critical since it's in operator namespace

### Testing After Integration

1. **Unit Tests**: Add tests for RBAC validation in handlers
2. **Integration Test**: Run `scripts/test-rbac-integration.sh`
3. **Manual Testing**: Follow the recipe you provided:
   - Deploy operator in test namespace
   - Deploy realm in different namespace
   - Deploy client in yet another namespace
   - Verify all reconcile successfully

### Environment Configuration

The handlers need to know the operator's namespace. Options:

1. **Environment Variable**: Set `OPERATOR_NAMESPACE` in deployment
2. **Downward API**: Inject namespace via Kubernetes downward API
3. **Config**: Pass via kopf settings

**Recommended**: Add to operator deployment:
```yaml
env:
- name: OPERATOR_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
```

This needs to be added to `charts/keycloak-operator/templates/03_operator_deployment.yaml`.

### Error Handling

When validation fails, handlers should:
1. Update status.phase = "Failed"
2. Update status.message with helpful error from validation functions
3. Log the error with appropriate context
4. **Not retry immediately** - wait for user to fix (label secret, create RoleBinding)

### Metrics

Consider adding metrics for:
- RBAC validation failures
- Namespace access denials
- Secret label violations

This helps operators understand permission issues.

## Summary

**Chart changes**: ✅ Complete and tested
**Python utilities**: ✅ Complete and tested
**Handler integration**: ❌ Not yet done - critical for functionality
**Documentation**: ✅ Complete
**Testing script**: ✅ Complete

The RBAC framework is in place, but the actual enforcement in the reconciliation logic still needs to be implemented.
