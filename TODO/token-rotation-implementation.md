# Token Rotation System Implementation

**Feature**: Bootstrap-based automatic token rotation system
**Branch**: `feat/token-rotation-system`
**Started**: 2025-10-20
**Status**: 🔄 In Progress

## Overview

Implement a two-phase token system:
1. **Admission Token**: Platform-provided, used for initial bootstrap (one-time per team)
2. **Operational Token**: Operator-generated, auto-rotates every 90 days with 7-day grace period

### Goals
- ✅ Zero maintenance for app teams
- ✅ Minimal platform team burden (one secret share per team)
- ✅ Automatic rotation without service disruption
- ✅ Per-team revocation capability
- ✅ No new CRDs or admission webhooks

---

## Implementation Checklist

### Phase 1: Core Infrastructure (Token Management)

#### 1.1 Token Metadata Storage
- [x] Create `TokenMetadata` Pydantic model in `src/keycloak_operator/models/common.py`
  - Fields: namespace, token_hash, issued_at, valid_until, version, token_type, created_by_realm
- [x] Add token metadata storage utilities in `src/keycloak_operator/utils/token_manager.py`
  - `store_token_metadata()` - Store in ConfigMap for persistence
  - `get_token_metadata()` - Retrieve metadata by hash
  - `list_tokens_for_namespace()` - List all tokens for a namespace
  - `validate_token()` - Validate token against stored metadata
  - `invalidate_token()` - Mark token as revoked

#### 1.2 Token Generation and Validation
- [x] Add `generate_operational_token()` in `src/keycloak_operator/utils/token_manager.py`
  - Generate cryptographically secure token (32 bytes, url-safe)
  - Store metadata with 90-day validity
  - Return token and metadata
- [x] Add `validate_admission_token()` in `src/keycloak_operator/utils/token_manager.py`
  - Validate against master admission token list
  - Support token hash comparison
- [x] Add `rotate_operational_token()` in `src/keycloak_operator/utils/token_manager.py`
  - Generate new token
  - Preserve current token as `token-previous`
  - Update metadata with grace period

#### 1.3 Secret Management
- [x] Create `SecretManager` class in `src/keycloak_operator/utils/secret_manager.py`
  - `get_secret()` - Retrieve secret with caching
  - `create_operational_secret()` - Create operational token secret
  - `update_secret_with_rotation()` - Update secret with dual tokens
  - `cleanup_previous_token()` - Remove token-previous after grace period
  - `get_token_from_secret()` - Extract token from secret (try current, fallback to previous)

---

### Phase 2: Authorization Logic Update

#### 2.1 Authorization Handler Refactor
- [x] Update `src/keycloak_operator/utils/auth.py` with new authorization flow
  - [x] Add `AuthorizationContext` dataclass
    - namespace, secret_ref, resource_name, resource_uid
  - [x] Replace `validate_authorization_token()` with `validate_and_bootstrap_authorization()`
    - Detect token type (admission vs operational)
    - Bootstrap operational token on first use
    - Return valid token for operation
  - [x] Add `bootstrap_operational_token()`
    - Create operational token secret in namespace
    - Store metadata
    - Update resource status with new secret reference
  - [x] Add `get_authorization_token()` - Main entry point
    - Check for operational token first
    - Fallback to admission token if operational missing
    - Bootstrap if needed

#### 2.2 Reconciler Integration
- [x] Update `KeycloakRealmReconciler` in `src/keycloak_operator/services/realm_reconciler.py`
  - [x] Use new authorization flow in `reconcile()`
  - [x] Update status with `authorizationStatus` field
  - [x] Handle authorization failures gracefully (Degraded state)
- [ ] Update `KeycloakClientReconciler` in `src/keycloak_operator/services/client_reconciler.py`
  - [ ] Use new authorization flow for realm tokens
  - [ ] Update status with `authorizationStatus` field

#### 2.3 Status Field Updates
- [x] Update `KeycloakRealmStatus` in `src/keycloak_operator/models/realm.py`
  - Add `authorizationStatus` field:
    - secretRef: {name: str}
    - tokenVersion: str
    - validUntil: datetime
    - requiresUpdate: bool
    - tokenType: str (admission/operational)
- [x] Update `KeycloakClientStatus` in `src/keycloak_operator/models/client.py`
  - Add similar `authorizationStatus` field
- [ ] Update CRD definitions in `k8s/crds/`
  - Add authorizationStatus to status schema

---

### Phase 3: Automatic Rotation Handlers

#### 3.1 Operational Token Rotation
- [ ] Add timer handler in `src/keycloak_operator/handlers/token_rotation.py`
  - [ ] `@kopf.timer` for operational secrets (daily check)
  - [ ] Check `valid-until` annotation, rotate if < 7 days remaining
  - [ ] Generate new token, update secret with dual tokens
  - [ ] Update metadata with grace period
  - [ ] Log rotation event
  - [ ] Emit Kubernetes event

#### 3.2 Grace Period Cleanup
- [ ] Add timer handler in `src/keycloak_operator/handlers/token_rotation.py`
  - [ ] `@kopf.timer` for operational secrets (hourly check)
  - [ ] Check `grace-period-ends` annotation
  - [ ] Remove `token-previous` after grace period expires
  - [ ] Update metadata
  - [ ] Log cleanup event

#### 3.3 Orphaned Token Detection
- [ ] Add daemon handler in `src/keycloak_operator/handlers/token_rotation.py`
  - [ ] Detect operational tokens with no owning realms
  - [ ] Mark for cleanup after 7 days
  - [ ] Optional: Emit warning event

---

### Phase 4: Observability

#### 4.1 Metrics
- [ ] Add metrics in `src/keycloak_operator/observability/metrics.py`
  - `keycloak_operator_token_rotations_total` - Counter by namespace
  - `keycloak_operator_token_expires_timestamp` - Gauge by namespace
  - `keycloak_operator_token_bootstrap_total` - Counter by namespace
  - `keycloak_operator_authorization_failures_total` - Counter by reason
  - `keycloak_operator_operational_tokens_active` - Gauge

#### 4.2 Logging
- [ ] Add structured logging for token lifecycle events
  - Bootstrap events (admission → operational)
  - Rotation events (version increments)
  - Validation failures (expired, invalid, missing)
  - Grace period transitions

#### 4.3 Kubernetes Events
- [ ] Emit events for user-visible token lifecycle
  - "OperationalTokenBootstrapped" - Normal
  - "OperationalTokenRotated" - Normal
  - "TokenExpiringSoon" - Warning (< 7 days)
  - "TokenExpired" - Warning
  - "AuthorizationFailed" - Warning

---

### Phase 5: Documentation

#### 5.1 User Documentation
- [ ] Update `docs/security.md`
  - [ ] Add "Token Rotation" section
  - [ ] Document two-phase model (admission → operational)
  - [ ] Document automatic rotation (90-day cycle, 7-day grace)
  - [ ] Document revocation procedures
  - [ ] Add troubleshooting section
- [ ] Update `docs/quickstart/README.md`
  - [ ] Update realm creation examples with token references
  - [ ] Show how to check token status
- [ ] Create `docs/operations/token-management.md`
  - [ ] Platform team procedures (admission token distribution)
  - [ ] Token lifecycle monitoring
  - [ ] Revocation procedures (soft vs hard)
  - [ ] Emergency procedures (force rotation)

#### 5.2 Developer Documentation
- [ ] Update `CLAUDE.md`
  - [ ] Document token rotation architecture
  - [ ] Update development workflow (testing with tokens)
  - [ ] Add token manager utilities to "Project Structure"
- [ ] Add docstrings to all new modules
  - TokenManager methods
  - SecretManager methods
  - Authorization utilities
  - Rotation handlers

#### 5.3 Examples
- [ ] Update `examples/02-realm-example.yaml`
  - Show admission token reference
  - Add comments explaining bootstrap
- [ ] Add `examples/05-token-management/`
  - `admission-token-secret.yaml` - Template for platform teams
  - `check-token-status.sh` - Script to check token health
  - `revoke-team-access.sh` - Script for revocation

---

### Phase 6: Testing

#### 6.1 Unit Tests
- [ ] `tests/unit/test_token_manager.py`
  - [ ] Test token generation (entropy, format)
  - [ ] Test metadata storage and retrieval
  - [ ] Test token validation (valid, expired, invalid)
  - [ ] Test rotation logic (dual token, grace period)
- [ ] `tests/unit/test_secret_manager.py`
  - [ ] Test secret creation with labels/annotations
  - [ ] Test dual token updates
  - [ ] Test token extraction (current, fallback to previous)
  - [ ] Test grace period cleanup
- [ ] `tests/unit/test_authorization_flow.py`
  - [ ] Test admission token validation
  - [ ] Test operational token validation
  - [ ] Test bootstrap logic (admission → operational)
  - [ ] Test fallback behavior (missing tokens)
- [ ] Update existing unit tests
  - [ ] Mock new authorization flow in realm tests
  - [ ] Mock new authorization flow in client tests

#### 6.2 Integration Tests
- [ ] `tests/integration/test_token_bootstrap.py`
  - [ ] Test first realm creation bootstraps operational token
  - [ ] Test subsequent realms use operational token
  - [ ] Test admission token can still be used after bootstrap
  - [ ] Test multiple teams in separate namespaces
- [ ] `tests/integration/test_token_rotation.py`
  - [ ] Test automatic rotation triggers before expiry
  - [ ] Test grace period (both tokens valid)
  - [ ] Test grace period cleanup
  - [ ] Test realm operations during grace period
- [ ] `tests/integration/test_token_revocation.py`
  - [ ] Test operational token deletion
  - [ ] Test realm enters Degraded state
  - [ ] Test re-bootstrap with admission token
  - [ ] Test per-team isolation (revoke one team, others unaffected)
- [ ] Update `tests/integration/conftest.py`
  - [ ] Add `admission_token` fixture
  - [ ] Add `operational_token` fixture
  - [ ] Update `shared_keycloak_instance` to handle new auth flow
- [ ] Update existing integration tests
  - [ ] All realm tests use new authorization flow
  - [ ] All client tests use new authorization flow
  - [ ] Update authorization expectations in assertions

#### 6.3 End-to-End Testing
- [ ] Manual test scenario: Platform team workflow
  - Create admission token for new team
  - Team creates first realm
  - Verify operational token created
  - Verify subsequent realms work
- [ ] Manual test scenario: Rotation
  - Force token expiry (mock time)
  - Verify rotation happens automatically
  - Verify grace period works
  - Verify cleanup after grace period
- [ ] Manual test scenario: Revocation
  - Delete operational token
  - Verify realm operations fail gracefully
  - Re-bootstrap with admission token
  - Verify recovery

---

### Phase 7: Migration & Compatibility

#### 7.1 Backward Compatibility
- [ ] Support existing deployments with old token model
  - [ ] Detect legacy tokens (no token-type label)
  - [ ] Auto-migrate on first reconciliation
  - [ ] Log migration event
- [ ] Add migration guide in `docs/migration/token-rotation-upgrade.md`
  - Steps for existing users
  - Expected behavior changes
  - Rollback procedure

#### 7.2 Helm Chart Updates
- [ ] Update `charts/keycloak-operator/values.yaml`
  - Add token rotation configuration options
  - Add grace period configuration
  - Add rotation interval configuration
- [ ] Update `charts/keycloak-realm/README.md`
  - Document new authorization flow
  - Update examples with admission tokens

---

## Testing Strategy

### Unit Test Coverage Target: 85%+
- Token manager: 90%+
- Secret manager: 90%+
- Authorization flow: 90%+

### Integration Test Coverage
- Bootstrap scenarios: 100%
- Rotation scenarios: 100%
- Revocation scenarios: 100%
- Multi-tenant isolation: 100%

---

## Success Criteria

- [ ] Platform team can distribute one admission token per team
- [ ] First realm creation automatically bootstraps operational token
- [ ] Operational tokens auto-rotate 7 days before expiry
- [ ] Grace period allows seamless rotation (zero downtime)
- [ ] Token revocation results in Degraded state (no data loss)
- [ ] All tests pass (unit + integration)
- [ ] Documentation complete and accurate
- [ ] No breaking changes to existing deployments

---

## Rollout Plan

1. **Development**: Implement in feature branch
2. **Testing**: Full test suite (unit + integration)
3. **Documentation**: Complete user and developer docs
4. **Review**: Code review + security review
5. **Merge**: PR to main branch
6. **Release**: Minor version bump (0.3.0)

---

## Progress Tracking

### Completed Tasks: 20/92

**Phase 1**: ✅ 9/9  
**Phase 2**: 🔄 11/11 (CRD updates deferred to Phase 7)  
**Phase 3**: ⬜ 0/8  
**Phase 4**: ⬜ 0/9  
**Phase 5**: ⬜ 0/13  
**Phase 6**: ⬜ 0/28  
**Phase 7**: ⬜ 1/7 (includes CRD updates)  

---

## Notes

- Token validity: 90 days
- Grace period: 7 days
- Rotation check: Daily
- Grace cleanup: Hourly
- Token format: `secrets.token_urlsafe(32)` (256 bits entropy)
- Token storage: SHA-256 hash in ConfigMap
- Metadata storage: ConfigMap `keycloak-operator-token-metadata` in operator namespace

---

## Dependencies

- No new external dependencies required
- Uses existing: kubernetes, kopf, pydantic, hashlib, secrets

---

## Security Considerations

- [x] Tokens are cryptographically random (256-bit entropy)
- [x] Tokens stored as SHA-256 hashes (not plaintext)
- [x] Grace period prevents service disruption during rotation
- [x] Per-namespace isolation (operational tokens)
- [x] Revocation does not delete data (Degraded state)
- [x] Audit trail via Kubernetes events and structured logs

---

## Future Enhancements (Out of Scope)

- External Secrets Operator integration
- Vault integration for admission tokens
- Token expiry customization per namespace
- Multi-cluster token federation
- Token usage analytics and reporting

---

**Last Updated**: 2025-10-20T21:17:39Z
**Next Review**: After Phase 1 completion
