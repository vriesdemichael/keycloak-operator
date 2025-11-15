# Token-Based Authorization System Cleanup

## Overview
Per ADR 063 (namespace-grant-list-authorization), the dual-token authorization model was superseded on 2025-11-10. This document tracks the cleanup of remaining references to the old system.

## Decision Records Status
- ✅ ADR 026 (three-layer-responsibility-system-with-token-delegation) - Marked as superseded
- ✅ ADR 039 (token-rotation-and-bootstrap-flows) - Marked as superseded
- ✅ ADR 063 (namespace-grant-list-authorization) - Active, replaces token system

## Code Changes

### Python Models
- ✅ **src/keycloak_operator/models/common.py** - REMOVED (was empty after removing token classes)

### Examples
- ✅ **examples/01-keycloak-instance.yaml** - No changes needed (doesn't use authorizationSecretRef)
- ✅ **examples/02-realm-example.yaml** - Removed authorizationSecretRef, updated prerequisites
- ✅ **examples/03-client-example.yaml** - Removed authorizationSecretRef, updated prerequisites
- ✅ **examples/realm-with-azure-ad-idp.yaml** - Removed authorizationSecretRef
- ✅ **examples/realm-with-custom-oidc-idp.yaml** - Removed authorizationSecretRef
- ✅ **examples/realm-with-github-idp.yaml** - Removed authorizationSecretRef
- ✅ **examples/realm-with-google-idp.yaml** - Removed authorizationSecretRef

## Documentation Changes

### Core Documentation - Completed
- ✅ **docs/architecture.md** - Removed authorizationSecretRef from example
- ✅ **docs/faq.md** - Removed "single-tenant vs multi-tenant" section about tokens
- ✅ **docs/identity-providers.md** - Removed all authorizationSecretRef references (7 instances)
- ✅ **docs/operations/migration.md** - Removed authorizationSecretRef references and entire "Migrating from Manual to Automatic Token Rotation" section
- ✅ **docs/operations/migration.md** - Updated comparison table to remove token-related features

### Core Documentation - Needs Major Work
- ⚠️ **docs/operations/troubleshooting.md** - NEEDS EXTENSIVE REWRITE
  - Entire section "Token & Authorization Issues" (lines 693-881) about old token system
  - Token-related diagnostics in "Realm Issues" section
  - Token-related diagnostics in "Client Issues" section
  - "Common Pitfalls" mentions token bootstrap (line 1186, 1222)
  - Should be rewritten to focus on:
    - RBAC permission issues
    - Namespace grant list misconfiguration
    - Cross-namespace access problems

### How-To Guides - Completed
- ✅ **docs/how-to/smtp-configuration.md** - Removed authorizationSecretRef (2 instances)

### How-To Guides - Need Major Rewrites
- ⚠️ **docs/how-to/end-to-end-setup.md** - NEEDS COMPLETE REWRITE
  - Currently focused on token bootstrap flows
  - Sections to rewrite:
    - Part 5: Multi-Tenant Setup (Platform Team)
    - Part 6: Realm Creation (Application Team)
    - Part 7: Client Configuration
    - Part 9.5: Token Management Checklist
    - Troubleshooting: Token Rotation Issues
  - Should focus on:
    - Kubernetes RBAC for realm creation
    - clientAuthorizationGrants for client authorization
    - GitOps workflow examples

- ⚠️ **docs/how-to/multi-tenant.md** - NEEDS COMPLETE REWRITE OR REMOVAL
  - Entire guide is about token-based delegation
  - Architecture diagram shows token flows
  - Should be rewritten to focus on:
    - RBAC setup for teams
    - Namespace grant list management
    - Cross-namespace client provisioning
  - Or possibly merged into end-to-end-setup.md

### Reference Documentation - Needs Updates
- ⚠️ **docs/reference/keycloak-client-crd.md** - NEEDS UPDATE
  - Remove authorizationSecretRef from RealmRef spec
  - Update field reference table
  - Update all examples (6+ instances)

- ⚠️ **docs/reference/keycloak-realm-crd.md** - NEEDS UPDATE
  - Remove authorizationSecretRef from OperatorRef spec
  - Update field reference table
  - Update all examples (3+ instances)
  - Remove "auto-discovery" notes

- ⚠️ **docs/rbac-implementation.md** - NEEDS UPDATE
  - Line 200: Remove `--set realmRef.authorizationSecretRef.name=$REALM_SECRET`
  - Update to show grant list approach

## Current State

### What Users Should Use Now
```yaml
# Realm creation - controlled by Kubernetes RBAC
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakRealm
spec:
  realmName: my-realm
  operatorRef:
    namespace: keycloak-system
  # Grant namespaces permission to create clients
  clientAuthorizationGrants:
    - team-alpha
    - team-beta
```

```yaml
# Client creation - authorized via grant list
apiVersion: vriesdemichael.github.io/v1
kind: KeycloakClient
spec:
  clientId: my-client
  realmRef:
    name: my-realm
    namespace: platform
  # No authorizationSecretRef needed
```

### Old System (REMOVED)
- ❌ Admission tokens for realm creation
- ❌ Operational tokens for client creation
- ❌ Token rotation and bootstrap flows
- ❌ Secret distribution between namespaces
- ❌ AuthorizationSecretRef in specs

## Next Steps

1. **CRITICAL Priority** - Rewrite docs/operations/troubleshooting.md (remove 200+ lines of token troubleshooting)
2. **High Priority** - Update reference documentation for CRDs (keycloak-client-crd.md, keycloak-realm-crd.md)
3. **High Priority** - Rewrite or remove docs/how-to/multi-tenant.md
4. **Medium Priority** - Rewrite docs/how-to/end-to-end-setup.md to focus on grant lists
5. **Low Priority** - Update docs/rbac-implementation.md

## Testing Checklist
- [ ] Verify all examples can be applied without errors
- [ ] Verify schemas don't reference authorizationSecretRef
- [ ] Check for any remaining token_manager.py or token_rotation.py references
- [ ] Ensure no helm charts reference authorizationSecretRef

## Migration Notes
No migration path provided - this was a breaking change with no active users yet (per user feedback).
