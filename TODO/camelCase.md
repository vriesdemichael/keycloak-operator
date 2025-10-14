User approved Claude's plan:
  ⎿  Complete camelCase Conversion Plan

     What I Found During Test Failures

     Critical Bug Fixed

     Location: src/keycloak_operator/services/client_reconciler.py:247
     - Issue: Looking for authorization_secret_name (snake_case) but realm status uses authorizationSecretName (camelCase)
     - Impact: ALL client reconciliations failed with "does not have an authorization secret yet"
     - Status: ✅ FIXED

     Additional Issues Found

     1. Keycloak status mismatch - CRD defines admin_secret (snake_case) but reconciler writes adminSecret (camelCase)
     2. Inconsistent naming across CRDs - Realm uses camelCase, Client/Keycloak use snake_case

     Current State Analysis

     ✅ KeycloakRealm CRD - ALREADY CORRECT

     - Spec: camelCase (realmName, operatorRef, smtpServer, etc.)
     - Status: camelCase (authorizationSecretName, keycloakInstance, etc.)
     - Reconciler: Writes camelCase
     - Action: None needed

     ❌ KeycloakClient CRD - NEEDS FULL CONVERSION

     Spec fields (57 fields):
     - client_id → clientId
     - client_name → clientName
     - public_client → publicClient
     - bearer_only → bearerOnly
     - redirect_uris → redirectUris
     - web_origins → webOrigins
     - post_logout_redirect_uris → postLogoutRedirectUris
     - always_display_in_console → alwaysDisplayInConsole
     - client_authenticator_type → clientAuthenticatorType
     - standard_flow_enabled → standardFlowEnabled
     - implicit_flow_enabled → implicitFlowEnabled
     - direct_access_grants_enabled → directAccessGrantsEnabled
     - service_accounts_enabled → serviceAccountsEnabled
     - consent_required → consentRequired
     - display_on_consent_screen → displayOnConsentScreen
     - include_in_token_scope → includeInTokenScope
     - access_token_lifespan → accessTokenLifespan
     - refresh_token_lifespan → refreshTokenLifespan
     - authentication_flows → authenticationFlows
     - browser_flow → browserFlow
     - direct_grant_flow → directGrantFlow
     - client_authentication_flow → clientAuthenticationFlow
     - default_client_scopes → defaultClientScopes
     - optional_client_scopes → optionalClientScopes
     - protocol_mappers → protocolMappers
     - protocol_mapper → protocolMapper
     - client_roles → clientRoles
     - service_account_roles → serviceAccountRoles
     - realm_roles → realmRoles
     - regenerate_secret → regenerateSecret
     - secret_name → secretName
     - manage_secret → manageSecret

     Status fields (14 fields):
     - observed_generation → observedGeneration
     - client_id → clientId
     - internal_id → internalId
     - public_client → publicClient
     - keycloak_instance → keycloakInstance
     - credentials_secret → credentialsSecret
     - end_session → endSession
     - last_health_check → lastHealthCheck
     - last_updated → lastUpdated
     - created_roles → createdRoles
     - applied_mappers → appliedMappers
     - last_transition_time → lastTransitionTime (in conditions)

     ❌ Keycloak CRD - NEEDS FULL CONVERSION

     Spec fields (23 fields):
     - password_secret → passwordSecret
     - credentials_secret → credentialsSecret
     - connection_params → connectionParams
     - connection_pool → connectionPool
     - max_connections → maxConnections
     - min_connections → minConnections
     - connection_timeout → connectionTimeout
     - ssl_mode → sslMode
     - migration_strategy → migrationStrategy
     - secret_name → secretName
     - tls_enabled → tlsEnabled
     - tls_secret_name → tlsSecretName
     - class_name → className
     - http_port → httpPort
     - https_port → httpsPort
     - jvm_options → jvmOptions
     - service_account → serviceAccount
     - startup_probe → startupProbe
     - liveness_probe → livenessProbe
     - readiness_probe → readinessProbe
     - pod_security_context → podSecurityContext
     - security_context → securityContext

     Status fields (11 fields):
     - observed_generation → observedGeneration
     - last_transition_time → lastTransitionTime (in conditions)
     - admin_username → adminUsername
     - admin_secret → adminSecret (CRD has both! Need to remove snake_case)
     - internal_url → internalUrl
     - external_url → externalUrl
     - ready_replicas → readyReplicas
     - last_health_check → lastHealthCheck
     - database_status → databaseStatus

     Implementation Plan

     Phase 1: Update CRD Definitions (3 files)

     1. k8s/crds/keycloakclient-crd.yaml - Convert all 71 snake_case fields to camelCase
     2. k8s/crds/keycloak-crd.yaml - Convert all 34 snake_case fields to camelCase
     3. Update additionalPrinterColumns jsonPath references

     Phase 2: Add Pydantic Field Aliases (3 files)

     Update Python models to support both snake_case (internal) and camelCase (serialization):
     1. src/keycloak_operator/models/client.py - Add Field(alias="camelCase") for all fields
     2. src/keycloak_operator/models/keycloak.py - Add field aliases for all models
     3. Configure Config.populate_by_name = True and Config.by_alias = True for serialization

     Phase 3: Update Status Writes (3 files)

     Change reconcilers to write status in camelCase:
     1. src/keycloak_operator/services/client_reconciler.py - Change 5 snake_case status writes
     2. src/keycloak_operator/services/keycloak_reconciler.py - Already uses camelCase, verify consistency
     3. src/keycloak_operator/services/base_reconciler.py - Change last_reconcile_time → lastReconcileTime

     Phase 4: Update Status Reads (Search & Fix)

     Search for all .get("status") and dict access patterns:
     - Already fixed: client_reconciler.py:247 (authorization_secret_name → authorizationSecretName)
     - Check for any other snake_case status field reads in utils/

     Phase 5: Testing

     1. Run make quality - Fix any type errors
     2. Run make test-unit - Fix unit test assertions
     3. Update test fixtures in tests/fixtures/ to use camelCase
     4. Run make deploy-local - Deploy with new CRDs
     5. Run make test-integration - Verify end-to-end functionality

     Risk Mitigation

     Breaking Change Strategy

     This is a BREAKING CHANGE. Existing resources will need migration:
     1. CRD Update: kubectl apply will update schema
     2. Existing Resources: Will fail validation until recreated
     3. Migration Path: Users must delete and recreate all Custom Resources

     Rollback Plan

     If tests fail after conversion:
     1. Git revert CRD changes
     2. kubectl apply old CRDs
     3. Investigate specific failures
     4. Fix incrementally

     Estimated Changes

     - CRD YAML files: ~150 field renames
     - Python models: ~100 field aliases
     - Reconcilers: ~10 status assignments
     - Test fixtures: ~20 field updates
     - Total: ~280 lines changed across 15 files