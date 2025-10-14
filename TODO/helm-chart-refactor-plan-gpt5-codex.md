
# Prefer the gemini 2.5 pro plan instead
# Helm Charts & Permission Refactor – Implementation Plan (GPT-5 Codex)

## Overview
- **Owner:** Platform Engineering
- **Priority:** P0 (blocks production adoption)
- **Scope:** Implement RBAC hardening, authorization tokens, and Helm chart restructure for the Keycloak operator.
- **Baseline Branch:** `main`
- **Target Timeline:** ~4.5 engineer-days (see per-phase estimates).

This plan decomposes the eight mandated phases from `helm-charts-refactor-context.md` into execution-ready steps. Each phase lists prerequisites, step-by-step actions, code references, testing checkpoints, rollback guidance, estimates, and dependencies so that a new team member can follow it without guesswork.

## Global Dependencies & Sequencing
- **Python tooling:** `uv`, `make`, `ruff`, `pyright` as described in `CLAUDE.md`.
- **Cluster tooling (for integration testing):** `docker`, `kind`, `kubectl`, `helm`, `jq`, `yq`.
- **Baseline state:** No uncommitted changes; CRDs and RBAC reflect current `main`.
- **Secrets:** Operator authorization token stored only after Phase 2 implementation.

| Phase | Depends On | Primary Outputs | Est. Duration |
| --- | --- | --- | --- |
| 1. CRD Schema Updates | None | Updated CRDs, models, validation | 6 hrs |
| 2. Authorization Infrastructure | Phase 1 | Token generation/validation utilities | 5 hrs |
| 3. Handler Updates | Phases 1-2 | Updated reconciliation logic | 8 hrs |
| 4. RBAC Refactor | Phase 3 | Hardened ClusterRole/Role bindings | 4 hrs |
| 5. Helm Charts Creation | Phases 1-4 | Three Helm charts & templates | 8 hrs |
| 6. Release Process Updates | Phase 5 | Multi-component release automation | 3 hrs |
| 7. Migration Guide & Examples | Phases 1-6 | Docs + examples | 4 hrs |
| 8. Testing | Phases 1-7 | Updated unit/integration suite | 5 hrs |

> **Note:** Allocate 0.5 day buffer for cross-phase integration fixes.

## Phase 1 – CRD Schema Updates
**Objective:** Replace `keycloak_instance_ref` with `operatorRef` / `realmRef` to restrict ownership and enable namespace scoping.

### Prerequisites
- Confirm understanding of new schema shapes in context doc.
- Open `k8s/crds/*.yaml` and Pydantic schema files under `src/keycloak_operator/models/`.

### Detailed Steps
1. Update `k8s/crds/keycloakrealm-crd.yaml`:
   - Remove `spec.properties.keycloak_instance_ref`.
   - Introduce required `operatorRef` object with `namespace` and `authorizationSecretRef` (default `key: token`).
2. Update `k8s/crds/keycloakclient-crd.yaml`:
   - Replace `keycloak_instance_ref` and `realm` with required `realmRef` object (same secret structure).
3. Regenerate or manually adjust Python data models:
   - Add new Pydantic models (e.g., `OperatorRef`, `AuthorizationSecretRef`, `RealmRef`) in `src/keycloak_operator/models/crds.py` (create file if needed) and update existing CRD schemas to consume them.
   - Ensure JSON schema validation matches CRD definitions.
4. Update validation logic (likely `src/keycloak_operator/utils/validation.py`) to enforce presence of new fields and to disallow deprecated fields.
5. Remove obsolete references to `keycloak_instance_ref` across codebase with targeted search.
6. Update default examples in `examples/*` to reflect new spec stubs (will be refined in Phase 7).

### Key Code Snippet
```yaml
# k8s/crds/keycloakrealm-crd.yaml (spec excerpt)
spec:
  versions:
    - name: v1
      schema:
        openAPIV3Schema:
          properties:
            spec:
              properties:
                operatorRef:
                  type: object
                  required: [namespace, authorizationSecretRef]
                  properties:
                    namespace:
                      type: string
                    authorizationSecretRef:
                      type: object
                      required: [name]
                      properties:
                        name:
                          type: string
                        key:
                          type: string
                          default: token
```

### Testing Checkpoints
- `make quality` (ensures formatting + linting for YAML via `pre-commit` hooks if configured).
- `make test-unit` focusing on schema validation tests (`tests/unit/test_crd_validation.py`).
- Verify generated OpenAPI schema with `kubectl explain keycloakrealm.spec.operatorRef` on local Kind cluster (optional but recommended).

### Rollback Strategy
- Reset CRD files via `git checkout -- k8s/crds/*.yaml` and revert model updates.
- Drop regenerated files if they introduce build errors and re-run `make quality` to confirm clean state.

### Time Estimate
- ~6 hours (2h CRD edits, 3h model alignment, 1h validation/test fixes).

## Phase 2 – Authorization Infrastructure
**Objective:** Introduce secure token generation, storage, and validation shared by operator, realms, and clients.

### Prerequisites
- Phase 1 schema merged.
- Familiarity with `src/keycloak_operator/utils/` utilities and operator startup code in `src/keycloak_operator/operator.py`.

### Detailed Steps
1. Create `src/keycloak_operator/utils/auth_tokens.py` with helpers:
   - `generate_token()` (cryptographically secure, e.g., `secrets.token_urlsafe(32)`).
   - `store_operator_token(namespace: str) -> str` to ensure Secret exists in operator namespace.
   - `fetch_token(secret_ref: AuthorizationSecretRef, namespace: str) -> str` to read secrets.
2. Update operator startup (`operator.py`) to generate or retrieve the operator authorization secret during `on_startup` handler.
3. Implement caching (in-memory) for tokens to avoid repeated API calls; leverage Kopf global store or module-level cache.
4. Add error handling for missing/invalid secrets with custom exceptions in `src/keycloak_operator/errors/operator_errors.py`.
5. Ensure tokens are base64-encoded when stored, matching CRD expectation.
6. Document secret naming convention (e.g., `keycloak-operator-auth-token`) and ensure uniqueness per namespace.

### Key Code Snippet
```python
# src/keycloak_operator/utils/auth_tokens.py
import base64
import secrets
from kubernetes import client

def generate_token(length: int = 48) -> str:
    return secrets.token_urlsafe(length)

def store_operator_token(namespace: str, secret_name: str) -> str:
    token = generate_token()
    encoded = base64.b64encode(token.encode()).decode()
    body = client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name, namespace=namespace),
        type="Opaque",
        data={"token": encoded},
    )
    # idempotent create-or-update logic here
    return token
```

### Testing Checkpoints
- Unit tests in `tests/unit/test_validation.py` to cover token fetch scenarios.
- New unit tests for utilities (`tests/unit/test_auth_tokens.py`).
- Dry-run operator startup locally: `uv run python -m keycloak_operator.operator --dry-run` (if supported) or run local Kind deployment (`make deploy-local`) to ensure secret creation.

### Rollback Strategy
- Remove new utility module and revert operator startup changes.
- Delete created secrets from Kind cluster (`kubectl delete secret keycloak-operator-auth-token -n keycloak-system`).

### Time Estimate
- ~5 hours (3h implementation, 2h tests/debugging).

## Phase 3 – Handler Updates
**Objective:** Align realm and client reconcilers with new authorization flow and namespace coupling logic.

### Prerequisites
- Phase 1 schemas and Phase 2 utilities in place.
- Review current handlers in `src/keycloak_operator/handlers/realm.py` and `client.py`.

### Detailed Steps
1. Refactor `RealmSpec` and `ClientSpec` models to include new ref objects.
2. Update realm handler:
   - Load `operatorRef`.
   - Validate operator token via `fetch_token` and compare with cached operator token.
   - Restrict Keycloak CR lookup to `operatorRef.namespace`.
   - Generate realm-specific token secret in realm namespace (new helper `store_realm_token`).
   - Populate status fields `managedBy`, `phase`, and labels as per context doc.
3. Update client handler:
   - Resolve `realmRef` and validate realm token.
   - Determine operator namespace from retrieved realm spec/status.
   - Ensure generated client credentials secret includes new labels.
4. Update finalizer logic to clean up secrets safely.
5. Adjust log messages to reference new fields for observability.

### Key Code Snippet
```python
# src/keycloak_operator/handlers/realm.py (excerpt)
from keycloak_operator.utils.auth_tokens import fetch_token, store_realm_token

operator_token = cached_operator_token()
auth_token = fetch_token(realm.spec.operator_ref.authorization_secret_ref, realm.spec.operator_ref.namespace)

if auth_token != operator_token:
    raise AuthorizationError("Invalid operator authorization token")

realm_secret_name = f"{realm.metadata.name}-auth-token"
realm_token = store_realm_token(realm.metadata.namespace, realm_secret_name)
```

### Testing Checkpoints
- Update and run unit tests: `tests/unit/test_finalizers.py`, `tests/unit/test_models.py`, `tests/unit/services/test_keycloak_admin_client.py` (if realm/client access changes).
- Add new unit tests covering authorization failures.
- Smoke-test operator on Kind: `make deploy-local` followed by applying sample CRs with updated spec to ensure reconciliation works.

### Rollback Strategy
- Revert handler files and spec models.
- Delete new realm/client secrets created during testing.

### Time Estimate
- ~8 hours (5h handler refactor, 3h tests + manual verification).

## Phase 4 – RBAC Refactor
**Objective:** Replace overly permissive ClusterRole with least-privilege configuration and namespace-scoped Roles.

### Prerequisites
- Phase 3 ensures operator logic aligns with new permissions.
- Familiarity with existing RBAC manifests under `k8s/rbac/`.

### Detailed Steps
1. Replace contents of `k8s/rbac/cluster-role.yaml` with minimal rules (watch/list CRDs, manage finalizers/status, read/create secrets, emit events, leader election).
2. Create new `k8s/rbac/role.yaml` (if not existing) for `keycloak-operator-manager` in `keycloak-system` namespace.
3. Update `k8s/rbac/cluster-role-binding.yaml` and `role-binding.yaml` to bind service account appropriately.
4. Remove obsolete RBAC documents `TODO/rbac-centralized-operator-design.md` and `TODO/rbac-security-implementation.md` (or replace with pointers to this plan once executed).
5. Ensure `k8s/rbac/install-rbac.yaml` aggregates new manifests.

### Key Code Snippet
```yaml
# k8s/rbac/cluster-role.yaml (excerpt)
rules:
  - apiGroups: ["keycloak.mdvr.nl"]
    resources: ["keycloakrealms", "keycloakclients"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["keycloak.mdvr.nl"]
    resources: ["keycloakrealms/status", "keycloakclients/status"]
    verbs: ["get", "update", "patch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update", "patch", "delete"]
```

### Testing Checkpoints
- `kubectl auth can-i` tests for service account in Kind cluster (use `make deploy-local` first).
- Run integration smoke test focusing on RBAC (`tests/integration/test_rbac_manual_mode.py`).

### Rollback Strategy
- Revert RBAC manifests and reapply previous versions using `kubectl` or `make deploy`.

### Time Estimate
- ~4 hours (RBAC edits + validation).

## Phase 5 – Helm Charts Creation
**Objective:** Provide three Helm charts (operator+Keycloak, realm, client) with GitOps-friendly templates.

### Prerequisites
- Phases 1-4 merged so templates match new API surface.
- Knowledge of Helm templating conventions.

### Detailed Steps
1. Scaffold chart directories:
   - `charts/keycloak-operator/`
   - `charts/keycloak-realm/`
   - `charts/keycloak-client/`
2. Populate each with `Chart.yaml`, `values.yaml`, and `templates/` files.
3. Operator chart templates:
   - Operator Deployment, Keycloak CR manifests, ServiceAccount, Roles, RoleBindings, CRDs (using `crds/` directory).
   - Template secret generation hints (documented for GitOps).
4. Realm chart templates:
   - KeycloakRealm CR with `operatorRef` values.
   - Role/RoleBinding to read operator namespace secret.
5. Client chart templates:
   - KeycloakClient CR with `realmRef` values.
   - Role/RoleBinding to read realm namespace secret.
6. Add helper templates (`_helpers.tpl`) for common labels/annotations.
7. Provide `README.md` per chart generated via `helm-docs` (optional but recommended).
8. Update `Makefile` with targets to lint/package charts (e.g., `make charts-lint`).

### Key Code Snippet
```yaml
# charts/keycloak-realm/templates/keycloakrealm.yaml
apiVersion: keycloak.mdvr.nl/v1
kind: KeycloakRealm
metadata:
  name: {{ .Values.realm.name }}
  namespace: {{ .Values.targetNamespace }}
spec:
  operatorRef:
    namespace: {{ .Values.operator.namespace }}
    authorizationSecretRef:
      name: {{ .Values.operator.authorizationSecret.name }}
      key: {{ default "token" .Values.operator.authorizationSecret.key }}
```

### Testing Checkpoints
- `helm lint charts/keycloak-operator` (and others).
- Package charts with `helm package` and verify output (optional).
- Deploy operator chart to Kind and ensure dependent charts render correctly.

### Rollback Strategy
- Remove `charts/` directories and undo Makefile modifications.
- Ensure CRDs still deployable via existing manifests if charts pulled.

### Time Estimate
- ~8 hours (scaffolding, templating, documentation).

## Phase 6 – Release Process Updates
**Objective:** Support multi-component releases (operator image + Helm charts) with conventional commit scopes.

### Prerequisites
- Charts present from Phase 5.
- Familiarity with `RELEASES.md` and GitHub workflows.

### Detailed Steps
1. Update `RELEASES.md` to include chart scopes (`feat(chart-operator):`, etc.) and release rules.
2. Modify `.github/workflows/release-please.yml` (or equivalent) to include Helm chart artifacts:
   - Configure additional release-please configs for each chart scope.
   - Ensure chart packaging steps (e.g., `helm package`) run before release upload.
3. Add automation to push charts to artifact repository (e.g., GitHub Pages or OCI registry) as needed.
4. Adjust Makefile/CI scripts to build both Docker image and charts when corresponding scopes detected.

### Key Code Snippet
```yaml
# .github/workflows/release-please.yml (excerpt)
      - name: Publish Helm charts
        if: steps.release.outputs.chart-operator_release == 'true'
        run: |
          helm package charts/keycloak-operator
          helm push keycloak-operator-*.tgz oci://ghcr.io/mdvr/charts
```

### Testing Checkpoints
- Run workflow locally with `act` (if available) or dry-run branch to ensure release-please picks up scopes.
- Verify `make quality` still passes to ensure docs formatting unaffected.

### Rollback Strategy
- Revert workflow and documentation changes.
- Remove chart publishing steps from CI.

### Time Estimate
- ~3 hours.

## Phase 7 – Migration Guide & Examples
**Objective:** Document new workflow and update sample manifests to guide teams.

### Prerequisites
- Phases 1-6 completed so documentation reflects final state.

### Detailed Steps
1. Create `docs/migration/helm-refactor.md` detailing migration steps from old operator.
2. Update root `README.md` with new installation instructions referencing Helm charts and authorization tokens.
3. Refresh examples under `examples/service-account/` (and other directories) with new CR spec.
4. Replace obsolete TODO documents with references to finalized architecture.
5. Update `docs/architecture.md` diagrams or descriptions where necessary.

### Key Code Snippet
```markdown
```bash
helm install keycloak-operator charts/keycloak-operator \
  --namespace keycloak-system --create-namespace

helm install team-a-realm charts/keycloak-realm \
  --namespace team-a \
  --set operator.authorizationSecret.name=keycloak-operator-auth-token
```
```

### Testing Checkpoints
- `mkdocs build` (if MkDocs docs changed).
- `make quality` to ensure Markdown linting (if configured).

### Rollback Strategy
- Restore previous documentation via `git checkout`.
- Reinstate old examples if migration guide needs further review.

### Time Estimate
- ~4 hours.

## Phase 8 – Testing Enhancements
**Objective:** Ensure automated coverage for new authorization mechanics, RBAC boundaries, and Helm provisioning.

### Prerequisites
- All functional changes merged; tests can rely on final APIs.

### Detailed Steps
1. Expand unit tests:
   - Add `tests/unit/test_auth_tokens.py` covering token generation, storage, retrieval, and error paths.
   - Update CRD schema tests to validate new required fields.
2. Update integration tests in `tests/integration/`:
   - Modify fixtures to provision operator/realm/client using new spec.
   - Ensure tests consume authorization tokens via secrets.
   - Add RBAC regression tests verifying restricted permissions (`kubectl auth can-i` assertions via python helpers).
3. Add Helm chart smoke tests (optional): use pytest marker or script under `tests/utils` to render Helm charts and assert key fields.
4. Run full test pipeline:
   - `make quality`
   - `make test-unit`
   - `make test-integration`

### Key Code Snippet
```python
# tests/unit/test_auth_tokens.py
def test_fetch_token_mismatched_secret_raises():
    with pytest.raises(AuthorizationError):
        fetch_token(AuthorizationSecretRef(name="missing"), "team-a")
```

### Testing Checkpoints
- As listed above; rerun targeted tests after each fix.
- Optional: add GitHub Actions matrix run to ensure parallelism safe.

### Rollback Strategy
- If tests introduce instability, revert individual test files while preserving production code.
- Disable new test markers temporarily only with team approval.

### Time Estimate
- ~5 hours (focus on integration suite).

## Risk & Mitigation Summary
- **Cross-namespace secret access:** Validate RBAC thoroughly in Phase 4 and Phase 8 tests.
- **Token drift:** Cache tokens and add health-check endpoints/logging to detect mismatches early.
- **Helm chart misconfiguration:** Provide opinionated defaults and `helm lint` automation.
- **Release automation mistakes:** Test release workflow on a staging branch before merging to `main`.

## Rollout Checklist
1. Complete Phases 1-8 sequentially with sign-off after each testing gate.
2. Perform final `make quality` and full test suite.
3. Update CHANGELOG (if applicable) with highlights of refactor.
4. Coordinate with platform team for production rollout using new Helm charts.

---

**Appendix:**
- **Estimated Total Duration:** ≈ 33 hours (+ buffer).
- **Key Contacts:** Security (RBAC review), DevOps (Helm registry access), QA (integration suite scheduling).
- **Follow-up Tasks:** Monitor production rollout, collect feedback for future Phase 9 (observability enhancements).
