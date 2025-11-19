# CI/CD and Documentation Issues - Task List

**Created**: 2025-01-19
**Branch**: `fix/cicd-docs-issues`

---

## 🔴 Critical Issues

### 1. Dev Documentation Not Updating
**Status**: 🔴 Not Started
**Priority**: P0 - Critical

**Problem**:
- PR #142 merged with Mermaid diagram changes
- Dev docs workflow ran successfully
- But pages at https://vriesdemichael.github.io/keycloak-operator/dev/ still show old ASCII art

**Investigation needed**:
- [ ] Check if `mike deploy --push dev` is actually updating gh-pages branch
- [ ] Verify GitHub Pages is serving from gh-pages branch
- [ ] Check if there's a caching issue
- [ ] Review mike deployment logs in workflow run
- [ ] Verify dev docs job actually ran after PR merge

**Expected behavior**:
- After PR #142 merges → `update-dev-docs` job runs → Mermaid diagrams visible at /dev/ URLs

**Files involved**:
- `.github/workflows/ci-cd-unified.yml` (lines 1132-1170)

---

### 2. Integration Test Coverage Not Collected
**Status**: 🔴 Not Started
**Priority**: P0 - Critical

**Problem**:
- Integration tests run but coverage is not uploaded to Codecov
- Old workflow (be001c8c) had proper coverage collection
- New unified workflow is missing critical steps

**Comparison with old workflow**:

**Old workflow had**:
```yaml
# 1. Separate coverage image artifact
- name: Download operator coverage image artifact
  uses: actions/download-artifact@v6
  with:
    name: operator-coverage-image
    path: /tmp

- name: Load operator images
  run: |
    docker load --input /tmp/operator-test.tar
    docker load --input /tmp/operator-test-coverage.tar

# 2. Load BOTH images into Kind
- name: Load operator and coverage images into Kind
  run: |
    kind load docker-image keycloak-operator:test --name keycloak-operator-test-${{ github.run_id }}
    kind load docker-image keycloak-operator:test-coverage --name keycloak-operator-test-${{ github.run_id }}

# 3. Generate coverage report from collected files
- name: Generate integration coverage report
  if: always()
  run: |
    if [ -d .tmp/coverage ] && [ -n "$(ls -A .tmp/coverage/.coverage* 2>/dev/null)" ]; then
      uv run coverage combine .tmp/coverage/.coverage*
      uv run coverage xml -o coverage.xml
      echo "✓ Generated coverage.xml from integration tests"
    else
      echo "ERROR: No integration coverage files found"
      exit 1
    fi

# 4. Upload generated coverage.xml
- name: Upload integration coverage to Codecov
  with:
    files: ./coverage.xml  # <-- IMPORTANT: XML file, not .coverage files
    flags: integration
```

**Current workflow problems**:
```yaml
# ❌ MISSING: Separate coverage image build
# Only downloads operator-image (no coverage variant)

# ❌ WRONG: Tags regular image as coverage
- name: Load operator image into Kind
  run: |
    docker tag keycloak-operator:test keycloak-operator:test-coverage  # <-- NOT coverage-instrumented!

# ❌ MISSING: Coverage file combination step
# Tries to upload raw .coverage.* files directly

# ❌ WRONG: Uploads .coverage files instead of XML
- name: Upload integration coverage to Codecov
  with:
    files: .tmp/coverage/.coverage.*  # <-- Codecov needs XML!
```

**Tasks**:
- [ ] Restore `build-coverage-image` job (or add to `build-operator` job)
- [ ] Add coverage image artifact upload/download
- [ ] Load actual coverage-instrumented image into Kind
- [ ] Add coverage combine + XML generation step after pytest
- [ ] Upload `coverage.xml` instead of raw `.coverage.*` files
- [ ] Verify INTEGRATION_COVERAGE env var is set
- [ ] Test that coverage files are actually collected in `.tmp/coverage/`

**Files involved**:
- `.github/workflows/ci-cd-unified.yml` (build-operator, integration-tests jobs)
- Old reference: `be001c8cd569fd77759d30132d653aff88149dbc/.github/workflows/ci-cd.yml`

---

## 🟡 Medium Priority Issues

### 3. MkDocs Build Warnings
**Status**: 🟡 Not Started
**Priority**: P1 - Important

**Warnings to fix**:

#### 3.1 Missing ADR navigation
```
WARNING - A reference to 'decisions/generated-markdown' is included in the 'nav'
          configuration, which is not found in the documentation files.
```

**Root cause**:
- `mkdocs.yml` references `decisions/generated-markdown/` in nav
- But ADR docs need to be built first with `scripts/build-adr-docs.sh`
- Dev docs workflow doesn't run this script

**Tasks**:
- [ ] Add ADR build step to `update-dev-docs` job
- [ ] Add CRD schema generation step to `update-dev-docs` job
- [ ] Match the steps from `publish-release-docs` job

**Current release docs workflow has**:
```yaml
# Missing from dev docs!
- name: Build ADR documentation
  run: bash scripts/build-adr-docs.sh

- name: Generate CRD JSON schemas
  run: uv run python scripts/generate-crd-schemas.py
```

#### 3.2 Broken internal links
```
INFO - Doc file 'faq.md' contains a link 'concepts/security.md#namespace-authorization',
       but the doc 'concepts/security.md' does not contain an anchor '#namespace-authorization'.

INFO - Doc file 'operations/troubleshooting.md' contains a link '#token-authorization-issues',
       but there is no such anchor on this page.
```

**Tasks**:
- [ ] Fix `faq.md` link - find correct anchor or update link
- [ ] Fix `operations/troubleshooting.md` - add missing anchor or update link

#### 3.3 Unrecognized relative links
```
INFO - Doc file 'index.md' contains an unrecognized relative link '../LICENSE'
INFO - Doc file 'reference/keycloak-client-crd.md' contains an unrecognized relative link '../../examples/clients/'
INFO - Doc file 'reference/keycloak-realm-crd.md' contains unrecognized relative links to '../../examples/'
```

**Tasks**:
- [ ] Review if these links should be external/absolute URLs
- [ ] Or fix relative paths to work within docs structure
- [ ] Add examples to docs if needed

---

## 🟢 Low Priority / Nice to Have

### 4. Documentation Improvements
**Status**: 🟢 Not Started
**Priority**: P2 - Enhancement

**Tasks**:
- [ ] Add note about Mermaid diagram interactivity in docs
- [ ] Document the cyan/teal color scheme choice
- [ ] Add dark mode screenshots to showcase diagrams
- [ ] Consider adding diagram legends/keys

---

## 📋 Testing Checklist

Before closing this issue, verify:

### Documentation
- [ ] Dev docs update after merge to main
- [ ] Mermaid diagrams render correctly on /dev/ pages
- [ ] All MkDocs build warnings resolved
- [ ] ADR documentation generates correctly
- [ ] CRD schemas generate correctly

### CI/CD
- [ ] Integration tests collect coverage
- [ ] Coverage combines correctly from .tmp/coverage/
- [ ] Coverage XML uploads to Codecov
- [ ] Coverage shows on Codecov dashboard with "integration" flag
- [ ] Test with actual PR to verify full workflow

### Manual Testing Commands
```bash
# Test docs build locally
uv run --group docs mkdocs build --clean

# Test coverage collection
INTEGRATION_COVERAGE=true uv run --group test pytest tests/integration/ -v
ls -la .tmp/coverage/

# Combine coverage
uv run coverage combine .tmp/coverage/.coverage*
uv run coverage xml -o coverage.xml
```

---

## 📝 Notes

- Old working CI/CD: `be001c8cd569fd77759d30132d653aff88149dbc`
- PR #141: Consolidated doc workflows
- PR #142: Mermaid diagrams (merged but not visible)

## Related Files

- `.github/workflows/ci-cd-unified.yml`
- `mkdocs.yml`
- `scripts/build-adr-docs.sh`
- `scripts/generate-crd-schemas.py`
- `docs/faq.md`
- `docs/operations/troubleshooting.md`
- `docs/index.md`
- `docs/reference/*.md`
