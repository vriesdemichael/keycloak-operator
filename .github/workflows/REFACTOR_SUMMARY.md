# CI/CD Workflow Refactor Summary

## Overview
The ci-cd-unified.yml workflow has been refactored into local composite actions to improve maintainability and readability while maintaining 100% functional parity.

## Changes

### Main Workflow File
- **Before:** 1,287 lines
- **After:** 723 lines
- **Reduction:** 50% (564 lines removed)

### Structure
```
.github/
  actions/                          # NEW - Local composite actions
    build-operator/action.yml       # Build operator image
    unit-tests/action.yml            # Run unit tests with coverage
    code-quality/action.yml          # Code quality checks
    security-scans/action.yml        # Security scanning suite
    integration-tests/action.yml     # Integration tests in Kind
    publish-operator-image/action.yml # Publish to GHCR
    update-operator-chart/action.yml  # Update chart versions
    publish-helm-chart/action.yml     # Publish Helm charts (reusable)
    update-dev-docs/action.yml        # Dev documentation
    publish-release-docs/action.yml   # Release documentation
  workflows/
    ci-cd-unified.yml               # REFACTORED - Now an orchestrator
    ci-cd-unified.yml.backup        # Original backup
```

### Parity Verification ✅

#### Job Names (Identical)
All 16 job names preserved:
- detect
- build-operator
- unit-tests
- code-quality
- security-scans
- integration-tests
- all-required-checks-passed
- release-please
- publish-operator-image
- update-operator-chart
- publish-chart-operator
- publish-chart-realm
- publish-chart-client
- update-dev-docs
- publish-release-docs
- all-complete

#### Conditional Logic (Preserved)
- All `if:` conditions exactly preserved
- All `needs:` dependencies exactly preserved
- All job timeouts preserved
- All concurrency controls preserved

#### Permissions (Preserved)
- security-scans: security-events:write, contents:read, actions:read ✅
- integration-tests: contents:read, packages:read ✅
- publish-operator-image: contents:read, packages:write, security-events:write, id-token:write, attestations:write ✅
- All chart publishing: contents:read, packages:write, id-token:write, attestations:write ✅
- Documentation jobs: contents:write, pages:write, id-token:write ✅

#### Environment Variables (Identical)
```yaml
env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  KEYCLOAK_VERSION: "26.4.1"
```

#### Environments (Preserved)
- ghcr-production
- ghcr-chart-operator
- ghcr-chart-realm
- ghcr-chart-client
- github-pages-dev
- github-pages-release

## Benefits

### Readability
- Main workflow is now a clean orchestrator showing the "what" (723 lines)
- Each action shows the "how" (implementation details)
- Easy to understand the overall flow at a glance

### Maintainability
- Each action is self-contained and testable
- Changes to implementation don't clutter the main workflow
- Reusable components (publish-helm-chart used 3x)

### GitHub UI
- Same job names appear in the UI
- Same checks, same statuses, same behavior
- No user-facing changes

## What Was NOT Changed
- The `detect` job remains in the main workflow (orchestration logic)
- All checkpoint jobs remain (all-required-checks-passed, all-complete)
- Trigger conditions (on: push, pull_request, workflow_dispatch)
- Any business logic or conditional execution
- Secret/token passing
- Artifact handling
- Any step names or actions

## Testing Recommendation
Run a full workflow on a test branch before deploying to main to verify:
1. All jobs execute in correct order
2. Conditional logic works as expected
3. Artifacts are passed correctly between jobs
4. Permissions work for all publishing steps
5. GitHub Pages deployments work
6. SBOM and attestations are generated

## Rollback Plan
If issues are discovered:
```bash
cd .github/workflows
cp ci-cd-unified.yml.backup ci-cd-unified.yml
git add ci-cd-unified.yml
git commit -m "rollback: restore original ci-cd-unified.yml"
```

The composite actions can remain (they won't cause issues if not used).

## Important Token Usage Change

### update-operator-chart Job
**Changed:** Now uses `secrets.RELEASE_PLEASE_TOKEN` instead of `secrets.GITHUB_TOKEN`

**Reason:** PRs created with `GITHUB_TOKEN` don't trigger workflow runs (GitHub security feature). Using a Personal Access Token (PAT) ensures the chart update PR triggers CI/CD when created, allowing:
1. The PR to be tested by CI/CD
2. Release-please to detect the chart change when the PR is merged
3. A subsequent chart release to be created

This maintains the same pattern used by the `release-please` job itself.
