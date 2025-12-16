# Improvements Over Original Workflow

## Major Refactor: Release-Please as the Gatekeeper (December 2024)

### The Problem

The original workflow had a fundamental design flaw: it tried to detect release commits by parsing commit messages and manifest diffs, then conditionally run publish jobs. This caused:

1. **Fragile Detection**: Regex-based commit message parsing was brittle
2. **Race Conditions**: Skipping CI on "release commits" meant trusting that previous CI passed
3. **Circular Dependencies**: release-please waited for publish jobs, but publish jobs needed release info
4. **Unpredictable Flow**: Hard to understand when releases would actually happen

### The Solution: Gatekeeper Architecture

The new workflow follows the **release-please as gatekeeper** pattern:

```
Push to main
    ↓
CI Phase (ALL commits)
    ↓
release-please (THE GATEKEEPER)
    ↓ (outputs signal what to publish)
CD Phase (conditional on outputs)
```

### Key Changes

#### 1. CI Runs on ALL Commits
No more skipping quality checks for "release commits". Release PRs are just version bumps - they should pass CI quickly.

**Before:**
```yaml
if: needs.detect.outputs.is_release_commit == 'false'
```

**After:**
```yaml
# Always runs - no condition
```

#### 2. Release-Please Runs AFTER CI Passes
Release-please is now the gatekeeper that runs after all quality checks pass.

**Before:**
```yaml
release-please:
  needs: [detect, all-required-checks-passed, publish-*, ...]
  if: always() && !contains(needs.*.result, 'failure')
```

**After:**
```yaml
release-please:
  needs: [detect, all-required-checks-passed]
  if: needs.all-required-checks-passed.result == 'success' && ...
```

#### 3. Publish Jobs Use release-please Outputs Directly
No more commit message parsing. release-please tells us exactly what was released.

**Before:**
```yaml
publish-operator-image:
  needs: [detect]
  if: needs.detect.outputs.operator_releasing == 'true'
```

**After:**
```yaml
publish-operator-image:
  needs: [release-please]
  if: needs.release-please.outputs.operator_released == 'true'
```

#### 4. Simplified Detection Phase
Removed all the complex release detection logic. Just checks if we're on main branch.

**Before:** 150+ lines of bash parsing commit messages and manifest diffs
**After:** Simple branch check

### Benefits

1. ✅ **Transparent**: release-please outputs are the single source of truth
2. ✅ **Predictable**: Quality checks always run, releases happen when release-please says so
3. ✅ **Simpler**: No complex detection logic, no race conditions
4. ✅ **Debuggable**: Clear job dependencies, easy to trace failures

### The Flow

```
Normal commit:
  CI passes → release-please creates/updates Release PR → Done

Release PR merged:
  CI passes → release-please creates releases → publish jobs run → Done
```

---

## Previous Improvements (Preserved)

### Fixed: Chart Update PR Not Triggering Workflows

Changed `update-operator-chart` to use `RELEASE_PLEASE_TOKEN` (PAT) instead of `GITHUB_TOKEN` so the created PR triggers workflow runs.

### Dev Docs Update After CI

Dev documentation now updates after CI passes on main, ensuring docs stay in sync with validated code.
