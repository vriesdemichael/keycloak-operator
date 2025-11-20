# Improvements Over Original Workflow

While the refactor maintains functional parity, one critical improvement was made:

## Fixed: Chart Update PR Not Triggering Workflows

### The Issue
In the original workflow, the `update-operator-chart` job created PRs using `secrets.GITHUB_TOKEN`:

```yaml
- name: Create Pull Request
  uses: peter-evans/create-pull-request@v7
  with:
    token: ${{ secrets.GITHUB_TOKEN }}  # ❌ Won't trigger workflows
```

**Problem:** GitHub's security model prevents `GITHUB_TOKEN` from triggering workflow runs on PRs it creates. This means:
1. The chart update PR wouldn't run CI/CD checks
2. When the PR merged, release-please wouldn't detect the change
3. The chart version bump wouldn't trigger a chart release

### The Fix
Changed to use `secrets.RELEASE_PLEASE_TOKEN` (a PAT):

```yaml
- name: Update chart version
  uses: ./.github/actions/update-operator-chart
  with:
    github-token: ${{ secrets.RELEASE_PLEASE_TOKEN }}  # ✅ Triggers workflows
```

**Result:**
1. ✅ Chart update PR runs full CI/CD validation
2. ✅ When merged, release-please detects the chart change
3. ✅ Chart release is automatically created
4. ✅ Consistent with release-please's own token usage

### Impact
This fix enables the complete automated release cycle:
```
Operator Release → Chart Update PR → CI/CD Validates → Auto-merge → Chart Release
```

Without this fix, the cycle breaks after "Chart Update PR" and requires manual intervention.

## Why This Wasn't Caught Before
The original workflow likely had auto-merge disabled or the PR wasn't being monitored for the missing CI/CD runs. This refactor surfaced the issue through careful review of token usage patterns.

## Changed: Dev Docs Always Update on Main

### The Change
Dev documentation now updates on every push to main, running in parallel with initial jobs.

**Before:**
```yaml
needs: [detect, all-required-checks-passed]
if: |
  needs.all-required-checks-passed.outputs.passed == 'true' &&
  needs.detect.outputs.is_main == 'true' &&
  needs.detect.outputs.is_release == 'false' &&
  needs.detect.outputs.docs_changed == 'true'
```

**After:**
```yaml
needs: [detect]
if: |
  needs.detect.outputs.is_main == 'true' &&
  needs.detect.outputs.is_release == 'false' &&
  github.event_name == 'push'
```

### Benefits
1. ✅ Dev docs stay in sync with main branch on every commit
2. ✅ Runs in parallel with tests (no waiting for all checks)
3. ✅ No conditional on `docs_changed` - always updates
4. ✅ Faster feedback - docs available while tests run

### Why
Development documentation should always reflect the current state of the main branch, regardless of whether specific doc files changed. Code changes can require doc updates, schema changes, etc.
