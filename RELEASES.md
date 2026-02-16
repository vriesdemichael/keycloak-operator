# Release Process

This project uses [release-please](https://github.com/googleapis/release-please) for automated semantic releases with **multi-component versioning**.

## Branch Protection & Development Workflow

**Important**: The `main` branch is protected and requires Pull Requests for all changes.

### Development Workflow

1. **Create a Feature Branch**
   ```bash
   git checkout -b feat/my-feature
   # or for fixes:
   git checkout -b fix/bug-description
   ```

2. **Make Changes & Commit**
   ```bash
   # Run checks before committing
   task test:all

   # If checks pass, commit your changes IF THEY DONT YOU FIX THE ISSUES FIRST!!!
   git add .
   git commit -m "feat: add new feature"
   git push origin feat/my-feature
   ```

3. **Create Pull Request**
   - Open PR against `main` branch
   - CI/CD pipeline runs all checks automatically
   - Review and address any feedback

4. **Merge to Main**
   - Once approved and checks pass, merge the PR
   - Release-please automatically creates/updates release PRs
   - Release PRs auto-merge when all checks pass

**Important**: Always run `task test:all` before committing to ensure your code passes linting, formatting, and type checking. This prevents CI failures and speeds up the review process.

### Branch Naming Convention

Follow conventional commit prefixes for branch names:
- `feat/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation changes
- `chore/` - Maintenance tasks
- `test/` - Test additions/changes

## Components

The repository contains four independently versioned components:

### 1. Operator (Docker Image)
- **Path**: Root directory (`.`)
- **Artifact**: Docker image at `ghcr.io/vriesdemichael/keycloak-operator`
- **Release Tags**: `v1.2.3` (semver format without component prefix)
- **Triggered by**: Any conventional commit **without** chart scope or with the `(operator)` scope

### 2. Keycloak Operator Helm Chart
- **Path**: `charts/keycloak-operator/`
- **Artifact**: Helm chart package
- **Release Tags**: `chart-operator-v0.5.0`
- **Triggered by**: Conventional commits with `(chart-operator)` scope

### 3. Keycloak Realm Helm Chart
- **Path**: `charts/keycloak-realm/`
- **Artifact**: Helm chart package
- **Release Tags**: `chart-realm-v0.5.0`
- **Triggered by**: Conventional commits with `(chart-realm)` scope

### 4. Keycloak Client Helm Chart
- **Path**: `charts/keycloak-client/`
- **Artifact**: Helm chart package
- **Release Tags**: `chart-client-v0.5.0`
- **Triggered by**: Conventional commits with `(chart-client)` scope

### 5. Migration Toolkit (Go Binary)
- **Path**: `tools/migration-toolkit/`
- **Artifact**: Go binary (standalone, no runtime dependencies)
- **Release Tags**: `migration-toolkit-v0.1.0`
- **Triggered by**: Conventional commits with `(migration-toolkit)` scope

## Conventional Commits & Scoping

### Valid Scopes

The pre-commit hook **enforces** the following scopes:
- `operator` - Operator code changes
- `chart-operator` - Keycloak Operator Helm chart
- `chart-realm` - Keycloak Realm Helm chart
- `chart-client` - Keycloak Client Helm chart
- `migration-toolkit` - Migration toolkit (Go binary in `tools/migration-toolkit/`)

**Scope validation rules:**
- Scopes can be combined using `+` (e.g., `feat(chart-client+chart-realm): ...`)
- Combined scopes must be in **alphabetical order**
- No duplicate components allowed
- Scope is optional for `chore`, `docs`, `ci`, and `test` commits

### Operator Releases (Docker Image)
Use standard conventional commits **without** scope, or use `(operator)` explicitly:
```bash
feat: add realm deletion protection
fix: resolve client sync issue
refactor!: remove deprecated admin_access field
feat(operator): implement external secrets integration
```

### Helm Chart Releases
Use specific chart scopes:

**Operator Chart:**
```bash
feat(chart-operator): add values for custom probes
fix(chart-operator): correct RBAC permissions
docs(chart-operator): update README with examples
```

**Realm Chart:**
```bash
feat(chart-realm): add support for custom themes
fix(chart-realm): correct realm import logic
```

**Client Chart:**
```bash
feat(chart-client): add protocol mapper configuration
fix(chart-client): handle missing redirect URIs
```

**Migration Toolkit:**
```bash
feat(migration-toolkit): add support for user federation transforms
fix(migration-toolkit): handle SMTP boolean string conversion
```

### Multi-Component Changes
When changes affect multiple components, combine scopes with `+` in alphabetical order:

```bash
# Update both client and realm charts
feat(chart-client+chart-realm): add identity provider support

# Update operator and its chart
feat(chart-operator+operator): add new configuration option

# Update all three charts
feat(chart-client+chart-operator+chart-realm): update to Keycloak 27

# Update migration toolkit alongside charts it generates values for
feat(chart-realm+migration-toolkit): add OTP policy support

# WRONG - not alphabetical
feat(operator+chart-client): ...  # ❌ Should be chart-client+operator

# WRONG - duplicate components
feat(operator+operator): ...  # ❌ No duplicates allowed
```

**Note:** The pre-commit hook validates scope format automatically. Invalid scopes will be rejected with helpful error messages.

## Release Workflow

### Automatic Process

The project follows a **build-once, promote-on-release** workflow to ensure released artifacts are identical to tested ones.

1. **Create Feature Branch & Push Commits**
   ```bash
   git checkout -b feat/new-feature
   git commit -m "feat: add new feature"
   git push origin feat/new-feature
   ```

2. **Create Pull Request**
   - Open PR to `main` branch
   - CI/CD runs all checks (tests, linting, security scans)
   - **No images published** on PRs
   - Review and get approval

3. **Merge to Main**
   - Merge the approved PR
   - CI/CD pipeline runs:
     - Builds operator image (once)
     - Runs all tests (unit, integration, security)
     - Publishes image with `sha-{commit}` tag only
   - **No `latest` tag** yet (only on release)

4. **Release-Please Creates PRs**
   - Scans commits since last release
   - Creates **separate PRs** for each component that has changes
   - Updates version in files (operator: `pyproject.toml`, chart: `Chart.yaml`)
   - Generates CHANGELOG
   - **Auto-merges** when all checks pass

5. **GitHub Release Created**
   - Release-please creates GitHub release automatically
   - For operator releases (tags like `v0.2.16`):
     - Promote-operator workflow triggers
     - **Pulls existing `sha-{commit}` image** (no rebuild!)
     - Re-tags with version tags: `v0.2.16`, `v0.2`, `v0`, `latest`
     - Pushes new tags to GHCR
   - For chart releases (tags like `chart-operator-v0.1.5`):
     - GitHub Pages workflow publishes Helm charts

6. **Artifacts Published**
   - **Operator:** Docker images at `ghcr.io/vriesdemichael/keycloak-operator`
   - **Charts:** Helm repository at https://vriesdemichael.github.io/keycloak-operator/charts

### Example: Operator Release

```bash
# 1. Push commits to main (via PR)
git commit -m "feat: add SMTP configuration"
git commit -m "fix: handle missing secrets gracefully"
# → CI/CD builds and tests
# → Publishes: ghcr.io/vriesdemichael/keycloak-operator:sha-abc123

# 2. Release-please creates and merges PR
# → Release-please creates PR: "chore: release Operator Image 0.2.0"
# → Auto-merges when checks pass
# → Creates GitHub Release with tag v0.2.0

# 3. Promote-operator workflow runs
# → Pulls: ghcr.io/vriesdemichael/keycloak-operator:sha-abc123
# → Re-tags and pushes:
#    - ghcr.io/vriesdemichael/keycloak-operator:v0.2.0
#    - ghcr.io/vriesdemichael/keycloak-operator:v0.2
#    - ghcr.io/vriesdemichael/keycloak-operator:v0
#    - ghcr.io/vriesdemichael/keycloak-operator:latest
```

**Key benefit:** The image tagged as `v0.2.0` is byte-for-byte identical to `sha-abc123` that passed all tests.

### Example: Operator Chart Release

```bash
# Operator chart commits
git commit -m "feat(chart-operator): add custom resource limits"
git commit -m "fix(chart-operator): correct service account annotations"
git push origin main

# → Release-please creates PR: "chore: release chart-operator 0.2.0"
# → Merge PR
# → Release chart-operator-v0.2.0 created
# → Helm chart published to GitHub Pages
```

### Example: Realm Chart Release

```bash
# Realm chart commits
git commit -m "feat(chart-realm): add theme support"
git commit -m "fix(chart-realm): handle empty realm names"
git push origin main

# → Release-please creates PR: "chore: release chart-realm 0.2.0"
# → Merge PR
# → Release chart-realm-v0.2.0 created
```

### Example: Multiple Components

```bash
# Mixed commits affecting different components
git commit -m "feat: add new CRD field"                           # → operator
git commit -m "feat(chart-operator): expose new field in values"  # → operator chart
git commit -m "feat(chart-realm): support new realm settings"     # → realm chart
git commit -m "feat(migration-toolkit): add new realm transform"  # → migration toolkit
git push origin main

# → Release-please creates FOUR separate PRs:
#    1. "chore: release operator 0.3.0"
#    2. "chore: release chart-operator 0.3.0"
#    3. "chore: release chart-realm 0.3.0"
#    4. "chore: release migration-toolkit 0.2.0"
# → Merge relevant PRs
# → Separate releases created with independent versions
```

## Version Bumping Rules

### Pre-1.0 (0.x.x)
- `feat:` → bump minor (0.1.0 → 0.2.0)
- `fix:` → bump patch (0.1.0 → 0.1.1)
- `feat!:` / `BREAKING CHANGE:` → bump minor (0.1.0 → 0.2.0)

### Post-1.0 (1.x.x)
- `feat:` → bump minor (1.0.0 → 1.1.0)
- `fix:` → bump patch (1.0.0 → 1.0.1)
- `feat!:` / `BREAKING CHANGE:` → bump major (1.0.0 → 2.0.0)

## Manual Release (Emergency)

If automation fails, create releases manually:

```bash
# Tag the release
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0

# Create GitHub release
gh release create v0.2.0 --title "v0.2.0" --notes "Emergency release"
```

## Configuration Files

- `.github/release-please-config.json` - Release strategy per component
- `.github/.release-please-manifest.json` - Current versions
- `.github/workflows/release-please.yml` - Release automation workflow
- `.github/workflows/ci-cd.yml` - Build, test, and publish SHA-tagged images
- `.github/workflows/promote-operator.yml` - Promote tested images with version tags on release
- `.github/workflows/pages.yml` - Publish Helm charts to GitHub Pages

## Troubleshooting

**Q: Release PR not created?**
- Check commits follow conventional format
- Verify commits are on `main` branch
- Review workflow logs in GitHub Actions

**Q: Wrong version bump?**
- Check commit type (`feat` vs `fix` vs `refactor!`)
- Ensure breaking changes use `!` or `BREAKING CHANGE:`

**Q: Chart not releasing separately?**
- Verify commits use correct scope:
  - Operator chart: `feat(chart-operator): ...`
  - Realm chart: `feat(chart-realm): ...`
  - Client chart: `feat(chart-client): ...`
- Check corresponding chart directory exists
- Ensure Chart.yaml has correct version

**Q: Multiple PRs for different charts?**
- This is expected - each component releases independently
- Merge only the PRs for components you want to release
- Each chart has independent versioning

**Q: Image promotion failed?**
- Check that the `sha-{commit}` image exists in GHCR for the release commit
- Verify the release tag matches an operator release (starts with `v`, no `chart-` prefix)
- Check promote-operator workflow logs in GitHub Actions
- The SHA image must be built from main before release can be promoted

**Q: Why does `latest` tag not update on main push?**
- This is intentional! `latest` only updates on operator releases
- Main branch pushes only create `sha-{commit}` tags
- This ensures `latest` always points to a stable, released version
- For bleeding-edge builds, use the `sha-{commit}` tag
