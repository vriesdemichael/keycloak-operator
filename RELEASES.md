# Release Process

This project uses [release-please](https://github.com/googleapis/release-please) for automated semantic releases with **multi-component versioning**.

## Components

The repository contains four independently versioned components:

### 1. Operator (Docker Image)
- **Path**: Root directory (`.`)
- **Artifact**: Docker image at `ghcr.io/vriesdemichael/keycloak-operator`
- **Release Tags**: `v1.2.3` (no component prefix)
- **Triggered by**: Any conventional commit **without** chart scope

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

## Conventional Commits & Scoping

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

## Release Workflow

### Automatic Process

1. **Push Commits to Main**
   ```bash
   git commit -m "feat: add new feature"
   git push origin main
   ```

2. **Integration Tests Run**
   - All tests must pass before image publishing
   - Unit tests + integration tests on multiple K8s versions
   - **Safety:** Build workflow only runs if tests succeed

3. **Release-Please Creates PRs**
   - Scans commits since last release
   - Creates **separate PRs** for each component (if both have changes)
   - Updates version in files (operator: `pyproject.toml`, chart: `Chart.yaml`)
   - Generates CHANGELOG

4. **Docker Images Published** (only if tests passed)
   - Build workflow waits for integration tests to succeed
   - On main push: publishes `latest` and `sha-<commit>` tags
   - Publishes versioned images to ghcr.io

5. **Merge Release PR**
   - Review the generated changelog
   - Merge the PR
   - Release-please creates GitHub release automatically
   - Triggers build workflow to publish versioned images (v1.2.3)

### Example: Operator Release

```bash
# Conventional commits
git commit -m "feat: add SMTP configuration"
git commit -m "fix: handle missing secrets gracefully"
git push origin main

# → Release-please creates PR: "chore: release operator 0.2.0"
# → Merge PR
# → Release v0.2.0 created
# → Docker images published:
#    - ghcr.io/vriesdemichael/keycloak-operator:v0.2.0
#    - ghcr.io/vriesdemichael/keycloak-operator:v0.2
#    - ghcr.io/vriesdemichael/keycloak-operator:v0
#    - ghcr.io/vriesdemichael/keycloak-operator:latest
```

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
git push origin main

# → Release-please creates THREE separate PRs:
#    1. "chore: release operator 0.3.0"
#    2. "chore: release chart-operator 0.3.0"
#    3. "chore: release chart-realm 0.3.0"
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
- `.github/workflows/release-please.yml` - Automation workflow
- `.github/workflows/build-and-publish.yml` - Image publishing

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

**Q: Image published despite test failures?**
- This should NEVER happen - build workflow requires tests to pass
- Check workflow dependencies in `.github/workflows/build-and-publish.yml`
- Workflow uses `workflow_run` trigger to wait for integration tests
- Only runs if `conclusion == 'success'` or manual trigger/release
