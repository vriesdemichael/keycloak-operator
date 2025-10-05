# Release Process

This project uses [release-please](https://github.com/googleapis/release-please) for automated semantic releases with **multi-component versioning**.

## Components

The repository contains two independently versioned components:

### 1. Operator (Docker Image)
- **Path**: Root directory (`.`)
- **Artifact**: Docker image at `ghcr.io/vriesdemichael/keycloak-operator`
- **Release Tags**: `v1.2.3` (no component prefix)
- **Triggered by**: Any conventional commit without `(chart)` scope

### 2. Helm Chart (Future)
- **Path**: `charts/keycloak-operator/`
- **Artifact**: Helm chart package
- **Release Tags**: `chart-v0.5.0` (includes component prefix)
- **Triggered by**: Conventional commits with `(chart)` scope

## Conventional Commits & Scoping

### Operator Releases
Use standard conventional commits or `(operator)` scope:
```bash
feat: add realm deletion protection
fix: resolve client sync issue
refactor!: remove deprecated admin_access field
feat(operator): implement external secrets integration
```

### Helm Chart Releases
Use `(chart)` scope explicitly:
```bash
feat(chart): add values for custom probes
fix(chart): correct RBAC permissions
docs(chart): update README with examples
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

### Example: Chart Release

```bash
# Chart-scoped commits
git commit -m "feat(chart): add custom resource limits"
git commit -m "fix(chart): correct service account annotations"
git push origin main

# → Release-please creates PR: "chore: release chart 0.2.0"
# → Merge PR
# → Release chart-v0.2.0 created
# → Helm chart published (when chart registry is configured)
```

### Example: Both Components

```bash
# Mixed commits
git commit -m "feat: add new CRD field"
git commit -m "feat(chart): expose new field in values"
git push origin main

# → Release-please creates TWO separate PRs:
#    1. "chore: release operator 0.3.0"
#    2. "chore: release chart 0.3.0"
# → Merge both PRs
# → Two releases created with independent versions
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
- Verify commits use `(chart)` scope: `feat(chart): ...`
- Check `charts/keycloak-operator/` directory exists

**Q: Multiple PRs for single component?**
- This is normal if separate-pull-requests is enabled
- Merge the PR for the component you want to release

**Q: Image published despite test failures?**
- This should NEVER happen - build workflow requires tests to pass
- Check workflow dependencies in `.github/workflows/build-and-publish.yml`
- Workflow uses `workflow_run` trigger to wait for integration tests
- Only runs if `conclusion == 'success'` or manual trigger/release
