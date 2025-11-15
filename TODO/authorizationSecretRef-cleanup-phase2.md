# AuthorizationSecretRef Cleanup - Phase 2

## Overview
Found 107+ remaining references to `authorizationSecret` in documentation, chart READMEs, and test code that need cleanup.

## Breakdown by Location

### Chart READMEs (~60 references)
- **charts/keycloak-realm/README.md** - ~20 references
- **charts/keycloak-client/README.md** - ~25 references
- **charts/keycloak-operator/README.md** - ~5 references
- **charts/README.md** - ~5 references
- **charts/examples/extraManifests-examples.md** - ~5 references

### Documentation (~37 references in docs/)
Already partially cleaned in Phase 1, but some remain in:
- Reference documentation
- How-to guides that need major rewrites

### Test Code (~11 references in tests/)
- Integration tests still using old authorization patterns
- Test fixtures and helpers

## Action Items

### CRITICAL - Chart READMEs
These are user-facing and need immediate attention:

1. **charts/keycloak-realm/README.md**
   - Remove all `authorizationSecretRef` examples
   - Update installation commands
   - Fix parameter tables
   - Update troubleshooting section

2. **charts/keycloak-client/README.md**
   - Remove all `authorizationSecretRef` examples
   - Update to show namespace grant list approach
   - Fix parameter tables
   - Update troubleshooting

3. **charts/keycloak-operator/README.md**
   - Remove token-related installation steps
   - Update examples

4. **charts/README.md** (main charts documentation)
   - Update multi-tenant workflow
   - Remove token distribution steps

5. **charts/examples/extraManifests-examples.md**
   - Update all examples

### HIGH - Test Code Cleanup
- **tests/integration/** - Update test fixtures to not use authorizationSecretRef
- Remove any test utilities that deal with token management

### MEDIUM - Documentation
Covered in phase 1 TODO file, but double-check:
- docs/reference/*.md
- docs/how-to/*.md
- docs/operations/troubleshooting.md

## GH-Pages Status

The `site/` directory contains ~38 references but this is:
- Generated output from mkdocs
- Listed in .gitignore
- Will be automatically fixed when source files are cleaned
- Published via GitHub Actions workflow

**Action**: No direct cleanup needed for site/ - it will regenerate from fixed source files.

## Search Commands

```bash
# Find all references
grep -r "authorizationSecret" . --include="*.md" --include="*.py" \
  --exclude-dir=".git" --exclude-dir=".venv" --exclude-dir="site"

# By category
grep -r "authorizationSecret" charts/ --include="*.md" | wc -l
grep -r "authorizationSecret" tests/ --include="*.py" | wc -l
grep -r "authorizationSecret" docs/ --include="*.md" | wc -l
```

## Estimated Effort

- Chart READMEs: 2-3 hours (complex docs, many examples)
- Test code: 1 hour
- Verification: 30 minutes

Total: ~4 hours of focused cleanup work

## Notes

- Phase 1 (completed) cleaned examples, core docs, and code
- Phase 2 focuses on chart documentation and remaining test code
- GH-pages will auto-update once source files are fixed
