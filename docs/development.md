# Development Guide

## Environment Setup

Install dependencies with [uv](https://github.com/astral-sh/uv):

```bash
# Install all dependencies and pre-commit hooks
make setup

# Or manually:
uv sync --group dev --group docs
make install-hooks
```

### Pre-commit Hooks

Pre-commit hooks automatically run code quality checks before each commit:

```bash
# Install hooks (done automatically with 'make setup')
make install-hooks

# Run hooks manually on all files
uv run --group quality pre-commit run --all-files

# Skip hooks for a specific commit (not recommended)
git commit --no-verify
```

The hooks will:
- Format code with Ruff
- Lint code with Ruff (with auto-fix)
- Run type checking with Basedpyright
- Check YAML, Markdown, and other file formats
- Validate conventional commit messages

## Coding Standards

- Formatting & lint: `make format` and `make lint`
- Type checking: `make type-check`
- All quality checks: `make quality`
- Tests: `make test-unit`

**Note:** Pre-commit hooks enforce these standards automatically, but you can also run them manually.

## Running the Operator Locally

You can run the operator process directly (it will watch the cluster your kubeconfig points to):

```bash
uv run keycloak-operator
```

## Docs Workflow

```bash
# Live reload documentation
uv run --group docs mkdocs serve

# Build static site
uv run --group docs mkdocs build
```

## Generating API Reference

API reference pages are generated automatically by mkdocstrings using the nav entry defined in `mkdocs.yml`. Add new modules under `keycloak_operator/` and they will appear after a rebuild if referenced.

To add a new explicit page:

```markdown
::: keycloak_operator.utils.kubernetes
```

## Release Checklist (Draft)

1. Update version in `pyproject.toml`
2. Ensure changelog section is complete
3. Run full test suite & type check
4. Build & tag container image
5. Push docs (e.g. GitHub Pages workflow)

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| Missing API docs | Ensure module is imported or referenced via `::: dotted.path` in a markdown file. |
| 404 for a page | Check nav path in `mkdocs.yml`. |
| Type errors block build | Run `uv run ty check` and adjust models/handlers. |

Return to [Home](index.md).
