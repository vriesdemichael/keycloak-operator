# Development Guide

## Environment Setup

Install dependencies with [uv](https://github.com/astral-sh/uv):

```bash
uv sync --group dev --group docs
```

## Coding Standards

- Formatting & lint: `ruff check .` and `ruff format .`
- Type checking (ty): `uv run ty check`
- Tests: `uv run pytest`

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
