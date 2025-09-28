# Keycloak Operator

A GitOps-friendly Kubernetes operator for provisioning and reconciling Keycloak realms, clients, and core instances via Custom Resources.

## Highlights

- Built with [Kopf](https://kopf.readthedocs.io/) and async Python
- GitOps oriented: declarative CRDs for Keycloak, Realm, Client
- Observability: Prometheus metrics, structured logging, health endpoints
- Extensible reconciliation services and clean domain models

## Quick Start

```bash
# Install runtime dependencies (operators are usually containerized)
uv sync

# (Optional) Install dev + docs tooling
uv sync --group dev --group docs

# Run unit tests
uv run pytest

# Serve documentation locally
uv run --group docs mkdocs serve
```

## Documentation Sections

- Architecture overview
- Development workflow
- API reference (auto-generated via mkdocstrings)
- Future roadmap

---

Continue with the [Architecture](architecture.md) to understand internal components.
