# Architecture

This operator is structured into clear layers to keep reconciliation logic maintainable and testable.

## High-Level Components

| Layer | Purpose |
|-------|---------|
| CRDs / Models | Pydantic models define the spec & status of custom resources. |
| Handlers | Kopf handlers reacting to create/update/delete events. |
| Services (Reconcilers) | Idempotent business logic for converging desired -> actual state. |
| Utils | Reusable helpers: Kubernetes API interactions, Keycloak admin client, validation. |
| Observability | Metrics, health endpoints, structured logging. |

## Reconciliation Flow

1. Kubernetes emits an event for a custom resource (e.g. `KeycloakRealm`).
2. Kopf invokes the registered handler in `handlers/realm.py`.
3. Handler validates input and delegates to a reconciler in `services/realm_reconciler.py`.
4. Reconciler:
   - Loads current state from Keycloak & cluster
   - Computes diff against desired spec
   - Applies required create/update/delete operations
   - Emits metrics & logs
5. Status field may be updated in the CR to reflect success or error.

## Key Modules

- `models/` define `Keycloak`, `KeycloakRealm`, `KeycloakClient` domain schemas.
- `handlers/` contain Kopf decorated async functions with minimal logic.
- `services/` hold reconcilers orchestrating API calls & ensuring idempotency.
- `utils/keycloak_admin.py` wraps Keycloak REST admin endpoints.
- `observability/metrics.py` defines Prometheus collectors.

## Error Handling

Custom exceptions in `errors/operator_errors.py` categorize recoverable vs fatal failures. Handlers catch and translate them to appropriate Kubernetes events/logs.

## Future Enhancements

- Finalizers for deterministic teardown
- Smarter diffing of realm/client sub-resources
- Rate limiting & backoff policies
- Pluggable auth strategies for Keycloak admin API

Return to the [index](index.md) or continue with the [development guide](development.md).
