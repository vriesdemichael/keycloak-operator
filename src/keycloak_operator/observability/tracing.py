"""
OpenTelemetry distributed tracing for the Keycloak operator.

This module provides:
- Automatic instrumentation of httpx and aiohttp HTTP clients
- Manual span creation for semantic operations (reconciliation, etc.)
- Trace context propagation to Keycloak (W3C traceparent header)
- Kopf handler decorator for automatic span creation

Usage:
    from keycloak_operator.observability.tracing import (
        setup_tracing,
        get_tracer,
        traced_handler,
    )

    # Initialize at startup
    setup_tracing()

    # Get tracer for manual spans
    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("my_operation"):
        ...

    # Use decorator for Kopf handlers
    @traced_handler("reconcile_realm")
    async def handle_realm_create(...):
        ...
"""

import contextlib
import functools
import logging
from collections.abc import Callable
from contextvars import ContextVar
from typing import ParamSpec, TypeVar

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.trace import SpanKind, Status, StatusCode, Tracer
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)

# Module-level state
_tracer_provider: TracerProvider | None = None
_initialized: bool = False

# Context variable for current resource context (namespace, name, etc.)
# Note: Using None as default and initializing with empty dict is required
# to avoid mutable default in ContextVar (B039)
_resource_context: ContextVar[dict[str, str] | None] = ContextVar(
    "resource_context", default=None
)

# Type variables for decorator
P = ParamSpec("P")
R = TypeVar("R")


def setup_tracing(
    enabled: bool = False,
    endpoint: str = "http://localhost:4317",
    service_name: str = "keycloak-operator",
    sample_rate: float = 1.0,
    insecure: bool = True,
    headers: dict[str, str] | None = None,
    use_simple_processor: bool = False,
) -> TracerProvider | None:
    """
    Initialize OpenTelemetry tracing for the operator.

    This function sets up:
    - TracerProvider with configurable sampling
    - OTLP exporter for sending traces to a collector
    - Auto-instrumentation for httpx and aiohttp clients
    - W3C trace context propagation

    Args:
        enabled: Enable tracing (if False, returns None and does nothing)
        endpoint: OTLP collector endpoint (gRPC)
        service_name: Service name for traces
        sample_rate: Sampling rate (0.0-1.0, 1.0 = 100% of traces)
        insecure: Use insecure connection (no TLS)
        headers: Additional headers for OTLP exporter
        use_simple_processor: Use SimpleSpanProcessor instead of BatchSpanProcessor
                              (useful for testing to ensure immediate export)

    Returns:
        TracerProvider if enabled, None otherwise
    """
    global _tracer_provider, _initialized

    if _initialized:
        logger.debug("Tracing already initialized, skipping")
        return _tracer_provider

    if not enabled:
        logger.info("OpenTelemetry tracing is disabled")
        _initialized = True
        return None

    logger.info(
        f"Initializing OpenTelemetry tracing: endpoint={endpoint}, "
        f"service={service_name}, sample_rate={sample_rate}"
    )

    # Create resource with service information
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "keycloak-operator",
            "deployment.environment": "kubernetes",
        }
    )

    # Configure sampling
    # ParentBased respects parent sampling decisions
    # and applies the TraceIdRatioBased sampling for root spans
    sampler = ParentBased(root=TraceIdRatioBased(sample_rate))

    # Create tracer provider
    _tracer_provider = TracerProvider(resource=resource, sampler=sampler)

    # Configure OTLP exporter
    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        insecure=insecure,
        headers=headers or {},
    )

    # Add span processor
    # Use SimpleSpanProcessor for testing (immediate export)
    # Use BatchSpanProcessor for production (better performance)
    if use_simple_processor:
        processor = SimpleSpanProcessor(exporter)
    else:
        processor = BatchSpanProcessor(exporter)
    _tracer_provider.add_span_processor(processor)

    # Set as global tracer provider
    trace.set_tracer_provider(_tracer_provider)

    # Instrument HTTP clients for automatic trace propagation
    # This ensures W3C traceparent headers are added to all outgoing requests
    _instrument_http_clients()

    _initialized = True
    logger.info("OpenTelemetry tracing initialized successfully")

    return _tracer_provider


def _instrument_http_clients() -> None:
    """Instrument HTTP clients for automatic trace context propagation."""
    try:
        # Instrument httpx (used by KeycloakAdminClient)
        HTTPXClientInstrumentor().instrument()
        logger.debug("Instrumented httpx client")
    except Exception as e:
        logger.warning(f"Failed to instrument httpx: {e}")

    try:
        # Instrument aiohttp (used by some async operations)
        AioHttpClientInstrumentor().instrument()
        logger.debug("Instrumented aiohttp client")
    except Exception as e:
        logger.warning(f"Failed to instrument aiohttp: {e}")


def shutdown_tracing() -> None:
    """Shutdown tracing and flush any pending spans."""
    global _tracer_provider, _initialized

    if _tracer_provider is not None:
        logger.info("Shutting down OpenTelemetry tracing")
        _tracer_provider.shutdown()
        _tracer_provider = None

    # Uninstrument HTTP clients (ignore errors if not instrumented)
    with contextlib.suppress(Exception):
        HTTPXClientInstrumentor().uninstrument()

    with contextlib.suppress(Exception):
        AioHttpClientInstrumentor().uninstrument()

    _initialized = False


def get_tracer(name: str = __name__) -> Tracer:
    """
    Get a tracer instance for creating spans.

    Args:
        name: Name of the tracer (typically __name__ of the module)

    Returns:
        Tracer instance (no-op if tracing is disabled)
    """
    return trace.get_tracer(name)


def get_propagator() -> TraceContextTextMapPropagator:
    """Get the W3C trace context propagator for manual propagation."""
    return TraceContextTextMapPropagator()


def set_resource_context(
    namespace: str | None = None,
    name: str | None = None,
    resource_type: str | None = None,
    **kwargs: str,
) -> None:
    """
    Set resource context for the current execution context.

    This context is automatically added to spans created by traced_handler.

    Args:
        namespace: Kubernetes namespace
        name: Resource name
        resource_type: Resource type (keycloak, realm, client)
        **kwargs: Additional context attributes
    """
    current = _resource_context.get()
    context = current.copy() if current is not None else {}
    if namespace:
        context["k8s.namespace"] = namespace
    if name:
        context["k8s.resource.name"] = name
    if resource_type:
        context["k8s.resource.type"] = resource_type
    context.update(kwargs)
    _resource_context.set(context)


def get_resource_context() -> dict[str, str]:
    """Get the current resource context."""
    current = _resource_context.get()
    return current.copy() if current is not None else {}


def clear_resource_context() -> None:
    """Clear the resource context."""
    _resource_context.set({})


def traced_handler(
    operation_name: str,
    span_kind: SpanKind = SpanKind.INTERNAL,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator for Kopf handlers to automatically create spans.

    This decorator:
    - Creates a span with the operation name
    - Adds Kubernetes resource attributes (namespace, name, type)
    - Records exceptions as span events
    - Sets span status based on success/failure

    Args:
        operation_name: Name of the operation (e.g., "reconcile_realm")
        span_kind: Kind of span (INTERNAL, SERVER, CLIENT, etc.)

    Returns:
        Decorated function

    Example:
        @kopf.on.create("keycloakrealms", ...)
        @traced_handler("create_realm")
        async def handle_realm_create(spec, name, namespace, **kwargs):
            ...
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            tracer = get_tracer(func.__module__ or __name__)

            # Extract resource information from kwargs (Kopf handler pattern)
            namespace = kwargs.get("namespace", "unknown")
            name = kwargs.get("name", "unknown")

            # Determine resource type from operation name or function
            resource_type = "unknown"
            if "realm" in operation_name.lower():
                resource_type = "keycloakrealm"
            elif "client" in operation_name.lower():
                resource_type = "keycloakclient"
            elif "keycloak" in operation_name.lower():
                resource_type = "keycloak"

            # Build span attributes
            handler_name = getattr(func, "__name__", "unknown")
            attributes = {
                "k8s.namespace": namespace,
                "k8s.resource.name": name,
                "k8s.resource.type": resource_type,
                "kopf.handler": handler_name,
            }

            # Add any resource context
            attributes.update(get_resource_context())

            with tracer.start_as_current_span(
                operation_name,
                kind=span_kind,
                attributes=attributes,
            ) as span:
                try:
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            tracer = get_tracer(func.__module__ or __name__)

            namespace = kwargs.get("namespace", "unknown")
            name = kwargs.get("name", "unknown")

            resource_type = "unknown"
            if "realm" in operation_name.lower():
                resource_type = "keycloakrealm"
            elif "client" in operation_name.lower():
                resource_type = "keycloakclient"
            elif "keycloak" in operation_name.lower():
                resource_type = "keycloak"

            handler_name = getattr(func, "__name__", "unknown")
            attributes = {
                "k8s.namespace": namespace,
                "k8s.resource.name": name,
                "k8s.resource.type": resource_type,
                "kopf.handler": handler_name,
            }
            attributes.update(get_resource_context())

            with tracer.start_as_current_span(
                operation_name,
                kind=span_kind,
                attributes=attributes,
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise

        # Return appropriate wrapper based on function type
        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def inject_trace_context(headers: dict[str, str]) -> dict[str, str]:
    """
    Inject current trace context into headers for propagation.

    This is useful for manual propagation when auto-instrumentation
    doesn't apply (e.g., custom HTTP clients).

    Args:
        headers: Existing headers dict (will be modified in place)

    Returns:
        Headers dict with trace context added
    """
    propagator = get_propagator()
    propagator.inject(headers)
    return headers


def extract_trace_context(headers: dict[str, str]) -> trace.Context | None:
    """
    Extract trace context from incoming headers.

    Args:
        headers: Headers containing trace context

    Returns:
        Extracted context or None
    """
    propagator = get_propagator()
    return propagator.extract(headers)


def is_tracing_enabled() -> bool:
    """Check if tracing is currently enabled and initialized."""
    return _initialized and _tracer_provider is not None
