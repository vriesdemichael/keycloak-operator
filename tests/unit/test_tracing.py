"""
Unit tests for OpenTelemetry tracing module.

Tests the tracing setup, traced_handler decorator,
context propagation, and resource context management.

Note: OpenTelemetry has global state that can only be set once per process.
Tests that need to capture spans use a module-scoped tracer provider,
while tests that mock the setup use patches to avoid global state issues.
"""

from unittest.mock import MagicMock, patch

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from keycloak_operator.observability.tracing import (
    clear_resource_context,
    extract_trace_context,
    get_propagator,
    get_resource_context,
    get_tracer,
    inject_trace_context,
    is_tracing_enabled,
    set_resource_context,
    setup_tracing,
    shutdown_tracing,
    traced_handler,
)


# Module-scoped fixtures for tests that need actual span capture
@pytest.fixture(scope="module")
def module_in_memory_exporter():
    """Module-scoped in-memory span exporter for testing."""
    return InMemorySpanExporter()


@pytest.fixture(scope="module")
def module_tracer_provider(module_in_memory_exporter):
    """Module-scoped tracer provider - set once for all tests in this module."""
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(module_in_memory_exporter))
    # Set it globally once for the module
    trace.set_tracer_provider(provider)
    return provider


@pytest.fixture(autouse=True)
def reset_tracing_state():
    """Reset tracing module state before and after each test."""
    # Import the module to access internal state
    import keycloak_operator.observability.tracing as tracing_module

    # Reset internal state
    tracing_module._initialized = False
    tracing_module._tracer_provider = None
    yield
    # Reset after test
    tracing_module._initialized = False
    tracing_module._tracer_provider = None
    # Clear resource context
    clear_resource_context()


@pytest.fixture
def clear_spans(module_in_memory_exporter):
    """Clear spans before each test that uses the module exporter."""
    module_in_memory_exporter.clear()
    yield module_in_memory_exporter
    module_in_memory_exporter.clear()


class TestSetupTracing:
    """Test setup_tracing function."""

    def test_setup_tracing_disabled(self):
        """Test setup_tracing with enabled=False returns None."""
        result = setup_tracing(enabled=False)
        assert result is None
        assert not is_tracing_enabled()

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_setup_tracing_enabled(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test setup_tracing with enabled=True creates TracerProvider."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        result = setup_tracing(
            enabled=True,
            endpoint="http://localhost:4317",
            service_name="test-service",
            sample_rate=1.0,
        )

        assert result is not None
        assert isinstance(result, TracerProvider)
        assert is_tracing_enabled()

        # Verify exporter was created with correct params
        mock_exporter.assert_called_once_with(
            endpoint="http://localhost:4317",
            insecure=True,
            headers={},
        )

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_setup_tracing_idempotent(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test that calling setup_tracing twice is idempotent."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        # First call
        result1 = setup_tracing(enabled=True)
        # Second call - should return same provider
        result2 = setup_tracing(enabled=True)

        assert result1 is result2
        # Exporter should only be created once
        mock_exporter.assert_called_once()

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_setup_tracing_with_custom_headers(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test setup_tracing with custom headers."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        custom_headers = {"Authorization": "Bearer token123"}

        setup_tracing(
            enabled=True,
            endpoint="http://collector:4317",
            headers=custom_headers,
        )

        mock_exporter.assert_called_once_with(
            endpoint="http://collector:4317",
            insecure=True,
            headers=custom_headers,
        )

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_setup_tracing_with_simple_processor(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test setup_tracing with SimpleSpanProcessor for testing."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        result = setup_tracing(
            enabled=True,
            use_simple_processor=True,
        )

        assert result is not None

    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    def test_setup_tracing_handles_instrumentation_failure(
        self, mock_httpx_instr, mock_set_provider
    ):
        """Test that instrumentation failures are handled gracefully."""
        mock_httpx_instr.return_value.instrument.side_effect = Exception("Mock error")

        with patch(
            "keycloak_operator.observability.tracing.OTLPSpanExporter"
        ) as mock_exporter:
            mock_exporter.return_value = MagicMock()
            with patch(
                "keycloak_operator.observability.tracing.AioHttpClientInstrumentor"
            ) as mock_aiohttp:
                mock_aiohttp.return_value.instrument = MagicMock()

                # Should not raise, just log warning
                result = setup_tracing(enabled=True)
                assert result is not None


class TestShutdownTracing:
    """Test shutdown_tracing function."""

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_shutdown_tracing(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test shutdown_tracing resets state."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_httpx_instr.return_value.uninstrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.uninstrument = MagicMock()

        setup_tracing(enabled=True)
        assert is_tracing_enabled()

        shutdown_tracing()
        assert not is_tracing_enabled()

    def test_shutdown_tracing_when_not_initialized(self):
        """Test shutdown_tracing when not initialized does nothing."""
        # Should not raise
        shutdown_tracing()
        assert not is_tracing_enabled()

    def test_shutdown_tracing_handles_uninstrument_errors(self):
        """Test that uninstrument errors are suppressed."""
        with patch(
            "keycloak_operator.observability.tracing.HTTPXClientInstrumentor"
        ) as mock_httpx:
            mock_httpx.return_value.uninstrument.side_effect = Exception("Mock error")

            # Should not raise
            shutdown_tracing()


class TestGetTracer:
    """Test get_tracer function."""

    def test_get_tracer_returns_tracer(self):
        """Test get_tracer returns a Tracer instance."""
        tracer = get_tracer("test_module")
        assert tracer is not None
        # Even when tracing is disabled, get_tracer returns a no-op tracer

    def test_get_tracer_with_different_names(self):
        """Test get_tracer with different module names."""
        tracer1 = get_tracer("module1")
        tracer2 = get_tracer("module2")
        # Both should be valid tracers
        assert tracer1 is not None
        assert tracer2 is not None


class TestGetPropagator:
    """Test get_propagator function."""

    def test_get_propagator_returns_propagator(self):
        """Test get_propagator returns W3C trace context propagator."""
        propagator = get_propagator()
        assert propagator is not None


class TestResourceContext:
    """Test resource context management."""

    def test_set_resource_context_basic(self):
        """Test setting basic resource context."""
        set_resource_context(
            namespace="test-ns",
            name="test-resource",
            resource_type="keycloakrealm",
        )

        context = get_resource_context()

        assert context["k8s.namespace"] == "test-ns"
        assert context["k8s.resource.name"] == "test-resource"
        assert context["k8s.resource.type"] == "keycloakrealm"

    def test_set_resource_context_with_custom_attrs(self):
        """Test setting resource context with custom attributes."""
        set_resource_context(
            namespace="ns",
            custom_attr="custom_value",
            another_attr="another_value",
        )

        context = get_resource_context()

        assert context["k8s.namespace"] == "ns"
        assert context["custom_attr"] == "custom_value"
        assert context["another_attr"] == "another_value"

    def test_set_resource_context_accumulates(self):
        """Test that set_resource_context accumulates values."""
        set_resource_context(namespace="ns1")
        set_resource_context(name="resource1")

        context = get_resource_context()

        assert context["k8s.namespace"] == "ns1"
        assert context["k8s.resource.name"] == "resource1"

    def test_set_resource_context_overrides(self):
        """Test that set_resource_context overrides existing values."""
        set_resource_context(namespace="ns1")
        set_resource_context(namespace="ns2")

        context = get_resource_context()

        assert context["k8s.namespace"] == "ns2"

    def test_get_resource_context_empty(self):
        """Test get_resource_context returns empty dict when not set."""
        clear_resource_context()
        context = get_resource_context()
        assert context == {}

    def test_get_resource_context_returns_copy(self):
        """Test get_resource_context returns a copy, not reference."""
        set_resource_context(namespace="ns")
        context1 = get_resource_context()
        context1["modified"] = "yes"

        context2 = get_resource_context()
        assert "modified" not in context2

    def test_clear_resource_context(self):
        """Test clear_resource_context resets context."""
        set_resource_context(namespace="ns", name="resource")
        clear_resource_context()

        context = get_resource_context()
        assert context == {}


class TestTracedHandler:
    """Test traced_handler decorator.

    These tests use the module-scoped tracer provider to capture actual spans.
    """

    @pytest.mark.asyncio
    async def test_traced_handler_async_function(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler with async function."""

        @traced_handler("test_operation")
        async def async_handler(namespace: str, name: str, **kwargs) -> str:
            return f"{namespace}/{name}"

        result = await async_handler(namespace="test-ns", name="test-resource")

        assert result == "test-ns/test-resource"

        # Verify span was created
        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1

        span = spans[0]
        assert span.name == "test_operation"
        assert span.attributes["k8s.namespace"] == "test-ns"
        assert span.attributes["k8s.resource.name"] == "test-resource"
        assert span.status.status_code == StatusCode.OK

    @pytest.mark.asyncio
    async def test_traced_handler_sync_function(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler with sync function."""

        @traced_handler("sync_operation")
        def sync_handler(namespace: str, name: str, **kwargs) -> str:
            return f"{namespace}/{name}"

        result = sync_handler(namespace="sync-ns", name="sync-resource")

        assert result == "sync-ns/sync-resource"

        # Verify span was created
        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1

        span = spans[0]
        assert span.name == "sync_operation"
        assert span.attributes["k8s.namespace"] == "sync-ns"

    @pytest.mark.asyncio
    async def test_traced_handler_exception_handling(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler records exceptions."""

        @traced_handler("failing_operation")
        async def failing_handler(**kwargs):
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            await failing_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1

        span = spans[0]
        assert span.status.status_code == StatusCode.ERROR
        assert "Test error" in span.status.description

        # Check exception was recorded
        events = span.events
        assert len(events) >= 1
        exception_events = [e for e in events if e.name == "exception"]
        assert len(exception_events) >= 1

    @pytest.mark.asyncio
    async def test_traced_handler_resource_type_detection_realm(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler detects realm resource type."""

        @traced_handler("reconcile_realm")
        async def realm_handler(**kwargs):
            pass

        await realm_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["k8s.resource.type"] == "keycloakrealm"

    @pytest.mark.asyncio
    async def test_traced_handler_resource_type_detection_client(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler detects client resource type."""

        @traced_handler("create_client")
        async def client_handler(**kwargs):
            pass

        await client_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["k8s.resource.type"] == "keycloakclient"

    @pytest.mark.asyncio
    async def test_traced_handler_resource_type_detection_keycloak(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler detects keycloak resource type."""

        @traced_handler("deploy_keycloak")
        async def keycloak_handler(**kwargs):
            pass

        await keycloak_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["k8s.resource.type"] == "keycloak"

    @pytest.mark.asyncio
    async def test_traced_handler_unknown_resource_type(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler handles unknown resource type."""

        @traced_handler("some_operation")
        async def unknown_handler(**kwargs):
            pass

        await unknown_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["k8s.resource.type"] == "unknown"

    @pytest.mark.asyncio
    async def test_traced_handler_with_custom_span_kind(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler with custom span kind."""

        @traced_handler("external_call", span_kind=SpanKind.CLIENT)
        async def client_call(**kwargs):
            pass

        await client_call(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.kind == SpanKind.CLIENT

    @pytest.mark.asyncio
    async def test_traced_handler_includes_resource_context(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler includes resource context in span."""
        set_resource_context(custom_context="custom_value")

        @traced_handler("context_operation")
        async def context_handler(**kwargs):
            pass

        await context_handler(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["custom_context"] == "custom_value"

    @pytest.mark.asyncio
    async def test_traced_handler_preserves_function_metadata(self):
        """Test traced_handler preserves function name and docstring."""

        @traced_handler("preserve_test")
        async def documented_handler(**kwargs):
            """This is a docstring."""
            pass

        assert documented_handler.__name__ == "documented_handler"
        assert documented_handler.__doc__ == "This is a docstring."

    @pytest.mark.asyncio
    async def test_traced_handler_default_values_for_missing_kwargs(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler uses defaults when namespace/name missing."""

        @traced_handler("no_kwargs_operation")
        async def handler_without_kwargs():
            pass

        await handler_without_kwargs()

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["k8s.namespace"] == "unknown"
        assert span.attributes["k8s.resource.name"] == "unknown"


class TestTraceContextPropagation:
    """Test trace context injection and extraction."""

    def test_inject_trace_context_no_active_span(self):
        """Test inject_trace_context when no span is active."""
        headers: dict[str, str] = {}
        result = inject_trace_context(headers)

        assert result is headers
        # With no active span, no traceparent should be added
        # (or it may add an invalid one - depends on OTEL behavior)

    @pytest.mark.asyncio
    async def test_inject_trace_context_with_active_span(self, module_tracer_provider):
        """Test inject_trace_context adds traceparent to headers."""
        tracer = get_tracer("test")

        with tracer.start_as_current_span("test_span"):
            headers: dict[str, str] = {}
            result = inject_trace_context(headers)

            assert "traceparent" in result
            # traceparent format: version-trace_id-span_id-flags
            assert result["traceparent"].startswith("00-")

    def test_extract_trace_context_empty_headers(self):
        """Test extract_trace_context with no trace headers."""
        headers: dict[str, str] = {}
        context = extract_trace_context(headers)

        # Returns a context even if empty
        assert context is not None

    def test_extract_trace_context_valid_traceparent(self):
        """Test extract_trace_context with valid traceparent."""
        headers = {
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        }
        context = extract_trace_context(headers)

        # Context should be populated
        assert context is not None


class TestIsTracingEnabled:
    """Test is_tracing_enabled function."""

    def test_is_tracing_enabled_when_disabled(self):
        """Test is_tracing_enabled returns False when disabled."""
        setup_tracing(enabled=False)
        assert not is_tracing_enabled()

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_is_tracing_enabled_when_enabled(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test is_tracing_enabled returns True when enabled."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        setup_tracing(enabled=True)
        assert is_tracing_enabled()

    @patch("keycloak_operator.observability.tracing.OTLPSpanExporter")
    @patch("keycloak_operator.observability.tracing.HTTPXClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.AioHttpClientInstrumentor")
    @patch("keycloak_operator.observability.tracing.trace.set_tracer_provider")
    def test_is_tracing_enabled_after_shutdown(
        self,
        mock_set_provider,
        mock_aiohttp_instr,
        mock_httpx_instr,
        mock_exporter,
    ):
        """Test is_tracing_enabled returns False after shutdown."""
        mock_exporter.return_value = MagicMock()
        mock_httpx_instr.return_value.instrument = MagicMock()
        mock_aiohttp_instr.return_value.instrument = MagicMock()

        setup_tracing(enabled=True)
        assert is_tracing_enabled()

        shutdown_tracing()
        assert not is_tracing_enabled()


class TestTracingEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_traced_handler_with_complex_return_value(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler with complex return value."""

        @traced_handler("complex_return")
        async def complex_handler(**kwargs):
            return {
                "status": "success",
                "data": [1, 2, 3],
                "nested": {"key": "value"},
            }

        result = await complex_handler(namespace="ns", name="resource")

        assert result["status"] == "success"
        assert result["data"] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_traced_handler_with_none_return(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler with None return value."""

        @traced_handler("none_return")
        async def none_handler(**kwargs) -> None:
            pass

        result = await none_handler(namespace="ns", name="resource")
        assert result is None

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].status.status_code == StatusCode.OK

    @pytest.mark.asyncio
    async def test_traced_handler_sync_exception(
        self, module_tracer_provider, clear_spans
    ):
        """Test traced_handler sync function with exception."""

        @traced_handler("sync_error")
        def sync_failing(**kwargs):
            raise RuntimeError("Sync error")

        with pytest.raises(RuntimeError, match="Sync error"):
            sync_failing(namespace="ns", name="resource")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].status.status_code == StatusCode.ERROR

    @pytest.mark.asyncio
    async def test_multiple_traced_handlers_create_separate_spans(
        self, module_tracer_provider, clear_spans
    ):
        """Test multiple traced handlers create separate spans."""

        @traced_handler("operation_1")
        async def handler_1(**kwargs):
            pass

        @traced_handler("operation_2")
        async def handler_2(**kwargs):
            pass

        await handler_1(namespace="ns", name="r1")
        await handler_2(namespace="ns", name="r2")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 2
        span_names = {s.name for s in spans}
        assert "operation_1" in span_names
        assert "operation_2" in span_names

    @pytest.mark.asyncio
    async def test_nested_traced_handlers(self, module_tracer_provider, clear_spans):
        """Test nested traced handlers create parent-child spans."""

        @traced_handler("inner_operation_nested")
        async def inner_handler(**kwargs):
            pass

        @traced_handler("outer_operation_nested")
        async def outer_handler(**kwargs):
            await inner_handler(namespace=kwargs.get("namespace"), name="inner")

        await outer_handler(namespace="ns", name="outer")

        spans = clear_spans.get_finished_spans()
        assert len(spans) == 2

        # Inner span should be child of outer span
        inner_span = next(s for s in spans if s.name == "inner_operation_nested")
        outer_span = next(s for s in spans if s.name == "outer_operation_nested")

        assert inner_span.parent is not None
        assert inner_span.parent.span_id == outer_span.context.span_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
