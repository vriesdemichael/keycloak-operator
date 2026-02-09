"""
Unit tests for MetricsServer HTTP endpoints.

Tests the handlers directly using mocked requests to avoid opening sockets,
keeping these strictly as unit tests.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import make_mocked_request
from prometheus_client import CollectorRegistry

from keycloak_operator.observability.metrics import MetricsServer


# ---------------------------------------------------------------------------
# Test Server Endpoints (Direct Handler Testing)
# ---------------------------------------------------------------------------
class TestMetricsEndpoint:
    """Test /metrics endpoint."""

    @pytest.mark.asyncio
    async def test_metrics_returns_200(self):
        """Prometheus scrape endpoint returns 200 with metric data."""
        registry = CollectorRegistry()
        # Add a metric so body is not empty
        from prometheus_client import Gauge

        g = Gauge("test_metric", "help", registry=registry)
        g.set(1)

        server = MetricsServer()
        request = make_mocked_request("GET", "/metrics")

        # We need to patch get_metrics_registry because the handler calls it directly
        with patch(
            "keycloak_operator.observability.metrics.get_metrics_registry",
            return_value=registry,
        ):
            resp = await server._metrics_handler(request)

        assert resp.status == 200
        assert resp.content_type == "text/plain"
        assert resp.charset == "utf-8"
        assert len(resp.body) > 0

    @pytest.mark.asyncio
    async def test_metrics_error_returns_500(self):
        """When generate_latest raises, the handler returns 500."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/metrics")

        with patch(
            "keycloak_operator.observability.metrics.generate_latest",
            side_effect=RuntimeError("boom"),
        ):
            resp = await server._metrics_handler(request)

        assert resp.status == 500
        assert resp.text is not None
        assert "RuntimeError" in resp.text


class TestHealthzEndpoint:
    """Test /healthz endpoint."""

    @pytest.mark.asyncio
    async def test_healthz_returns_200_ok(self):
        """/healthz should always return 200 'ok'."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/healthz")

        resp = await server._healthz_handler(request)

        assert resp.status == 200
        assert resp.text == "ok"


class TestHealthEndpoint:
    """Test /health endpoint."""

    @pytest.mark.asyncio
    async def test_health_healthy_returns_200(self):
        """When HealthChecker reports healthy, return 200."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/health")

        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={"overall": "healthy"})
        mock_checker.to_dict.return_value = {"status": "healthy", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._health_handler(request)

        assert resp.status == 200
        data = json.loads(resp.text)
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_degraded_returns_200(self):
        """Degraded is still 200 (operational but impaired)."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/health")

        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={})
        mock_checker.to_dict.return_value = {"status": "degraded", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._health_handler(request)

        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_health_unhealthy_returns_503(self):
        """When HealthChecker reports unhealthy, return 503."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/health")

        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={})
        mock_checker.to_dict.return_value = {"status": "unhealthy", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._health_handler(request)

        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_health_exception_returns_500(self):
        """When HealthChecker raises, return 500 with error info."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/health")

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            side_effect=RuntimeError("kaboom"),
        ):
            resp = await server._health_handler(request)

        assert resp.status == 500
        data = json.loads(resp.text)
        assert data["status"] == "unhealthy"
        assert "RuntimeError" in data["error"]


class TestReadyEndpoint:
    """Test /ready endpoint."""

    @pytest.mark.asyncio
    async def test_ready_all_healthy_returns_200(self):
        """When K8s API and CRDs are healthy, return 200."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/ready")

        mock_k8s = MagicMock()
        mock_k8s.status = "healthy"
        mock_crds = MagicMock()
        mock_crds.status = "healthy"

        mock_checker = MagicMock()
        mock_checker._check_kubernetes_api = AsyncMock(return_value=mock_k8s)
        mock_checker._check_crds_installed = AsyncMock(return_value=mock_crds)

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._ready_handler(request)

        assert resp.status == 200
        data = json.loads(resp.text)
        assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_ready_k8s_unhealthy_returns_503(self):
        """When K8s API is unhealthy, return 503."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/ready")

        mock_k8s = MagicMock()
        mock_k8s.status = "unhealthy"
        mock_crds = MagicMock()
        mock_crds.status = "healthy"

        mock_checker = MagicMock()
        mock_checker._check_kubernetes_api = AsyncMock(return_value=mock_k8s)
        mock_checker._check_crds_installed = AsyncMock(return_value=mock_crds)

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._ready_handler(request)

        assert resp.status == 503
        data = json.loads(resp.text)
        assert data["status"] == "not_ready"

    @pytest.mark.asyncio
    async def test_ready_crds_unhealthy_returns_503(self):
        """When CRDs are not installed, return 503."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/ready")

        mock_k8s = MagicMock()
        mock_k8s.status = "healthy"
        mock_crds = MagicMock()
        mock_crds.status = "unhealthy"

        mock_checker = MagicMock()
        mock_checker._check_kubernetes_api = AsyncMock(return_value=mock_k8s)
        mock_checker._check_crds_installed = AsyncMock(return_value=mock_crds)

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await server._ready_handler(request)

        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_ready_exception_returns_503(self):
        """When HealthChecker raises, return 503."""
        server = MetricsServer()
        request = make_mocked_request("GET", "/ready")

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            side_effect=RuntimeError("nope"),
        ):
            resp = await server._ready_handler(request)

        assert resp.status == 503
        data = json.loads(resp.text)
        assert "RuntimeError" in data["error"]
