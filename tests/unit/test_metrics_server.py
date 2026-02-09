"""
Unit tests for MetricsServer HTTP endpoints.

Uses ``aiohttp.test_utils`` to drive the server's aiohttp application
without opening real sockets, so the tests work with ``--disable-socket``.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import TestClient, TestServer

from keycloak_operator.observability.metrics import MetricsServer


# ---------------------------------------------------------------------------
# Helper to build a test-client from the MetricsServer app
# ---------------------------------------------------------------------------
@pytest.fixture
def metrics_server():
    """Create a fresh MetricsServer instance per test."""
    return MetricsServer(port=0)  # port doesn't matter for test_utils


@pytest.fixture
def enable_socket(socket_enabled):
    """Enable sockets for aiohttp server tests."""
    pass


@pytest.fixture
async def client(metrics_server, enable_socket):
    """Create an aiohttp TestClient from the MetricsServer app."""
    server = TestServer(metrics_server.app)
    async with TestClient(server) as cli:
        yield cli


# ---------------------------------------------------------------------------
# /metrics endpoint
# ---------------------------------------------------------------------------
class TestMetricsEndpoint:
    """Tests for ``GET /metrics``."""

    @pytest.mark.asyncio
    async def test_metrics_returns_200(self, client):
        """Prometheus scrape endpoint returns 200 with metric data."""
        resp = await client.get("/metrics")
        assert resp.status == 200
        body = await resp.text()
        # Should contain at least the standard process metrics from prometheus_client
        assert len(body) > 0

    @pytest.mark.asyncio
    async def test_metrics_error_returns_500(self, client):
        """When generate_latest raises, the handler returns 500."""
        with patch(
            "keycloak_operator.observability.metrics.generate_latest",
            side_effect=RuntimeError("boom"),
        ):
            resp = await client.get("/metrics")
        assert resp.status == 500
        body = await resp.text()
        assert "RuntimeError" in body


# ---------------------------------------------------------------------------
# /healthz endpoint (simple)
# ---------------------------------------------------------------------------
class TestHealthzEndpoint:
    """Tests for ``GET /healthz`` (K8s liveness probe)."""

    @pytest.mark.asyncio
    async def test_healthz_returns_200_ok(self, client):
        """/healthz should always return 200 'ok'."""
        resp = await client.get("/healthz")
        assert resp.status == 200
        body = await resp.text()
        assert body == "ok"


# ---------------------------------------------------------------------------
# /health endpoint
# ---------------------------------------------------------------------------
class TestHealthEndpoint:
    """Tests for ``GET /health``."""

    @pytest.mark.asyncio
    async def test_health_healthy_returns_200(self, client):
        """When HealthChecker reports healthy, return 200."""
        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={"overall": "healthy"})
        mock_checker.to_dict.return_value = {"status": "healthy", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_degraded_returns_200(self, client):
        """Degraded is still 200 (operational but impaired)."""
        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={})
        mock_checker.to_dict.return_value = {"status": "degraded", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await client.get("/health")
        assert resp.status == 200

    @pytest.mark.asyncio
    async def test_health_unhealthy_returns_503(self, client):
        """When HealthChecker reports unhealthy, return 503."""
        mock_checker = MagicMock()
        mock_checker.check_all = AsyncMock(return_value={})
        mock_checker.to_dict.return_value = {"status": "unhealthy", "checks": {}}

        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            return_value=mock_checker,
        ):
            resp = await client.get("/health")
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_health_exception_returns_500(self, client):
        """When HealthChecker raises, return 500 with error info."""
        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            side_effect=RuntimeError("kaboom"),
        ):
            resp = await client.get("/health")
        assert resp.status == 500
        data = await resp.json()
        assert data["status"] == "unhealthy"
        assert "RuntimeError" in data["error"]


# ---------------------------------------------------------------------------
# /ready endpoint
# ---------------------------------------------------------------------------
class TestReadyEndpoint:
    """Tests for ``GET /ready``."""

    @pytest.mark.asyncio
    async def test_ready_all_healthy_returns_200(self, client):
        """When K8s API and CRDs are healthy, return 200."""
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
            resp = await client.get("/ready")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ready"

    @pytest.mark.asyncio
    async def test_ready_k8s_unhealthy_returns_503(self, client):
        """When K8s API is unhealthy, return 503."""
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
            resp = await client.get("/ready")
        assert resp.status == 503
        data = await resp.json()
        assert data["status"] == "not_ready"

    @pytest.mark.asyncio
    async def test_ready_crds_unhealthy_returns_503(self, client):
        """When CRDs are not installed, return 503."""
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
            resp = await client.get("/ready")
        assert resp.status == 503

    @pytest.mark.asyncio
    async def test_ready_exception_returns_503(self, client):
        """When HealthChecker raises, return 503."""
        with patch(
            "keycloak_operator.observability.health.HealthChecker",
            side_effect=RuntimeError("nope"),
        ):
            resp = await client.get("/ready")
        assert resp.status == 503
        data = await resp.json()
        assert data["status"] == "not_ready"
        assert "RuntimeError" in data["error"]
