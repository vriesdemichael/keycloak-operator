"""
Unit tests for ``_run_keycloak_health_check`` in ``handlers/keycloak.py``.

Each test patches the external dependencies (K8s API, HTTP health check,
admin credentials, resource usage) so the function runs entirely in-memory.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# We test the extracted helper, not the daemon wrapper
from keycloak_operator.handlers.keycloak import _run_keycloak_health_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_patch():
    """Return a kopf-like Patch object with a nested status dict."""
    p = MagicMock()
    p.status = {}
    return p


def _base_patches():
    """Return a dict of ``patch()`` context-managers covering common deps."""
    return {
        "k8s_client": patch(
            "keycloak_operator.handlers.keycloak.get_kubernetes_client",
            return_value=MagicMock(),
        ),
        "health_port": patch(
            "keycloak_operator.handlers.keycloak.get_health_port",
            return_value=8080,
        ),
        "resource_usage": patch(
            "keycloak_operator.handlers.keycloak.get_pod_resource_usage",
            return_value={"pods": [], "failed_pods": 0, "pending_pods": 0},
        ),
        "admin_creds": patch(
            "keycloak_operator.handlers.keycloak.get_admin_credentials",
            return_value=None,
        ),
        "http_health": patch(
            "keycloak_operator.handlers.keycloak.check_http_health",
            new_callable=AsyncMock,
            return_value=(True, None),
        ),
    }


def _ready_deployment():
    """Return a mock deployment that reports fully ready."""
    dep = MagicMock()
    dep.status.ready_replicas = 1
    dep.spec.replicas = 1
    dep.status.conditions = []
    return dep


# ---------------------------------------------------------------------------
# Deployment not found (404)
# ---------------------------------------------------------------------------
class TestDeploymentNotFound:
    @pytest.mark.asyncio
    async def test_deployment_404_sets_failed(self):
        """When the deployment is missing, phase should be Failed."""
        from kubernetes.client.rest import ApiException

        kpatch = _make_patch()
        status = {"phase": "Ready"}

        with (
            _base_patches()["k8s_client"],
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
        ):
            mock_apps.return_value.read_namespaced_deployment_status.side_effect = (
                ApiException(status=404, reason="Not Found")
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Failed"
        assert "not found" in kpatch.status["message"].lower()


# ---------------------------------------------------------------------------
# Deployment not ready
# ---------------------------------------------------------------------------
class TestDeploymentNotReady:
    @pytest.mark.asyncio
    async def test_zero_ready_replicas_sets_degraded(self):
        """When no replicas are ready, phase should be Degraded."""
        kpatch = _make_patch()
        status = {"phase": "Ready"}

        dep = MagicMock()
        dep.status.ready_replicas = 0
        dep.spec.replicas = 1

        with (
            _base_patches()["k8s_client"],
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = dep

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Degraded"
        assert "not ready" in kpatch.status["message"].lower()


# ---------------------------------------------------------------------------
# Keycloak not responding to health checks
# ---------------------------------------------------------------------------
class TestKeycloakNotResponding:
    @pytest.mark.asyncio
    async def test_http_health_failure_sets_degraded(self):
        """When Keycloak doesn't respond to health checks, phase is Degraded."""
        kpatch = _make_patch()
        status = {"phase": "Ready"}

        with (
            _base_patches()["k8s_client"],
            _base_patches()["health_port"],
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
            patch(
                "keycloak_operator.handlers.keycloak.check_http_health",
                new_callable=AsyncMock,
                return_value=(False, "Connection refused"),
            ),
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = (
                _ready_deployment()
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Degraded"
        assert "health check" in kpatch.status["message"].lower()


# ---------------------------------------------------------------------------
# Everything healthy → Ready
# ---------------------------------------------------------------------------
class TestAllHealthy:
    @pytest.mark.asyncio
    async def test_healthy_sets_ready(self):
        """When deployment is ready, Keycloak responds, admin creds absent → Ready."""
        kpatch = _make_patch()
        status = {"phase": "Degraded"}

        with (
            _base_patches()["k8s_client"],
            _base_patches()["health_port"],
            _base_patches()["resource_usage"],
            _base_patches()["admin_creds"],
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
            patch(
                "keycloak_operator.handlers.keycloak.check_http_health",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
            patch(
                "keycloak_operator.handlers.keycloak._record_instance_status"
            ) as mock_record,
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = (
                _ready_deployment()
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Ready"
        mock_record.assert_called_once_with("ns", running=True)


# ---------------------------------------------------------------------------
# Already Ready — no status change
# ---------------------------------------------------------------------------
class TestAlreadyReady:
    @pytest.mark.asyncio
    async def test_already_ready_keeps_phase(self):
        """When already in Ready phase and healthy, status dict phase is not re-set."""
        kpatch = _make_patch()
        status = {"phase": "Ready"}

        with (
            _base_patches()["k8s_client"],
            _base_patches()["health_port"],
            _base_patches()["resource_usage"],
            _base_patches()["admin_creds"],
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
            patch(
                "keycloak_operator.handlers.keycloak.check_http_health",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
            patch(
                "keycloak_operator.handlers.keycloak._record_instance_status"
            ) as mock_record,
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = (
                _ready_deployment()
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        # Phase should NOT be written because it's already "Ready"
        assert "phase" not in kpatch.status
        # But the metric should still fire
        mock_record.assert_called_once_with("ns", running=True)


# ---------------------------------------------------------------------------
# Admin API failure → Degraded
# ---------------------------------------------------------------------------
class TestAdminApiFailure:
    @pytest.mark.asyncio
    async def test_admin_api_error_sets_degraded(self):
        """When admin API check fails, phase should be Degraded."""
        kpatch = _make_patch()
        status = {"phase": "Degraded"}

        mock_admin = AsyncMock()
        mock_admin.__aenter__ = AsyncMock(return_value=mock_admin)
        mock_admin.__aexit__ = AsyncMock(return_value=False)
        mock_admin.authenticate = AsyncMock(side_effect=ConnectionError("refused"))

        with (
            _base_patches()["k8s_client"],
            _base_patches()["health_port"],
            _base_patches()["resource_usage"],
            patch(
                "keycloak_operator.handlers.keycloak.get_admin_credentials",
                return_value=("admin", "admin"),
            ),
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
            patch(
                "keycloak_operator.handlers.keycloak.check_http_health",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
            patch(
                "keycloak_operator.handlers.keycloak.KeycloakAdminClient",
                return_value=mock_admin,
            ),
            patch("keycloak_operator.handlers.keycloak._record_instance_status"),
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = (
                _ready_deployment()
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Degraded"
        assert "admin api" in kpatch.status["message"].lower()


# ---------------------------------------------------------------------------
# Top-level exception → Degraded + metric
# ---------------------------------------------------------------------------
class TestTopLevelException:
    @pytest.mark.asyncio
    async def test_unexpected_error_sets_degraded_and_records_metric(self):
        """When an unexpected exception occurs, status → Degraded and metric recorded."""
        kpatch = _make_patch()
        status = {"phase": "Ready"}

        with (
            patch(
                "keycloak_operator.handlers.keycloak.get_kubernetes_client",
                side_effect=RuntimeError("oops"),
            ),
            patch(
                "keycloak_operator.handlers.keycloak._record_instance_status"
            ) as mock_record,
        ):
            await _run_keycloak_health_check(
                spec={},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Degraded"
        assert "Health check failed" in kpatch.status["message"]
        mock_record.assert_called_once_with("ns", running=False)


# ---------------------------------------------------------------------------
# Failed pods → Degraded
# ---------------------------------------------------------------------------
class TestFailedPods:
    @pytest.mark.asyncio
    async def test_failed_pods_sets_degraded(self):
        """When resource usage reports failed pods, phase is Degraded."""
        kpatch = _make_patch()
        status = {"phase": "Ready"}

        with (
            _base_patches()["k8s_client"],
            _base_patches()["health_port"],
            _base_patches()["admin_creds"],
            patch(
                "keycloak_operator.handlers.keycloak.get_pod_resource_usage",
                return_value={"pods": [], "failed_pods": 2, "pending_pods": 0},
            ),
            patch("keycloak_operator.handlers.keycloak.client.AppsV1Api") as mock_apps,
            patch(
                "keycloak_operator.handlers.keycloak.check_http_health",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
        ):
            mock_apps.return_value.read_namespaced_deployment_status.return_value = (
                _ready_deployment()
            )

            await _run_keycloak_health_check(
                spec={"image": "quay.io/keycloak/keycloak:25.0.0"},
                name="kc",
                namespace="ns",
                status=status,
                patch=kpatch,
                meta={},
                memo=MagicMock(),
            )

        assert kpatch.status["phase"] == "Degraded"
        assert "failed pods" in kpatch.status["message"].lower()
