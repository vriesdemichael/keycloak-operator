"""
Unit tests for health daemon structure in handlers.

Tests the daemon loop pattern shared by monitor_keycloak_health,
monitor_realm_health, and monitor_client_health:
- Jitter on startup
- Phase skip logic
- deletionTimestamp early return
- stopped signal exits loop
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.handlers.client import monitor_client_health
from keycloak_operator.handlers.keycloak import monitor_keycloak_health
from keycloak_operator.handlers.realm import monitor_realm_health


class TestKeycloakHealthDaemon:
    """Test monitor_keycloak_health daemon structure."""

    @pytest.fixture
    def mock_stopped(self):
        """Create a mock DaemonStopped that runs one iteration then stops."""
        stopped = MagicMock()
        stopped.__bool__ = MagicMock(side_effect=[False, True])
        stopped.wait = AsyncMock(return_value=True)
        return stopped

    @pytest.fixture
    def base_kwargs(self):
        """Create base kwargs for the daemon call."""
        return {
            "spec": {"hostname": "kc.example.com"},
            "name": "keycloak",
            "namespace": "test-ns",
            "status": MagicMock(),
            "patch": MagicMock(),
            "meta": {},
            "memo": MagicMock(),
        }

    @pytest.mark.asyncio
    async def test_deletion_timestamp_returns_early(self, mock_stopped, base_kwargs):
        """Daemon returns early if deletionTimestamp is set."""
        base_kwargs["meta"] = {"deletionTimestamp": "2025-01-01T00:00:00Z"}
        base_kwargs["status"].get = MagicMock(return_value="Ready")

        with (
            patch(
                "keycloak_operator.handlers.keycloak._run_keycloak_health_check",
                new_callable=AsyncMock,
            ) as mock_check,
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
        ):
            await monitor_keycloak_health(stopped=mock_stopped, **base_kwargs)

            # _run_keycloak_health_check should NOT be called
            mock_check.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "phase",
        ["Failed", "Pending", "Unknown", "Provisioning", "Updating", "Reconciling"],
    )
    async def test_skipped_phases(self, phase, mock_stopped, base_kwargs):
        """Daemon skips _run_keycloak_health_check for non-stable phases."""
        base_kwargs["meta"] = {}
        base_kwargs["status"].get = MagicMock(return_value=phase)

        with (
            patch(
                "keycloak_operator.handlers.keycloak._run_keycloak_health_check",
                new_callable=AsyncMock,
            ) as mock_check,
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
        ):
            await monitor_keycloak_health(stopped=mock_stopped, **base_kwargs)

            mock_check.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("phase", ["Ready", "Degraded"])
    async def test_stable_phases_run_health_check(
        self, phase, mock_stopped, base_kwargs
    ):
        """Daemon calls _run_keycloak_health_check for Ready/Degraded phases."""
        base_kwargs["meta"] = {}
        base_kwargs["status"].get = MagicMock(return_value=phase)

        with (
            patch(
                "keycloak_operator.handlers.keycloak._run_keycloak_health_check",
                new_callable=AsyncMock,
            ) as mock_check,
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
        ):
            await monitor_keycloak_health(stopped=mock_stopped, **base_kwargs)

            mock_check.assert_called_once()


class TestRealmHealthDaemon:
    """Test monitor_realm_health daemon structure."""

    @pytest.fixture
    def mock_stopped(self):
        stopped = MagicMock()
        stopped.__bool__ = MagicMock(side_effect=[False, True])
        stopped.wait = AsyncMock(return_value=True)
        return stopped

    @pytest.fixture
    def base_kwargs(self):
        return {
            "spec": {"realmName": "test"},
            "name": "test-realm",
            "namespace": "test-ns",
            "status": {},
            "patch": MagicMock(),
            "meta": {},
            "memo": MagicMock(),
        }

    @pytest.mark.asyncio
    async def test_skipped_phases(self, mock_stopped, base_kwargs):
        base_kwargs["status"] = {"phase": "Updating"}

        with (
            patch(
                "keycloak_operator.handlers.realm._run_realm_health_check",
                new_callable=AsyncMock,
            ) as mock_check,
            patch(
                "keycloak_operator.handlers.realm.is_managed_by_this_operator",
                return_value=True,
            ),
        ):
            await monitor_realm_health(stopped=mock_stopped, **base_kwargs)
            mock_check.assert_not_called()


class TestClientHealthDaemon:
    """Test monitor_client_health daemon structure."""

    @pytest.fixture
    def mock_stopped(self):
        stopped = MagicMock()
        stopped.__bool__ = MagicMock(side_effect=[False, True])
        stopped.wait = AsyncMock(return_value=True)
        return stopped

    @pytest.fixture
    def base_kwargs(self):
        return {
            "spec": {"clientId": "test"},
            "name": "test-client",
            "namespace": "test-ns",
            "status": {},
            "patch": MagicMock(),
            "meta": {},
            "memo": MagicMock(),
        }

    @pytest.mark.asyncio
    async def test_skipped_phases(self, mock_stopped, base_kwargs):
        base_kwargs["status"] = {"phase": "Provisioning"}

        with (
            patch(
                "keycloak_operator.handlers.client._run_client_health_check",
                new_callable=AsyncMock,
            ) as mock_check,
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                return_value=True,
            ),
            patch("keycloak_operator.handlers.client.get_kubernetes_client"),
        ):
            await monitor_client_health(stopped=mock_stopped, **base_kwargs)
            mock_check.assert_not_called()
