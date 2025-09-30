"""
Unit tests for leader election failure scenarios.

Tests various failure modes and edge cases in leader election behavior
to ensure robustness and proper error handling.
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.observability.leader_election import (
    LeaderElectionMonitor,
    get_leader_election_monitor,
)


class TestLeaderElectionFailureScenarios:
    """Test failure scenarios for leader election."""

    @pytest.fixture
    def monitor(self):
        """Create a leader election monitor for testing."""
        with patch.dict(os.environ, {"POD_NAME": "test-operator-pod"}):
            return LeaderElectionMonitor()

    def test_instance_id_generation_fallbacks(self):
        """Test instance ID generation with various environment conditions."""
        # Test with POD_NAME set
        with patch.dict(os.environ, {"POD_NAME": "test-pod-123"}):
            monitor = LeaderElectionMonitor()
            assert monitor.instance_id == "test-pod-123"

        # Test without POD_NAME but with hostname
        with patch.dict(os.environ, {}, clear=True):
            with patch("platform.node", return_value="test-hostname"):
                monitor = LeaderElectionMonitor()
                assert monitor.instance_id == "test-hostname"

        # Test without POD_NAME or hostname (fallback to UUID)
        with patch.dict(os.environ, {}, clear=True):
            with patch("platform.node", return_value=""):
                with patch("uuid.uuid4") as mock_uuid:
                    mock_uuid.return_value.hex = "abcdef1234567890"
                    monitor = LeaderElectionMonitor()
                    assert monitor.instance_id == "operator-abcdef12"

    def test_leadership_acquired_metrics(self, monitor):
        """Test metrics collection when leadership is acquired."""
        with patch.object(monitor, "previous_leader", "old-leader"):
            with patch(
                "keycloak_operator.observability.leader_election.metrics_collector"
            ) as mock_metrics:
                monitor.on_leadership_acquired()

                # Verify leadership change was recorded
                mock_metrics.record_leader_election_change.assert_called_once_with(
                    previous_leader="old-leader",
                    new_leader=monitor.instance_id,
                    namespace=monitor.namespace,
                )

                # Verify status was updated
                mock_metrics.update_leader_election_status.assert_called_once_with(
                    instance_id=monitor.instance_id,
                    namespace=monitor.namespace,
                    is_leader=True,
                )

                # Verify state changes
                assert monitor.is_leader is True
                assert monitor.previous_leader == monitor.instance_id

    def test_leadership_lost_metrics(self, monitor):
        """Test metrics collection when leadership is lost."""
        monitor.is_leader = True

        with patch(
            "keycloak_operator.observability.leader_election.metrics_collector"
        ) as mock_metrics:
            monitor.on_leadership_lost()

            # Verify status was updated
            mock_metrics.update_leader_election_status.assert_called_once_with(
                instance_id=monitor.instance_id,
                namespace=monitor.namespace,
                is_leader=False,
            )

            # Verify state changes
            assert monitor.is_leader is False

    @pytest.mark.asyncio
    async def test_leadership_check_api_exception(self, monitor):
        """Test leadership check when Kubernetes API fails."""
        with patch.object(
            monitor, "_get_current_leader", side_effect=ApiException("API Error")
        ):
            result = await monitor.check_leadership_status()
            assert result is False

    @pytest.mark.asyncio
    async def test_leadership_check_general_exception(self, monitor):
        """Test leadership check when unexpected exception occurs."""
        with patch.object(
            monitor, "_get_current_leader", side_effect=Exception("Unexpected error")
        ):
            result = await monitor.check_leadership_status()
            assert result is False

    @pytest.mark.asyncio
    async def test_leadership_transition_from_leader_to_follower(self, monitor):
        """Test transition from leader to follower."""
        monitor.is_leader = True
        monitor.previous_leader = monitor.instance_id

        with patch.object(monitor, "_get_current_leader", return_value="other-leader"):
            with patch.object(monitor, "on_leadership_lost") as mock_lost:
                with patch(
                    "keycloak_operator.observability.leader_election.metrics_collector"
                ) as mock_metrics:
                    result = await monitor.check_leadership_status()

                    assert result is False
                    assert monitor.is_leader is False
                    mock_lost.assert_called_once()
                    mock_metrics.update_leader_election_status.assert_called_once_with(
                        instance_id=monitor.instance_id,
                        namespace=monitor.namespace,
                        is_leader=False,
                    )

    @pytest.mark.asyncio
    async def test_leadership_transition_from_follower_to_leader(self, monitor):
        """Test transition from follower to leader."""
        monitor.is_leader = False
        monitor.previous_leader = "other-leader"

        with patch.object(
            monitor, "_get_current_leader", return_value=monitor.instance_id
        ):
            with patch.object(monitor, "on_leadership_acquired") as mock_acquired:
                with patch(
                    "keycloak_operator.observability.leader_election.metrics_collector"
                ) as mock_metrics:
                    result = await monitor.check_leadership_status()

                    assert result is True
                    assert monitor.is_leader is True
                    mock_acquired.assert_called_once()
                    mock_metrics.update_leader_election_status.assert_called_once_with(
                        instance_id=monitor.instance_id,
                        namespace=monitor.namespace,
                        is_leader=True,
                    )

    @pytest.mark.asyncio
    async def test_get_current_leader_no_lease(self, monitor):
        """Test getting current leader when no lease exists."""
        mock_api = MagicMock()
        mock_api.read_namespaced_lease.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        with patch(
            "keycloak_operator.observability.leader_election.client"
        ) as mock_client:
            with patch("keycloak_operator.observability.leader_election.config"):
                mock_client.CoordinationV1Api.return_value = mock_api

                result = await monitor._get_current_leader()
                assert result is None

    @pytest.mark.asyncio
    async def test_get_current_leader_api_error(self, monitor):
        """Test getting current leader when API returns error."""
        mock_api = MagicMock()
        mock_api.read_namespaced_lease.side_effect = ApiException(
            status=500, reason="Server Error"
        )

        with patch(
            "keycloak_operator.observability.leader_election.client"
        ) as mock_client:
            with patch("keycloak_operator.observability.leader_election.config"):
                mock_client.CoordinationV1Api.return_value = mock_api

                result = await monitor._get_current_leader()
                assert result is None

    @pytest.mark.asyncio
    async def test_get_current_leader_success(self, monitor):
        """Test getting current leader successfully."""
        mock_lease = MagicMock()
        mock_lease.spec.holder_identity = "current-leader-id"

        mock_api = MagicMock()
        mock_api.read_namespaced_lease.return_value = mock_lease

        with patch(
            "keycloak_operator.observability.leader_election.client"
        ) as mock_client:
            with patch("keycloak_operator.observability.leader_election.config"):
                mock_client.CoordinationV1Api.return_value = mock_api

                result = await monitor._get_current_leader()
                assert result == "current-leader-id"

    @pytest.mark.asyncio
    async def test_get_current_leader_no_holder(self, monitor):
        """Test getting current leader when lease has no holder."""
        mock_lease = MagicMock()
        mock_lease.spec.holder_identity = None

        mock_api = MagicMock()
        mock_api.read_namespaced_lease.return_value = mock_lease

        with patch(
            "keycloak_operator.observability.leader_election.client"
        ) as mock_client:
            with patch("keycloak_operator.observability.leader_election.config"):
                mock_client.CoordinationV1Api.return_value = mock_api

                result = await monitor._get_current_leader()
                assert result is None

    def test_lease_renewal_success_metrics(self, monitor):
        """Test lease renewal success metrics."""
        with patch(
            "keycloak_operator.observability.leader_election.metrics_collector"
        ) as mock_metrics:
            monitor.record_lease_renewal(success=True, duration=0.123)

            mock_metrics.record_lease_renewal.assert_called_once_with(
                instance_id=monitor.instance_id,
                namespace=monitor.namespace,
                success=True,
                duration=0.123,
            )

    def test_lease_renewal_failure_metrics(self, monitor):
        """Test lease renewal failure metrics."""
        with patch(
            "keycloak_operator.observability.leader_election.metrics_collector"
        ) as mock_metrics:
            monitor.record_lease_renewal(success=False, duration=5.0)

            mock_metrics.record_lease_renewal.assert_called_once_with(
                instance_id=monitor.instance_id,
                namespace=monitor.namespace,
                success=False,
                duration=5.0,
            )

    def test_global_monitor_singleton(self):
        """Test that get_leader_election_monitor returns singleton."""
        # Clear any existing global instance
        import keycloak_operator.observability.leader_election as le_module

        le_module._leader_election_monitor = None

        monitor1 = get_leader_election_monitor()
        monitor2 = get_leader_election_monitor()

        assert monitor1 is monitor2

    @pytest.mark.asyncio
    async def test_network_partition_scenario(self, monitor):
        """Test behavior during network partition scenario."""

        # Simulate network partition where API calls timeout
        async def timeout_side_effect(*args, **kwargs):
            raise TimeoutError("Network timeout")

        with patch.object(
            monitor, "_get_current_leader", side_effect=timeout_side_effect
        ):
            result = await monitor.check_leadership_status()
            assert result is False

    @pytest.mark.asyncio
    async def test_rapid_leadership_changes(self, monitor):
        """Test rapid leadership changes (flapping scenario)."""
        # Simulate rapid changes between leaders
        leaders = [
            monitor.instance_id,
            "other-leader",
            monitor.instance_id,
            "third-leader",
        ]

        with patch(
            "keycloak_operator.observability.leader_election.metrics_collector"
        ) as mock_metrics:
            for _, leader in enumerate(leaders):
                with patch.object(monitor, "_get_current_leader", return_value=leader):
                    await monitor.check_leadership_status()

        # Should have recorded multiple status updates
        assert mock_metrics.update_leader_election_status.call_count == len(leaders)

    @pytest.mark.asyncio
    async def test_kubernetes_config_loading_failure(self, monitor):
        """Test behavior when Kubernetes config loading fails."""
        with patch(
            "keycloak_operator.observability.leader_election.config"
        ) as mock_config:
            mock_config.load_incluster_config.side_effect = Exception(
                "Config load failed"
            )
            mock_config.load_kube_config.side_effect = Exception("Config load failed")

            result = await monitor._get_current_leader()
            assert result is None

    @pytest.mark.asyncio
    async def test_concurrent_leadership_checks(self, monitor):
        """Test concurrent leadership status checks don't interfere."""

        async def check_with_delay():
            await asyncio.sleep(0.1)
            return await monitor.check_leadership_status()

        with patch.object(
            monitor, "_get_current_leader", return_value=monitor.instance_id
        ):
            tasks = [check_with_delay() for _ in range(5)]
            results = await asyncio.gather(*tasks)

        # All checks should succeed
        assert all(results)


class TestLeaderElectionEventHandlers:
    """Test Kopf event handlers for leader election."""

    @pytest.mark.asyncio
    async def test_lease_event_handler_correct_lease(self):
        """Test lease event handler for correct lease."""
        from keycloak_operator.observability.leader_election import on_lease_event

        event = {"type": "MODIFIED"}
        name = "keycloak-operator"
        namespace = "keycloak-system"

        mock_monitor = MagicMock()
        mock_monitor.namespace = namespace
        mock_monitor.check_leadership_status = AsyncMock()

        with patch(
            "keycloak_operator.observability.leader_election.get_leader_election_monitor",
            return_value=mock_monitor,
        ):
            await on_lease_event(event=event, name=name, namespace=namespace)

        mock_monitor.check_leadership_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_lease_event_handler_wrong_lease(self):
        """Test lease event handler ignores wrong lease."""
        from keycloak_operator.observability.leader_election import on_lease_event

        event = {"type": "MODIFIED"}
        name = "other-operator"
        namespace = "keycloak-system"

        mock_monitor = MagicMock()
        mock_monitor.namespace = namespace
        mock_monitor.check_leadership_status = AsyncMock()

        with patch(
            "keycloak_operator.observability.leader_election.get_leader_election_monitor",
            return_value=mock_monitor,
        ):
            await on_lease_event(event=event, name=name, namespace=namespace)

        mock_monitor.check_leadership_status.assert_not_called()

    @pytest.mark.asyncio
    async def test_periodic_leadership_check_own_pod(self):
        """Test periodic leadership check for own pod."""
        from keycloak_operator.observability.leader_election import (
            periodic_leadership_check,
        )

        mock_monitor = MagicMock()
        mock_monitor.check_leadership_status = AsyncMock()

        with patch(
            "keycloak_operator.observability.leader_election.get_leader_election_monitor",
            return_value=mock_monitor,
        ):
            with patch.dict(os.environ, {"POD_NAME": "test-pod"}):
                await periodic_leadership_check(name="test-pod")

        mock_monitor.check_leadership_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_periodic_leadership_check_other_pod(self):
        """Test periodic leadership check ignores other pods."""
        from keycloak_operator.observability.leader_election import (
            periodic_leadership_check,
        )

        mock_monitor = MagicMock()
        mock_monitor.check_leadership_status = AsyncMock()

        with patch(
            "keycloak_operator.observability.leader_election.get_leader_election_monitor",
            return_value=mock_monitor,
        ):
            with patch.dict(os.environ, {"POD_NAME": "our-pod"}):
                await periodic_leadership_check(name="other-pod")

        mock_monitor.check_leadership_status.assert_not_called()
