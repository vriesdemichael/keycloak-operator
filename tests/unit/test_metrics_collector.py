"""
Unit tests for MetricsCollector methods in observability/metrics.py.

Tests the individual methods of MetricsCollector to verify they call the
correct Prometheus metric objects with the correct label values.
"""

from unittest.mock import MagicMock, patch

import pytest

from keycloak_operator.observability.metrics import MetricsCollector


@pytest.fixture
def collector():
    """Create a MetricsCollector with the registry init patched out."""
    with patch(
        "keycloak_operator.observability.metrics.get_metrics_registry",
        return_value=MagicMock(),
    ):
        return MetricsCollector()


class TestMetricsCollectorLeaderElection:
    """Test leader election metric methods."""

    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_STATUS")
    def test_update_leader_election_status_leader(self, mock_status, collector):
        """Setting is_leader=True sets gauge to 1."""
        collector.update_leader_election_status("pod-abc", is_leader=True)
        mock_status.labels.assert_called_with(instance_id="pod-abc")
        mock_status.labels().set.assert_called_with(1)

    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_STATUS")
    def test_update_leader_election_status_follower(self, mock_status, collector):
        """Setting is_leader=False sets gauge to 0."""
        collector.update_leader_election_status("pod-xyz", is_leader=False)
        mock_status.labels.assert_called_with(instance_id="pod-xyz")
        mock_status.labels().set.assert_called_with(0)

    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_CHANGES")
    def test_record_leader_election_change(self, mock_changes, collector):
        """Recording a leader change increments the counter."""
        collector.record_leader_election_change()
        mock_changes.inc.assert_called_once()

    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_LEASE_DURATION")
    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_LEASE_RENEWALS")
    def test_record_lease_renewal_success(
        self, mock_renewals, mock_duration, collector
    ):
        """Successful lease renewal records both counter and histogram."""
        collector.record_lease_renewal("pod-abc", success=True, duration=0.05)
        mock_renewals.labels.assert_called_with(instance_id="pod-abc", result="success")
        mock_renewals.labels().inc.assert_called_once()
        mock_duration.labels.assert_called_with(instance_id="pod-abc")
        mock_duration.labels().observe.assert_called_with(0.05)

    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_LEASE_DURATION")
    @patch("keycloak_operator.observability.metrics.LEADER_ELECTION_LEASE_RENEWALS")
    def test_record_lease_renewal_failure(
        self, mock_renewals, mock_duration, collector
    ):
        """Failed lease renewal records result='failure'."""
        collector.record_lease_renewal("pod-abc", success=False, duration=1.5)
        mock_renewals.labels.assert_called_with(instance_id="pod-abc", result="failure")
        mock_renewals.labels().inc.assert_called_once()


class TestMetricsCollectorReconciliation:
    """Test reconciliation metric methods."""

    @patch("keycloak_operator.observability.metrics.RECONCILIATION_SKIPPED_TOTAL")
    def test_record_reconciliation_skip(self, mock_skipped, collector):
        """Skipping reconciliation increments the counter with correct labels."""
        collector.record_reconciliation_skip("realm", "ns-a", "my-realm")
        mock_skipped.labels.assert_called_with(
            resource_type="realm",
            namespace="ns-a",
        )
        mock_skipped.labels().inc.assert_called_once()

    @patch("keycloak_operator.observability.metrics.ACTIVE_RESOURCES")
    def test_update_resource_status(self, mock_active, collector):
        """Updating resource status sets the gauge with correct labels."""
        collector.update_resource_status("client", "ns-b", "Ready", count=5)
        mock_active.labels.assert_called_with(
            resource_type="client",
            namespace="ns-b",
            phase="Ready",
        )
        mock_active.labels().set.assert_called_with(5)

    @patch("keycloak_operator.observability.metrics.ACTIVE_RESOURCES")
    def test_update_resource_status_default_count(self, mock_active, collector):
        """Default count is 1."""
        collector.update_resource_status("realm", "ns-a", "Degraded")
        mock_active.labels().set.assert_called_with(1)

    @pytest.mark.asyncio
    @patch("keycloak_operator.observability.metrics.RECONCILIATION_DURATION")
    @patch("keycloak_operator.observability.metrics.RECONCILIATION_TOTAL")
    async def test_track_reconciliation_success(
        self, mock_total, mock_duration, collector
    ):
        """Successful reconciliation records total and duration."""
        async with collector.track_reconciliation("realm", "ns-a", "my-realm"):
            pass  # simulate successful reconciliation

        mock_total.labels.assert_called_with(
            resource_type="realm",
            namespace="ns-a",
            result="success",
        )
        mock_total.labels().inc.assert_called_once()
        mock_duration.labels.assert_called_with(
            resource_type="realm",
            namespace="ns-a",
            operation="reconcile",
        )
        mock_duration.labels().observe.assert_called_once()

    @pytest.mark.asyncio
    @patch("keycloak_operator.observability.metrics.RECONCILIATION_ERRORS")
    @patch("keycloak_operator.observability.metrics.RECONCILIATION_DURATION")
    @patch("keycloak_operator.observability.metrics.RECONCILIATION_TOTAL")
    async def test_track_reconciliation_error(
        self, mock_total, mock_duration, mock_errors, collector
    ):
        """Failed reconciliation records error counter with error type."""
        exc = ValueError("boom")
        with pytest.raises(ValueError, match="boom"):
            async with collector.track_reconciliation("client", "ns-b", "my-client"):
                raise exc

        # Assertions are outside the with-block; the exception was caught by pytest.raises
        mock_total.labels.assert_called_with(
            resource_type="client",
            namespace="ns-b",
            result="error",
        )
        mock_errors.labels.assert_called_with(
            resource_type="client",
            namespace="ns-b",
            error_type="ValueError",
            retryable="false",
        )
        mock_errors.labels().inc.assert_called_once()


class TestMetricsCollectorDatabase:
    """Test database metric methods."""

    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_DURATION")
    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS")
    def test_record_database_connection_test_success(
        self, mock_status, mock_duration, collector
    ):
        """Successful DB connection sets gauge=1 and observes duration."""
        collector.record_database_connection_test("ns-a", "postgresql", True, 0.25)
        mock_status.labels.assert_called_with(
            namespace="ns-a",
            database_type="postgresql",
        )
        mock_status.labels().set.assert_called_with(1)
        mock_duration.labels.assert_called_with(
            namespace="ns-a",
            database_type="postgresql",
        )
        mock_duration.labels().observe.assert_called_with(0.25)

    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_DURATION")
    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS")
    def test_record_database_connection_test_failure(
        self, mock_status, mock_duration, collector
    ):
        """Failed DB connection sets gauge=0."""
        collector.record_database_connection_test("ns-a", "postgresql", False, 5.0)
        mock_status.labels().set.assert_called_with(0)


class TestMetricsCollectorInstanceStatus:
    """Test instance/cluster status metric methods."""

    @patch("keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS")
    def test_update_keycloak_instance_status_running(self, mock_status, collector):
        """Running=True sets gauge to 1."""
        collector.update_keycloak_instance_status("ns-a", running=True)
        mock_status.labels.assert_called_with(namespace="ns-a")
        mock_status.labels().set.assert_called_with(1)

    @patch("keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS")
    def test_update_keycloak_instance_status_not_running(self, mock_status, collector):
        """Running=False sets gauge to 0."""
        collector.update_keycloak_instance_status("ns-a", running=False)
        mock_status.labels().set.assert_called_with(0)

    @patch("keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS")
    def test_update_cnpg_cluster_status_healthy(self, mock_status, collector):
        """Healthy=True sets gauge to 1."""
        collector.update_cnpg_cluster_status("ns-a", healthy=True)
        mock_status.labels.assert_called_with(namespace="ns-a")
        mock_status.labels().set.assert_called_with(1)

    @patch("keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS")
    def test_update_cnpg_cluster_status_unhealthy(self, mock_status, collector):
        """Healthy=False sets gauge to 0."""
        collector.update_cnpg_cluster_status("ns-a", healthy=False)
        mock_status.labels().set.assert_called_with(0)


class TestMetricsCollectorRbac:
    """Test RBAC validation metric methods."""

    @patch("keycloak_operator.observability.metrics.RBAC_VALIDATIONS")
    def test_record_rbac_validation_success(self, mock_rbac, collector):
        """Successful RBAC validation records result='success'."""
        collector.record_rbac_validation("src-ns", "tgt-ns", success=True)
        mock_rbac.labels.assert_called_with(
            source_namespace="src-ns",
            target_namespace="tgt-ns",
            result="success",
        )
        mock_rbac.labels().inc.assert_called_once()

    @patch("keycloak_operator.observability.metrics.RBAC_VALIDATIONS")
    def test_record_rbac_validation_failure(self, mock_rbac, collector):
        """Failed RBAC validation records result='failure'."""
        collector.record_rbac_validation("src-ns", "tgt-ns", success=False)
        mock_rbac.labels.assert_called_with(
            source_namespace="src-ns",
            target_namespace="tgt-ns",
            result="failure",
        )
