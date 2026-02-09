"""
Unit tests for _record_instance_status helper in handlers/keycloak.py.

Tests the Prometheus metric recording for Keycloak instance status.
"""

from unittest.mock import patch


class TestRecordInstanceStatus:
    """Test _record_instance_status function."""

    def test_running_true_sets_gauge_to_1(self):
        """When running=True, gauge is set to 1."""
        with patch(
            "keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS"
        ) as mock_metric:
            from keycloak_operator.handlers.keycloak import _record_instance_status

            _record_instance_status("test-ns", running=True)
            mock_metric.labels.assert_called_with(namespace="test-ns")
            mock_metric.labels().set.assert_called_with(1)

    def test_running_false_sets_gauge_to_0(self):
        """When running=False, gauge is set to 0."""
        with patch(
            "keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS"
        ) as mock_metric:
            from keycloak_operator.handlers.keycloak import _record_instance_status

            _record_instance_status("test-ns", running=False)
            mock_metric.labels.assert_called_with(namespace="test-ns")
            mock_metric.labels().set.assert_called_with(0)

    def test_import_error_handled_gracefully(self):
        """If metrics import fails, no exception is raised."""
        with patch(
            "keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS",
            side_effect=ImportError("boom"),
        ):
            from keycloak_operator.handlers.keycloak import _record_instance_status

            # Should not raise
            _record_instance_status("test-ns", running=True)

    def test_metric_error_handled_gracefully(self):
        """If metric call raises, exception is swallowed."""
        with patch(
            "keycloak_operator.observability.metrics.KEYCLOAK_INSTANCE_STATUS"
        ) as mock_metric:
            mock_metric.labels.side_effect = RuntimeError("metric broken")

            from keycloak_operator.handlers.keycloak import _record_instance_status

            # Should not raise
            _record_instance_status("test-ns", running=True)
