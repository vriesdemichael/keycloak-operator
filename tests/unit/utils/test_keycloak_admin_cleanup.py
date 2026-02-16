"""Unit tests for KeycloakAdminClient cleanup method."""

from unittest.mock import patch


class TestKeycloakAdminCleanup:
    """Tests for cleanup method."""

    def test_cleanup_decrements_metrics_when_tracked(self, mock_admin_client):
        """Should decrement active sessions metric when session is tracked."""
        mock_admin_client._session_tracked = True

        # Use patch to mock the metric incremented in src/keycloak_operator/utils/keycloak_admin.py
        with patch(
            "keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE"
        ) as mock_metric:
            mock_admin_client.cleanup()

            assert mock_admin_client._session_tracked is False
            mock_metric.dec.assert_called_once()

    def test_cleanup_does_nothing_when_not_tracked(self, mock_admin_client):
        """Should do nothing when session is not tracked."""
        mock_admin_client._session_tracked = False

        with patch(
            "keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE"
        ) as mock_metric:
            mock_admin_client.cleanup()

            assert mock_admin_client._session_tracked is False
            mock_metric.dec.assert_not_called()

    def test_cleanup_handles_missing_metrics(self, mock_admin_client):
        """Should handle case where metrics cannot be imported."""
        mock_admin_client._session_tracked = True

        # Simulate import error or other exception during metrics access
        with patch(
            "keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE",
            side_effect=ImportError,
        ):
            # This should not raise an exception due to try-except block in cleanup()
            mock_admin_client.cleanup()

            assert mock_admin_client._session_tracked is False
