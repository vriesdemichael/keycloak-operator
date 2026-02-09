"""
Unit tests for Prometheus metric wiring in utility and service modules.

These tests verify the lazy-import metric recording helpers that were added
as part of issue #171 (metric cardinality reduction). Each helper follows
the pattern: try to import the metric, call it, and swallow any exception.
"""

from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# DatabaseConnectionManager._record_connection_metrics
# ---------------------------------------------------------------------------
class TestDatabaseRecordConnectionMetrics:
    """Test DatabaseConnectionManager._record_connection_metrics."""

    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_DURATION")
    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS")
    def test_success_sets_gauge_to_1(self, mock_status, mock_duration):
        """Successful connection records gauge=1 and observes duration."""
        from keycloak_operator.utils.database import DatabaseConnectionManager

        DatabaseConnectionManager._record_connection_metrics(
            namespace="ns-a", database_type="postgresql", success=True, duration=0.12
        )
        mock_status.labels.assert_called_with(
            namespace="ns-a", database_type="postgresql"
        )
        mock_status.labels().set.assert_called_with(1)
        mock_duration.labels.assert_called_with(
            namespace="ns-a", database_type="postgresql"
        )
        mock_duration.labels().observe.assert_called_with(0.12)

    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_DURATION")
    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS")
    def test_failure_sets_gauge_to_0(self, mock_status, mock_duration):
        """Failed connection records gauge=0."""
        from keycloak_operator.utils.database import DatabaseConnectionManager

        DatabaseConnectionManager._record_connection_metrics(
            namespace="ns-a", database_type="postgresql", success=False, duration=5.0
        )
        mock_status.labels().set.assert_called_with(0)

    @patch(
        "keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS",
        side_effect=ImportError("no metrics"),
    )
    def test_import_error_swallowed(self, _mock):
        """If metrics import fails, no exception propagates."""
        from keycloak_operator.utils.database import DatabaseConnectionManager

        # Should not raise
        DatabaseConnectionManager._record_connection_metrics(
            namespace="ns-a", database_type="postgresql", success=True, duration=0.1
        )

    @patch("keycloak_operator.observability.metrics.DATABASE_CONNECTION_STATUS")
    def test_metric_error_swallowed(self, mock_status):
        """If metric call raises, exception is swallowed."""
        mock_status.labels.side_effect = RuntimeError("broken")
        from keycloak_operator.utils.database import DatabaseConnectionManager

        DatabaseConnectionManager._record_connection_metrics(
            namespace="ns-a", database_type="postgresql", success=True, duration=0.1
        )


# ---------------------------------------------------------------------------
# rbac._record_rbac_metric
# ---------------------------------------------------------------------------
class TestRbacRecordMetric:
    """Test _record_rbac_metric in rbac.py."""

    @patch("keycloak_operator.observability.metrics.RBAC_VALIDATIONS")
    def test_allowed_records_success(self, mock_rbac):
        """Allowed=True records result='success'."""
        from keycloak_operator.utils.rbac import _record_rbac_metric

        _record_rbac_metric("src-ns", "tgt-ns", allowed=True)
        mock_rbac.labels.assert_called_with(
            source_namespace="src-ns",
            target_namespace="tgt-ns",
            result="success",
        )
        mock_rbac.labels().inc.assert_called_once()

    @patch("keycloak_operator.observability.metrics.RBAC_VALIDATIONS")
    def test_denied_records_failure(self, mock_rbac):
        """Allowed=False records result='failure'."""
        from keycloak_operator.utils.rbac import _record_rbac_metric

        _record_rbac_metric("src-ns", "tgt-ns", allowed=False)
        mock_rbac.labels.assert_called_with(
            source_namespace="src-ns",
            target_namespace="tgt-ns",
            result="failure",
        )

    @patch(
        "keycloak_operator.observability.metrics.RBAC_VALIDATIONS",
        side_effect=ImportError("no metrics"),
    )
    def test_import_error_swallowed(self, _mock):
        """If metrics import fails, no exception propagates."""
        from keycloak_operator.utils.rbac import _record_rbac_metric

        _record_rbac_metric("src-ns", "tgt-ns", allowed=True)

    @patch("keycloak_operator.observability.metrics.RBAC_VALIDATIONS")
    def test_metric_error_swallowed(self, mock_rbac):
        """If metric call raises, exception is swallowed."""
        mock_rbac.labels.side_effect = RuntimeError("broken")
        from keycloak_operator.utils.rbac import _record_rbac_metric

        _record_rbac_metric("src-ns", "tgt-ns", allowed=True)


# ---------------------------------------------------------------------------
# KeycloakAdminClient._record_session_metrics
# ---------------------------------------------------------------------------
class TestRecordSessionMetrics:
    """Test KeycloakAdminClient._record_session_metrics."""

    def _make_client(self, **overrides):
        """Create a minimal KeycloakAdminClient for testing."""
        with patch("keycloak_operator.utils.keycloak_admin.get_adapter_for_version"):
            from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

            defaults = {
                "server_url": "http://localhost:8080",
                "username": "admin",
                "password": "admin",
                "keycloak_name": "my-kc",
                "keycloak_namespace": "kc-ns",
            }
            defaults.update(overrides)
            return KeycloakAdminClient(**defaults)

    @patch("keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE")
    @patch("keycloak_operator.observability.metrics.ADMIN_SESSION_EXPIRES_TIMESTAMP")
    def test_first_auth_records_expiry_and_increments_active(
        self, mock_expires, mock_active
    ):
        """First authentication records expiry timestamp and increments active sessions."""
        client = self._make_client()
        client.token_expires_at = 9999.0

        client._record_session_metrics()

        mock_expires.labels.assert_called_with(
            namespace="kc-ns", keycloak_instance="my-kc"
        )
        mock_expires.labels().set.assert_called_with(9999.0)
        mock_active.inc.assert_called_once()
        assert client._session_tracked is True

    @patch("keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE")
    @patch("keycloak_operator.observability.metrics.ADMIN_SESSION_EXPIRES_TIMESTAMP")
    def test_second_auth_does_not_double_increment(self, mock_expires, mock_active):
        """Subsequent calls don't increment active sessions again."""
        client = self._make_client()
        client.token_expires_at = 9999.0

        client._record_session_metrics()
        client._record_session_metrics()

        # Only called once despite two calls
        mock_active.inc.assert_called_once()

    @patch("keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE")
    @patch("keycloak_operator.observability.metrics.ADMIN_SESSION_EXPIRES_TIMESTAMP")
    def test_no_namespace_skips_expiry(self, mock_expires, mock_active):
        """Without keycloak_namespace, expiry timestamp is not recorded."""
        client = self._make_client(keycloak_namespace=None)
        client.token_expires_at = 9999.0

        client._record_session_metrics()

        mock_expires.labels.assert_not_called()
        # Active sessions still incremented
        mock_active.inc.assert_called_once()

    @patch(
        "keycloak_operator.observability.metrics.ADMIN_SESSION_EXPIRES_TIMESTAMP",
        side_effect=ImportError("no metrics"),
    )
    def test_import_error_swallowed(self, _mock):
        """If metrics import fails, no exception propagates."""
        client = self._make_client()
        client.token_expires_at = 9999.0
        client._record_session_metrics()


# ---------------------------------------------------------------------------
# KeycloakAdminClient.close() session decrement
# ---------------------------------------------------------------------------
class TestCloseSessionDecrement:
    """Test that close() decrements active sessions gauge."""

    def _make_client(self, **overrides):
        """Create a minimal KeycloakAdminClient for testing."""
        with patch("keycloak_operator.utils.keycloak_admin.get_adapter_for_version"):
            from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient

            defaults = {
                "server_url": "http://localhost:8080",
                "username": "admin",
                "password": "admin",
                "keycloak_name": "my-kc",
                "keycloak_namespace": "kc-ns",
            }
            defaults.update(overrides)
            return KeycloakAdminClient(**defaults)

    @pytest.mark.asyncio
    @patch("keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE")
    async def test_close_decrements_when_tracked(self, mock_active):
        """close() decrements gauge when session was tracked."""
        client = self._make_client()
        client._session_tracked = True

        await client.close()

        mock_active.dec.assert_called_once()
        assert client._session_tracked is False

    @pytest.mark.asyncio
    @patch("keycloak_operator.observability.metrics.ADMIN_SESSIONS_ACTIVE")
    async def test_close_skips_when_not_tracked(self, mock_active):
        """close() does nothing when session was not tracked."""
        client = self._make_client()
        client._session_tracked = False

        await client.close()

        mock_active.dec.assert_not_called()

    @pytest.mark.asyncio
    async def test_close_clears_tokens(self):
        """close() clears authentication state regardless of metrics."""
        client = self._make_client()
        client.access_token = "some-token"
        client.refresh_token = "some-refresh"
        client.token_expires_at = 9999.0

        await client.close()

        assert client.access_token is None
        assert client.refresh_token is None
        assert client.token_expires_at is None


# ---------------------------------------------------------------------------
# KeycloakInstanceReconciler._record_cnpg_status
# ---------------------------------------------------------------------------
class TestRecordCnpgStatus:
    """Test KeycloakInstanceReconciler._record_cnpg_status."""

    @patch("keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS")
    def test_healthy_sets_gauge_to_1(self, mock_status):
        """Healthy=True sets gauge to 1."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        KeycloakInstanceReconciler._record_cnpg_status("ns-a", healthy=True)
        mock_status.labels.assert_called_with(namespace="ns-a")
        mock_status.labels().set.assert_called_with(1)

    @patch("keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS")
    def test_unhealthy_sets_gauge_to_0(self, mock_status):
        """Healthy=False sets gauge to 0."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        KeycloakInstanceReconciler._record_cnpg_status("ns-a", healthy=False)
        mock_status.labels().set.assert_called_with(0)

    @patch(
        "keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS",
        side_effect=ImportError("no metrics"),
    )
    def test_import_error_swallowed(self, _mock):
        """If metrics import fails, no exception propagates."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        KeycloakInstanceReconciler._record_cnpg_status("ns-a", healthy=True)

    @patch("keycloak_operator.observability.metrics.CNPG_CLUSTER_STATUS")
    def test_metric_error_swallowed(self, mock_status):
        """If metric call raises, exception is swallowed."""
        mock_status.labels.side_effect = RuntimeError("broken")
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        KeycloakInstanceReconciler._record_cnpg_status("ns-a", healthy=True)
