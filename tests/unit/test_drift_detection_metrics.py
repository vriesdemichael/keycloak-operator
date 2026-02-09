"""
Unit tests for drift detection metrics in DriftDetector._update_drift_metrics.

Tests the aggregation logic that counts drift items per label set and
resets gauges to 0 when no items of that category are found.
"""

from unittest.mock import MagicMock, patch

from keycloak_operator.services.drift_detection_service import (
    DriftDetectionConfig,
    DriftDetector,
    DriftResult,
)


def _make_detector() -> DriftDetector:
    """Create a DriftDetector with all dependencies mocked out."""
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=False,
        minimum_age_hours=1,
        scope_realms=True,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )
    with (
        patch("keycloak_operator.services.drift_detection_service.client"),
        patch(
            "keycloak_operator.services.drift_detection_service.settings"
        ) as mock_settings,
    ):
        mock_settings.operator_namespace = "test-ns"
        mock_settings.operator_instance_id = "test-instance-id"
        detector = DriftDetector(
            config=config,
            k8s_client=MagicMock(),
            keycloak_admin_factory=MagicMock(),
            operator_instance_id="test-instance-id",
            operator_namespace="test-ns",
        )
    return detector


class TestUpdateDriftMetrics:
    """Test _update_drift_metrics aggregation logic."""

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_single_orphaned_drift(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """A single orphaned drift result sets gauge to 1."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="realm",
                resource_name="orphan-realm",
                drift_type="orphaned",
                keycloak_resource={},
            )
        ]

        detector._update_drift_metrics(results, "realm")

        mock_orphaned.labels.assert_called_with(
            resource_type="realm",
            operator_instance="test-instance-id",
        )
        mock_orphaned.labels().set.assert_called_with(1)
        # config_drift and unmanaged should be reset to 0
        mock_config_drift.labels.assert_called_with(
            resource_type="realm",
            cr_namespace="unknown",
        )
        mock_config_drift.labels().set.assert_called_with(0)
        mock_unmanaged.labels.assert_called_with(resource_type="realm")
        mock_unmanaged.labels().set.assert_called_with(0)

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_multiple_orphaned_same_type_counted(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Multiple orphaned drifts of same resource_type aggregate the count."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="realm",
                resource_name=f"orphan-{i}",
                drift_type="orphaned",
                keycloak_resource={},
            )
            for i in range(3)
        ]

        detector._update_drift_metrics(results, "realm")

        mock_orphaned.labels.assert_called_with(
            resource_type="realm",
            operator_instance="test-instance-id",
        )
        mock_orphaned.labels().set.assert_called_with(3)

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_config_drift_with_namespace(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Config drift results aggregate by (resource_type, cr_namespace)."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="client",
                resource_name="client-a",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace="ns-a",
                cr_name="cr-a",
            ),
            DriftResult(
                resource_type="client",
                resource_name="client-b",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace="ns-a",
                cr_name="cr-b",
            ),
            DriftResult(
                resource_type="client",
                resource_name="client-c",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace="ns-b",
                cr_name="cr-c",
            ),
        ]

        detector._update_drift_metrics(results, "client")

        # Should have two calls to config_drift labels: ns-a with count 2, ns-b with count 1
        calls = mock_config_drift.labels.call_args_list
        label_sets = [c.kwargs for c in calls]
        assert {"resource_type": "client", "cr_namespace": "ns-a"} in label_sets
        assert {"resource_type": "client", "cr_namespace": "ns-b"} in label_sets

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_config_drift_missing_namespace_uses_unknown(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Config drift with no cr_namespace falls back to 'unknown'."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="realm",
                resource_name="drifted-realm",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace=None,
            ),
        ]

        detector._update_drift_metrics(results, "realm")

        mock_config_drift.labels.assert_any_call(
            resource_type="realm",
            cr_namespace="unknown",
        )

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_unmanaged_resources_counted(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Unmanaged resources aggregate by resource_type."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="realm",
                resource_name=f"unmanaged-{i}",
                drift_type="unmanaged",
                keycloak_resource={},
            )
            for i in range(4)
        ]

        detector._update_drift_metrics(results, "realm")

        mock_unmanaged.labels.assert_called_with(resource_type="realm")
        mock_unmanaged.labels().set.assert_called_with(4)

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_empty_results_resets_all_gauges(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Empty drift_results resets all gauges to 0."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        detector._update_drift_metrics([], "realm")

        mock_orphaned.labels.assert_called_with(
            resource_type="realm",
            operator_instance="test-instance-id",
        )
        mock_orphaned.labels().set.assert_called_with(0)
        mock_config_drift.labels.assert_called_with(
            resource_type="realm",
            cr_namespace="unknown",
        )
        mock_config_drift.labels().set.assert_called_with(0)
        mock_unmanaged.labels.assert_called_with(resource_type="realm")
        mock_unmanaged.labels().set.assert_called_with(0)

    @patch("keycloak_operator.services.drift_detection_service.UNMANAGED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.CONFIG_DRIFT")
    @patch("keycloak_operator.services.drift_detection_service.ORPHANED_RESOURCES")
    @patch("keycloak_operator.services.drift_detection_service.settings")
    def test_mixed_drift_types(
        self, mock_settings, mock_orphaned, mock_config_drift, mock_unmanaged
    ):
        """Mixed drift types each have correct counts."""
        mock_settings.operator_instance_id = "test-instance-id"
        detector = _make_detector()

        results = [
            DriftResult(
                resource_type="client",
                resource_name="orphan-1",
                drift_type="orphaned",
                keycloak_resource={},
            ),
            DriftResult(
                resource_type="client",
                resource_name="drifted-1",
                drift_type="config_drift",
                keycloak_resource={},
                cr_namespace="ns-x",
            ),
            DriftResult(
                resource_type="client",
                resource_name="unmanaged-1",
                drift_type="unmanaged",
                keycloak_resource={},
            ),
            DriftResult(
                resource_type="client",
                resource_name="unmanaged-2",
                drift_type="unmanaged",
                keycloak_resource={},
            ),
        ]

        detector._update_drift_metrics(results, "client")

        # Verify orphaned count = 1
        mock_orphaned.labels.assert_called_with(
            resource_type="client",
            operator_instance="test-instance-id",
        )
        mock_orphaned.labels().set.assert_called_with(1)

        # Verify config_drift count = 1 in ns-x
        mock_config_drift.labels.assert_called_with(
            resource_type="client",
            cr_namespace="ns-x",
        )
        mock_config_drift.labels().set.assert_called_with(1)

        # Verify unmanaged count = 2
        mock_unmanaged.labels.assert_called_with(resource_type="client")
        mock_unmanaged.labels().set.assert_called_with(2)
