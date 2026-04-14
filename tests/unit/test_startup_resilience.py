"""Unit tests for startup race handling and resilience helpers."""

from unittest.mock import AsyncMock, MagicMock, patch

import kopf
import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.utils.isolation import (
    ClientManagementDecision,
    get_client_management_decision,
)


class TestDriftDetectionReadiness:
    """Tests for managed-mode drift detection startup gating."""

    @pytest.mark.asyncio
    async def test_managed_keycloak_readiness_skips_external_mode(self):
        """External mode should not require a managed Keycloak CR."""
        from keycloak_operator.operator import (
            _is_managed_keycloak_ready_for_drift_detection,
            operator_settings,
        )

        with (
            patch.object(operator_settings, "keycloak_managed", False),
            patch("kubernetes.client.CustomObjectsApi") as mock_custom_objects,
        ):
            ready, phase = await _is_managed_keycloak_ready_for_drift_detection()

        assert ready is True
        assert phase == "external"
        mock_custom_objects.assert_not_called()

    @pytest.mark.asyncio
    async def test_managed_keycloak_readiness_returns_false_for_non_ready_phase(self):
        """Managed mode should skip drift detection until the Keycloak CR is operational."""
        from keycloak_operator.operator import (
            _is_managed_keycloak_ready_for_drift_detection,
            operator_settings,
        )

        mock_custom_api = MagicMock()
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "status": {"phase": "Provisioning"}
        }

        with (
            patch.object(operator_settings, "keycloak_managed", True),
            patch.object(operator_settings, "pod_namespace", "keycloak-system"),
            patch("kubernetes.client.CustomObjectsApi", return_value=mock_custom_api),
            patch(
                "keycloak_operator.utils.kubernetes.get_kubernetes_client",
                return_value=MagicMock(),
            ),
        ):
            ready, phase = await _is_managed_keycloak_ready_for_drift_detection()

        assert ready is False
        assert phase == "Provisioning"

    @pytest.mark.asyncio
    async def test_drift_detection_timer_skips_until_managed_keycloak_ready(self):
        """The timer should not instantiate the detector before Keycloak is operational."""
        from keycloak_operator.operator import drift_detection_timer

        with (
            patch(
                "keycloak_operator.utils.pause.is_realms_paused",
                return_value=False,
            ),
            patch(
                "keycloak_operator.utils.pause.is_clients_paused",
                return_value=False,
            ),
            patch(
                "keycloak_operator.operator._is_managed_keycloak_ready_for_drift_detection",
                new=AsyncMock(return_value=(False, "Provisioning")),
            ),
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetectionConfig.from_env",
            ) as mock_config,
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetector",
            ) as mock_detector_cls,
        ):
            mock_config.return_value.enabled = True

            await drift_detection_timer()

        mock_detector_cls.assert_not_called()


class TestClientOwnershipDecisions:
    """Tests for retry-aware client ownership resolution."""

    @staticmethod
    def _client_spec() -> dict[str, object]:
        return {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "realm-ns"},
        }

    @pytest.mark.asyncio
    async def test_missing_parent_realm_returns_retry_decision(self):
        """A missing parent realm should be treated as a transient startup condition."""
        mock_custom_api = MagicMock()
        mock_custom_api.get_namespaced_custom_object.side_effect = ApiException(
            status=404,
            reason="Not Found",
        )

        with patch("kubernetes.client.CustomObjectsApi", return_value=mock_custom_api):
            decision = await get_client_management_decision(
                self._client_spec(),
                "client-ns",
                MagicMock(),
            )

        assert decision.should_retry is True
        assert decision.is_managed is False
        assert decision.realm_name == "test-realm"
        assert decision.realm_namespace == "realm-ns"

    @pytest.mark.asyncio
    async def test_parent_realm_owned_by_other_operator_is_not_managed(self):
        """Ownership mismatch should not be retried."""
        mock_custom_api = MagicMock()
        mock_custom_api.get_namespaced_custom_object.return_value = {"spec": {}}

        with (
            patch("kubernetes.client.CustomObjectsApi", return_value=mock_custom_api),
            patch(
                "keycloak_operator.utils.isolation.is_managed_by_this_operator",
                return_value=False,
            ),
        ):
            decision = await get_client_management_decision(
                self._client_spec(),
                "client-ns",
                MagicMock(),
            )

        assert decision.should_retry is False
        assert decision.is_managed is False

    @pytest.mark.asyncio
    async def test_ensure_client_retries_when_parent_realm_missing(self):
        """Create/resume handler should requeue until the parent realm exists."""
        from keycloak_operator.handlers.client import ensure_keycloak_client

        with (
            patch(
                "keycloak_operator.handlers.client.get_client_management_decision",
                new=AsyncMock(
                    return_value=ClientManagementDecision(
                        status="retry",
                        realm_name="test-realm",
                        realm_namespace="realm-ns",
                    )
                ),
            ),
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client",
                return_value=MagicMock(),
            ),
        ):
            with pytest.raises(kopf.TemporaryError, match="Waiting for parent realm"):
                await ensure_keycloak_client(
                    spec=self._client_spec(),
                    name="test-client",
                    namespace="client-ns",
                    status={},
                    patch=MagicMock(status={}),
                    memo=MagicMock(rate_limiter=MagicMock()),
                )

    @pytest.mark.asyncio
    async def test_update_client_retries_when_parent_realm_missing(self):
        """Update handler should requeue until the parent realm exists."""
        from keycloak_operator.handlers.client import update_keycloak_client

        with (
            patch(
                "keycloak_operator.handlers.client.get_client_management_decision",
                new=AsyncMock(
                    return_value=ClientManagementDecision(
                        status="retry",
                        realm_name="test-realm",
                        realm_namespace="realm-ns",
                    )
                ),
            ),
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client",
                return_value=MagicMock(),
            ),
        ):
            with pytest.raises(kopf.TemporaryError, match="Waiting for parent realm"):
                await update_keycloak_client(
                    old={"spec": self._client_spec()},
                    new={"spec": self._client_spec()},
                    diff=[],
                    name="test-client",
                    namespace="client-ns",
                    status={},
                    patch=MagicMock(status={}),
                    memo=MagicMock(rate_limiter=MagicMock()),
                )
