"""
Unit tests for handler-level pause wiring.

These tests verify that when is_*_paused() returns True, the handler functions:
- Create the correct reconciler
- Extract the generation from kwargs meta
- Call update_status_paused() with the correct arguments
- Return early without proceeding to full reconciliation

This provides genuine coverage of the pause code paths in the handler functions
(keycloak.py, realm.py, client.py, operator.py) which run inside the operator pod
and are otherwise only covered by integration tests.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestKeycloakHandlerPause:
    """Test pause wiring in keycloak.py create/resume and update handlers."""

    @pytest.fixture
    def mock_memo(self):
        memo = MagicMock()
        memo.rate_limiter = MagicMock()
        return memo

    @pytest.fixture
    def mock_patch(self):
        p = MagicMock()
        p.status = {}
        return p

    @pytest.mark.asyncio
    async def test_ensure_keycloak_paused_creates_reconciler_and_sets_status(
        self, mock_memo, mock_patch
    ):
        """When keycloak is paused, ensure_keycloak_instance sets Paused status."""
        from keycloak_operator.handlers.keycloak import ensure_keycloak_instance

        generation = 42
        pause_msg = "Maintenance: upgrade in progress"

        with (
            patch(
                "keycloak_operator.handlers.keycloak.is_keycloak_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.KeycloakInstanceReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await ensure_keycloak_instance(
                spec={"hostname": "kc.example.com"},
                name="test-kc",
                namespace="test-ns",
                status=MagicMock(),
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler_cls.assert_called_once_with(
                rate_limiter=mock_memo.rate_limiter,
                operator_namespace="test-ns",
            )
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            # StatusWrapper is the first arg, message is second, generation is third
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation

    @pytest.mark.asyncio
    async def test_ensure_keycloak_not_paused_proceeds_to_reconcile(
        self, mock_memo, mock_patch
    ):
        """When keycloak is NOT paused, reconciliation proceeds normally."""
        from keycloak_operator.handlers.keycloak import ensure_keycloak_instance

        with (
            patch(
                "keycloak_operator.handlers.keycloak.is_keycloak_paused",
                return_value=False,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.KeycloakInstanceReconciler"
            ) as mock_reconciler_cls,
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_reconciler = AsyncMock()
            mock_reconciler_cls.return_value = mock_reconciler

            await ensure_keycloak_instance(
                spec={"hostname": "kc.example.com"},
                name="test-kc",
                namespace="test-ns",
                status=MagicMock(),
                patch=mock_patch,
                memo=mock_memo,
                meta={},
            )

            # update_status_paused should NOT be called
            mock_reconciler.update_status_paused.assert_not_called()
            # reconcile SHOULD be called
            mock_reconciler.reconcile.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_keycloak_paused_sets_status(self, mock_memo, mock_patch):
        """When keycloak is paused, update_keycloak_instance sets Paused status."""
        from keycloak_operator.handlers.keycloak import update_keycloak_instance

        generation = 7
        pause_msg = "DB migration in progress"

        with (
            patch(
                "keycloak_operator.handlers.keycloak.is_keycloak_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.is_managed_by_this_operator",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.keycloak.KeycloakInstanceReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await update_keycloak_instance(
                old={"spec": {"hostname": "kc.example.com"}},
                new={"spec": {"hostname": "kc.example.com"}},
                diff=[],
                name="test-kc",
                namespace="test-ns",
                status=MagicMock(),
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation


class TestRealmHandlerPause:
    """Test pause wiring in realm.py create/resume and update handlers."""

    @pytest.fixture
    def mock_memo(self):
        memo = MagicMock()
        memo.rate_limiter = MagicMock()
        return memo

    @pytest.fixture
    def mock_patch(self):
        p = MagicMock()
        p.status = {}
        return p

    @pytest.mark.asyncio
    async def test_ensure_realm_paused_creates_reconciler_and_sets_status(
        self, mock_memo, mock_patch
    ):
        """When realms are paused, ensure_keycloak_realm sets Paused status."""
        from keycloak_operator.handlers.realm import ensure_keycloak_realm

        generation = 13
        pause_msg = "Realm reconciliation paused"

        with (
            patch(
                "keycloak_operator.handlers.realm.is_realms_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.realm.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.realm.KeycloakRealmReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await ensure_keycloak_realm(
                spec={"realmName": "test-realm"},
                name="test-realm",
                namespace="test-ns",
                status={},
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler_cls.assert_called_once_with(
                rate_limiter=mock_memo.rate_limiter,
            )
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation

    @pytest.mark.asyncio
    async def test_update_realm_paused_sets_status(self, mock_memo, mock_patch):
        """When realms are paused, update_keycloak_realm sets Paused status."""
        from keycloak_operator.handlers.realm import update_keycloak_realm

        generation = 5
        pause_msg = "Upgrade: realm paused"

        with (
            patch(
                "keycloak_operator.handlers.realm.is_realms_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.realm.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.realm.KeycloakRealmReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await update_keycloak_realm(
                old={"spec": {"realmName": "test-realm"}},
                new={"spec": {"realmName": "test-realm"}},
                diff=[],
                name="test-realm",
                namespace="test-ns",
                status={},
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation


class TestClientHandlerPause:
    """Test pause wiring in client.py create/resume, update, and secret rotation."""

    @pytest.fixture
    def mock_memo(self):
        memo = MagicMock()
        memo.rate_limiter = MagicMock()
        return memo

    @pytest.fixture
    def mock_patch(self):
        p = MagicMock()
        p.status = {}
        return p

    @pytest.mark.asyncio
    async def test_ensure_client_paused_sets_status(self, mock_memo, mock_patch):
        """When clients are paused, ensure_keycloak_client sets Paused status."""
        from keycloak_operator.handlers.client import ensure_keycloak_client

        generation = 9
        pause_msg = "Client reconciliation paused"

        with (
            patch(
                "keycloak_operator.handlers.client.is_clients_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.client.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.handlers.client.get_kubernetes_client"),
            patch(
                "keycloak_operator.handlers.client.KeycloakClientReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await ensure_keycloak_client(
                spec={
                    "clientId": "test-client",
                    "realmRef": {"name": "test-realm", "namespace": "test-ns"},
                },
                name="test-client",
                namespace="test-ns",
                status={},
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation

    @pytest.mark.asyncio
    async def test_update_client_paused_sets_status(self, mock_memo, mock_patch):
        """When clients are paused, update_keycloak_client sets Paused status."""
        from keycloak_operator.handlers.client import update_keycloak_client

        generation = 3
        pause_msg = "Client reconciliation paused for maintenance"

        with (
            patch(
                "keycloak_operator.handlers.client.is_clients_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.client.get_pause_message",
                return_value=pause_msg,
            ),
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.handlers.client.get_kubernetes_client"),
            patch(
                "keycloak_operator.handlers.client.KeycloakClientReconciler"
            ) as mock_reconciler_cls,
        ):
            mock_reconciler = MagicMock()
            mock_reconciler_cls.return_value = mock_reconciler

            result = await update_keycloak_client(
                old={
                    "spec": {
                        "clientId": "test-client",
                        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
                    }
                },
                new={
                    "spec": {
                        "clientId": "test-client",
                        "realmRef": {"name": "test-realm", "namespace": "test-ns"},
                    }
                },
                diff=[],
                name="test-client",
                namespace="test-ns",
                status={},
                patch=mock_patch,
                memo=mock_memo,
                meta={"generation": generation},
            )

            assert result is None
            mock_reconciler.update_status_paused.assert_called_once()
            call_args = mock_reconciler.update_status_paused.call_args
            assert call_args[0][1] == pause_msg
            assert call_args[0][2] == generation

    @pytest.mark.asyncio
    async def test_secret_rotation_daemon_skips_when_paused(self):
        """When clients are paused, secret_rotation_daemon waits instead of rotating."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        mock_stopped = MagicMock()
        # First loop: not stopped, second loop check: stopped
        mock_stopped.__bool__ = MagicMock(side_effect=[False, True])
        mock_stopped.wait = AsyncMock(return_value=True)

        mock_patch = MagicMock()
        mock_patch.status = {}

        with (
            patch(
                "keycloak_operator.handlers.client.is_clients_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch("keycloak_operator.handlers.client.get_kubernetes_client"),
            patch("keycloak_operator.handlers.client.client.CoreV1Api"),
        ):
            await secret_rotation_daemon(
                spec={
                    "clientId": "test-client",
                    "realmRef": {"name": "test-realm", "namespace": "test-ns"},
                    "secretRotation": {
                        "enabled": True,
                        "rotationPeriod": "90d",
                    },
                },
                name="test-client",
                namespace="test-ns",
                status={},
                meta={"uid": "test-uid"},
                stopped=mock_stopped,
                patch=mock_patch,
                memo=MagicMock(),
                logger=logging.getLogger("test"),
            )

            # stopped.wait should have been called with timeout=60 (pause wait)
            mock_stopped.wait.assert_called()
            call_args = mock_stopped.wait.call_args
            assert call_args[1]["timeout"] == 60


class TestDriftDetectionPause:
    """Test pause wiring in operator.py drift_detection_timer."""

    @pytest.mark.asyncio
    async def test_drift_detection_skipped_when_both_paused(self):
        """When both realms and clients are paused, drift detection returns early."""
        from keycloak_operator.operator import drift_detection_timer

        with (
            patch(
                "keycloak_operator.utils.pause.is_realms_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.utils.pause.is_clients_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetectionConfig.from_env",
            ) as mock_config,
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetector",
            ) as mock_detector_cls,
        ):
            # Config must say enabled=True so we get past the first check
            mock_config.return_value.enabled = True

            await drift_detection_timer()

            # DriftDetector should NOT be instantiated because both are paused
            mock_detector_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_drift_detection_runs_when_only_one_paused(self):
        """When only one CR type is paused, drift detection should still run."""
        from keycloak_operator.operator import drift_detection_timer

        with (
            patch(
                "keycloak_operator.utils.pause.is_realms_paused",
                return_value=True,
            ),
            patch(
                "keycloak_operator.utils.pause.is_clients_paused",
                return_value=False,
            ),
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetectionConfig.from_env",
            ) as mock_config,
            patch(
                "keycloak_operator.services.drift_detection_service.DriftDetector",
            ) as mock_detector_cls,
        ):
            mock_config.return_value.enabled = True
            mock_detector = AsyncMock()
            mock_detector.scan_for_drift.return_value = []
            mock_detector_cls.return_value = mock_detector

            await drift_detection_timer()

            # DriftDetector should be instantiated
            mock_detector_cls.assert_called_once()
            mock_detector.scan_for_drift.assert_called_once()
