"""
Unit tests for PreUpgradeBackupService (ADR-088 Phase 2).

Covers:
- BackupResult dataclass
- CNPG backup creation and polling (Tier 1)
- VolumeSnapshot backup creation and polling (Tier 2)
- External warn-and-proceed (Tier 3, including flat-field configs normalized per ADR-091)
- Unknown tier handling
- Timeout handling for all tiers
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.services.backup_service import (
    BackupResult,
    PreUpgradeBackupService,
)

# ===========================================================================
# BackupResult
# ===========================================================================


class TestBackupResult:
    """Test BackupResult dataclass."""

    def test_successful_result(self):
        result = BackupResult(success=True, tier="cnpg", backup_name="test-backup")
        assert result.success is True
        assert result.tier == "cnpg"
        assert result.backup_name == "test-backup"
        assert result.warnings == []

    def test_failed_result(self):
        result = BackupResult(
            success=False,
            tier="cnpg",
            message="Backup failed",
        )
        assert result.success is False
        assert result.message == "Backup failed"

    def test_warnings_list(self):
        result = BackupResult(
            success=True,
            tier="managed",
            warnings=["No PVC configured"],
        )
        assert len(result.warnings) == 1
        assert "No PVC configured" in result.warnings[0]


# ===========================================================================
# Helpers
# ===========================================================================


def _make_db_config(tier="cnpg", **overrides):
    """Create a mock database config for the given tier.

    Accepted values: 'cnpg', 'managed', 'managed_no_pvc', 'external'.
    Any other value produces an empty config (no sub-objects set).
    """
    if tier == "cnpg":
        cnpg_config = SimpleNamespace(
            cluster_name="keycloak-postgres",
            namespace=overrides.get("cnpg_namespace"),
        )
        return SimpleNamespace(cnpg=cnpg_config, managed=None, external=None)
    elif tier == "managed":
        managed_config = SimpleNamespace(
            pvc_name=overrides.get("pvc_name", "data-pvc"),
            volume_snapshot_class_name=overrides.get("snapshot_class"),
        )
        return SimpleNamespace(cnpg=None, managed=managed_config, external=None)
    elif tier == "managed_no_pvc":
        managed_config = SimpleNamespace(
            pvc_name=None,
            volume_snapshot_class_name=None,
        )
        return SimpleNamespace(cnpg=None, managed=managed_config, external=None)
    else:
        return SimpleNamespace(cnpg=None, managed=None, external=None)


def _make_upgrade_policy(backup_timeout=600):
    """Create a mock UpgradePolicy."""
    return SimpleNamespace(
        backup_timeout=backup_timeout,
    )


# ===========================================================================
# perform_backup — Tier Dispatch
# ===========================================================================


class TestPerformBackupDispatch:
    """Test that perform_backup dispatches to the correct tier handler."""

    @pytest.mark.asyncio
    async def test_unknown_tier(self):
        service = PreUpgradeBackupService()
        result = await service.perform_backup(
            keycloak_name="test",
            namespace="default",
            db_tier="unknown_tier",
            db_config=_make_db_config("external"),
        )
        assert result.success is False
        assert "Unknown database tier" in result.message

    @pytest.mark.asyncio
    async def test_dispatches_to_cnpg(self):
        service = PreUpgradeBackupService()
        with patch.object(service, "_backup_cnpg", new_callable=AsyncMock) as mock_cnpg:
            mock_cnpg.return_value = BackupResult(success=True, tier="cnpg")
            result = await service.perform_backup(
                keycloak_name="test",
                namespace="default",
                db_tier="cnpg",
                db_config=_make_db_config("cnpg"),
            )
            mock_cnpg.assert_called_once()
            assert result.success is True

    @pytest.mark.asyncio
    async def test_dispatches_to_managed(self):
        service = PreUpgradeBackupService()
        with patch.object(
            service, "_backup_volume_snapshot", new_callable=AsyncMock
        ) as mock_vs:
            mock_vs.return_value = BackupResult(success=True, tier="managed")
            result = await service.perform_backup(
                keycloak_name="test",
                namespace="default",
                db_tier="managed",
                db_config=_make_db_config("managed"),
            )
            mock_vs.assert_called_once()
            assert result.success is True

    @pytest.mark.asyncio
    async def test_dispatches_to_external(self):
        service = PreUpgradeBackupService()
        with patch.object(service, "_handle_external_backup") as mock_ext:
            mock_ext.return_value = BackupResult(success=True, tier="external")
            await service.perform_backup(
                keycloak_name="test",
                namespace="default",
                db_tier="external",
                db_config=_make_db_config("external"),
            )
            mock_ext.assert_called_once()

    @pytest.mark.asyncio
    async def test_custom_backup_timeout(self):
        """upgrade_policy.backup_timeout is passed to the tier handler."""
        service = PreUpgradeBackupService()
        policy = _make_upgrade_policy(backup_timeout=120)
        with patch.object(service, "_backup_cnpg", new_callable=AsyncMock) as mock_cnpg:
            mock_cnpg.return_value = BackupResult(success=True, tier="cnpg")
            await service.perform_backup(
                keycloak_name="test",
                namespace="default",
                db_tier="cnpg",
                db_config=_make_db_config("cnpg"),
                upgrade_policy=policy,
            )
            # Verify the timeout parameter
            _, kwargs = mock_cnpg.call_args
            # The fourth positional arg is timeout
            args = mock_cnpg.call_args[0]
            assert args[3] == 120  # timeout


# ===========================================================================
# Tier 1: CNPG Backup
# ===========================================================================


class TestCnpgBackup:
    """Test CNPG backup creation and polling."""

    @pytest.mark.asyncio
    async def test_cnpg_backup_success(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"phase": "completed"}}
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            result = await service._backup_cnpg(
                "test-kc", "default", _make_db_config("cnpg"), 600
            )

        assert result.success is True
        assert result.tier == "cnpg"
        assert result.backup_name is not None
        assert "pre-upgrade" in result.backup_name

    @pytest.mark.asyncio
    async def test_cnpg_backup_create_fails(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(
            side_effect=ApiException(status=403, reason="Forbidden")
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            result = await service._backup_cnpg(
                "test-kc", "default", _make_db_config("cnpg"), 600
            )

        assert result.success is False
        assert "Failed to create CNPG Backup" in result.message

    @pytest.mark.asyncio
    async def test_cnpg_backup_failed_phase(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"phase": "failed", "error": "disk full"}}
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            result = await service._backup_cnpg(
                "test-kc", "default", _make_db_config("cnpg"), 600
            )

        assert result.success is False
        assert "disk full" in result.message

    @pytest.mark.asyncio
    async def test_cnpg_backup_missing_config(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        db_config = SimpleNamespace(cnpg=None, managed=None, external=None)

        result = await service._backup_cnpg("test-kc", "default", db_config, 600)

        assert result.success is False
        assert "CNPG database configuration is missing" in result.message

    @pytest.mark.asyncio
    async def test_cnpg_backup_custom_namespace(self):
        """CNPG cluster can be in a different namespace."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"phase": "completed"}}
        )

        db_config = _make_db_config("cnpg", cnpg_namespace="cnpg-system")

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            result = await service._backup_cnpg("test-kc", "default", db_config, 600)

        # Verify the backup was created in the CNPG namespace
        create_call = mock_api.create_namespaced_custom_object.call_args
        assert create_call[1]["namespace"] == "cnpg-system"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_cnpg_backup_timeout(self):
        """Backup times out after the specified duration."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(return_value={})
        # Always return pending phase
        mock_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"phase": "pending"}}
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            with patch(
                "keycloak_operator.services.backup_service.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                result = await service._backup_cnpg(
                    "test-kc", "default", _make_db_config("cnpg"), 10
                )

        assert result.success is False
        assert "timed out" in result.message

    @pytest.mark.asyncio
    async def test_cnpg_backup_poll_api_error_recovery(self):
        """API errors during polling don't immediately fail — polling continues."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(return_value={})
        # First poll: error, second poll: completed
        mock_api.get_namespaced_custom_object = MagicMock(
            side_effect=[
                ApiException(status=500, reason="Server Error"),
                {"status": {"phase": "completed"}},
            ]
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            with patch(
                "keycloak_operator.services.backup_service.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                result = await service._backup_cnpg(
                    "test-kc", "default", _make_db_config("cnpg"), 600
                )

        assert result.success is True


# ===========================================================================
# Tier 2: VolumeSnapshot
# ===========================================================================


class TestVolumeSnapshotBackup:
    """Test VolumeSnapshot backup creation and polling."""

    @pytest.mark.asyncio
    async def test_snapshot_success(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_custom_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"readyToUse": True}}
        )
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert result.success is True
        assert result.tier == "managed"
        assert result.backup_name is not None
        assert "pre-upgrade" in result.backup_name

    @pytest.mark.asyncio
    async def test_snapshot_with_custom_class(self):
        """VolumeSnapshotClassName is included when set."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_custom_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"readyToUse": True}}
        )
        # get_cluster_custom_object succeeds => VolumeSnapshotClass exists
        mock_custom_api.get_cluster_custom_object = MagicMock(return_value={})
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        db_config = _make_db_config("managed", snapshot_class="my-snapshot-class")

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", db_config, 600
            )

        create_call = mock_custom_api.create_namespaced_custom_object.call_args
        body = create_call[1]["body"]
        assert body["spec"]["volumeSnapshotClassName"] == "my-snapshot-class"
        assert result.success is True

    @pytest.mark.asyncio
    async def test_snapshot_no_pvc_name(self):
        """No pvcName configured => skip with warning."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        db_config = _make_db_config("managed_no_pvc")

        result = await service._backup_volume_snapshot(
            "test-kc", "default", db_config, 600
        )

        assert result.success is True  # Not a failure, just skipped
        assert len(result.warnings) == 1
        assert "pvcName" in result.warnings[0]

    @pytest.mark.asyncio
    async def test_snapshot_create_fails(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(
            side_effect=ApiException(status=403, reason="Forbidden")
        )
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert result.success is False
        assert "Failed to create VolumeSnapshot" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_error_status(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_custom_api.get_namespaced_custom_object = MagicMock(
            return_value={
                "status": {
                    "readyToUse": False,
                    "error": {"message": "snapshot controller error"},
                }
            }
        )
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert result.success is False
        assert "snapshot controller error" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_timeout(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(return_value={})
        mock_custom_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"readyToUse": False}}
        )
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.asyncio.sleep",
                new_callable=AsyncMock,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 10
            )

        assert result.success is False
        assert "timed out" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_missing_managed_config(self):
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        db_config = SimpleNamespace(cnpg=None, managed=None, external=None)

        result = await service._backup_volume_snapshot(
            "test-kc", "default", db_config, 600
        )

        assert result.success is False
        assert "Managed database configuration is missing" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_pvc_not_found(self):
        """PVC does not exist => fail with descriptive message."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            side_effect=ApiException(status=404, reason="Not Found")
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CoreV1Api",
            return_value=mock_core_api,
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert result.success is False
        assert "PVC 'data-pvc' not found" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_pvc_api_error_propagates(self):
        """Non-404 errors from PVC check should propagate."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            side_effect=ApiException(status=500, reason="Internal Server Error")
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
            pytest.raises(ApiException) as exc_info,
        ):
            await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert exc_info.value.status == 500

    @pytest.mark.asyncio
    async def test_snapshot_class_not_found(self):
        """VolumeSnapshotClass does not exist => fail with descriptive message."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )
        mock_custom_api = MagicMock()
        mock_custom_api.get_cluster_custom_object = MagicMock(
            side_effect=ApiException(status=404, reason="Not Found")
        )

        db_config = _make_db_config("managed", snapshot_class="nonexistent-class")

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", db_config, 600
            )

        assert result.success is False
        assert "VolumeSnapshotClass 'nonexistent-class' not found" in result.message

    @pytest.mark.asyncio
    async def test_snapshot_class_api_error_propagates(self):
        """Non-404 errors from VolumeSnapshotClass check should propagate."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )
        mock_custom_api = MagicMock()
        mock_custom_api.get_cluster_custom_object = MagicMock(
            side_effect=ApiException(status=403, reason="Forbidden")
        )

        db_config = _make_db_config("managed", snapshot_class="some-class")

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            pytest.raises(ApiException) as exc_info,
        ):
            await service._backup_volume_snapshot("test-kc", "default", db_config, 600)

        assert exc_info.value.status == 403

    @pytest.mark.asyncio
    async def test_cnpg_backup_409_idempotent(self):
        """CNPG Backup 409 Conflict is treated as idempotent — polling continues."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_api = MagicMock()
        mock_api.create_namespaced_custom_object = MagicMock(
            side_effect=ApiException(status=409, reason="Conflict")
        )
        mock_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"phase": "completed"}}
        )

        with patch(
            "keycloak_operator.services.backup_service.client.CustomObjectsApi",
            return_value=mock_api,
        ):
            result = await service._backup_cnpg(
                "test-kc", "default", _make_db_config("cnpg"), 600
            )

        assert result.success is True
        assert result.tier == "cnpg"
        # Verify polling happened (get was called) even after 409
        mock_api.get_namespaced_custom_object.assert_called()

    @pytest.mark.asyncio
    async def test_snapshot_409_idempotent(self):
        """VolumeSnapshot 409 Conflict is treated as idempotent — polling continues."""
        service = PreUpgradeBackupService(k8s_client=MagicMock())
        mock_custom_api = MagicMock()
        mock_custom_api.create_namespaced_custom_object = MagicMock(
            side_effect=ApiException(status=409, reason="Conflict")
        )
        mock_custom_api.get_namespaced_custom_object = MagicMock(
            return_value={"status": {"readyToUse": True}}
        )
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_persistent_volume_claim = MagicMock(
            return_value=MagicMock()
        )

        with (
            patch(
                "keycloak_operator.services.backup_service.client.CustomObjectsApi",
                return_value=mock_custom_api,
            ),
            patch(
                "keycloak_operator.services.backup_service.client.CoreV1Api",
                return_value=mock_core_api,
            ),
        ):
            result = await service._backup_volume_snapshot(
                "test-kc", "default", _make_db_config("managed"), 600
            )

        assert result.success is True
        assert result.tier == "managed"
        # Verify polling happened (get was called) even after 409
        mock_custom_api.get_namespaced_custom_object.assert_called()


# ===========================================================================
# Tier 3: External (includes flat-field configs normalized per ADR-091)
# ===========================================================================


class TestExternalBackup:
    """Test external tier backup handling (always warn-and-proceed).

    Flat-field (legacy) configs are normalized to 'external' at the model
    level (ADR-091), so they also exercise this path in production.
    """

    def test_warn_and_proceed_external(self):
        """External tier: always warn and proceed."""
        service = PreUpgradeBackupService()
        result = service._handle_external_backup("test-kc", "default", "external")

        assert result.success is True
        assert result.tier == "external"
        assert len(result.warnings) == 1
        assert "does not support automated backups" in result.warnings[0]

    def test_message_mentions_manual_backup(self):
        """Message should tell users to ensure a manual backup exists."""
        service = PreUpgradeBackupService()
        result = service._handle_external_backup("test-kc", "default", "external")

        assert "manual backup" in result.message.lower()

    def test_no_backup_name(self):
        """No backup resource is created for external/legacy tiers."""
        service = PreUpgradeBackupService()
        result = service._handle_external_backup("test-kc", "default", "external")

        assert result.backup_name is None
