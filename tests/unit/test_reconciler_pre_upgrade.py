"""
Unit tests for the pre-upgrade backup hook in KeycloakInstanceReconciler.

Covers `_maybe_perform_pre_upgrade_backup()`:
- Fresh install (no deployment exists → skip)
- Same image (no change → skip)
- Patch upgrade (no backup required → skip)
- Minor upgrade (backup triggered)
- Major upgrade (backup triggered)
- Downgrade (skip with warning)
- Unparseable version (skip with warning)
- Backup success (continues normally)
- Backup failure (raises TemporaryError delay=60)
- Backup warnings are logged
- No running image extractable (skip with warning)
- Default image used when spec.image is None
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.errors import TemporaryError
from keycloak_operator.services.backup_service import BackupResult
from keycloak_operator.services.keycloak_reconciler import KeycloakInstanceReconciler

# ===========================================================================
# Helpers
# ===========================================================================


def _make_reconciler(k8s_client=None):
    """Create a reconciler with mocked dependencies."""
    with patch(
        "keycloak_operator.services.keycloak_reconciler.settings"
    ) as mock_settings:
        mock_settings.keycloak_managed = True
        mock_settings.operator_namespace = "operator-ns"
        reconciler = KeycloakInstanceReconciler(
            k8s_client=k8s_client or MagicMock(),
        )
    return reconciler


def _make_spec(image=None, db_tier="cnpg", upgrade_policy=None):
    """Create a mock KeycloakSpec."""
    db_config = SimpleNamespace(tier=db_tier)
    return SimpleNamespace(
        image=image,
        database=db_config,
        upgrade_policy=upgrade_policy,
    )


def _make_deployment(image="quay.io/keycloak/keycloak:25.0.0"):
    """Create a mock V1Deployment with a keycloak container."""
    container = SimpleNamespace(name="keycloak", image=image)
    pod_spec = SimpleNamespace(containers=[container])
    template = SimpleNamespace(spec=pod_spec)
    deployment_spec = SimpleNamespace(template=template)
    return SimpleNamespace(spec=deployment_spec)


def _make_kwargs(annotations=None):
    """Create kwargs dict as passed by Kopf handlers."""
    return {"meta": {"annotations": annotations or {}}}


# ===========================================================================
# Fresh Install (no existing deployment)
# ===========================================================================


class TestFreshInstall:
    """When no deployment exists, the hook should skip — it's a fresh install."""

    @pytest.mark.asyncio
    async def test_no_deployment_skips_upgrade_check(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0")
        kwargs = _make_kwargs()

        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(
            side_effect=ApiException(status=404, reason="Not Found")
        )

        # Set the mock BEFORE calling the method so we can verify it wasn't called
        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            # Should return without raising
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        # backup_service.perform_backup should NOT have been called
        assert reconciler.backup_service.perform_backup.call_count == 0

    @pytest.mark.asyncio
    async def test_api_error_non_404_propagates(self):
        """Non-404 errors from the API should propagate."""
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0")
        kwargs = _make_kwargs()

        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(
            side_effect=ApiException(status=500, reason="Internal Server Error")
        )

        with (
            patch(
                "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
                return_value=mock_apps_api,
            ),
            pytest.raises(ApiException) as exc_info,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )
        assert exc_info.value.status == 500


# ===========================================================================
# Same Image (no change)
# ===========================================================================


class TestSameImage:
    """When the running image matches the desired image, skip."""

    @pytest.mark.asyncio
    async def test_same_image_skips(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:25.0.0")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()

    @pytest.mark.asyncio
    async def test_none_image_uses_default(self):
        """When spec.image is None, the DEFAULT_KEYCLOAK_IMAGE is used."""
        reconciler = _make_reconciler()
        spec = _make_spec(image=None)  # Will use default
        kwargs = _make_kwargs()

        from keycloak_operator.constants import DEFAULT_KEYCLOAK_IMAGE

        deployment = _make_deployment(DEFAULT_KEYCLOAK_IMAGE)
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()


# ===========================================================================
# Patch Upgrade (no backup required)
# ===========================================================================


class TestPatchUpgrade:
    """Patch-level upgrades should not trigger a backup."""

    @pytest.mark.asyncio
    async def test_patch_upgrade_skips_backup(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:25.0.2")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()


# ===========================================================================
# Minor Upgrade (backup triggered)
# ===========================================================================


class TestMinorUpgrade:
    """Minor upgrades should trigger a pre-upgrade backup."""

    @pytest.mark.asyncio
    async def test_minor_upgrade_triggers_backup(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:25.1.0", db_tier="cnpg")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="cnpg",
                backup_name="test-backup",
                message="Backup completed",
                warnings=[],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_called_once()
        call_kwargs = reconciler.backup_service.perform_backup.call_args[1]
        assert call_kwargs["keycloak_name"] == "test-kc"
        assert call_kwargs["namespace"] == "default"
        assert call_kwargs["db_tier"] == "cnpg"


# ===========================================================================
# Major Upgrade (backup triggered)
# ===========================================================================


class TestMajorUpgrade:
    """Major upgrades should trigger a pre-upgrade backup."""

    @pytest.mark.asyncio
    async def test_major_upgrade_triggers_backup(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0", db_tier="managed")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="managed",
                backup_name="test-snapshot",
                message="VolumeSnapshot completed",
                warnings=[],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_called_once()
        call_kwargs = reconciler.backup_service.perform_backup.call_args[1]
        assert call_kwargs["db_tier"] == "managed"


# ===========================================================================
# Downgrade (skip with warning)
# ===========================================================================


class TestDowngrade:
    """Downgrades should skip backup and log a warning."""

    @pytest.mark.asyncio
    async def test_downgrade_skips_backup(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:24.0.0")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()


# ===========================================================================
# Unparseable Version (skip with warning)
# ===========================================================================


class TestUnparseableVersion:
    """When versions can't be parsed, skip with a warning."""

    @pytest.mark.asyncio
    async def test_digest_image_skips_backup(self):
        """Images using digests can't have version extracted."""
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak@sha256:abc123")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        # Images differ but version is unparseable => no backup
        reconciler.backup_service.perform_backup.assert_not_called()

    @pytest.mark.asyncio
    async def test_custom_tag_skips_backup(self):
        """Custom tags like 'latest' can't be parsed as semver."""
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:latest")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        # Version is unparseable → VersionBumpType.NONE → requires_backup=False
        reconciler.backup_service.perform_backup.assert_not_called()


# ===========================================================================
# Cannot Extract Running Image
# ===========================================================================


class TestCannotExtractImage:
    """When the running image can't be extracted from the deployment."""

    @pytest.mark.asyncio
    async def test_no_containers_skips_backup(self):
        """Deployment with no containers → can't extract image."""
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0")
        kwargs = _make_kwargs()

        # Deployment with no containers
        pod_spec = SimpleNamespace(containers=[])
        template = SimpleNamespace(spec=pod_spec)
        deployment_spec = SimpleNamespace(template=template)
        deployment = SimpleNamespace(spec=deployment_spec)

        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()

    @pytest.mark.asyncio
    async def test_malformed_deployment_skips_backup(self):
        """Deployment with missing spec structure."""
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0")
        kwargs = _make_kwargs()

        # Deployment with None spec
        deployment = SimpleNamespace(spec=None)

        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock()

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        reconciler.backup_service.perform_backup.assert_not_called()


# ===========================================================================
# Backup Success
# ===========================================================================


class TestBackupSuccess:
    """When backup succeeds, the hook should return normally."""

    @pytest.mark.asyncio
    async def test_backup_success_continues(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0", db_tier="cnpg")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="cnpg",
                backup_name="kc-pre-upgrade-20260101120000",
                message="CNPG backup completed: kc-pre-upgrade-20260101120000",
                warnings=[],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            # Should not raise
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )


# ===========================================================================
# Backup Failure (TemporaryError delay=60)
# ===========================================================================


class TestBackupFailure:
    """When backup fails, a TemporaryError with delay=60 should be raised."""

    @pytest.mark.asyncio
    async def test_backup_failure_raises_temporary_error(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0", db_tier="cnpg")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=False,
                tier="cnpg",
                backup_name="kc-pre-upgrade-20260101120000",
                message="CNPG backup failed: disk full",
                warnings=[],
            )
        )

        with (
            patch(
                "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
                return_value=mock_apps_api,
            ),
            pytest.raises(TemporaryError) as exc_info,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        assert exc_info.value.delay == 60
        assert "Pre-upgrade backup failed" in str(exc_info.value)


# ===========================================================================
# Backup Warnings Are Logged
# ===========================================================================


class TestBackupWarnings:
    """Warnings from the backup result should be logged."""

    @pytest.mark.asyncio
    async def test_warnings_are_logged(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0", db_tier="managed")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        warning_msg = "No pvcName configured — skipping VolumeSnapshot"
        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="managed",
                message="Skipping VolumeSnapshot",
                warnings=[warning_msg],
            )
        )

        with (
            patch(
                "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
                return_value=mock_apps_api,
            ),
            patch.object(reconciler.logger, "warning") as mock_warn,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        # The warning should have been logged
        mock_warn.assert_any_call(
            f"Pre-upgrade backup warning for test-kc: {warning_msg}"
        )


# ===========================================================================
# Upgrade Policy Passed Through
# ===========================================================================


class TestUpgradePolicyPassthrough:
    """The upgrade_policy from the spec should be forwarded to backup service."""

    @pytest.mark.asyncio
    async def test_upgrade_policy_forwarded(self):
        upgrade_policy = SimpleNamespace(
            backup_timeout=120,
        )
        reconciler = _make_reconciler()
        spec = _make_spec(
            image="quay.io/keycloak/keycloak:26.0.0",
            db_tier="external",
            upgrade_policy=upgrade_policy,
        )
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="external",
                message="Warn and proceed",
                warnings=["External tier does not support automated backups"],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        call_kwargs = reconciler.backup_service.perform_backup.call_args[1]
        assert call_kwargs["upgrade_policy"] is upgrade_policy

    @pytest.mark.asyncio
    async def test_none_upgrade_policy_forwarded(self):
        """When upgrade_policy is None, it should still be forwarded."""
        reconciler = _make_reconciler()
        spec = _make_spec(
            image="quay.io/keycloak/keycloak:26.0.0",
            db_tier="cnpg",
            upgrade_policy=None,
        )
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="cnpg",
                message="Backup done",
                warnings=[],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        call_kwargs = reconciler.backup_service.perform_backup.call_args[1]
        assert call_kwargs["upgrade_policy"] is None


# ===========================================================================
# Deployment Name Convention
# ===========================================================================


class TestDeploymentNaming:
    """The hook should look up '{name}-keycloak' deployment."""

    @pytest.mark.asyncio
    async def test_deployment_name_convention(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0")
        kwargs = _make_kwargs()

        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(
            side_effect=ApiException(status=404, reason="Not Found")
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "my-keycloak", "test-ns", kwargs
            )

        mock_apps_api.read_namespaced_deployment.assert_called_once_with(
            name="my-keycloak-keycloak", namespace="test-ns"
        )


# ===========================================================================
# Database Config Passed Through
# ===========================================================================


class TestDatabaseConfigPassthrough:
    """The database config from the spec should be forwarded to backup service."""

    @pytest.mark.asyncio
    async def test_db_config_forwarded(self):
        reconciler = _make_reconciler()
        db_config = SimpleNamespace(tier="cnpg")
        spec = SimpleNamespace(
            image="quay.io/keycloak/keycloak:26.0.0",
            database=db_config,
            upgrade_policy=None,
        )
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="cnpg",
                message="Done",
                warnings=[],
            )
        )

        with patch(
            "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
            return_value=mock_apps_api,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        call_kwargs = reconciler.backup_service.perform_backup.call_args[1]
        assert call_kwargs["db_config"] is db_config


# ===========================================================================
# Multiple Warnings
# ===========================================================================


class TestMultipleWarnings:
    """Multiple warnings from the backup result should all be logged."""

    @pytest.mark.asyncio
    async def test_all_warnings_logged(self):
        reconciler = _make_reconciler()
        spec = _make_spec(image="quay.io/keycloak/keycloak:26.0.0", db_tier="managed")
        kwargs = _make_kwargs()

        deployment = _make_deployment("quay.io/keycloak/keycloak:25.0.0")
        mock_apps_api = MagicMock()
        mock_apps_api.read_namespaced_deployment = MagicMock(return_value=deployment)

        warnings = ["Warning one", "Warning two", "Warning three"]
        reconciler.backup_service.perform_backup = AsyncMock(
            return_value=BackupResult(
                success=True,
                tier="managed",
                message="Done with warnings",
                warnings=warnings,
            )
        )

        with (
            patch(
                "keycloak_operator.services.keycloak_reconciler.client.AppsV1Api",
                return_value=mock_apps_api,
            ),
            patch.object(reconciler.logger, "warning") as mock_warn,
        ):
            await reconciler._maybe_perform_pre_upgrade_backup(
                spec, "test-kc", "default", kwargs
            )

        # Each warning should produce a log call
        warning_calls = [
            call
            for call in mock_warn.call_args_list
            if "Pre-upgrade backup warning" in str(call)
        ]
        assert len(warning_calls) == 3
