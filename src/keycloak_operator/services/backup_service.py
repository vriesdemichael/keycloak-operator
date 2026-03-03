"""
Pre-upgrade backup service for Keycloak version upgrades (ADR-088 Phase 2).

This module implements tier-aware backup orchestration that runs before
Keycloak version upgrades. The backup strategy depends on the database tier:

- **Tier 1 (CNPG)**: Creates a CNPG ``Backup`` CR and polls until complete.
- **Tier 2 (Managed)**: Creates a ``VolumeSnapshot`` of the database PVC.
- **Tier 3 (External)**: Cannot back up automatically. Logs a warning
  and returns a result indicating no backup was performed. Optionally blocks
  until manual confirmation via annotation.
- **Tier 4 (Legacy)**: Same as External — warn-and-proceed or manual gate.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from dataclasses import dataclass, field
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    BACKUP_CONFIRMED_ANNOTATION,
    DEFAULT_BACKUP_TIMEOUT,
    INSTANCE_LABEL_KEY,
    OPERATOR_LABEL_KEY,
    OPERATOR_LABEL_VALUE,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackupResult:
    """
    Result of a pre-upgrade backup attempt.

    Attributes:
        success: Whether the backup completed successfully.
        tier: The database tier that was backed up.
        backup_name: Name of the backup resource (CNPG Backup or VolumeSnapshot).
        message: Human-readable description of the result.
        requires_confirmation: True if the upgrade is blocked pending manual
            confirmation (external/legacy tier with requireBackupConfirmation).
        warnings: Non-fatal warnings emitted during the backup.
    """

    success: bool
    tier: str
    backup_name: str | None = None
    message: str = ""
    requires_confirmation: bool = False
    warnings: list[str] = field(default_factory=list)


class PreUpgradeBackupService:
    """
    Orchestrates pre-upgrade backups based on the database tier.

    This service is called by the reconciler when a version upgrade is
    detected. It dispatches to the appropriate backup strategy and returns
    a ``BackupResult`` that the reconciler uses to decide whether to
    proceed with the upgrade.

    Args:
        k8s_client: Kubernetes API client for creating resources.
    """

    def __init__(self, k8s_client: client.ApiClient | None = None) -> None:
        self.k8s_client = k8s_client

    async def perform_backup(
        self,
        keycloak_name: str,
        namespace: str,
        db_tier: str,
        db_config: Any,
        upgrade_policy: Any | None = None,
        annotations: dict[str, str] | None = None,
    ) -> BackupResult:
        """
        Perform a pre-upgrade backup based on the database tier.

        Args:
            keycloak_name: Name of the Keycloak CR.
            namespace: Namespace of the Keycloak CR.
            db_tier: Database tier ('cnpg', 'managed', 'external', 'legacy').
            db_config: The database configuration object (KeycloakDatabaseConfig).
            upgrade_policy: Optional UpgradePolicy from the Keycloak spec.
            annotations: Current annotations on the Keycloak CR.

        Returns:
            BackupResult with outcome details.
        """
        timeout = DEFAULT_BACKUP_TIMEOUT
        if upgrade_policy is not None:
            timeout = getattr(upgrade_policy, "backup_timeout", DEFAULT_BACKUP_TIMEOUT)

        if db_tier == "cnpg":
            return await self._backup_cnpg(keycloak_name, namespace, db_config, timeout)
        elif db_tier == "managed":
            return await self._backup_volume_snapshot(
                keycloak_name, namespace, db_config, timeout
            )
        elif db_tier in ("external", "legacy"):
            return await self._handle_external_backup(
                keycloak_name, namespace, db_tier, upgrade_policy, annotations
            )
        else:
            return BackupResult(
                success=False,
                tier=db_tier,
                message=f"Unknown database tier '{db_tier}' — cannot perform backup.",
            )

    # ──────────────────────────────────────────────────────────────
    # Tier 1: CNPG Backup
    # ──────────────────────────────────────────────────────────────

    async def _backup_cnpg(
        self,
        keycloak_name: str,
        namespace: str,
        db_config: Any,
        timeout: int,
    ) -> BackupResult:
        """Create a CNPG Backup CR and wait for completion."""
        cnpg_config = getattr(db_config, "cnpg", None)
        if cnpg_config is None:
            return BackupResult(
                success=False,
                tier="cnpg",
                message="CNPG database configuration is missing.",
            )

        cluster_name = cnpg_config.cluster_name
        cnpg_namespace = cnpg_config.namespace or namespace
        timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d%H%M%S")
        backup_name = f"{keycloak_name}-pre-upgrade-{timestamp}"

        backup_body = {
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "Backup",
            "metadata": {
                "name": backup_name,
                "namespace": cnpg_namespace,
                "labels": {
                    OPERATOR_LABEL_KEY: OPERATOR_LABEL_VALUE,
                    INSTANCE_LABEL_KEY: keycloak_name,
                    "vriesdemichael.github.io/backup-type": "pre-upgrade",
                },
            },
            "spec": {
                "cluster": {
                    "name": cluster_name,
                },
            },
        }

        custom_api = client.CustomObjectsApi(self.k8s_client)

        try:
            custom_api.create_namespaced_custom_object(
                group="postgresql.cnpg.io",
                version="v1",
                namespace=cnpg_namespace,
                plural="backups",
                body=backup_body,
            )
            logger.info(
                "Created CNPG Backup %s for cluster %s in %s",
                backup_name,
                cluster_name,
                cnpg_namespace,
            )
        except ApiException as e:
            return BackupResult(
                success=False,
                tier="cnpg",
                backup_name=backup_name,
                message=f"Failed to create CNPG Backup: {e.reason}",
            )

        # Poll for completion
        return await self._wait_for_cnpg_backup(
            backup_name, cnpg_namespace, timeout, custom_api
        )

    async def _wait_for_cnpg_backup(
        self,
        backup_name: str,
        namespace: str,
        timeout: int,
        custom_api: client.CustomObjectsApi,
    ) -> BackupResult:
        """Poll a CNPG Backup until it reaches completed or failed."""
        poll_interval = 5
        elapsed = 0

        while elapsed < timeout:
            try:
                backup = custom_api.get_namespaced_custom_object(
                    group="postgresql.cnpg.io",
                    version="v1",
                    namespace=namespace,
                    plural="backups",
                    name=backup_name,
                )
                phase = backup.get("status", {}).get("phase", "").lower()

                if phase == "completed":
                    logger.info("CNPG Backup %s completed successfully", backup_name)
                    return BackupResult(
                        success=True,
                        tier="cnpg",
                        backup_name=backup_name,
                        message=f"CNPG backup completed: {backup_name}",
                    )
                elif phase == "failed":
                    error = backup.get("status", {}).get("error", "Unknown error")
                    logger.error("CNPG Backup %s failed: %s", backup_name, error)
                    return BackupResult(
                        success=False,
                        tier="cnpg",
                        backup_name=backup_name,
                        message=f"CNPG backup failed: {error}",
                    )

                logger.debug(
                    "CNPG Backup %s phase: %s (elapsed: %ds)",
                    backup_name,
                    phase or "pending",
                    elapsed,
                )
            except ApiException as e:
                logger.warning(
                    "Error polling CNPG Backup %s: %s", backup_name, e.reason
                )

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        return BackupResult(
            success=False,
            tier="cnpg",
            backup_name=backup_name,
            message=f"CNPG backup timed out after {timeout}s",
        )

    # ──────────────────────────────────────────────────────────────
    # Tier 2: VolumeSnapshot
    # ──────────────────────────────────────────────────────────────

    async def _backup_volume_snapshot(
        self,
        keycloak_name: str,
        namespace: str,
        db_config: Any,
        timeout: int,
    ) -> BackupResult:
        """Create a VolumeSnapshot of the managed database PVC."""
        managed_config = getattr(db_config, "managed", None)
        if managed_config is None:
            return BackupResult(
                success=False,
                tier="managed",
                message="Managed database configuration is missing.",
            )

        pvc_name = getattr(managed_config, "pvc_name", None)
        snapshot_class = getattr(managed_config, "volume_snapshot_class_name", None)

        if not pvc_name:
            return BackupResult(
                success=True,
                tier="managed",
                message="No pvcName configured for managed database — skipping VolumeSnapshot backup.",
                warnings=[
                    "Managed database tier has no pvcName configured. "
                    "Set database.managed.pvcName and database.managed.volumeSnapshotClassName "
                    "to enable automated VolumeSnapshot backups before upgrades."
                ],
            )

        # Pre-flight validation: verify PVC exists
        core_api = client.CoreV1Api(self.k8s_client)
        try:
            core_api.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=namespace
            )
        except ApiException as e:
            if e.status == 404:
                return BackupResult(
                    success=False,
                    tier="managed",
                    message=(
                        f"PVC '{pvc_name}' not found in namespace '{namespace}'. "
                        "Verify database.managed.pvcName is correct."
                    ),
                )
            raise

        custom_api = client.CustomObjectsApi(self.k8s_client)

        # Pre-flight validation: verify VolumeSnapshotClass exists (if specified)
        if snapshot_class:
            try:
                custom_api.get_cluster_custom_object(
                    group="snapshot.storage.k8s.io",
                    version="v1",
                    plural="volumesnapshotclasses",
                    name=snapshot_class,
                )
            except ApiException as e:
                if e.status == 404:
                    return BackupResult(
                        success=False,
                        tier="managed",
                        message=(
                            f"VolumeSnapshotClass '{snapshot_class}' not found. "
                            "Verify database.managed.volumeSnapshotClassName is correct, "
                            "or omit it to use the cluster default."
                        ),
                    )
                raise

        timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y%m%d%H%M%S")
        snapshot_name = f"{keycloak_name}-pre-upgrade-{timestamp}"

        snapshot_body: dict[str, Any] = {
            "apiVersion": "snapshot.storage.k8s.io/v1",
            "kind": "VolumeSnapshot",
            "metadata": {
                "name": snapshot_name,
                "namespace": namespace,
                "labels": {
                    OPERATOR_LABEL_KEY: OPERATOR_LABEL_VALUE,
                    INSTANCE_LABEL_KEY: keycloak_name,
                    "vriesdemichael.github.io/backup-type": "pre-upgrade",
                },
            },
            "spec": {
                "source": {
                    "persistentVolumeClaimName": pvc_name,
                },
            },
        }

        if snapshot_class:
            snapshot_body["spec"]["volumeSnapshotClassName"] = snapshot_class

        try:
            custom_api.create_namespaced_custom_object(
                group="snapshot.storage.k8s.io",
                version="v1",
                namespace=namespace,
                plural="volumesnapshots",
                body=snapshot_body,
            )
            logger.info(
                "Created VolumeSnapshot %s for PVC %s in %s",
                snapshot_name,
                pvc_name,
                namespace,
            )
        except ApiException as e:
            return BackupResult(
                success=False,
                tier="managed",
                backup_name=snapshot_name,
                message=f"Failed to create VolumeSnapshot: {e.reason}",
            )

        # Poll for readyToUse
        return await self._wait_for_volume_snapshot(
            snapshot_name, namespace, timeout, custom_api
        )

    async def _wait_for_volume_snapshot(
        self,
        snapshot_name: str,
        namespace: str,
        timeout: int,
        custom_api: client.CustomObjectsApi,
    ) -> BackupResult:
        """Poll a VolumeSnapshot until readyToUse is true or an error occurs."""
        poll_interval = 5
        elapsed = 0

        while elapsed < timeout:
            try:
                snapshot = custom_api.get_namespaced_custom_object(
                    group="snapshot.storage.k8s.io",
                    version="v1",
                    namespace=namespace,
                    plural="volumesnapshots",
                    name=snapshot_name,
                )
                status = snapshot.get("status", {})
                ready = status.get("readyToUse", False)
                error = status.get("error", None)

                if ready:
                    logger.info("VolumeSnapshot %s is readyToUse", snapshot_name)
                    return BackupResult(
                        success=True,
                        tier="managed",
                        backup_name=snapshot_name,
                        message=f"VolumeSnapshot completed: {snapshot_name}",
                    )

                if error:
                    error_msg = error.get("message", "Unknown error")
                    logger.error(
                        "VolumeSnapshot %s failed: %s", snapshot_name, error_msg
                    )
                    return BackupResult(
                        success=False,
                        tier="managed",
                        backup_name=snapshot_name,
                        message=f"VolumeSnapshot failed: {error_msg}",
                    )

                logger.debug(
                    "VolumeSnapshot %s not ready yet (elapsed: %ds)",
                    snapshot_name,
                    elapsed,
                )
            except ApiException as e:
                logger.warning(
                    "Error polling VolumeSnapshot %s: %s", snapshot_name, e.reason
                )

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        return BackupResult(
            success=False,
            tier="managed",
            backup_name=snapshot_name,
            message=f"VolumeSnapshot timed out after {timeout}s",
        )

    # ──────────────────────────────────────────────────────────────
    # Tier 3+4: External / Legacy — warn or gate
    # ──────────────────────────────────────────────────────────────

    async def _handle_external_backup(
        self,
        keycloak_name: str,
        namespace: str,
        db_tier: str,
        upgrade_policy: Any | None,
        annotations: dict[str, str] | None,
    ) -> BackupResult:
        """
        Handle backup for external/legacy tiers.

        Default (requireBackupConfirmation=false): warn-and-proceed.
        Opt-in (requireBackupConfirmation=true): block until annotation.
        """
        require_confirmation = False
        if upgrade_policy is not None:
            require_confirmation = getattr(
                upgrade_policy, "require_backup_confirmation", False
            )

        if not require_confirmation:
            # Warn-and-proceed
            logger.warning(
                "Keycloak %s/%s uses %s database tier. "
                "The operator cannot perform automated backups for this tier. "
                "Ensure you have a recent backup before upgrading.",
                namespace,
                keycloak_name,
                db_tier,
            )
            return BackupResult(
                success=True,
                tier=db_tier,
                message=(
                    f"No automated backup available for {db_tier} database tier. "
                    "Proceeding with upgrade. Ensure a manual backup exists."
                ),
                warnings=[
                    f"Database tier '{db_tier}' does not support automated backups. "
                    "Set upgradePolicy.requireBackupConfirmation=true to enforce "
                    "manual backup verification before upgrades."
                ],
            )

        # Manual gate: check for confirmation annotation
        annotations = annotations or {}
        confirmed = annotations.get(BACKUP_CONFIRMED_ANNOTATION, "").lower() == "true"

        if confirmed:
            logger.info(
                "Backup confirmation annotation found for Keycloak %s/%s. "
                "Proceeding with upgrade.",
                namespace,
                keycloak_name,
            )
            return BackupResult(
                success=True,
                tier=db_tier,
                message=(f"Manual backup confirmed via annotation for {db_tier} tier."),
            )

        # Not confirmed — block
        logger.warning(
            "Keycloak %s/%s upgrade blocked: waiting for manual backup confirmation. "
            "Apply annotation '%s: \"true\"' to proceed.",
            namespace,
            keycloak_name,
            BACKUP_CONFIRMED_ANNOTATION,
        )
        return BackupResult(
            success=False,
            tier=db_tier,
            requires_confirmation=True,
            message=(
                f"Upgrade blocked for {db_tier} database tier. "
                f"Apply annotation '{BACKUP_CONFIRMED_ANNOTATION}: \"true\"' "
                "to the Keycloak CR after ensuring a manual backup exists."
            ),
        )
