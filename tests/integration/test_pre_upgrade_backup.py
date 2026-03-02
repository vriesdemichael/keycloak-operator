"""
Integration tests for pre-upgrade backup orchestration (ADR-088 Phase 2).

These tests verify that the operator correctly detects Keycloak version
changes during reconciliation and performs tier-appropriate backup actions
before proceeding with the deployment update.

Scenarios tested:
- Fresh install does NOT trigger a backup (no existing deployment)
- Legacy tier minor upgrade: warn-and-proceed (default behavior)
- Legacy tier with requireBackupConfirmation: blocks until annotation
- Patch version upgrade: no backup required
- CNPG tier minor upgrade: creates a CNPG Backup CR

NOTE: The test cluster only has `keycloak-optimized:26.5.2` loaded into Kind.
When we patch to a non-existent image (e.g., 27.0.0), the backup hook runs
BEFORE the deployment is updated, so backup behavior is exercised even though
the deployment will subsequently fail to pull the new image. Tests are designed
to verify backup-specific side effects rather than full Ready state after upgrade.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from tests.integration.conftest import get_keycloak_test_image

from .wait_helpers import wait_for_resource_ready

logger = logging.getLogger(__name__)

# Annotation key used to confirm manual backup (external/legacy tiers)
BACKUP_CONFIRMED_ANNOTATION = "operator.keycloak.io/backup-confirmed"


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestPreUpgradeBackupFreshInstall:
    """Verify that a fresh Keycloak install does not trigger any backup logic."""

    @pytest.mark.timeout(240)
    async def test_fresh_install_reaches_ready_without_backup(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """A brand-new Keycloak instance should go straight to Ready.

        There is no existing deployment, so the pre-upgrade backup hook
        should detect a 404 on the deployment read and skip entirely.
        No CNPG Backup CRs or VolumeSnapshots should be created.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-fresh-{suffix}"
        namespace = test_keycloak_namespace

        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": {**spec, "operatorRef": {"namespace": operator_namespace}},
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Should reach Ready without any backup shenanigans
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Verify no CNPG Backup CRs were created in the operator namespace
            # (the shared CNPG cluster lives there)
            try:
                backups = await k8s_custom_objects.list_namespaced_custom_object(
                    group="postgresql.cnpg.io",
                    version="v1",
                    namespace=operator_namespace,
                    plural="backups",
                    label_selector=f"vriesdemichael.github.io/keycloak-instance={keycloak_name}",
                )
                backup_items = backups.get("items", [])
                assert len(backup_items) == 0, (
                    f"Expected no CNPG Backup CRs for fresh install, found {len(backup_items)}"
                )
            except ApiException as e:
                if e.status != 404:
                    raise
                # 404 means the CRD is fine but no backups exist — expected

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestPreUpgradeBackupLegacyTier:
    """Tests for pre-upgrade backup behavior with legacy database tier.

    The sample_keycloak_spec_factory produces legacy-tier config (flat
    database fields without cnpg/managed/external sub-objects). Legacy
    tier cannot do automated backups, so the default behavior is
    warn-and-proceed.
    """

    @pytest.mark.timeout(360)
    async def test_legacy_minor_upgrade_proceeds_without_blocking(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Legacy tier minor upgrade should warn and proceed (no blocking).

        Steps:
        1. Deploy Keycloak with legacy DB config, wait for Ready.
        2. Patch the image to a new minor version (non-existent).
        3. Verify the deployment image is updated (backup hook allowed it).
        4. The deployment will eventually fail (image not found) — that's OK.
           We only care that the backup hook didn't block.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-legacy-upgrade-{suffix}"
        namespace = test_keycloak_namespace

        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": {**spec, "operatorRef": {"namespace": operator_namespace}},
        }

        try:
            # Deploy initial instance
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Verify initial deployment image
            deployment_name = f"{keycloak_name}-keycloak"
            deployment = await k8s_apps_v1.read_namespaced_deployment(
                deployment_name, namespace
            )
            initial_image = deployment.spec.template.spec.containers[0].image
            assert "26.5" in initial_image, (
                f"Expected 26.5.x image, got {initial_image}"
            )

            # Patch to a minor version upgrade (non-existent image, but that's OK)
            # The backup hook runs BEFORE the deployment update
            new_image = "keycloak-optimized:27.0.0"
            patch_body = {
                "spec": {
                    "image": new_image,
                }
            }

            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # Wait for the deployment to be updated with the new image.
            # The reconciler should NOT block for legacy tier (warn-and-proceed).
            # Poll deployment until image changes (or timeout).
            updated = False
            for _ in range(30):
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        updated = True
                        break
                except ApiException:
                    pass

            assert updated, (
                f"Deployment image was not updated to {new_image} within timeout. "
                "The backup hook may have incorrectly blocked the legacy tier upgrade."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    @pytest.mark.timeout(420)
    async def test_legacy_manual_gate_blocks_then_unblocks(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Legacy tier with requireBackupConfirmation blocks, then annotation unblocks.

        Steps:
        1. Deploy Keycloak with legacy DB and upgradePolicy.requireBackupConfirmation=true.
        2. Wait for Ready.
        3. Patch image to trigger a minor upgrade.
        4. Verify the deployment image does NOT update (blocked by manual gate).
        5. Apply the backup-confirmed annotation.
        6. Verify the deployment image updates after annotation.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-legacy-gate-{suffix}"
        namespace = test_keycloak_namespace

        spec = await sample_keycloak_spec_factory(namespace)
        spec["upgradePolicy"] = {
            "requireBackupConfirmation": True,
        }

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": {**spec, "operatorRef": {"namespace": operator_namespace}},
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Patch to minor version upgrade
            new_image = "keycloak-optimized:27.0.0"
            patch_body = {
                "spec": {
                    "image": new_image,
                }
            }
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # Wait a reasonable time and verify the deployment is NOT updated
            # (manual gate should block the reconciler with TemporaryError)
            deployment_name = f"{keycloak_name}-keycloak"
            blocked = True
            for _ in range(12):  # 12 * 5s = 60s of checking
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        blocked = False
                        break
                except ApiException:
                    pass

            assert blocked, (
                "Deployment image was updated despite requireBackupConfirmation=true. "
                "The manual gate did not block the upgrade."
            )

            # Now apply the backup-confirmed annotation to unblock
            annotation_patch = {
                "metadata": {
                    "annotations": {
                        BACKUP_CONFIRMED_ANNOTATION: "true",
                    }
                }
            }
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=annotation_patch,
            )

            # Now wait for the deployment to be updated (unblocked)
            unblocked = False
            for _ in range(30):  # 30 * 5s = 150s
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        unblocked = True
                        break
                except ApiException:
                    pass

            assert unblocked, (
                f"Deployment image was not updated to {new_image} after applying "
                "backup-confirmed annotation. The manual gate did not unblock."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestPreUpgradeBackupPatchVersion:
    """Verify that patch version changes do NOT trigger backup."""

    @pytest.mark.timeout(360)
    async def test_patch_upgrade_skips_backup(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        sample_keycloak_spec_factory,
    ) -> None:
        """Patch version changes should not trigger pre-upgrade backup.

        Steps:
        1. Deploy Keycloak with 26.5.2, wait for Ready.
        2. Patch image to 26.5.99 (patch-only change, non-existent but irrelevant).
        3. Verify deployment image updates quickly — no backup delay.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-patch-{suffix}"
        namespace = test_keycloak_namespace

        spec = await sample_keycloak_spec_factory(namespace)

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": {**spec, "operatorRef": {"namespace": operator_namespace}},
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Patch to a patch version (same major.minor, different patch)
            new_image = "keycloak-optimized:26.5.99"
            patch_body = {"spec": {"image": new_image}}
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # Deployment should update within a reasonable time
            # (no backup delay for patch versions)
            deployment_name = f"{keycloak_name}-keycloak"
            updated = False
            for _ in range(20):
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        updated = True
                        break
                except ApiException:
                    pass

            assert updated, (
                f"Deployment image was not updated to {new_image} within timeout. "
                "Patch version upgrade should not trigger any backup behavior."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestPreUpgradeBackupCNPGTier:
    """Tests for CNPG tier pre-upgrade backup behavior.

    When a CNPG-tier Keycloak detects a minor or major version upgrade,
    the operator should create a CNPG Backup CR. In the test cluster,
    the shared CNPG cluster has no barman/S3 backup destination, so the
    Backup CR will likely fail. We verify CR creation, not completion.

    NOTE: The sample_keycloak_spec_factory produces legacy-tier config.
    To test CNPG tier, we build a custom spec with database.cnpg fields.
    """

    @pytest.mark.timeout(420)
    async def test_cnpg_minor_upgrade_creates_backup_cr(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        k8s_core_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        shared_cnpg_info,
    ) -> None:
        """CNPG tier minor upgrade should create a CNPG Backup CR.

        Steps:
        1. Deploy Keycloak with CNPG tier config.
        2. Wait for Ready.
        3. Patch image to trigger a minor version upgrade.
        4. Verify that a CNPG Backup CR is created with the expected labels.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-cnpg-backup-{suffix}"
        namespace = test_keycloak_namespace

        # Copy the CNPG secret to the test namespace
        source_secret_name = shared_cnpg_info["password_secret"]
        source_namespace = shared_cnpg_info["password_secret_namespace"]

        source_secret = await k8s_core_v1.read_namespaced_secret(
            name=source_secret_name, namespace=source_namespace
        )

        target_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=source_secret_name,
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            data=source_secret.data,
            type=source_secret.type,
        )
        try:
            await k8s_core_v1.create_namespaced_secret(namespace, target_secret)
        except ApiException as e:
            if e.status != 409:
                raise

        # Build CNPG-tier spec (NOT legacy)
        spec = {
            "replicas": 1,
            "image": get_keycloak_test_image(),
            "operatorRef": {"namespace": operator_namespace},
            "database": {
                "type": "postgresql",
                "cnpg": {
                    "clusterName": "keycloak-cnpg",
                    "namespace": operator_namespace,
                },
            },
            "resources": {
                "requests": {"cpu": "200m", "memory": "512Mi"},
                "limits": {"cpu": "2000m", "memory": "2Gi"},
            },
        }

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
        }

        created_backup_crs: list[str] = []

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Patch to trigger minor version upgrade
            new_image = "keycloak-optimized:27.0.0"
            patch_body = {"spec": {"image": new_image}}
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # Poll for CNPG Backup CR creation in the CNPG cluster's namespace.
            # The backup service creates it in cnpg_namespace (operator_namespace).
            backup_found = False
            for _ in range(24):  # 24 * 5s = 120s
                await asyncio.sleep(5)
                try:
                    backups = await k8s_custom_objects.list_namespaced_custom_object(
                        group="postgresql.cnpg.io",
                        version="v1",
                        namespace=operator_namespace,
                        plural="backups",
                        label_selector=f"vriesdemichael.github.io/keycloak-instance={keycloak_name}",
                    )
                    items = backups.get("items", [])
                    if items:
                        backup_found = True
                        for item in items:
                            created_backup_crs.append(item["metadata"]["name"])
                            # Verify labels
                            labels = item["metadata"].get("labels", {})
                            assert (
                                labels.get(
                                    "vriesdemichael.github.io/keycloak-managed-by"
                                )
                                == "keycloak-operator"
                            ), f"Backup CR missing managed-by label: {labels}"
                            assert (
                                labels.get("vriesdemichael.github.io/keycloak-instance")
                                == keycloak_name
                            ), f"Backup CR has wrong instance label: {labels}"
                            assert (
                                labels.get("vriesdemichael.github.io/backup-type")
                                == "pre-upgrade"
                            ), f"Backup CR missing backup-type label: {labels}"
                            # Verify the backup targets the right cluster
                            cluster_ref = (
                                item.get("spec", {}).get("cluster", {}).get("name")
                            )
                            assert cluster_ref == "keycloak-cnpg", (
                                f"Backup CR targets wrong cluster: {cluster_ref}"
                            )
                        break
                except ApiException:
                    pass

            assert backup_found, (
                f"No CNPG Backup CR was created for Keycloak {keycloak_name} "
                "after triggering a minor version upgrade."
            )

            logger.info("CNPG Backup CR(s) created: %s", ", ".join(created_backup_crs))

        finally:
            # Clean up Keycloak CR
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

            # Clean up CNPG Backup CRs
            for backup_name in created_backup_crs:
                with contextlib.suppress(ApiException):
                    await k8s_custom_objects.delete_namespaced_custom_object(
                        group="postgresql.cnpg.io",
                        version="v1",
                        namespace=operator_namespace,
                        plural="backups",
                        name=backup_name,
                    )

            # Clean up copied secret
            with contextlib.suppress(ApiException):
                await k8s_core_v1.delete_namespaced_secret(
                    source_secret_name, namespace
                )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestPreUpgradeBackupExternalTier:
    """Tests for external database tier (Tier 3) pre-upgrade backup behavior.

    External tier cannot do automated backups. Default: warn-and-proceed.
    With requireBackupConfirmation: blocks until annotation.
    """

    @pytest.mark.timeout(360)
    async def test_external_tier_warn_and_proceed(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        k8s_core_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        shared_cnpg_info,
    ) -> None:
        """External tier should warn and proceed with upgrade by default.

        We create a Keycloak with external DB config that still points to
        the shared CNPG database (so the instance can actually start), but
        the tier is classified as 'external' because database.external is set.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-ext-warn-{suffix}"
        namespace = test_keycloak_namespace

        # Copy the CNPG secret to the test namespace
        source_secret_name = shared_cnpg_info["password_secret"]
        source_namespace = shared_cnpg_info["password_secret_namespace"]

        source_secret = await k8s_core_v1.read_namespaced_secret(
            name=source_secret_name, namespace=source_namespace
        )

        target_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=source_secret_name,
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            data=source_secret.data,
            type=source_secret.type,
        )
        try:
            await k8s_core_v1.create_namespaced_secret(namespace, target_secret)
        except ApiException as e:
            if e.status != 409:
                raise

        # Build external-tier spec: uses database.external
        spec = {
            "replicas": 1,
            "image": get_keycloak_test_image(),
            "operatorRef": {"namespace": operator_namespace},
            "database": {
                "type": "postgresql",
                "external": {
                    "host": shared_cnpg_info["host"],
                    "port": shared_cnpg_info["port"],
                    "database": shared_cnpg_info["database"],
                    "username": shared_cnpg_info["username"],
                    "passwordSecret": {
                        "name": source_secret_name,
                        "key": "password",
                    },
                },
            },
            "resources": {
                "requests": {"cpu": "200m", "memory": "512Mi"},
                "limits": {"cpu": "2000m", "memory": "2Gi"},
            },
        }

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Trigger minor version upgrade
            new_image = "keycloak-optimized:27.0.0"
            patch_body = {"spec": {"image": new_image}}
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # External tier default: warn-and-proceed. Deployment should update.
            deployment_name = f"{keycloak_name}-keycloak"
            updated = False
            for _ in range(30):
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        updated = True
                        break
                except ApiException:
                    pass

            assert updated, (
                f"Deployment image was not updated to {new_image}. "
                "External tier (default) should warn-and-proceed, not block."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_core_v1.delete_namespaced_secret(
                    source_secret_name, namespace
                )

    @pytest.mark.timeout(420)
    async def test_external_tier_manual_gate_blocks_and_unblocks(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        k8s_core_v1,
        test_keycloak_namespace,
        operator_namespace,
        shared_operator,
        shared_cnpg_info,
    ) -> None:
        """External tier with requireBackupConfirmation blocks until annotation.

        Same as legacy manual gate test but explicitly using the external tier.
        """
        suffix = uuid.uuid4().hex[:8]
        keycloak_name = f"test-ext-gate-{suffix}"
        namespace = test_keycloak_namespace

        # Copy secret
        source_secret_name = shared_cnpg_info["password_secret"]
        source_namespace = shared_cnpg_info["password_secret_namespace"]

        source_secret = await k8s_core_v1.read_namespaced_secret(
            name=source_secret_name, namespace=source_namespace
        )

        target_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=source_secret_name,
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            data=source_secret.data,
            type=source_secret.type,
        )
        try:
            await k8s_core_v1.create_namespaced_secret(namespace, target_secret)
        except ApiException as e:
            if e.status != 409:
                raise

        spec = {
            "replicas": 1,
            "image": get_keycloak_test_image(),
            "operatorRef": {"namespace": operator_namespace},
            "database": {
                "type": "postgresql",
                "external": {
                    "host": shared_cnpg_info["host"],
                    "port": shared_cnpg_info["port"],
                    "database": shared_cnpg_info["database"],
                    "username": shared_cnpg_info["username"],
                    "passwordSecret": {
                        "name": source_secret_name,
                        "key": "password",
                    },
                },
            },
            "upgradePolicy": {
                "requireBackupConfirmation": True,
            },
            "resources": {
                "requests": {"cpu": "200m", "memory": "512Mi"},
                "limits": {"cpu": "2000m", "memory": "2Gi"},
            },
        }

        keycloak_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "Keycloak",
            "metadata": {"name": keycloak_name, "namespace": namespace},
            "spec": spec,
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                timeout=180,
                operator_namespace=operator_namespace,
            )

            # Trigger minor upgrade
            new_image = "keycloak-optimized:27.0.0"
            patch_body = {"spec": {"image": new_image}}
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=patch_body,
            )

            # Verify blocked: deployment should NOT update
            deployment_name = f"{keycloak_name}-keycloak"
            blocked = True
            for _ in range(12):  # 60s
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        blocked = False
                        break
                except ApiException:
                    pass

            assert blocked, (
                "Deployment updated despite requireBackupConfirmation=true on external tier."
            )

            # Apply confirmation annotation
            annotation_patch = {
                "metadata": {
                    "annotations": {
                        BACKUP_CONFIRMED_ANNOTATION: "true",
                    }
                }
            }
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
                body=annotation_patch,
            )

            # Verify unblocked
            unblocked = False
            for _ in range(30):  # 150s
                await asyncio.sleep(5)
                try:
                    dep = await k8s_apps_v1.read_namespaced_deployment(
                        deployment_name, namespace
                    )
                    current_image = dep.spec.template.spec.containers[0].image
                    if current_image == new_image:
                        unblocked = True
                        break
                except ApiException:
                    pass

            assert unblocked, (
                f"Deployment not updated to {new_image} after applying backup-confirmed annotation."
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
            with contextlib.suppress(ApiException):
                await k8s_core_v1.delete_namespaced_secret(
                    source_secret_name, namespace
                )
