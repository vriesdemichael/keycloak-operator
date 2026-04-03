"""
Blue-green upgrade orchestration service (ADR-088 Phase 3, ADR-092).

This module implements the state machine that drives zero-downtime Keycloak
major/minor version upgrades using the blue-green deployment pattern.

## How it works

When ``spec.upgradePolicy.strategy == "BlueGreen"`` and the operator detects a
major or minor version bump, ``BlueGreenUpgradeService.run_upgrade`` is called
instead of the normal in-place deployment update.  The state machine progresses
through these states:

1. **Idle** – no upgrade in progress.
2. **BackingUp** – pre-upgrade backup (delegated to BackupService).  Only CNPG
   and managed tiers can produce automated backups; external tier warns and
   proceeds immediately.
3. **ProvisioningGreen** – second (green) Deployment and its headless discovery
   Service are created with the new image and a revision-derived JGroups cluster
   name.
4. **WaitingForGreen** – operator polls the green Deployment until
   ``readyReplicas == replicas`` or a timeout is reached.
5. **CuttingOver** – Service selector is patched atomically to point to green
   pods.  Blue traffic stops; customers never see both versions simultaneously.
6. **TearingDownBlue** – (optional, controlled by ``autoTeardown``) remove the
   old blue Deployment and discovery Service.
7. **Completed** / **Failed** – terminal states; ``status.blueGreen`` is
   retained for observability and cleared on the *next* reconciliation cycle.

## Resumability

Each state transition persists the new state to ``status.blueGreen`` via the
``status`` (kopf patch dict).  On operator restart the reconciler reads the
persisted state and calls ``run_upgrade`` which resumes from the recorded step.

## Naming convention

Green deployment:  ``{name}-green-keycloak``
Green discovery:   ``{name}-green-discovery``

These names are deterministic so ArgoCD never enters a sync loop.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..models.keycloak import BlueGreenUpgradeStatus, KeycloakSpec  # noqa: TC001
from ..utils.kubernetes import (
    create_keycloak_deployment,
    create_keycloak_discovery_service,
)

if TYPE_CHECKING:
    from ..services.base_reconciler import StatusProtocol

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------

STATE_IDLE = "Idle"
STATE_BACKING_UP = "BackingUp"
STATE_PROVISIONING_GREEN = "ProvisioningGreen"
STATE_WAITING_FOR_GREEN = "WaitingForGreen"
STATE_CUTTING_OVER = "CuttingOver"
STATE_TEARING_DOWN_BLUE = "TearingDownBlue"
STATE_COMPLETED = "Completed"
STATE_FAILED = "Failed"

# Maximum seconds to wait for the green deployment to become ready.
# Separate from the backup timeout because image pull and Keycloak boot
# is a different workload than a CNPG backup.
_DEFAULT_GREEN_READY_TIMEOUT = 600


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _green_deployment_name(name: str) -> str:
    return f"{name}-green-keycloak"


def _green_discovery_name(name: str) -> str:
    return f"{name}-green-discovery"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _write_bg_status(
    status: StatusProtocol,
    bg: BlueGreenUpgradeStatus,
) -> None:
    """Persist BlueGreenUpgradeStatus to the kopf status patch dict."""
    status["blueGreen"] = bg.model_dump(by_alias=True, exclude_none=True)  # type: ignore[call-overload]


# ---------------------------------------------------------------------------
# Public service class
# ---------------------------------------------------------------------------


class BlueGreenUpgradeService:
    """
    Orchestrates zero-downtime Keycloak upgrades via the blue-green pattern.

    This class is instantiated once per reconciliation pass and may be called
    from both ``do_update`` (image change detected) and ``do_reconcile`` (resume
    after operator restart).
    """

    def __init__(self, kubernetes_client: client.ApiClient | None = None) -> None:
        self._k8s = kubernetes_client
        self.logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run_upgrade(
        self,
        name: str,
        namespace: str,
        spec: KeycloakSpec,
        running_image: str,
        desired_image: str,
        status: StatusProtocol,
        db_connection_info: dict[str, Any] | None = None,
    ) -> None:
        """
        Drive the blue-green state machine for a single upgrade cycle.

        Called from the reconciler whenever ``strategy == "BlueGreen"`` and an
        upgrade has been detected (or was already in progress).  Resumes from
        the last persisted state stored in ``status.blueGreen``.

        Args:
            name: Keycloak CR name.
            namespace: Resource namespace.
            spec: Validated KeycloakSpec.
            running_image: Image currently running in the blue deployment.
            desired_image: New image from the spec.
            status: Kopf status patch dict (mutated in-place to persist state).
            db_connection_info: Optional resolved DB connection info (for CNPG).

        Raises:
            kopf.TemporaryError: If green deployment is not yet ready (retry).
            kopf.PermanentError: If an unrecoverable failure is detected.
        """
        import kopf

        # Determine current state from persisted status
        raw_bg = status.get("blueGreen") if hasattr(status, "get") else None  # type: ignore[union-attr]
        if isinstance(raw_bg, dict):
            bg = BlueGreenUpgradeStatus.model_validate(raw_bg)
        else:
            bg = BlueGreenUpgradeStatus(
                state=STATE_IDLE,
                blue_revision=running_image,
                green_revision=desired_image,
                started_at=_now_iso(),
            )

        self.logger.info(
            f"Blue-green upgrade for {name}: state={bg.state} "
            f"blue={bg.blue_revision} green={bg.green_revision}"
        )

        # ------------------------------------------------------------------
        # State: Idle / BackingUp  (already handled by reconciler's backup step)
        # ------------------------------------------------------------------
        # By the time we get here the reconciler has already called
        # _maybe_perform_pre_upgrade_backup which either completed the backup
        # (CNPG/managed) or warned-and-proceeded (external).  We skip directly
        # to ProvisioningGreen.

        if bg.state in (STATE_IDLE, STATE_BACKING_UP):
            bg.state = STATE_PROVISIONING_GREEN
            bg.message = "Provisioning green deployment"
            _write_bg_status(status, bg)
            self.logger.info(f"[{name}] Transitioning to ProvisioningGreen")

        # ------------------------------------------------------------------
        # State: ProvisioningGreen
        # ------------------------------------------------------------------
        if bg.state == STATE_PROVISIONING_GREEN:
            await self._provision_green(
                name, namespace, spec, desired_image, db_connection_info
            )
            bg.state = STATE_WAITING_FOR_GREEN
            bg.green_deployment = _green_deployment_name(name)
            bg.green_discovery_service = _green_discovery_name(name)
            bg.message = (
                f"Waiting for green deployment {bg.green_deployment} to become ready"
            )
            _write_bg_status(status, bg)
            self.logger.info(f"[{name}] Transitioning to WaitingForGreen")

        # ------------------------------------------------------------------
        # State: WaitingForGreen
        # ------------------------------------------------------------------
        if bg.state == STATE_WAITING_FOR_GREEN:
            assert bg.green_deployment is not None  # always set in ProvisioningGreen
            ready = await self._wait_for_green_ready(
                name=name,
                namespace=namespace,
                green_deployment_name=bg.green_deployment,
                timeout=_DEFAULT_GREEN_READY_TIMEOUT,
            )
            if not ready:
                # Not ready yet — raise TemporaryError to retry later
                raise kopf.TemporaryError(
                    f"Green deployment {bg.green_deployment} is not yet ready; "
                    "will retry",
                    delay=30,
                )
            bg.state = STATE_CUTTING_OVER
            bg.message = "Cutting over Service selector to green deployment"
            _write_bg_status(status, bg)
            self.logger.info(
                f"[{name}] Green deployment ready; transitioning to CuttingOver"
            )

        # ------------------------------------------------------------------
        # State: CuttingOver
        # ------------------------------------------------------------------
        if bg.state == STATE_CUTTING_OVER:
            await self._cutover_service(name, namespace)
            bg.state = (
                STATE_TEARING_DOWN_BLUE
                if spec.upgrade_policy.auto_teardown
                else STATE_COMPLETED
            )  # type: ignore[union-attr]
            bg.message = "Service selector updated; blue traffic stopped"
            _write_bg_status(status, bg)
            self.logger.info(f"[{name}] Service cutover complete")

        # ------------------------------------------------------------------
        # State: TearingDownBlue
        # ------------------------------------------------------------------
        if bg.state == STATE_TEARING_DOWN_BLUE:
            await self._teardown_blue(name, namespace)
            bg.state = STATE_COMPLETED
            bg.message = "Blue deployment removed; upgrade complete"
            _write_bg_status(status, bg)
            self.logger.info(f"[{name}] Blue deployment torn down; upgrade complete")

        # ------------------------------------------------------------------
        # State: Completed
        # ------------------------------------------------------------------
        if bg.state == STATE_COMPLETED:
            bg.completed_at = _now_iso()
            _write_bg_status(status, bg)
            self.logger.info(
                f"[{name}] Blue-green upgrade completed successfully. "
                f"{bg.blue_revision} -> {bg.green_revision}"
            )
            # Rename green deployment to canonical name so the next reconcile
            # pass treats it as the primary deployment.
            await self._promote_green_to_primary(name, namespace, spec)

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    async def _provision_green(
        self,
        name: str,
        namespace: str,
        spec: KeycloakSpec,
        desired_image: str,
        db_connection_info: dict[str, Any] | None,
    ) -> None:
        """Create the green Deployment and its headless discovery Service."""
        apps_api = client.AppsV1Api(self._k8s)
        core_api = client.CoreV1Api(self._k8s)

        green_name = _green_deployment_name(name)
        green_discovery = _green_discovery_name(name)

        # Build a modified spec with the new image only
        green_spec = copy.deepcopy(spec)
        green_spec.image = desired_image  # type: ignore[assignment]

        # --- Green deployment ---
        try:
            apps_api.read_namespaced_deployment(name=green_name, namespace=namespace)
            self.logger.info(
                f"Green deployment {green_name} already exists — skipping create"
            )
        except ApiException as e:
            if e.status == 404:
                deployment = create_keycloak_deployment(
                    name=f"{name}-green",
                    namespace=namespace,
                    spec=green_spec,
                    k8s_client=self._k8s,
                    db_connection_info=db_connection_info,
                )
                self.logger.info(
                    f"Created green deployment: {deployment.metadata.name}"
                )
            else:
                raise

        # --- Green discovery service ---
        try:
            core_api.read_namespaced_service(name=green_discovery, namespace=namespace)
            self.logger.info(
                f"Green discovery service {green_discovery} already exists — skipping create"
            )
        except ApiException as e:
            if e.status == 404:
                disc_service = create_keycloak_discovery_service(
                    name=f"{name}-green",
                    namespace=namespace,
                    k8s_client=self._k8s,
                    spec=green_spec,
                )
                self.logger.info(
                    f"Created green discovery service: {disc_service.metadata.name}"
                )
            else:
                raise

    async def _wait_for_green_ready(
        self,
        name: str,
        namespace: str,
        green_deployment_name: str,
        timeout: int,
    ) -> bool:
        """
        Poll the green Deployment until readyReplicas == replicas or timeout.

        Returns True if ready, False if timed out.  This is deliberately
        non-blocking with very small polling intervals so the caller can raise a
        TemporaryError and let kopf retry rather than blocking the event loop for
        10 minutes.

        Actually we do a *quick* non-blocking check here (10 s max) and return
        False if not ready so the kopf retry mechanism naturally handles the
        wait via TemporaryError delay=30.
        """
        apps_api = client.AppsV1Api(self._k8s)

        deadline = asyncio.get_event_loop().time() + min(timeout, 10)
        while asyncio.get_event_loop().time() < deadline:
            try:
                dep = apps_api.read_namespaced_deployment(
                    name=green_deployment_name, namespace=namespace
                )
                desired = dep.spec.replicas or 1
                ready = dep.status.ready_replicas or 0
                if ready >= desired:
                    self.logger.info(
                        f"Green deployment {green_deployment_name} ready "
                        f"({ready}/{desired} replicas)"
                    )
                    return True
                self.logger.debug(
                    f"Green deployment {green_deployment_name}: {ready}/{desired} replicas ready"
                )
            except ApiException as e:
                if e.status == 404:
                    self.logger.debug(
                        f"Green deployment {green_deployment_name} not found yet"
                    )
                else:
                    raise
            await asyncio.sleep(2)

        return False

    async def _cutover_service(self, name: str, namespace: str) -> None:
        """Patch the main Service selector to point to green pods."""
        core_api = client.CoreV1Api(self._k8s)
        service_name = f"{name}-keycloak"

        patch = {
            "spec": {
                "selector": {
                    "app": "keycloak",
                    "vriesdemichael.github.io/keycloak-instance": f"{name}-green",
                }
            }
        }
        core_api.patch_namespaced_service(
            name=service_name,
            namespace=namespace,
            body=patch,
        )
        self.logger.info(
            f"[{name}] Service {service_name} selector patched to green pods"
        )

    async def _teardown_blue(self, name: str, namespace: str) -> None:
        """Delete the original blue Deployment and its discovery Service."""
        apps_api = client.AppsV1Api(self._k8s)
        core_api = client.CoreV1Api(self._k8s)

        blue_deployment = f"{name}-keycloak"
        blue_discovery = f"{name}-discovery"

        for resource_name, delete_fn in [
            (
                blue_deployment,
                lambda n: apps_api.delete_namespaced_deployment(
                    name=n, namespace=namespace
                ),
            ),
            (
                blue_discovery,
                lambda n: core_api.delete_namespaced_service(
                    name=n, namespace=namespace
                ),
            ),
        ]:
            try:
                delete_fn(resource_name)
                self.logger.info(f"[{name}] Deleted blue resource: {resource_name}")
            except ApiException as e:
                if e.status == 404:
                    self.logger.debug(
                        f"[{name}] Blue resource {resource_name} already gone"
                    )
                else:
                    raise

    async def _promote_green_to_primary(
        self,
        name: str,
        namespace: str,
        spec: KeycloakSpec,
    ) -> None:
        """
        After teardown, rename green resources to canonical names.

        Kubernetes does not support in-place resource rename, so we:
        1. Read the green Deployment/Service
        2. Create new resources with the canonical name (``{name}-keycloak``)
        3. Delete the green-suffixed resources

        This step is idempotent — if the canonical resource already exists
        (previous run completed step 3) we simply skip creation.
        """
        apps_api = client.AppsV1Api(self._k8s)
        core_api = client.CoreV1Api(self._k8s)

        green_deploy_name = _green_deployment_name(name)  # {name}-green-keycloak
        canonical_deploy_name = f"{name}-keycloak"
        green_disc_name = _green_discovery_name(name)  # {name}-green-discovery
        canonical_disc_name = f"{name}-discovery"

        # --- Promote deployment ---
        canonical_exists = False
        try:
            apps_api.read_namespaced_deployment(
                name=canonical_deploy_name, namespace=namespace
            )
            canonical_exists = True
        except ApiException as e:
            if e.status != 404:
                raise

        if not canonical_exists:
            try:
                green_dep = apps_api.read_namespaced_deployment(
                    name=green_deploy_name, namespace=namespace
                )
                # Copy and rename
                new_meta = client.V1ObjectMeta(
                    name=canonical_deploy_name,
                    namespace=namespace,
                    labels=green_dep.metadata.labels,
                    annotations=green_dep.metadata.annotations,
                )
                green_dep.metadata = new_meta
                green_dep.status = None
                apps_api.create_namespaced_deployment(
                    namespace=namespace, body=green_dep
                )
                self.logger.info(
                    f"[{name}] Promoted green deployment to {canonical_deploy_name}"
                )
            except ApiException as e:
                if e.status == 409:
                    pass  # created concurrently
                elif e.status == 404:
                    self.logger.warning(
                        f"[{name}] Green deployment {green_deploy_name} already gone"
                    )
                else:
                    raise

        # Delete green deployment
        try:
            apps_api.delete_namespaced_deployment(
                name=green_deploy_name, namespace=namespace
            )
            self.logger.info(f"[{name}] Deleted green deployment {green_deploy_name}")
        except ApiException as e:
            if e.status != 404:
                raise

        # --- Promote discovery service ---
        disc_canonical_exists = False
        try:
            core_api.read_namespaced_service(
                name=canonical_disc_name, namespace=namespace
            )
            disc_canonical_exists = True
        except ApiException as e:
            if e.status != 404:
                raise

        if not disc_canonical_exists:
            try:
                green_disc = core_api.read_namespaced_service(
                    name=green_disc_name, namespace=namespace
                )
                new_meta = client.V1ObjectMeta(
                    name=canonical_disc_name,
                    namespace=namespace,
                    labels=green_disc.metadata.labels,
                    annotations=green_disc.metadata.annotations,
                )
                green_disc.metadata = new_meta
                green_disc.status = None
                green_disc.spec.cluster_ip = None  # can't copy ClusterIP
                core_api.create_namespaced_service(namespace=namespace, body=green_disc)
                self.logger.info(
                    f"[{name}] Promoted green discovery to {canonical_disc_name}"
                )
            except ApiException as e:
                if e.status == 409:
                    pass
                elif e.status == 404:
                    self.logger.warning(
                        f"[{name}] Green discovery {green_disc_name} already gone"
                    )
                else:
                    raise

        # Delete green discovery
        try:
            core_api.delete_namespaced_service(
                name=green_disc_name, namespace=namespace
            )
            self.logger.info(
                f"[{name}] Deleted green discovery service {green_disc_name}"
            )
        except ApiException as e:
            if e.status != 404:
                raise

        # Patch service selector back to canonical name
        service_name = f"{name}-keycloak"
        patch = {
            "spec": {
                "selector": {
                    "app": "keycloak",
                    "vriesdemichael.github.io/keycloak-instance": name,
                }
            }
        }
        try:
            core_api.patch_namespaced_service(
                name=service_name, namespace=namespace, body=patch
            )
            self.logger.info(
                f"[{name}] Service selector restored to canonical instance label"
            )
        except ApiException as e:
            if e.status != 404:
                raise
