"""
Unit tests for BlueGreenUpgradeService and related model additions (ADR-092).

Covers:
- UpgradePolicy model: strategy validation, autoTeardown
- BlueGreenUpgradeStatus model: field aliases, defaults
- BlueGreenUpgradeService state machine: each step
- Resume from mid-upgrade state
- autoTeardown=False skips teardown step
- Reconciler integration: blue-green called on image change with BlueGreen strategy
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.models.keycloak import (
    BlueGreenUpgradeStatus,
    UpgradePolicy,
)
from keycloak_operator.services.blue_green_service import (
    STATE_COMPLETED,
    STATE_CUTTING_OVER,
    STATE_IDLE,
    STATE_WAITING_FOR_GREEN,
    BlueGreenUpgradeService,
    _green_deployment_name,
    _green_discovery_name,
)

# ===========================================================================
# Model Tests
# ===========================================================================


class TestUpgradePolicyModel:
    """Tests for updated UpgradePolicy model fields."""

    def test_default_strategy_is_recreate(self):
        policy = UpgradePolicy()
        assert policy.strategy == "Recreate"

    def test_blue_green_strategy(self):
        policy = UpgradePolicy(strategy="BlueGreen")
        assert policy.strategy == "BlueGreen"

    def test_invalid_strategy_raises(self):
        with pytest.raises(ValueError):
            UpgradePolicy(strategy="Rolling")

    def test_default_auto_teardown_true(self):
        policy = UpgradePolicy()
        assert policy.auto_teardown is True

    def test_auto_teardown_false(self):
        policy = UpgradePolicy(autoTeardown=False)
        assert policy.auto_teardown is False

    def test_alias_auto_teardown(self):
        data = {"autoTeardown": False, "strategy": "BlueGreen"}
        policy = UpgradePolicy.model_validate(data)
        assert policy.auto_teardown is False

    def test_camel_case_strategy(self):
        # strategy has no alias but field name is snake_case internally
        policy = UpgradePolicy.model_validate({"strategy": "BlueGreen"})
        assert policy.strategy == "BlueGreen"

    def test_dump_includes_strategy(self):
        policy = UpgradePolicy(strategy="BlueGreen", autoTeardown=False)
        dumped = policy.model_dump(by_alias=True, exclude_none=True)
        assert dumped["strategy"] == "BlueGreen"
        assert dumped["autoTeardown"] is False


class TestBlueGreenUpgradeStatusModel:
    """Tests for BlueGreenUpgradeStatus model."""

    def test_default_state_idle(self):
        bg = BlueGreenUpgradeStatus()
        assert bg.state == STATE_IDLE

    def test_field_aliases(self):
        bg = BlueGreenUpgradeStatus.model_validate(
            {
                "state": "WaitingForGreen",
                "blueRevision": "img:26",
                "greenRevision": "img:27",
                "greenDeployment": "kc-green-keycloak",
                "greenDiscoveryService": "kc-green-discovery",
                "startedAt": "2026-01-01T00:00:00+00:00",
            }
        )
        assert bg.state == "WaitingForGreen"
        assert bg.blue_revision == "img:26"
        assert bg.green_revision == "img:27"
        assert bg.green_deployment == "kc-green-keycloak"
        assert bg.green_discovery_service == "kc-green-discovery"
        assert bg.started_at == "2026-01-01T00:00:00+00:00"

    def test_dump_by_alias(self):
        bg = BlueGreenUpgradeStatus(
            state=STATE_CUTTING_OVER,
            blue_revision="img:26",
            green_revision="img:27",
        )
        dumped = bg.model_dump(by_alias=True, exclude_none=True)
        assert dumped["state"] == STATE_CUTTING_OVER
        assert dumped["blueRevision"] == "img:26"
        assert dumped["greenRevision"] == "img:27"

    def test_none_fields_excluded_when_exclude_none(self):
        bg = BlueGreenUpgradeStatus(state=STATE_IDLE)
        dumped = bg.model_dump(by_alias=True, exclude_none=True)
        assert "blueRevision" not in dumped
        assert "greenDeployment" not in dumped


# ===========================================================================
# Naming helpers
# ===========================================================================


def test_green_deployment_name():
    assert _green_deployment_name("my-kc") == "my-kc-green-keycloak"


def test_green_discovery_name():
    assert _green_discovery_name("my-kc") == "my-kc-green-discovery"


# ===========================================================================
# BlueGreenUpgradeService state machine
# ===========================================================================


def _make_service() -> BlueGreenUpgradeService:
    k8s_client = MagicMock()
    return BlueGreenUpgradeService(kubernetes_client=k8s_client)


def _make_spec(strategy: str = "BlueGreen", auto_teardown: bool = True) -> MagicMock:
    spec = MagicMock()
    spec.upgrade_policy = UpgradePolicy(strategy=strategy, autoTeardown=auto_teardown)
    spec.image = "keycloak:27.0.0"
    return spec


def _make_status(initial: dict | None = None) -> dict:
    """Return a plain dict that mimics the kopf status patch object."""
    return initial or {}


class TestBlueGreenServiceProvisionGreen:
    """Test _provision_green step."""

    @pytest.mark.asyncio
    async def test_creates_deployment_and_discovery_service(self):
        svc = _make_service()
        spec = _make_spec()

        with (
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=True
            ),
            patch.object(svc, "_cutover_service", new_callable=AsyncMock),
            patch.object(svc, "_teardown_blue", new_callable=AsyncMock),
            patch.object(svc, "_promote_green_to_primary", new_callable=AsyncMock),
            patch(
                "keycloak_operator.services.blue_green_service.create_keycloak_deployment"
            ) as mock_create_deploy,
            patch(
                "keycloak_operator.services.blue_green_service.create_keycloak_discovery_service"
            ) as mock_create_disc,
        ):
            # Simulate 404 on read (resources don't exist yet)
            apps_api_instance = MagicMock()
            core_api_instance = MagicMock()
            apps_api_instance.read_namespaced_deployment.side_effect = ApiException(
                status=404
            )
            core_api_instance.read_namespaced_service.side_effect = ApiException(
                status=404
            )

            mock_deploy = MagicMock()
            mock_deploy.metadata.name = "kc-green-keycloak"
            mock_create_deploy.return_value = mock_deploy

            mock_disc = MagicMock()
            mock_disc.metadata.name = "kc-green-discovery"
            mock_create_disc.return_value = mock_disc

            with (
                patch(
                    "keycloak_operator.services.blue_green_service.client.AppsV1Api",
                    return_value=apps_api_instance,
                ),
                patch(
                    "keycloak_operator.services.blue_green_service.client.CoreV1Api",
                    return_value=core_api_instance,
                ),
            ):
                await svc._provision_green("kc", "ns", spec, "keycloak:27.0.0", None)

        mock_create_deploy.assert_called_once()
        # Verify canonical admin secret is forwarded so green pods can authenticate
        assert (
            mock_create_deploy.call_args.kwargs.get("admin_secret_name")
            == "kc-admin-credentials"
        )
        mock_create_disc.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_create_when_already_exists(self):
        svc = _make_service()
        spec = _make_spec()

        with (
            patch(
                "keycloak_operator.services.blue_green_service.create_keycloak_deployment"
            ) as mock_create_deploy,
            patch(
                "keycloak_operator.services.blue_green_service.create_keycloak_discovery_service"
            ) as mock_create_disc,
        ):
            apps_api_instance = MagicMock()
            core_api_instance = MagicMock()
            # Both already exist — read returns successfully
            apps_api_instance.read_namespaced_deployment.return_value = MagicMock()
            core_api_instance.read_namespaced_service.return_value = MagicMock()

            with (
                patch(
                    "keycloak_operator.services.blue_green_service.client.AppsV1Api",
                    return_value=apps_api_instance,
                ),
                patch(
                    "keycloak_operator.services.blue_green_service.client.CoreV1Api",
                    return_value=core_api_instance,
                ),
            ):
                await svc._provision_green("kc", "ns", spec, "keycloak:27.0.0", None)

        mock_create_deploy.assert_not_called()
        mock_create_disc.assert_not_called()


class TestBlueGreenServiceWaitForGreen:
    """Test _wait_for_green_ready step."""

    @pytest.mark.asyncio
    async def test_returns_true_when_ready(self):
        svc = _make_service()
        dep = MagicMock()
        dep.spec.replicas = 1
        dep.status.ready_replicas = 1

        apps_api_instance = MagicMock()
        apps_api_instance.read_namespaced_deployment.return_value = dep

        with patch(
            "keycloak_operator.services.blue_green_service.client.AppsV1Api",
            return_value=apps_api_instance,
        ):
            result = await svc._wait_for_green_ready(
                "kc", "ns", "kc-green-keycloak", timeout=60
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_not_ready_within_timeout(self):
        svc = _make_service()
        dep = MagicMock()
        dep.spec.replicas = 1
        dep.status.ready_replicas = 0  # never ready

        apps_api_instance = MagicMock()
        apps_api_instance.read_namespaced_deployment.return_value = dep

        with patch(
            "keycloak_operator.services.blue_green_service.client.AppsV1Api",
            return_value=apps_api_instance,
        ):
            result = await svc._wait_for_green_ready(
                "kc", "ns", "kc-green-keycloak", timeout=1
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_deployment_not_found(self):
        svc = _make_service()
        apps_api_instance = MagicMock()
        apps_api_instance.read_namespaced_deployment.side_effect = ApiException(
            status=404
        )

        with patch(
            "keycloak_operator.services.blue_green_service.client.AppsV1Api",
            return_value=apps_api_instance,
        ):
            result = await svc._wait_for_green_ready(
                "kc", "ns", "kc-green-keycloak", timeout=1
            )

        assert result is False


class TestBlueGreenServiceCutover:
    """Test _cutover_service step."""

    @pytest.mark.asyncio
    async def test_patches_service_selector(self):
        svc = _make_service()
        core_api_instance = MagicMock()

        with patch(
            "keycloak_operator.services.blue_green_service.client.CoreV1Api",
            return_value=core_api_instance,
        ):
            await svc._cutover_service("kc", "ns")

        core_api_instance.patch_namespaced_service.assert_called_once()
        call_kwargs = core_api_instance.patch_namespaced_service.call_args
        assert (
            call_kwargs.kwargs.get(
                "name", call_kwargs.args[0] if call_kwargs.args else None
            )
            == "kc-keycloak"
            or call_kwargs[1].get("name") == "kc-keycloak"
            or call_kwargs[0][0] == "kc-keycloak"
        )
        # Verify the selector points to green instance
        patch_body = core_api_instance.patch_namespaced_service.call_args.kwargs.get(
            "body"
        ) or core_api_instance.patch_namespaced_service.call_args[1].get(
            "body",
            core_api_instance.patch_namespaced_service.call_args[0][2]
            if len(core_api_instance.patch_namespaced_service.call_args[0]) > 2
            else {},
        )
        selector = patch_body.get("spec", {}).get("selector", {})
        assert selector.get("vriesdemichael.github.io/keycloak-instance") == "kc-green"


class TestBlueGreenServiceTeardownBlue:
    """Test _teardown_blue step."""

    @pytest.mark.asyncio
    async def test_deletes_blue_deployment_and_discovery(self):
        svc = _make_service()
        apps_api_instance = MagicMock()
        core_api_instance = MagicMock()

        with (
            patch(
                "keycloak_operator.services.blue_green_service.client.AppsV1Api",
                return_value=apps_api_instance,
            ),
            patch(
                "keycloak_operator.services.blue_green_service.client.CoreV1Api",
                return_value=core_api_instance,
            ),
        ):
            await svc._teardown_blue("kc", "ns")

        apps_api_instance.delete_namespaced_deployment.assert_called_once()
        core_api_instance.delete_namespaced_service.assert_called_once()

    @pytest.mark.asyncio
    async def test_tolerates_already_deleted(self):
        svc = _make_service()
        apps_api_instance = MagicMock()
        core_api_instance = MagicMock()
        apps_api_instance.delete_namespaced_deployment.side_effect = ApiException(
            status=404
        )
        core_api_instance.delete_namespaced_service.side_effect = ApiException(
            status=404
        )

        with (
            patch(
                "keycloak_operator.services.blue_green_service.client.AppsV1Api",
                return_value=apps_api_instance,
            ),
            patch(
                "keycloak_operator.services.blue_green_service.client.CoreV1Api",
                return_value=core_api_instance,
            ),
        ):
            # Should not raise
            await svc._teardown_blue("kc", "ns")


# ===========================================================================
# Full state machine run_upgrade
# ===========================================================================


class TestRunUpgrade:
    """Test the full run_upgrade state machine transitions."""

    def _mock_all_steps(self, svc: BlueGreenUpgradeService) -> dict:
        """Patch all internal steps and return the mock dict."""
        mocks = {
            "_provision_green": patch.object(
                svc, "_provision_green", new_callable=AsyncMock
            ),
            "_wait_for_green_ready": patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=True
            ),
            "_cutover_service": patch.object(
                svc, "_cutover_service", new_callable=AsyncMock
            ),
            "_teardown_blue": patch.object(
                svc, "_teardown_blue", new_callable=AsyncMock
            ),
            "_promote_green_to_primary": patch.object(
                svc, "_promote_green_to_primary", new_callable=AsyncMock
            ),
        }
        return mocks

    @pytest.mark.asyncio
    async def test_happy_path_with_auto_teardown(self):
        """Full run from Idle → Completed with autoTeardown=True."""
        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=True)
        status = _make_status()

        with (
            patch.object(svc, "_provision_green", new_callable=AsyncMock),
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=True
            ),
            patch.object(svc, "_cutover_service", new_callable=AsyncMock),
            patch.object(
                svc, "_teardown_blue", new_callable=AsyncMock
            ) as mock_teardown,
            patch.object(svc, "_promote_green_to_primary", new_callable=AsyncMock),
        ):
            await svc.run_upgrade(
                name="kc",
                namespace="ns",
                spec=spec,
                running_image="keycloak:26.0.0",
                desired_image="keycloak:27.0.0",
                status=status,
            )

        assert status["blueGreen"]["state"] == STATE_COMPLETED
        mock_teardown.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_teardown_when_auto_teardown_false(self):
        """autoTeardown=False skips TearingDownBlue AND _promote_green_to_primary."""
        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=False)
        status = _make_status()

        with (
            patch.object(svc, "_provision_green", new_callable=AsyncMock),
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=True
            ),
            patch.object(svc, "_cutover_service", new_callable=AsyncMock),
            patch.object(
                svc, "_teardown_blue", new_callable=AsyncMock
            ) as mock_teardown,
            patch.object(
                svc, "_promote_green_to_primary", new_callable=AsyncMock
            ) as mock_promote,
        ):
            await svc.run_upgrade(
                name="kc",
                namespace="ns",
                spec=spec,
                running_image="keycloak:26.0.0",
                desired_image="keycloak:27.0.0",
                status=status,
            )

        assert status["blueGreen"]["state"] == STATE_COMPLETED
        mock_teardown.assert_not_awaited()
        # With autoTeardown=False, green deployment stays; do NOT rename/promote
        mock_promote.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_raises_temporary_error_when_green_not_ready(self):
        """WaitingForGreen raises TemporaryError when green is not ready."""
        import kopf

        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=True)
        status = _make_status(
            {
                "blueGreen": {
                    "state": STATE_WAITING_FOR_GREEN,
                    "greenDeployment": "kc-green-keycloak",
                }
            }
        )

        with (
            patch.object(svc, "_provision_green", new_callable=AsyncMock),
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=False
            ),
        ):
            with pytest.raises(kopf.TemporaryError):
                await svc.run_upgrade(
                    name="kc",
                    namespace="ns",
                    spec=spec,
                    running_image="keycloak:26.0.0",
                    desired_image="keycloak:27.0.0",
                    status=status,
                )

    @pytest.mark.asyncio
    async def test_resumes_from_waiting_for_green(self):
        """Operator restart mid-upgrade: resumes from WaitingForGreen."""
        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=True)
        # Simulate persisted state from previous reconciliation
        status = _make_status(
            {
                "blueGreen": {
                    "state": STATE_WAITING_FOR_GREEN,
                    "blueRevision": "keycloak:26.0.0",
                    "greenRevision": "keycloak:27.0.0",
                    "greenDeployment": "kc-green-keycloak",
                    "greenDiscoveryService": "kc-green-discovery",
                }
            }
        )

        with (
            patch.object(
                svc, "_provision_green", new_callable=AsyncMock
            ) as mock_provision,
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock, return_value=True
            ),
            patch.object(svc, "_cutover_service", new_callable=AsyncMock),
            patch.object(svc, "_teardown_blue", new_callable=AsyncMock),
            patch.object(svc, "_promote_green_to_primary", new_callable=AsyncMock),
        ):
            await svc.run_upgrade(
                name="kc",
                namespace="ns",
                spec=spec,
                running_image="keycloak:26.0.0",
                desired_image="keycloak:27.0.0",
                status=status,
            )

        # _provision_green should NOT be called — we're past that state
        mock_provision.assert_not_awaited()
        assert status["blueGreen"]["state"] == STATE_COMPLETED

    @pytest.mark.asyncio
    async def test_resumes_from_cutting_over(self):
        """Resumes from CuttingOver state (post-green-ready)."""
        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=True)
        status = _make_status(
            {
                "blueGreen": {
                    "state": STATE_CUTTING_OVER,
                    "blueRevision": "keycloak:26.0.0",
                    "greenRevision": "keycloak:27.0.0",
                    "greenDeployment": "kc-green-keycloak",
                }
            }
        )

        with (
            patch.object(
                svc, "_provision_green", new_callable=AsyncMock
            ) as mock_provision,
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock
            ) as mock_wait,
            patch.object(svc, "_cutover_service", new_callable=AsyncMock),
            patch.object(svc, "_teardown_blue", new_callable=AsyncMock),
            patch.object(svc, "_promote_green_to_primary", new_callable=AsyncMock),
        ):
            await svc.run_upgrade(
                name="kc",
                namespace="ns",
                spec=spec,
                running_image="keycloak:26.0.0",
                desired_image="keycloak:27.0.0",
                status=status,
            )

        mock_provision.assert_not_awaited()
        mock_wait.assert_not_awaited()
        assert status["blueGreen"]["state"] == STATE_COMPLETED

    @pytest.mark.asyncio
    async def test_completed_state_is_idempotent(self):
        """Calling run_upgrade on an already-Completed status is a no-op."""
        svc = _make_service()
        spec = _make_spec(strategy="BlueGreen", auto_teardown=True)
        status = _make_status(
            {
                "blueGreen": {
                    "state": STATE_COMPLETED,
                    "blueRevision": "keycloak:26.0.0",
                    "greenRevision": "keycloak:27.0.0",
                }
            }
        )

        with (
            patch.object(
                svc, "_provision_green", new_callable=AsyncMock
            ) as mock_provision,
            patch.object(
                svc, "_wait_for_green_ready", new_callable=AsyncMock
            ) as mock_wait,
            patch.object(
                svc, "_cutover_service", new_callable=AsyncMock
            ) as mock_cutover,
            patch.object(
                svc, "_teardown_blue", new_callable=AsyncMock
            ) as mock_teardown,
            patch.object(svc, "_promote_green_to_primary", new_callable=AsyncMock),
        ):
            await svc.run_upgrade(
                name="kc",
                namespace="ns",
                spec=spec,
                running_image="keycloak:26.0.0",
                desired_image="keycloak:27.0.0",
                status=status,
            )

        mock_provision.assert_not_awaited()
        mock_wait.assert_not_awaited()
        mock_cutover.assert_not_awaited()
        mock_teardown.assert_not_awaited()
        # promote IS called because default spec has auto_teardown=True


# ===========================================================================
# Reconciler integration: do_update routes to blue-green service
# ===========================================================================


class TestReconcilerBlueGreenIntegration:
    """Verify do_update calls blue_green_service.run_upgrade on image change."""

    @pytest.mark.asyncio
    async def test_do_update_calls_blue_green_on_image_change(self):
        """do_update should call run_upgrade when strategy == BlueGreen."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        reconciler = KeycloakInstanceReconciler(k8s_client=MagicMock())

        # Patch heavy dependencies
        reconciler.blue_green_service = MagicMock()
        reconciler.blue_green_service.run_upgrade = AsyncMock()
        reconciler._maybe_perform_pre_upgrade_backup = AsyncMock()
        reconciler._update_deployment = AsyncMock()
        reconciler._update_ingress = AsyncMock()
        reconciler.do_reconcile = AsyncMock(return_value={})

        old_spec = {
            "image": "keycloak:26.0.0",
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "kc",
                "credentials_secret": "s",
            },
            "operatorRef": {"namespace": "ops"},
        }
        new_spec = {
            "image": "keycloak:27.0.0",
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "kc",
                "credentials_secret": "s",
            },
            "operatorRef": {"namespace": "ops"},
            "upgradePolicy": {"strategy": "BlueGreen"},
        }

        diff = [("change", ("spec", "image"), "keycloak:26.0.0", "keycloak:27.0.0")]

        status = {}
        await reconciler.do_update(
            old_spec=old_spec,
            new_spec=new_spec,
            diff=diff,
            name="kc",
            namespace="ns",
            status=status,
            meta={"generation": 1},
        )

        reconciler.blue_green_service.run_upgrade.assert_awaited_once()
        call_kwargs = reconciler.blue_green_service.run_upgrade.call_args.kwargs
        assert call_kwargs["name"] == "kc"
        assert call_kwargs["desired_image"] == "keycloak:27.0.0"
        # _update_deployment should NOT be called for blue-green
        reconciler._update_deployment.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_do_update_does_not_call_blue_green_for_recreate(self):
        """do_update should NOT call run_upgrade when strategy == Recreate."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        reconciler = KeycloakInstanceReconciler(k8s_client=MagicMock())

        reconciler.blue_green_service = MagicMock()
        reconciler.blue_green_service.run_upgrade = AsyncMock()
        reconciler._maybe_perform_pre_upgrade_backup = AsyncMock()
        reconciler._update_deployment = AsyncMock()
        reconciler._update_ingress = AsyncMock()
        reconciler.do_reconcile = AsyncMock(return_value={})

        old_spec = {
            "image": "keycloak:26.0.0",
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "kc",
                "credentials_secret": "s",
            },
            "operatorRef": {"namespace": "ops"},
        }
        new_spec = {
            "image": "keycloak:27.0.0",
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "kc",
                "credentials_secret": "s",
            },
            "operatorRef": {"namespace": "ops"},
            "upgradePolicy": {"strategy": "Recreate"},
        }

        diff = [("change", ("spec", "image"), "keycloak:26.0.0", "keycloak:27.0.0")]

        await reconciler.do_update(
            old_spec=old_spec,
            new_spec=new_spec,
            diff=diff,
            name="kc",
            namespace="ns",
            status={},
            meta={"generation": 1},
        )

        reconciler.blue_green_service.run_upgrade.assert_not_awaited()
        reconciler._update_deployment.assert_awaited_once()
