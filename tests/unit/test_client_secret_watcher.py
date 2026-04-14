import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import ANNOTATION_RECONCILE_FORCE
from keycloak_operator.handlers.client import (
    _trigger_client_reconciliation,
    monitor_client_credentials_secret,
)


@pytest.mark.asyncio
async def test_trigger_client_reconciliation_patches_client_resource():
    logger = MagicMock(spec=logging.Logger)

    with (
        patch("keycloak_operator.handlers.client.get_kubernetes_client"),
        patch(
            "keycloak_operator.handlers.client.client.CustomObjectsApi"
        ) as mock_api_cls,
    ):
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api

        triggered = await _trigger_client_reconciliation(
            name="my-client",
            namespace="my-ns",
            reason="secret-missing",
            logger=logger,
        )

        assert triggered is True
        assert mock_api.patch_namespaced_custom_object.called
        _, kwargs = mock_api.patch_namespaced_custom_object.call_args
        assert kwargs["group"] == "vriesdemichael.github.io"
        assert kwargs["version"] == "v1"
        assert kwargs["namespace"] == "my-ns"
        assert kwargs["plural"] == "keycloakclients"
        assert kwargs["name"] == "my-client"
        assert ANNOTATION_RECONCILE_FORCE in kwargs["body"]["metadata"]["annotations"]


@pytest.mark.asyncio
async def test_monitor_client_credentials_secret_missing_triggers_reconcile():
    logger = MagicMock(spec=logging.Logger)
    patch_obj = MagicMock()
    patch_obj.status = {}
    stopped = MagicMock()
    stopped.__bool__ = MagicMock(side_effect=[False, True])
    stopped.wait = AsyncMock(return_value=True)

    with (
        patch("keycloak_operator.handlers.client.get_kubernetes_client"),
        patch(
            "keycloak_operator.handlers.client.client.CoreV1Api"
        ) as mock_core_api_cls,
        patch(
            "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
            return_value=True,
        ),
        patch(
            "keycloak_operator.handlers.client._trigger_client_reconciliation",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_trigger,
    ):
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=404)
        mock_core_api_cls.return_value = mock_core_api

        await monitor_client_credentials_secret(
            spec={"clientId": "test-client", "manageSecret": True},
            name="test-client",
            namespace="test-ns",
            status={},
            meta={},
            stopped=stopped,
            patch=patch_obj,
            logger=logger,
        )

        mock_trigger.assert_awaited_once()
        assert patch_obj.status["phase"] == "Degraded"
        assert "recreating" in patch_obj.status["message"].lower()


@pytest.mark.asyncio
async def test_monitor_client_credentials_secret_forbidden_degrades_without_reconcile():
    logger = MagicMock(spec=logging.Logger)
    patch_obj = MagicMock()
    patch_obj.status = {}
    stopped = MagicMock()
    stopped.__bool__ = MagicMock(side_effect=[False, True])
    stopped.wait = AsyncMock(return_value=True)

    with (
        patch("keycloak_operator.handlers.client.get_kubernetes_client"),
        patch(
            "keycloak_operator.handlers.client.client.CoreV1Api"
        ) as mock_core_api_cls,
        patch(
            "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
            return_value=True,
        ),
        patch(
            "keycloak_operator.handlers.client._trigger_client_reconciliation",
            new_callable=AsyncMock,
        ) as mock_trigger,
    ):
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=403)
        mock_core_api_cls.return_value = mock_core_api

        await monitor_client_credentials_secret(
            spec={"clientId": "test-client", "manageSecret": True},
            name="test-client",
            namespace="test-ns",
            status={},
            meta={},
            stopped=stopped,
            patch=patch_obj,
            logger=logger,
        )

        mock_trigger.assert_not_awaited()
        assert patch_obj.status["phase"] == "Degraded"
        assert "lacks permission" in patch_obj.status["message"].lower()
