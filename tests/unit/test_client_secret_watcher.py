import logging
from unittest.mock import MagicMock, patch

import pytest

from keycloak_operator.handlers.client import monitor_client_secrets


@pytest.mark.asyncio
async def test_monitor_client_secrets_deleted():
    # Setup
    event = {
        "type": "DELETED",
        "object": {
            "metadata": {
                "name": "my-secret",
                "namespace": "my-ns",
                "labels": {"vriesdemichael.github.io/keycloak-client": "my-client"},
            }
        },
    }
    logger = MagicMock(spec=logging.Logger)

    # Mock K8s API
    with (
        patch("keycloak_operator.handlers.client.get_kubernetes_client"),
        patch(
            "keycloak_operator.handlers.client.client.CustomObjectsApi"
        ) as mock_api_cls,
    ):
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api

        # Execute
        await monitor_client_secrets(event, logger)

        # Verify
        # Should call patch_namespaced_custom_object
        assert mock_api.patch_namespaced_custom_object.called
        call_args = mock_api.patch_namespaced_custom_object.call_args
        args, kwargs = call_args

        # Handle both keyword and positional argument patterns
        if not kwargs and args:
            # kubernetes.client.CustomObjectsApi.patch_namespaced_custom_object(
            #     group, version, namespace, plural, name, body, **kwargs
            # )
            group, version, namespace, plural, name, body = args[:6]
            call_params = {
                "group": group,
                "version": version,
                "namespace": namespace,
                "plural": plural,
                "name": name,
                "body": body,
            }
        else:
            call_params = kwargs

        # Verify patch arguments
        assert call_params["group"] == "vriesdemichael.github.io"
        assert call_params["version"] == "v1"
        assert call_params["namespace"] == "my-ns"
        assert call_params["plural"] == "keycloakclients"
        assert call_params["name"] == "my-client"
        assert (
            "keycloak-operator/force-reconcile"
            in call_params["body"]["metadata"]["annotations"]
        )


@pytest.mark.asyncio
async def test_monitor_client_secrets_ignored():
    # Setup - Wrong event type
    event = {
        "type": "ADDED",
        "object": {
            "metadata": {
                "name": "s",
                "namespace": "n",
                "labels": {"vriesdemichael.github.io/keycloak-client": "c"},
            }
        },
    }
    logger = MagicMock()

    with patch(
        "keycloak_operator.handlers.client.get_kubernetes_client"
    ) as mock_get_client:
        await monitor_client_secrets(event, logger)
        assert not mock_get_client.called

    # Setup - Missing label
    event = {
        "type": "DELETED",
        "object": {"metadata": {"name": "s", "namespace": "n", "labels": {}}},
    }
    with patch(
        "keycloak_operator.handlers.client.get_kubernetes_client"
    ) as mock_get_client:
        await monitor_client_secrets(event, logger)
        assert not mock_get_client.called
