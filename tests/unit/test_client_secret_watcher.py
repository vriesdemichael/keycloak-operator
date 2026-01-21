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
        _, kwargs = call_args
        if not kwargs:  # If called with positional args
            # The lambda in run_in_executor might hide call details if not carefully mocked or if run_in_executor runs it
            pass

        # Wait, monitor_client_secrets uses loop.run_in_executor(None, lambda: ...)
        # So the mock_api call happens in a thread.
        # But we are in an async test.
        # Verify patch arguments
        assert kwargs["group"] == "vriesdemichael.github.io"
        assert kwargs["version"] == "v1"
        assert kwargs["namespace"] == "my-ns"
        assert kwargs["plural"] == "keycloakclients"
        assert kwargs["name"] == "my-client"
        assert (
            "keycloak-operator/force-reconcile"
            in kwargs["body"]["metadata"]["annotations"]
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
