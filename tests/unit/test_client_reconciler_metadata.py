"""Unit tests for KeycloakClientReconciler metadata handling."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.models.client import KeycloakClientSpec, RealmRef, SecretMetadata
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.mark.asyncio
async def test_manage_client_credentials_passes_metadata():
    """Test that manage_client_credentials passes metadata to create_client_secret."""

    # Mock dependencies
    mock_k8s_client = MagicMock()
    mock_admin_factory = AsyncMock()

    reconciler = KeycloakClientReconciler(
        k8s_client=mock_k8s_client, keycloak_admin_factory=mock_admin_factory
    )

    # Mock _get_realm_info to return values
    reconciler._get_realm_info = MagicMock(return_value=("realm-name", "ns", "kc", {}))  # type: ignore

    # Mock validate_keycloak_reference
    with patch(
        "keycloak_operator.utils.kubernetes.validate_keycloak_reference"
    ) as mock_validate:
        mock_validate.return_value = {"status": {"endpoints": {"public": "http://kc"}}}

        with patch(
            "keycloak_operator.utils.kubernetes.create_client_secret"
        ) as mock_create_secret:
            # Setup inputs
            spec = KeycloakClientSpec(
                clientId="test-client",
                realmRef=RealmRef(name="my-realm", namespace="ns"),
                secretMetadata=SecretMetadata(
                    labels={"l1": "v1"}, annotations={"a1": "v1"}
                ),
            )

            # Execute
            await reconciler.manage_client_credentials(
                spec=spec, client_uuid="uuid", name="test-client-cr", namespace="ns"
            )

            # Verify
            mock_create_secret.assert_called_once()
            call_kwargs = mock_create_secret.call_args[1]

            assert call_kwargs["labels"] == {"l1": "v1"}
            assert call_kwargs["annotations"] == {"a1": "v1"}


@pytest.mark.asyncio
async def test_do_update_passes_metadata_on_regeneration():
    """Test that do_update passes metadata when regenerating secret."""

    # Mock dependencies
    mock_k8s_client = MagicMock()
    mock_admin_factory = AsyncMock()
    mock_admin_client = AsyncMock()
    mock_admin_factory.return_value = mock_admin_client

    reconciler = KeycloakClientReconciler(
        k8s_client=mock_k8s_client, keycloak_admin_factory=mock_admin_factory
    )

    reconciler._get_realm_info = MagicMock(return_value=("realm-name", "ns", "kc", {}))  # type: ignore
    reconciler.update_status_ready = MagicMock()  # type: ignore

    with (
        patch(
            "keycloak_operator.utils.kubernetes.validate_keycloak_reference"
        ) as mock_validate,
        patch(
            "keycloak_operator.utils.kubernetes.create_client_secret"
        ) as mock_create_secret,
    ):
        mock_validate.return_value = {"status": {"endpoints": {"public": "http://kc"}}}
        mock_admin_client.regenerate_client_secret.return_value = "new-secret"

        # Setup inputs
        old_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
        }

        new_spec = {
            "clientId": "test-client",
            "realmRef": {"name": "my-realm", "namespace": "ns"},
            "regenerateSecret": True,
            "secretMetadata": {"labels": {"l2": "v2"}, "annotations": {"a2": "v2"}},
        }

        # Diff that triggers update
        diff = []  # We don't need diff to trigger regeneration, it's checked via new_spec flag

        # Execute
        await reconciler.do_update(
            old_spec=old_spec,
            new_spec=new_spec,
            diff=diff,
            name="test-client-cr",
            namespace="ns",
            status=MagicMock(),
        )

        # Verify
        mock_create_secret.assert_called_once()
        call_kwargs = mock_create_secret.call_args[1]

        assert call_kwargs["labels"] == {"l2": "v2"}
        assert call_kwargs["annotations"] == {"a2": "v2"}
