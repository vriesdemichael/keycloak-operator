from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.mark.asyncio
async def test_fix_secret_regeneration_and_owner_ref():
    # Setup
    reconciler = KeycloakClientReconciler()
    reconciler.logger = MagicMock()

    # Mocks
    admin_client = AsyncMock()
    admin_client.regenerate_client_secret = AsyncMock(return_value="new-secret")
    admin_client.get_client_uuid = AsyncMock(return_value="client-uuid")

    reconciler.keycloak_admin_factory = AsyncMock(return_value=admin_client)

    # Mock Kubernetes utils
    with (
        patch(
            "keycloak_operator.utils.kubernetes.validate_keycloak_reference"
        ) as mock_validate_kc,
        patch(
            "keycloak_operator.utils.kubernetes.create_client_secret"
        ) as mock_create_secret,
        patch.object(
            KeycloakClientReconciler, "_get_realm_info"
        ) as mock_get_realm_info,
    ):
        mock_validate_kc.return_value = {
            "status": {"endpoints": {"public": "http://keycloak"}}
        }
        mock_get_realm_info.return_value = ("realm", "ns", "kc", "realm-cr")

        # Test data
        old_spec = {
            "realmRef": {"name": "realm", "namespace": "ns"},
            "clientId": "test-client",
            "regenerateSecret": False,
        }
        new_spec = {
            "realmRef": {"name": "realm", "namespace": "ns"},
            "clientId": "test-client",
            "regenerateSecret": True,
        }
        diff = [("change", ["spec", "regenerateSecret"], False, True)]

        status = MagicMock()

        # Pass UID in kwargs (body)
        kwargs = {"body": {"metadata": {"uid": "owner-uid-123"}}}

        # Execute
        await reconciler.do_update(
            old_spec, new_spec, diff, "test-client", "ns", status, **kwargs
        )

        # Verification
        # 1. Verify create_client_secret call args
        call_args, call_kwargs = mock_create_secret.call_args

        client_secret = call_kwargs.get("client_secret")
        owner_uid = call_kwargs.get("owner_uid")
        owner_name = call_kwargs.get("owner_name")

        # 2. Verify bug fix (Issue 380/381)
        assert isinstance(client_secret, str), (
            f"Expected string, got {type(client_secret)}"
        )
        assert client_secret == "new-secret"

        # 3. Verify OwnerReference (Issue 382)
        assert owner_uid == "owner-uid-123"
        assert owner_name == "test-client"
