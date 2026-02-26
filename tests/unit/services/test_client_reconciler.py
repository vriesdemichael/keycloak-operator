"""Unit tests for KeycloakClientReconciler service account role management."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from keycloak_operator.errors import ReconciliationError
from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


@pytest.fixture
def spec_base() -> dict:
    """Return minimal valid client spec dictionary."""

    return {
        "client_id": "test-client",
        "realm_ref": {
            "name": "master",
            "namespace": "default",
            "authorization_secret_ref": {"name": "realm-token"},
        },
        "settings": {"service_accounts_enabled": True},
    }


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client."""

    mock = MagicMock()
    # Return objects with .id attribute (not dicts)
    service_account_user_mock = MagicMock()
    service_account_user_mock.id = "service-user-id"
    mock.get_service_account_user = AsyncMock(return_value=service_account_user_mock)

    target_client_mock = MagicMock()
    target_client_mock.id = "target-client-uuid"
    mock.get_client_by_name = AsyncMock(return_value=target_client_mock)

    # Make role assignment methods async
    mock.assign_realm_roles_to_user = AsyncMock()
    mock.assign_client_roles_to_user = AsyncMock()

    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakClientReconciler:
    """KeycloakClientReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace):
        return admin_mock

    reconciler_instance = KeycloakClientReconciler(
        keycloak_admin_factory=mock_factory,
    )
    reconciler_instance.logger = MagicMock()

    return reconciler_instance


@pytest.mark.asyncio
async def test_manage_service_account_roles_skips_when_no_roles(
    reconciler: KeycloakClientReconciler,
    admin_mock: MagicMock,
    spec_base: dict,
) -> None:
    """Method should return early if no roles are configured."""

    spec_dict = {
        **spec_base,
        "service_account_roles": {
            "realm_roles": [],
            "client_roles": {},
        },
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    await reconciler.manage_service_account_roles(
        spec, "client-uuid", "resource", "ns", "master"
    )

    admin_mock.get_service_account_user.assert_not_called()
    admin_mock.assign_realm_roles_to_user.assert_not_called()
    admin_mock.assign_client_roles_to_user.assert_not_called()


@pytest.mark.asyncio
async def test_manage_service_account_roles_missing_service_account_id_raises(
    reconciler: KeycloakClientReconciler,
    admin_mock: MagicMock,
    spec_base: dict,
) -> None:
    """Missing service account identifiers should raise reconciliation error."""

    admin_mock.get_service_account_user.return_value = {}

    spec_dict = {
        **spec_base,
        "service_account_roles": {
            "realm_roles": ["offline_access"],
            "client_roles": {},
        },
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    with pytest.raises(ReconciliationError):
        await reconciler.manage_service_account_roles(
            spec, "client-uuid", "resource", "ns", "master"
        )
