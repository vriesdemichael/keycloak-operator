"""Unit tests for KeycloakClientReconciler service account role management."""

from unittest.mock import MagicMock

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
    mock.get_service_account_user.return_value = service_account_user_mock

    target_client_mock = MagicMock()
    target_client_mock.id = "target-client-uuid"
    mock.get_client_by_name.return_value = target_client_mock
    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock) -> KeycloakClientReconciler:
    """KeycloakClientReconciler configured with mock admin factory."""

    reconciler_instance = KeycloakClientReconciler(
        keycloak_admin_factory=lambda name, namespace: admin_mock,
    )
    reconciler_instance.logger = MagicMock()

    # Mock _get_realm_info to return expected values without calling K8s API
    # Returns: (actual_realm_name, keycloak_namespace, keycloak_name, realm_resource)
    reconciler_instance._get_realm_info = MagicMock(  # ty: ignore[invalid-assignment]
        return_value=("master", "default", "keycloak", {})
    )

    return reconciler_instance


@pytest.mark.asyncio
async def test_manage_service_account_roles_assigns_realm_roles(
    reconciler: KeycloakClientReconciler,
    admin_mock: MagicMock,
    spec_base: dict,
) -> None:
    """Realm roles should be assigned when provided in the spec."""

    spec_dict = {
        **spec_base,
        "service_account_roles": {
            "realm_roles": ["offline_access"],
            "client_roles": {},
        },
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    await reconciler.manage_service_account_roles(spec, "client-uuid", "resource", "ns")

    admin_mock.get_service_account_user.assert_called_once_with("client-uuid", "master")
    admin_mock.assign_realm_roles_to_user.assert_called_once_with(
        user_id="service-user-id",
        role_names=["offline_access"],
        realm_name="master",
    )


@pytest.mark.asyncio
async def test_manage_service_account_roles_assigns_client_roles(
    reconciler: KeycloakClientReconciler,
    admin_mock: MagicMock,
    spec_base: dict,
) -> None:
    """Client roles should be fetched and assigned per target client."""

    spec_dict = {
        **spec_base,
        "service_account_roles": {
            "realm_roles": [],
            "client_roles": {"api-server": ["read:data", "write:data"]},
        },
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    await reconciler.manage_service_account_roles(spec, "client-uuid", "resource", "ns")

    admin_mock.get_client_by_name.assert_called_once_with("api-server", "master", "ns")
    admin_mock.assign_client_roles_to_user.assert_called_once_with(
        user_id="service-user-id",
        client_uuid="target-client-uuid",
        role_names=["read:data", "write:data"],
        realm_name="master",
    )


@pytest.mark.asyncio
async def test_manage_service_account_roles_skips_when_no_roles(
    reconciler: KeycloakClientReconciler,
    admin_mock: MagicMock,
    spec_base: dict,
) -> None:
    """No Keycloak operations occur when no roles are defined."""

    spec_dict = {
        **spec_base,
        "service_account_roles": {"realm_roles": [], "client_roles": {}},
    }
    spec = KeycloakClientSpec.model_validate(spec_dict)

    await reconciler.manage_service_account_roles(spec, "client-uuid", "resource", "ns")

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
            spec,
            "client-uuid",
            "resource",
            "ns",
        )
