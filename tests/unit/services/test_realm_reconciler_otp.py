"""Unit tests for KeycloakRealmReconciler OTP policy methods."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.models.realm import (
    KeycloakOTPPolicy,
    KeycloakRealmSpec,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.fixture
def admin_mock() -> MagicMock:
    """Mock Keycloak admin client."""
    mock = MagicMock()
    mock.get_realm = AsyncMock(return_value=None)
    mock.create_realm = AsyncMock(return_value=True)
    mock.update_realm = AsyncMock(return_value=True)
    return mock


@pytest.fixture
def reconciler(admin_mock: MagicMock, monkeypatch) -> KeycloakRealmReconciler:
    """KeycloakRealmReconciler configured with mock admin factory."""

    async def mock_factory(name, namespace, rate_limiter=None):
        return admin_mock

    # Mock settings.operator_instance_id
    # We patch the 'settings' object imported in keycloak_operator.utils.ownership
    # or the global settings object if we can access it.
    from keycloak_operator.settings import settings

    monkeypatch.setattr(settings, "operator_instance_id", "test-operator-instance")

    # Mock k8s client for capacity check
    k8s_client = MagicMock()

    # Mock CustomObjectsApi response
    with patch("kubernetes.client.CustomObjectsApi") as mock_custom_api:
        # Configure the mock to return a dictionary (not a string)
        mock_instance = mock_custom_api.return_value
        mock_instance.get_namespaced_custom_object.return_value = {
            "spec": {},
            "status": {"ready": True},
        }

        reconciler_instance = KeycloakRealmReconciler(
            k8s_client=k8s_client,
            keycloak_admin_factory=mock_factory,
        )
        reconciler_instance.logger = MagicMock()

        # We also need to mock validate_keycloak_reference which is called in ensure_realm_exists
        with patch(
            "keycloak_operator.utils.kubernetes.validate_keycloak_reference",
            return_value={"status": {"ready": True}},
        ):
            yield reconciler_instance


class TestEnsureRealmExistsOTP:
    """Tests for ensure_realm_exists method with OTP policy."""

    @pytest.mark.asyncio
    async def test_create_realm_with_otp_policy(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """OTP policy should be included when creating a realm."""
        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            otp_policy=KeycloakOTPPolicy(
                type="totp",
                algorithm="HmacSHA256",
                digits=6,
                period=30,
            ),
        )

        await reconciler.ensure_realm_exists(spec, "test-realm-cr", "default")

        admin_mock.create_realm.assert_called_once()
        call_args = admin_mock.create_realm.call_args
        payload = call_args[0][0]

        assert payload["otpPolicyType"] == "totp"
        assert payload["otpPolicyAlgorithm"] == "HmacSHA256"
        assert payload["otpPolicyDigits"] == 6
        assert payload["otpPolicyPeriod"] == 30

    @pytest.mark.asyncio
    async def test_update_realm_with_otp_policy(
        self,
        reconciler: KeycloakRealmReconciler,
        admin_mock: MagicMock,
    ) -> None:
        """OTP policy should be included when updating a realm."""
        # Mock existing realm
        existing_realm = MagicMock()
        existing_realm.attributes = {
            "kubernetes.operator.uid": "uid-123",
            "kubernetes.operator.name": "test-realm-cr",
            "kubernetes.operator.namespace": "default",
        }
        admin_mock.get_realm = AsyncMock(return_value=existing_realm)

        spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace="keycloak-system"),
            realm_name="test-realm",
            otp_policy=KeycloakOTPPolicy(
                type="hotp",
                algorithm="HmacSHA512",
                initial_counter=10,
                digits=8,
            ),
        )

        await reconciler.ensure_realm_exists(
            spec, "test-realm-cr", "default", uid="uid-123"
        )

        admin_mock.update_realm.assert_called_once()
        call_args = admin_mock.update_realm.call_args
        payload = call_args[0][1]

        assert payload["otpPolicyType"] == "hotp"
        assert payload["otpPolicyAlgorithm"] == "HmacSHA512"
        assert payload["otpPolicyInitialCounter"] == 10
        assert payload["otpPolicyDigits"] == 8
