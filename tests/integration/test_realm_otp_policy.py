import uuid
from unittest.mock import AsyncMock, patch

import pytest

from keycloak_operator.models.realm import (
    KeycloakOTPPolicy,
    KeycloakRealmSpec,
    OperatorRef,
)
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


@pytest.mark.asyncio
async def test_realm_otp_policy_reconciliation(
    keycloak_admin_client, test_namespace, k8s_client, operator_namespace
):
    """
    Test that OTP policy is correctly applied to a Keycloak realm.
    """
    realm_name = f"otp-test-{uuid.uuid4().hex[:8]}"

    # Create a realm spec with OTP policy
    otp_policy = KeycloakOTPPolicy(
        type="hotp",
        algorithm="HmacSHA512",
        initial_counter=10,
        digits=8,
        look_ahead_window=5,
        period=60,
        code_reusable=True,
        supported_applications=["totpAppFreeOTPName", "totpAppGoogleName"],
    )

    realm_spec = KeycloakRealmSpec(
        realmName=realm_name,
        operatorRef=OperatorRef(namespace=operator_namespace),
        otpPolicy=otp_policy,
    )

    # Create the reconciler
    async def mock_admin_factory(*args, **kwargs):
        return keycloak_admin_client

    with patch("keycloak_operator.services.realm_reconciler.settings") as mock_settings:
        mock_settings.operator_namespace = operator_namespace
        reconciler = KeycloakRealmReconciler(
            k8s_client=k8s_client,
            keycloak_admin_factory=mock_admin_factory,
        )

        # Mock RBAC validation since we are running outside the cluster
        reconciler.validate_cross_namespace_access = AsyncMock()  # type: ignore
        # Mock capacity check as well since we don't need to test that logic here
        reconciler._check_realm_capacity = AsyncMock()  # type: ignore

        # Create a mock status object
        class MockStatus:
            def __init__(self):
                self.conditions = []
                self.phase = "Unknown"
                self.observedGeneration = 0

        status = MockStatus()

        # Reconcile the realm
        await reconciler.do_reconcile(
            spec=realm_spec.model_dump(by_alias=True, exclude_none=True),
            name=f"kcr-{realm_name}",
            namespace=test_namespace,
            status=status,
            meta={"generation": 1, "uid": str(uuid.uuid4())},
        )

        # Verify the realm was created in Keycloak
        realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
        assert realm is not None

        # Verify OTP policy settings
        assert realm.otp_policy_type == "hotp"
        assert realm.otp_policy_algorithm == "HmacSHA512"
        assert realm.otp_policy_initial_counter == 10
        assert realm.otp_policy_digits == 8
        assert realm.otp_policy_look_ahead_window == 5
        assert realm.otp_policy_period == 60
        assert realm.otp_policy_code_reusable is True
        # Keycloak seems to always include both if either is present or defaults to both?
        # We verify that our requested app is present.
        assert "totpAppFreeOTPName" in realm.otp_supported_applications
        assert "totpAppGoogleName" in realm.otp_supported_applications

        # Verify update scenario: Change from HOTP to TOTP
        otp_policy_update = KeycloakOTPPolicy(
            type="totp", algorithm="HmacSHA256", digits=6, period=30
        )

        realm_spec.otp_policy = otp_policy_update

        # Reconcile update
        await reconciler.do_reconcile(
            spec=realm_spec.model_dump(by_alias=True, exclude_none=True),
            name=f"kcr-{realm_name}",
            namespace=test_namespace,
            status=status,
            meta={"generation": 2, "uid": str(uuid.uuid4())},
        )

        # Verify update in Keycloak
        updated_realm = await keycloak_admin_client.get_realm(
            realm_name, test_namespace
        )
        assert updated_realm.otp_policy_type == "totp"
        assert updated_realm.otp_policy_algorithm == "HmacSHA256"
        assert updated_realm.otp_policy_digits == 6
        assert updated_realm.otp_policy_period == 30

        # Clean up
        await keycloak_admin_client.delete_realm(realm_name, test_namespace)
