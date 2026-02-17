import pytest

from keycloak_operator.models.realm import KeycloakOTPPolicy, KeycloakRealmSpec


def test_otp_policy_defaults():
    """Test OTP policy defaults."""
    otp = KeycloakOTPPolicy()
    assert otp.type == "totp"
    assert otp.algorithm == "HmacSHA256"
    assert otp.initial_counter == 1
    assert otp.digits == 6
    assert otp.look_ahead_window == 1
    assert otp.period == 30
    assert otp.code_reusable is False
    assert "totpAppFreeOTPName" in otp.supported_applications
    assert "totpAppGoogleName" in otp.supported_applications


def test_otp_policy_validation():
    """Test OTP policy validation."""
    # Test valid values
    otp = KeycloakOTPPolicy(type="hotp", algorithm="HmacSHA512", digits=8, period=60)
    assert otp.type == "hotp"
    assert otp.algorithm == "HmacSHA512"
    assert otp.digits == 8
    assert otp.period == 60

    # Test invalid type
    with pytest.raises(ValueError):
        KeycloakOTPPolicy(type="invalid")

    # Test invalid algorithm
    with pytest.raises(ValueError):
        KeycloakOTPPolicy(algorithm="MD5")

    # Test invalid digits
    with pytest.raises(ValueError):
        KeycloakOTPPolicy(digits=7)


def test_realm_spec_flattening():
    """Test that OTP policy is correctly flattened in to_keycloak_config."""
    otp_policy = KeycloakOTPPolicy(
        type="totp",
        algorithm="HmacSHA256",
        digits=6,
        period=30,
        initial_counter=5,
        look_ahead_window=2,
        code_reusable=True,
    )

    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "keycloak-system"},
        otpPolicy=otp_policy,
    )

    config = spec.to_keycloak_config()

    # Check flattened fields
    assert config["otpPolicyType"] == "totp"
    assert config["otpPolicyAlgorithm"] == "HmacSHA256"
    assert config["otpPolicyDigits"] == 6
    assert config["otpPolicyPeriod"] == 30
    assert config["otpPolicyInitialCounter"] == 5
    assert config["otpPolicyLookAheadWindow"] == 2
    assert config["otpPolicyCodeReusable"] is True
    assert "totpAppFreeOTPName" in config["otpSupportedApplications"]


def test_realm_spec_no_otp_policy():
    """Test to_keycloak_config when OTP policy is None."""
    spec = KeycloakRealmSpec(
        realmName="test-realm", operatorRef={"namespace": "keycloak-system"}
    )

    config = spec.to_keycloak_config()

    # Check that fields are not present
    assert "otpPolicyType" not in config
    assert "otpPolicyAlgorithm" not in config
