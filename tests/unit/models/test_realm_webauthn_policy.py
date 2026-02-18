from keycloak_operator.models.realm import (
    KeycloakRealmSpec,
    KeycloakWebAuthnPasswordlessPolicy,
    KeycloakWebAuthnPolicy,
)


def test_webauthn_policy_flattening():
    """Test that WebAuthn policies are correctly flattened in to_keycloak_config."""
    webauthn_policy = KeycloakWebAuthnPolicy(
        rpEntityName="test-rp",
        signatureAlgorithms=["ES256", "RS256"],
        rpId="example.com",
        attestationConveyancePreference="none",
        authenticatorAttachment="platform",
        requireResidentKey="Yes",
        userVerificationRequirement="preferred",
        createTimeout=30,
        avoidSameAuthenticatorRegister=True,
        acceptableAaguids=["123", "456"],
        extraOrigins=["https://example.com"],
    )

    passwordless_policy = KeycloakWebAuthnPasswordlessPolicy(
        rpEntityName="test-passwordless-rp",
        signatureAlgorithms=["ES256"],
        rpId="passwordless.example.com",
        passkeysEnabled=True,
    )

    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "keycloak-system"},
        webAuthnPolicy=webauthn_policy,
        webAuthnPasswordlessPolicy=passwordless_policy,
    )

    config = spec.to_keycloak_config()

    # Check flattened fields for regular policy
    assert config["webAuthnPolicyRpEntityName"] == "test-rp"
    assert config["webAuthnPolicySignatureAlgorithms"] == ["ES256", "RS256"]
    assert config["webAuthnPolicyRpId"] == "example.com"
    assert config["webAuthnPolicyAttestationConveyancePreference"] == "none"
    assert config["webAuthnPolicyAuthenticatorAttachment"] == "platform"
    assert config["webAuthnPolicyRequireResidentKey"] == "Yes"
    assert config["webAuthnPolicyUserVerificationRequirement"] == "preferred"
    assert config["webAuthnPolicyCreateTimeout"] == 30
    assert config["webAuthnPolicyAvoidSameAuthenticatorRegister"] is True
    assert config["webAuthnPolicyAcceptableAaguids"] == ["123", "456"]
    assert config["webAuthnPolicyExtraOrigins"] == ["https://example.com"]

    # Check flattened fields for passwordless policy
    assert config["webAuthnPolicyPasswordlessRpEntityName"] == "test-passwordless-rp"
    assert config["webAuthnPolicyPasswordlessSignatureAlgorithms"] == ["ES256"]
    assert config["webAuthnPolicyPasswordlessRpId"] == "passwordless.example.com"
    assert config["webAuthnPolicyPasswordlessPasskeysEnabled"] is True


def test_webauthn_policy_defaults():
    """Test defaults for WebAuthn policy."""
    policy = KeycloakWebAuthnPolicy()
    assert policy.rp_entity_name is None
    assert policy.signature_algorithms is None
    assert policy.avoid_same_authenticator_register is False


def test_no_webauthn_policy():
    """Test to_keycloak_config when WebAuthn policies are None."""
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "keycloak-system"},
    )
    config = spec.to_keycloak_config()

    assert "webAuthnPolicyRpEntityName" not in config
    assert "webAuthnPolicyPasswordlessRpEntityName" not in config
