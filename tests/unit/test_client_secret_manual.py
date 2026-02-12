import pytest
from pydantic import ValidationError

from keycloak_operator.models.client import (
    KeycloakClientSecretRef,
    KeycloakClientSpec,
    RealmRef,
    SecretRotationConfig,
)


def test_client_secret_ref_model():
    """Test KeycloakClientSecretRef model validation."""
    # Valid model
    ref = KeycloakClientSecretRef(name="my-secret", key="my-key")
    assert ref.name == "my-secret"
    assert ref.key == "my-key"

    # Missing fields
    with pytest.raises(ValidationError):
        KeycloakClientSecretRef(name="my-secret")


def test_client_spec_with_manual_secret():
    """Test KeycloakClientSpec with manual secret."""
    spec = KeycloakClientSpec(
        clientId="test-client",
        realmRef=RealmRef(name="test-realm", namespace="test-ns"),
        clientSecret=KeycloakClientSecretRef(name="my-secret", key="my-key"),
        manageSecret=True,
    )
    assert spec.client_secret is not None
    assert spec.client_secret.name == "my-secret"
    assert spec.client_secret.key == "my-key"
    assert spec.secret_rotation.enabled is False  # Default is False


def test_client_spec_validation_conflict():
    """Test validation error when both manual secret and rotation are enabled."""
    with pytest.raises(ValidationError) as excinfo:
        KeycloakClientSpec(
            clientId="test-client",
            realmRef=RealmRef(name="test-realm", namespace="test-ns"),
            clientSecret=KeycloakClientSecretRef(name="my-secret", key="my-key"),
            secretRotation=SecretRotationConfig(enabled=True),
        )

    assert (
        "Manual client secret (clientSecret) cannot be used with automated secret rotation"
        in str(excinfo.value)
    )


def test_client_spec_validation_public_client_conflict():
    """Test validation error when both manual secret and public client are enabled."""
    with pytest.raises(ValidationError) as excinfo:
        KeycloakClientSpec(
            clientId="test-client",
            realmRef=RealmRef(name="test-realm", namespace="test-ns"),
            clientSecret=KeycloakClientSecretRef(name="my-secret", key="my-key"),
            publicClient=True,
        )

    assert (
        "Manual client secret (clientSecret) cannot be used with public clients"
        in str(excinfo.value)
    )
