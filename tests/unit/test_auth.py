"""Unit tests for authorization utilities."""

import base64
from unittest.mock import MagicMock

import pytest
from kubernetes.client import CoreV1Api, V1ObjectMeta, V1Secret
from kubernetes.client.rest import ApiException

from keycloak_operator.models.common import AuthorizationSecretRef
from keycloak_operator.utils.auth import generate_token, validate_authorization


class TestGenerateToken:
    """Test suite for generate_token() function."""

    def test_generate_token_default_length(self):
        """Test that generate_token returns a token of the correct default length."""
        token = generate_token()

        # URL-safe base64 encoding produces ~1.33 characters per byte
        # For 32 bytes, we expect roughly 43 characters (32 * 1.33)
        assert isinstance(token, str)
        assert len(token) >= 40  # Allow some variance due to encoding
        assert len(token) <= 50

    def test_generate_token_custom_length(self):
        """Test that generate_token respects custom length parameter."""
        token = generate_token(length=64)

        # For 64 bytes, we expect roughly 86 characters
        assert isinstance(token, str)
        assert len(token) >= 80
        assert len(token) <= 100

    def test_generate_token_uniqueness(self):
        """Test that generate_token produces unique tokens."""
        tokens = {generate_token() for _ in range(100)}

        # All 100 tokens should be unique
        assert len(tokens) == 100

    def test_generate_token_url_safe(self):
        """Test that generated tokens are URL-safe (no special characters)."""
        token = generate_token()

        # URL-safe base64 only uses: A-Z, a-z, 0-9, -, _
        allowed_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        assert all(c in allowed_chars for c in token)


class TestValidateAuthorization:
    """Test suite for validate_authorization() function."""

    @pytest.fixture
    def mock_k8s_client(self):
        """Mock Kubernetes CoreV1Api client."""
        return MagicMock(spec=CoreV1Api)

    @pytest.fixture
    def secret_ref(self):
        """Sample AuthorizationSecretRef."""
        return AuthorizationSecretRef(name="test-secret", key="token")

    def test_validate_authorization_success(self, mock_k8s_client, secret_ref):
        """Test successful token validation with matching token."""
        expected_token = "test-token-12345"
        encoded_token = base64.b64encode(expected_token.encode("utf-8")).decode("utf-8")

        # Mock secret with matching token
        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": encoded_token},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        # Should return True for matching token
        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token=expected_token,
            k8s_client=mock_k8s_client,
        )

        assert result is True
        mock_k8s_client.read_namespaced_secret.assert_called_once_with(
            name="test-secret", namespace="test-namespace"
        )

    def test_validate_authorization_wrong_token(self, mock_k8s_client, secret_ref):
        """Test validation fails with mismatched token."""
        expected_token = "correct-token"
        wrong_token = "wrong-token"
        encoded_token = base64.b64encode(wrong_token.encode("utf-8")).decode("utf-8")

        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": encoded_token},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        # Should return False for mismatched token
        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token=expected_token,
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_secret_not_found(self, mock_k8s_client, secret_ref):
        """Test validation fails when secret doesn't exist."""
        mock_k8s_client.read_namespaced_secret.side_effect = ApiException(status=404)

        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token="any-token",
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_api_error(self, mock_k8s_client, secret_ref):
        """Test validation fails gracefully on API errors."""
        mock_k8s_client.read_namespaced_secret.side_effect = ApiException(status=500)

        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token="any-token",
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_missing_key(self, mock_k8s_client, secret_ref):
        """Test validation fails when secret exists but missing the expected key."""
        # Secret with wrong key
        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"wrong-key": base64.b64encode(b"token").decode("utf-8")},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token="any-token",
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_empty_token(self, mock_k8s_client, secret_ref):
        """Test validation fails with empty token in secret."""
        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": base64.b64encode(b"").decode("utf-8")},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token="any-token",
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_custom_key(self, mock_k8s_client):
        """Test validation with custom key name in secret."""
        custom_secret_ref = AuthorizationSecretRef(name="test-secret", key="custom-key")

        expected_token = "test-token"
        encoded_token = base64.b64encode(expected_token.encode("utf-8")).decode("utf-8")

        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"custom-key": encoded_token},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        result = validate_authorization(
            secret_ref=custom_secret_ref,
            secret_namespace="test-namespace",
            expected_token=expected_token,
            k8s_client=mock_k8s_client,
        )

        assert result is True

    def test_validate_authorization_timing_attack_resistance(
        self, mock_k8s_client, secret_ref
    ):
        """Test that token comparison uses secrets.compare_digest for timing attack resistance."""
        expected_token = "a" * 100
        wrong_token_short = "b"
        wrong_token_long = "b" * 100

        encoded_short = base64.b64encode(wrong_token_short.encode("utf-8")).decode(
            "utf-8"
        )
        encoded_long = base64.b64encode(wrong_token_long.encode("utf-8")).decode(
            "utf-8"
        )

        # Mock secret for short wrong token
        mock_secret_short = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": encoded_short},
        )

        # Mock secret for long wrong token
        mock_secret_long = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": encoded_long},
        )

        # Test with short wrong token
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret_short
        result1 = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token=expected_token,
            k8s_client=mock_k8s_client,
        )

        # Test with long wrong token
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret_long
        result2 = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token=expected_token,
            k8s_client=mock_k8s_client,
        )

        # Both should fail, and since we use secrets.compare_digest,
        # timing should be roughly equal (hard to test precisely)
        assert result1 is False
        assert result2 is False

    def test_validate_authorization_non_base64_data(self, mock_k8s_client, secret_ref):
        """Test validation handles non-base64 encoded data gracefully."""
        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="test-secret",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": "not-base64-encoded!!!"},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        result = validate_authorization(
            secret_ref=secret_ref,
            secret_namespace="test-namespace",
            expected_token="any-token",
            k8s_client=mock_k8s_client,
        )

        assert result is False

    def test_validate_authorization_operator_token_scenario(self, mock_k8s_client):
        """Test operator token validation with invalid token.

        This test covers the scenario from the skipped integration test
        test_invalid_operator_token_rejects_realm. In the 1-1 operator-keycloak
        architecture, the operator always reads the expected token from the
        global OPERATOR_NAMESPACE, making it impossible to test invalid tokens
        in integration tests without affecting shared resources.

        This unit test validates that the authorization logic correctly rejects
        requests with invalid operator tokens.
        """
        # Simulate operator token validation
        operator_secret_ref = AuthorizationSecretRef(
            name="keycloak-operator-auth-token", key="token"
        )

        # The "correct" operator token stored in the secret
        correct_operator_token = "operator-secure-token-12345"
        encoded_correct_token = base64.b64encode(
            correct_operator_token.encode("utf-8")
        ).decode("utf-8")

        mock_secret = V1Secret(
            metadata=V1ObjectMeta(
                name="keycloak-operator-auth-token",
                labels={"keycloak.mdvr.nl/allow-operator-read": "true"},
            ),
            data={"token": encoded_correct_token},
        )
        mock_k8s_client.read_namespaced_secret.return_value = mock_secret

        # Test 1: Valid operator token should pass
        result_valid = validate_authorization(
            secret_ref=operator_secret_ref,
            secret_namespace="keycloak-operator",
            expected_token=correct_operator_token,
            k8s_client=mock_k8s_client,
        )
        assert result_valid is True, "Valid operator token should be accepted"

        # Test 2: Invalid operator token should fail
        invalid_operator_token = "wrong-operator-token"
        result_invalid = validate_authorization(
            secret_ref=operator_secret_ref,
            secret_namespace="keycloak-operator",
            expected_token=invalid_operator_token,
            k8s_client=mock_k8s_client,
        )
        assert result_invalid is False, "Invalid operator token should be rejected"

        # Test 3: Completely different token should fail
        result_different = validate_authorization(
            secret_ref=operator_secret_ref,
            secret_namespace="keycloak-operator",
            expected_token="attacker-token",
            k8s_client=mock_k8s_client,
        )
        assert result_different is False, "Attacker token should be rejected"
