"""Unit tests for secret_manager module."""

import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.errors import AuthorizationError, KubernetesAPIError
from keycloak_operator.utils.secret_manager import SecretManager
from keycloak_operator.utils.token_manager import GRACE_PERIOD_DAYS


class TestSecretManagerInit:
    """Test SecretManager initialization."""

    def test_init_without_client(self):
        """Should initialize without explicit client."""
        manager = SecretManager()
        assert manager.k8s_client is None

    def test_init_with_client(self):
        """Should initialize with provided client."""
        mock_client = MagicMock()
        manager = SecretManager(k8s_client=mock_client)
        assert manager.k8s_client is mock_client

    def test_v1_property_creates_client(self):
        """Should create CoreV1Api client on first access."""
        manager = SecretManager()
        
        with patch("keycloak_operator.utils.secret_manager.client.CoreV1Api") as mock_v1:
            _ = manager.v1
            mock_v1.assert_called_once()


class TestGetSecret:
    """Test secret retrieval."""

    @pytest.mark.asyncio
    async def test_retrieves_existing_secret(self):
        """Should retrieve existing secret."""
        expected_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test-secret", namespace="test-ns"),
            data={"token": base64.b64encode(b"test-token").decode()},
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_secret = MagicMock(return_value=expected_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        result = await manager.get_secret("test-secret", "test-ns")

        assert result is not None
        assert result.metadata.name == "test-secret"
        mock_v1.read_namespaced_secret.assert_called_once_with(
            name="test-secret", namespace="test-ns"
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_secret(self):
        """Should return None for non-existent secret."""
        mock_v1 = MagicMock()
        mock_v1.read_namespaced_secret = MagicMock(
            side_effect=ApiException(status=404)
        )

        manager = SecretManager()
        manager._v1 = mock_v1

        result = await manager.get_secret("missing-secret", "test-ns")
        assert result is None

    @pytest.mark.asyncio
    async def test_raises_on_api_error(self):
        """Should raise KubernetesAPIError on API failures."""
        mock_v1 = MagicMock()
        mock_v1.read_namespaced_secret = MagicMock(
            side_effect=ApiException(status=500, reason="Internal Error")
        )

        manager = SecretManager()
        manager._v1 = mock_v1

        with pytest.raises(KubernetesAPIError) as exc_info:
            await manager.get_secret("test-secret", "test-ns")

        assert "Failed to read secret" in str(exc_info.value)


class TestCreateOperationalSecret:
    """Test operational secret creation."""

    @pytest.mark.asyncio
    async def test_creates_secret_with_correct_structure(self):
        """Should create secret with proper labels and annotations."""
        manager = SecretManager()
        mock_v1 = MagicMock()
        manager._v1 = mock_v1

        token = "test-operational-token"
        namespace = "test-ns"
        version = 1
        valid_until = datetime.now(UTC) + timedelta(days=90)

        await manager.create_operational_secret(
            namespace=namespace,
            token=token,
            token_version=version,
            valid_until=valid_until,
        )

        # Verify create was called
        mock_v1.create_namespaced_secret.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_secret_with_owner_reference(self):
        """Should add owner reference when provided."""
        manager = SecretManager()
        mock_v1 = MagicMock()
        manager._v1 = mock_v1

        owner_name = "test-realm"
        owner_uid = "realm-uid-123"

        await manager.create_operational_secret(
            namespace="test-ns",
            token="token",
            token_version=1,
            valid_until=datetime.now(UTC) + timedelta(days=90),
            owner_realm_name=owner_name,
            owner_realm_uid=owner_uid,
        )

        # Verify create was called
        mock_v1.create_namespaced_secret.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_existing_secret_on_conflict(self):
        """Should return existing secret if creation conflicts."""
        existing_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="existing", namespace="test-ns")
        )

        mock_v1 = MagicMock()
        mock_v1.create_namespaced_secret = MagicMock(
            side_effect=ApiException(status=409)
        )
        mock_v1.read_namespaced_secret = MagicMock(return_value=existing_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        result = await manager.create_operational_secret(
            namespace="test-ns",
            token="token",
            token_version=1,
            valid_until=datetime.now(UTC) + timedelta(days=90),
        )

        assert result is not None
        assert result.metadata.name == "existing"

    @pytest.mark.asyncio
    async def test_raises_on_create_failure(self):
        """Should raise KubernetesAPIError on creation failure."""
        mock_v1 = MagicMock()
        mock_v1.create_namespaced_secret = MagicMock(
            side_effect=ApiException(status=500, reason="Internal Error")
        )

        manager = SecretManager()
        manager._v1 = mock_v1

        with pytest.raises(KubernetesAPIError) as exc_info:
            await manager.create_operational_secret(
                namespace="test-ns",
                token="token",
                token_version=1,
                valid_until=datetime.now(UTC) + timedelta(days=90),
            )

        assert "Failed to create operational token secret" in str(exc_info.value)


class TestUpdateSecretWithRotation:
    """Test secret update during rotation."""

    @pytest.mark.asyncio
    async def test_adds_previous_token_during_rotation(self):
        """Should add token-previous field during rotation."""
        old_token = base64.b64encode(b"old-token").decode()
        new_token = "new-token"

        existing_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="token-secret",
                namespace="test-ns",
                annotations={"keycloak.mdvr.nl/version": "1"},
            ),
            data={"token": old_token},
        )

        mock_v1 = MagicMock()
        mock_v1.replace_namespaced_secret = MagicMock(return_value=existing_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        grace_period_ends = datetime.now(UTC) + timedelta(days=GRACE_PERIOD_DAYS)

        await manager.update_secret_with_rotation(
            secret=existing_secret,
            new_token=new_token,
            new_version=2,
            new_valid_until=datetime.now(UTC) + timedelta(days=90),
        )

        # Verify update was called
        mock_v1.replace_namespaced_secret.assert_called_once()
        
        call_args = mock_v1.replace_namespaced_secret.call_args
        updated_secret = call_args[1]["body"]

        # Should have both tokens
        assert "token" in updated_secret.data
        assert "token-previous" in updated_secret.data

        # New token should be current
        decoded_new = base64.b64decode(updated_secret.data["token"]).decode()
        assert decoded_new == new_token

        # Old token should be in token-previous
        assert updated_secret.data["token-previous"] == old_token

        # Should have grace period annotation
        assert "keycloak.mdvr.nl/grace-period-ends" in updated_secret.metadata.annotations

    @pytest.mark.asyncio
    async def test_updates_version_annotation(self):
        """Should update version annotation."""
        existing_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="token-secret",
                namespace="test-ns",
                annotations={"keycloak.mdvr.nl/version": "1"},
            ),
            data={"token": base64.b64encode(b"old").decode()},
        )

        mock_v1 = MagicMock()
        mock_v1.replace_namespaced_secret = MagicMock(return_value=existing_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        await manager.update_secret_with_rotation(
            secret=existing_secret,
            new_token="new",
            new_version=5,
            new_valid_until=datetime.now(UTC) + timedelta(days=90),
        )

        call_args = mock_v1.replace_namespaced_secret.call_args
        updated_secret = call_args[1]["body"]

        assert updated_secret.metadata.annotations["keycloak.mdvr.nl/version"] == "5"


class TestCleanupPreviousToken:
    """Test cleanup of previous token after grace period."""

    @pytest.mark.asyncio
    async def test_removes_previous_token_and_grace_period(self):
        """Should remove token-previous and grace period annotation."""
        old_token = base64.b64encode(b"old-token").decode()
        current_token = base64.b64encode(b"current-token").decode()

        existing_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="token-secret",
                namespace="test-ns",
                annotations={
                    "keycloak.mdvr.nl/version": "2",
                    "keycloak.mdvr.nl/grace-period-ends": "2025-01-01T00:00:00Z",
                },
            ),
            data={
                "token": current_token,
                "token-previous": old_token,
            },
        )

        mock_v1 = MagicMock()
        mock_v1.replace_namespaced_secret = MagicMock(return_value=existing_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        result = await manager.cleanup_previous_token(existing_secret)

        call_args = mock_v1.replace_namespaced_secret.call_args
        updated_secret = call_args[1]["body"]

        # token-previous should be removed
        assert "token-previous" not in updated_secret.data
        
        # Current token should remain
        assert "token" in updated_secret.data
        assert updated_secret.data["token"] == current_token

        # Grace period annotation should be removed
        assert "keycloak.mdvr.nl/grace-period-ends" not in updated_secret.metadata.annotations

    @pytest.mark.asyncio
    async def test_handles_secret_without_previous_token(self):
        """Should handle cleanup when no previous token exists."""
        current_token = base64.b64encode(b"current-token").decode()

        existing_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="token-secret",
                namespace="test-ns",
                annotations={"keycloak.mdvr.nl/version": "1"},
            ),
            data={"token": current_token},
        )

        mock_v1 = MagicMock()
        mock_v1.replace_namespaced_secret = MagicMock(return_value=existing_secret)

        manager = SecretManager()
        manager._v1 = mock_v1

        # Should not raise error
        result = await manager.cleanup_previous_token(existing_secret)

        # Should still update the secret
        mock_v1.replace_namespaced_secret.assert_called_once()


class TestGetTokenFromSecret:
    """Test token extraction from secrets."""

    @pytest.mark.asyncio
    async def test_extracts_current_token(self):
        """Should extract token from data field."""
        token_value = "test-token-123"
        encoded = base64.b64encode(token_value.encode()).decode()

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test", namespace="test-ns"),
            data={"token": encoded},
        )

        manager = SecretManager()
        
        result = await manager.get_token_from_secret(secret, "test-ns")
        
        assert result == token_value

    @pytest.mark.asyncio
    async def test_falls_back_to_previous_token(self):
        """Should fall back to token-previous if token missing."""
        previous_value = "previous-token"
        encoded = base64.b64encode(previous_value.encode()).decode()

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test", namespace="test-ns"),
            data={"token-previous": encoded},
        )

        manager = SecretManager()
        
        result = await manager.get_token_from_secret(secret, "test-ns")
        
        assert result == previous_value

    @pytest.mark.asyncio
    async def test_prefers_current_over_previous(self):
        """Should prefer token over token-previous when both exist."""
        current = "current-token"
        previous = "previous-token"

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test", namespace="test-ns"),
            data={
                "token": base64.b64encode(current.encode()).decode(),
                "token-previous": base64.b64encode(previous.encode()).decode(),
            },
        )

        manager = SecretManager()
        
        result = await manager.get_token_from_secret(secret, "test-ns")
        
        assert result == current

    @pytest.mark.asyncio
    async def test_raises_when_no_token_found(self):
        """Should raise AuthorizationError when no token exists."""
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test", namespace="test-ns"),
            data={},
        )

        manager = SecretManager()

        with pytest.raises(AuthorizationError) as exc_info:
            await manager.get_token_from_secret(secret, "test-ns")

        assert "Secret has no data" in str(exc_info.value)
