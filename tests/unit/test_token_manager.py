"""Unit tests for token_manager module."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.errors import KubernetesAPIError
from keycloak_operator.models.common import TokenMetadata
from keycloak_operator.utils.token_manager import (
    TOKEN_VALIDITY_DAYS,
    _hash_token,
    generate_operational_token,
    get_token_metadata,
    list_tokens_for_namespace,
    rotate_operational_token,
    store_token_metadata,
    validate_token,
)


class TestTokenHashing:
    """Test token hashing functionality."""

    def test_hash_token_generates_sha256(self):
        """Verify token is hashed with SHA-256."""
        token = "test-token-123"
        expected = hashlib.sha256(token.encode()).hexdigest()
        assert _hash_token(token) == expected

    def test_hash_token_is_deterministic(self):
        """Same token produces same hash."""
        token = "consistent-token"
        hash1 = _hash_token(token)
        hash2 = _hash_token(token)
        assert hash1 == hash2

    def test_hash_token_different_tokens_different_hashes(self):
        """Different tokens produce different hashes."""
        token1 = "token-one"
        token2 = "token-two"
        assert _hash_token(token1) != _hash_token(token2)


class TestGenerateOperationalToken:
    """Test operational token generation."""

    @pytest.mark.asyncio
    async def test_generates_token_with_correct_structure(self):
        """Generated token should have correct format and fields."""
        namespace = "test-namespace"
        created_by_realm = "test-realm"

        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            token, metadata = await generate_operational_token(
                namespace=namespace, created_by_realm=created_by_realm
            )

            # Token should be a string
            assert isinstance(token, str)
            # Token should be long enough (256-bit = 32 bytes = 64 hex chars minimum base64)
            assert len(token) >= 40

            # Metadata should be correct
            assert metadata.namespace == namespace
            assert metadata.token_type == "operational"
            assert metadata.version == 1  # First version
            assert metadata.created_by_realm == created_by_realm
            assert metadata.revoked is False

            # Token hash should match
            expected_hash = _hash_token(token)
            assert metadata.token_hash == expected_hash

    @pytest.mark.asyncio
    async def test_generates_unique_tokens(self):
        """Each call should generate a unique token."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            token1, _ = await generate_operational_token("ns1", "realm1")
            token2, _ = await generate_operational_token("ns1", "realm1")
            assert token1 != token2

    @pytest.mark.asyncio
    async def test_token_validity_period(self):
        """Token should have correct validity period."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, metadata = await generate_operational_token("ns", "realm")

            # Should be valid for TOKEN_VALIDITY_DAYS
            expected_valid_until = datetime.now(UTC) + timedelta(
                days=TOKEN_VALIDITY_DAYS
            )
            actual_valid_until = metadata.valid_until

            # Allow 1 second tolerance for test execution time
            diff = abs((expected_valid_until - actual_valid_until).total_seconds())
            assert diff < 1

    @pytest.mark.asyncio
    async def test_issued_at_is_current_time(self):
        """Token issued_at should be current UTC time."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, metadata = await generate_operational_token("ns", "realm")

            issued_at = metadata.issued_at
            now = datetime.now(UTC)

            # Allow 1 second tolerance
            diff = abs((now - issued_at).total_seconds())
            assert diff < 1


class TestRotateToken:
    """Test token rotation functionality."""

    @pytest.mark.asyncio
    async def test_rotate_increments_version(self):
        """Rotation should increment version number."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            original_token, original_metadata = await generate_operational_token(
                "ns", created_by_realm="realm"
            )

            new_token, new_metadata = await rotate_operational_token(
                "ns", original_metadata
            )

            assert new_metadata.version == original_metadata.version + 1
            assert new_token != original_token

    @pytest.mark.asyncio
    async def test_rotate_preserves_namespace(self):
        """Rotation should preserve namespace."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, original_metadata = await generate_operational_token("test-ns", "realm")
            _, new_metadata = await rotate_operational_token(
                "test-ns", original_metadata
            )

            assert new_metadata.namespace == original_metadata.namespace

    @pytest.mark.asyncio
    async def test_rotate_preserves_created_by_realm(self):
        """Rotation should preserve created_by_realm."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, original_metadata = await generate_operational_token(
                "ns", "original-realm"
            )
            _, new_metadata = await rotate_operational_token("ns", original_metadata)

            assert new_metadata.created_by_realm == original_metadata.created_by_realm

    @pytest.mark.asyncio
    async def test_rotate_extends_validity(self):
        """Rotation should extend validity period."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, original_metadata = await generate_operational_token("ns", "realm")

            # Simulate aging the token
            old_valid_until = original_metadata.valid_until

            _, new_metadata = await rotate_operational_token("ns", original_metadata)

            new_valid_until = new_metadata.valid_until

            # New token should be valid for TOKEN_VALIDITY_DAYS from now
            expected_valid_until = datetime.now(UTC) + timedelta(
                days=TOKEN_VALIDITY_DAYS
            )
            diff = abs((new_valid_until - expected_valid_until).total_seconds())
            assert diff < 1

            # New validity should be later than old
            assert new_valid_until > old_valid_until

    @pytest.mark.asyncio
    async def test_rotate_updates_issued_at(self):
        """Rotation should update issued_at to current time."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, original_metadata = await generate_operational_token("ns", "realm")
            _, new_metadata = await rotate_operational_token("ns", original_metadata)

            new_issued_at = new_metadata.issued_at
            now = datetime.now(UTC)

            diff = abs((now - new_issued_at).total_seconds())
            assert diff < 1

    @pytest.mark.asyncio
    async def test_rotate_generates_new_token_hash(self):
        """Rotation should generate new token with new hash."""
        with patch("keycloak_operator.utils.token_manager.store_token_metadata"):
            _, original_metadata = await generate_operational_token("ns", "realm")
            _, new_metadata = await rotate_operational_token("ns", original_metadata)

            assert new_metadata.token_hash != original_metadata.token_hash


class TestStoreTokenMetadata:
    """Test token metadata storage in ConfigMap."""

    @pytest.mark.asyncio
    async def test_creates_configmap_if_not_exists(self):
        """Should create ConfigMap if it doesn't exist."""
        metadata = TokenMetadata(
            namespace="test-ns",
            token_type="operational",
            token_hash="abc123",
            issued_at=datetime.now(UTC),
            valid_until=datetime.now(UTC) + timedelta(days=90),
            version=1,
            created_by_realm="realm",
            revoked=False,
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(
            side_effect=ApiException(status=404)
        )
        mock_v1.create_namespaced_config_map = MagicMock()

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            await store_token_metadata(metadata)

            # Should attempt to read first
            mock_v1.read_namespaced_config_map.assert_called_once()

            # Should create new ConfigMap
            mock_v1.create_namespaced_config_map.assert_called_once()

    @pytest.mark.asyncio
    async def test_updates_existing_configmap(self):
        """Should update existing ConfigMap with new metadata."""
        metadata = TokenMetadata(
            namespace="test-ns",
            token_type="operational",
            token_hash="newtoken123",
            issued_at=datetime.now(UTC).isoformat(),
            valid_until=(datetime.now(UTC) + timedelta(days=90)).isoformat(),
            version=2,
            created_by_realm="realm",
            revoked=False,
        )

        existing_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="token-metadata"),
            data={"oldtoken": '{"namespace": "old", "version": 1}'},
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(return_value=existing_cm)
        mock_v1.replace_namespaced_config_map = MagicMock()

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            await store_token_metadata(metadata)

            # Should update existing ConfigMap
            mock_v1.replace_namespaced_config_map.assert_called_once()
            call_args = mock_v1.replace_namespaced_config_map.call_args
            updated_cm = call_args[1]["body"]

            # Should contain both old and new metadata
            assert "oldtoken" in updated_cm.data
            assert metadata.token_hash in updated_cm.data

    @pytest.mark.asyncio
    async def test_raises_on_api_error(self):
        """Should raise KubernetesAPIError on API failures."""
        metadata = TokenMetadata(
            namespace="test-ns",
            token_type="operational",
            token_hash="abc123",
            issued_at=datetime.now(UTC),
            valid_until=datetime.now(UTC) + timedelta(days=90),
            version=1,
            created_by_realm="realm",
            revoked=False,
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(
            side_effect=ApiException(status=500, reason="Internal Error")
        )

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            with pytest.raises(KubernetesAPIError) as exc_info:
                await store_token_metadata(metadata)

            assert "Failed to read token metadata ConfigMap" in str(exc_info.value)


class TestGetTokenMetadata:
    """Test retrieving token metadata from ConfigMap."""

    @pytest.mark.asyncio
    async def test_retrieves_valid_metadata(self):
        """Should retrieve and parse valid metadata."""
        token_hash = "abc123"
        metadata_json = json.dumps(
            {
                "namespace": "test-ns",
                "token_type": "operational",
                "token_hash": token_hash,
                "issued_at": "2025-01-01T00:00:00+00:00",
                "valid_until": "2025-04-01T00:00:00+00:00",
                "version": 1,
                "created_by_realm": "realm",
                "revoked": False,
            }
        )

        existing_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="token-metadata"),
            data={token_hash: metadata_json},
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(return_value=existing_cm)

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await get_token_metadata(token_hash)

            assert result is not None
            assert result.namespace == "test-ns"
            assert result.version == 1
            assert result.token_hash == token_hash

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_token(self):
        """Should return None if token not found in ConfigMap."""
        existing_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="token-metadata"),
            data={"other-token": "{}"},
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(return_value=existing_cm)

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await get_token_metadata("nonexistent-hash")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_configmap(self):
        """Should return None if ConfigMap doesn't exist."""
        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(
            side_effect=ApiException(status=404)
        )

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await get_token_metadata("any-hash")
            assert result is None


class TestValidateToken:
    """Test token validation logic."""

    @pytest.mark.asyncio
    async def test_validates_correct_token(self):
        """Should validate a token with valid metadata."""
        token = "valid-token-123"
        token_hash = _hash_token(token)
        namespace = "test-ns"

        metadata = TokenMetadata(
            namespace=namespace,
            token_type="operational",
            token_hash=token_hash,
            issued_at=datetime.now(UTC).isoformat(),
            valid_until=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
            version=1,
            created_by_realm="realm",
            revoked=False,
        )

        with patch(
            "keycloak_operator.utils.token_manager.get_token_metadata",
            return_value=metadata,
        ):
            result = await validate_token(token, namespace)

            assert result is not None
            assert result.namespace == namespace
            assert result.token_hash == token_hash

    @pytest.mark.asyncio
    async def test_rejects_expired_token(self):
        """Should reject a token that has expired."""
        token = "expired-token"
        token_hash = _hash_token(token)

        metadata = TokenMetadata(
            namespace="test-ns",
            token_type="operational",
            token_hash=token_hash,
            issued_at=(datetime.now(UTC) - timedelta(days=100)).isoformat(),
            valid_until=(datetime.now(UTC) - timedelta(days=10)).isoformat(),
            version=1,
            created_by_realm="realm",
            revoked=False,
        )

        with patch(
            "keycloak_operator.utils.token_manager.get_token_metadata",
            return_value=metadata,
        ):
            result = await validate_token(token, "test-ns")
            assert result is None

    @pytest.mark.asyncio
    async def test_rejects_revoked_token(self):
        """Should reject a token that has been revoked."""
        token = "revoked-token"
        token_hash = _hash_token(token)

        metadata = TokenMetadata(
            namespace="test-ns",
            token_type="operational",
            token_hash=token_hash,
            issued_at=datetime.now(UTC).isoformat(),
            valid_until=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
            version=1,
            created_by_realm="realm",
            revoked=True,  # Revoked!
        )

        with patch(
            "keycloak_operator.utils.token_manager.get_token_metadata",
            return_value=metadata,
        ):
            result = await validate_token(token, "test-ns")
            assert result is None

    @pytest.mark.asyncio
    async def test_rejects_wrong_namespace(self):
        """Should reject a token from a different namespace."""
        token = "token"
        token_hash = _hash_token(token)

        metadata = TokenMetadata(
            namespace="other-namespace",
            token_type="operational",
            token_hash=token_hash,
            issued_at=datetime.now(UTC).isoformat(),
            valid_until=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
            version=1,
            created_by_realm="realm",
            revoked=False,
        )

        with patch(
            "keycloak_operator.utils.token_manager.get_token_metadata",
            return_value=metadata,
        ):
            result = await validate_token(token, "test-namespace")
            assert result is None

    @pytest.mark.asyncio
    async def test_rejects_unknown_token(self):
        """Should reject a token with no metadata."""
        with patch(
            "keycloak_operator.utils.token_manager.get_token_metadata",
            return_value=None,
        ):
            result = await validate_token("unknown-token", "test-ns")
            assert result is None


class TestListTokensForNamespace:
    """Test retrieving tokens for a specific namespace."""

    @pytest.mark.asyncio
    async def test_retrieves_namespace_tokens(self):
        """Should retrieve only tokens for specified namespace."""
        metadata1 = {
            "namespace": "target-ns",
            "token_type": "operational",
            "token_hash": "hash1",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-04-01T00:00:00+00:00",
            "version": 1,
            "created_by_realm": "realm1",
            "revoked": False,
        }
        metadata2 = {
            "namespace": "other-ns",
            "token_type": "operational",
            "token_hash": "hash2",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-04-01T00:00:00+00:00",
            "version": 2,
            "created_by_realm": "realm2",
            "revoked": False,
        }
        metadata3 = {
            "namespace": "target-ns",
            "token_type": "operational",
            "token_hash": "hash3",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-04-01T00:00:00+00:00",
            "version": 1,
            "created_by_realm": "realm3",
            "revoked": False,
        }

        existing_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="token-metadata"),
            data={
                "hash1": json.dumps(metadata1),
                "hash2": json.dumps(metadata2),
                "hash3": json.dumps(metadata3),
            },
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(return_value=existing_cm)

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await list_tokens_for_namespace("target-ns")

            # Should only return tokens for target-ns
            assert len(result) == 2
            assert all(m.namespace == "target-ns" for m in result)

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_no_matches(self):
        """Should return empty list if no tokens match namespace."""
        metadata1 = {
            "namespace": "other-ns",
            "token_type": "operational",
            "token_hash": "hash1",
            "issued_at": "2025-01-01T00:00:00+00:00",
            "valid_until": "2025-04-01T00:00:00+00:00",
            "version": 1,
            "created_by_realm": "realm1",
            "revoked": False,
        }

        existing_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="token-metadata"),
            data={"hash1": json.dumps(metadata1)},
        )

        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(return_value=existing_cm)

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await list_tokens_for_namespace("target-ns")
            assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_list_for_missing_configmap(self):
        """Should return empty list if ConfigMap doesn't exist."""
        mock_v1 = MagicMock()
        mock_v1.read_namespaced_config_map = MagicMock(
            side_effect=ApiException(status=404)
        )

        with patch(
            "keycloak_operator.utils.token_manager.client.CoreV1Api",
            return_value=mock_v1,
        ):
            result = await list_tokens_for_namespace("any-ns")
            assert result == []
