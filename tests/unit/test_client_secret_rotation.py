import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.errors import ValidationError
from keycloak_operator.models.client import KeycloakClientSpec, SecretRotationConfig
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler


class TestClientSecretRotation:
    @pytest.fixture
    def reconciler(self):
        return KeycloakClientReconciler(k8s_client=MagicMock())

    @pytest.fixture
    def spec(self):
        spec = MagicMock(spec=KeycloakClientSpec)
        spec.secret_rotation = SecretRotationConfig(enabled=True, rotation_period="90d")
        spec.client_id = "test-client"
        return spec

    @pytest.fixture
    def secret(self):
        secret = MagicMock()
        secret.metadata.annotations = {}
        return secret

    def test_parse_duration_valid(self, reconciler):
        assert reconciler._parse_duration("90d") == timedelta(days=90)
        assert reconciler._parse_duration("24h") == timedelta(hours=24)
        assert reconciler._parse_duration("10m") == timedelta(minutes=10)
        assert reconciler._parse_duration("30s") == timedelta(seconds=30)

    def test_parse_duration_invalid(self, reconciler):
        with pytest.raises(ValidationError):
            reconciler._parse_duration("90x")
        with pytest.raises(ValidationError):
            reconciler._parse_duration("invalid")

    def test_parse_duration_zero_value(self, reconciler):
        """Test that zero duration values are rejected."""
        with pytest.raises(ValidationError, match="must be a positive integer"):
            reconciler._parse_duration("0d")
        with pytest.raises(ValidationError, match="must be a positive integer"):
            reconciler._parse_duration("0h")

    def test_parse_duration_negative_value(self, reconciler):
        """Test that negative duration values are rejected."""
        with pytest.raises(ValidationError, match="must be a positive integer"):
            reconciler._parse_duration("-1d")
        with pytest.raises(ValidationError, match="must be a positive integer"):
            reconciler._parse_duration("-5h")

    def test_should_rotate_secret_disabled(self, reconciler, spec, secret):
        spec.secret_rotation.enabled = False
        assert not reconciler._should_rotate_secret(spec, secret)

    def test_should_rotate_secret_no_annotation(self, reconciler, spec, secret):
        # No annotation means it's a new rotation cycle starts NOW, so no rotation yet
        assert not reconciler._should_rotate_secret(spec, secret)

    def test_should_rotate_secret_not_expired(self, reconciler, spec, secret):
        now = datetime.now(UTC)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": now.isoformat()}
        assert not reconciler._should_rotate_secret(spec, secret)

    def test_should_rotate_secret_expired(self, reconciler, spec, secret):
        # Set rotated_at to 91 days ago (expired since period is 90d)
        past = datetime.now(UTC) - timedelta(days=91)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": past.isoformat()}
        assert reconciler._should_rotate_secret(spec, secret)


class TestSecretRotationDaemon:
    """
    Unit tests for the secret_rotation_daemon function.
    """

    @pytest.fixture
    def mock_stopped(self):
        """Create a mock DaemonStopped object."""
        stopped = MagicMock()
        stopped.__bool__ = MagicMock(side_effect=[False, True])  # Run once then stop
        stopped.wait = AsyncMock(return_value=True)  # Simulate stop signal
        return stopped

    @pytest.fixture
    def mock_patch_obj(self):
        """Create a mock Patch object."""
        p = MagicMock()
        p.status = {}
        return p

    @pytest.fixture
    def base_spec(self):
        """Create a base client spec dict for testing."""
        return {
            "clientId": "test-client",
            "realmRef": {"name": "test-realm", "namespace": "test-ns"},
            "secretRotation": {
                "enabled": True,
                "rotationPeriod": "1d",
            },
        }

    @pytest.fixture
    def mock_secret(self):
        """Create a mock Kubernetes secret."""
        secret = MagicMock()
        secret.metadata.annotations = {
            "keycloak-operator/rotated-at": datetime.now(UTC).isoformat()
        }
        return secret

    @pytest.mark.asyncio
    async def test_daemon_secret_not_found_waits(
        self, mock_stopped, mock_patch_obj, base_spec
    ):
        """Test daemon waits when secret is not found."""
        from kubernetes.client.rest import ApiException

        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_secret.side_effect = ApiException(status=404)

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                return_value=True,
            ),
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api

            # stopped.wait returns True immediately (simulate stop)
            mock_stopped.wait = AsyncMock(return_value=True)
            mock_stopped.__bool__ = MagicMock(return_value=False)

            await secret_rotation_daemon(
                spec=base_spec,
                name="test-client",
                namespace="test-ns",
                status={},
                meta={"uid": "test-uid"},
                stopped=mock_stopped,
                patch=mock_patch_obj,
                memo=MagicMock(),
                logger=logging.getLogger("test"),
            )

            mock_stopped.wait.assert_called()

    @pytest.mark.asyncio
    async def test_daemon_successful_rotation(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon successfully rotates secret when due."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired (rotation needed)
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
            }
        }

        # Mock admin client
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.return_value = "new-secret-value"

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
            patch(
                "keycloak_operator.handlers.client.client.CustomObjectsApi"
            ) as mock_custom_api_cls,
            patch(
                "keycloak_operator.handlers.client.get_keycloak_admin_client"
            ) as mock_get_admin,
            patch(
                "keycloak_operator.handlers.client.create_client_secret"
            ) as mock_create_secret,
            patch(
                "keycloak_operator.handlers.client.is_client_managed_by_this_operator",
                return_value=True,
            ),
            patch("keycloak_operator.handlers.client.settings") as mock_settings,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client
            mock_settings.keycloak_url = "http://keycloak:8080"

            mock_stopped.wait = AsyncMock(return_value=True)
            mock_stopped.__bool__ = MagicMock(side_effect=[False, False, True])

            await secret_rotation_daemon(
                spec=base_spec,
                name="test-client",
                namespace="test-ns",
                status={},
                meta={"uid": "test-uid"},
                stopped=mock_stopped,
                patch=mock_patch_obj,
                memo=MagicMock(),
                logger=logging.getLogger("test"),
            )

            # Verify rotation happened
            mock_admin_client.regenerate_client_secret.assert_called_once()
            mock_create_secret.assert_called_once()

            # Verify status was updated
            assert mock_patch_obj.status.get("phase") == "Ready"
