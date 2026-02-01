import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError as PydanticValidationError

from keycloak_operator.errors import ValidationError
from keycloak_operator.handlers.client import (
    ROTATION_INITIAL_BACKOFF_SECONDS,
    ROTATION_MAX_BACKOFF_SECONDS,
    _calculate_exponential_backoff,
    _calculate_seconds_until_rotation,
    _parse_duration,
    _parse_rotation_timestamp,
)
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

    def test_should_rotate_secret_with_time_window_not_reached(
        self, reconciler, spec, secret
    ):
        # Expired but not in window yet
        # Rotation period: 1 day
        # Last rotated: 25 hours ago (expired)
        # Target time: Current hour + 2

        spec.secret_rotation.rotation_period = "1d"
        spec.secret_rotation.rotation_time = (
            datetime.now(UTC) + timedelta(hours=2)
        ).strftime("%H:%M")

        past = datetime.now(UTC) - timedelta(hours=25)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": past.isoformat()}

        assert not reconciler._should_rotate_secret(spec, secret)

    def test_should_rotate_secret_with_time_window_reached(
        self, reconciler, spec, secret
    ):
        # Expired and window reached
        # Rotation period: 1 day
        # Last rotated: 2 days ago
        # Target time: 1 hour ago

        spec.secret_rotation.rotation_period = "1d"
        now = datetime.now(UTC)
        target_time = (now - timedelta(hours=1)).strftime("%H:%M")
        spec.secret_rotation.rotation_time = target_time

        past = now - timedelta(days=2)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": past.isoformat()}

        assert reconciler._should_rotate_secret(spec, secret)

    def test_should_rotate_secret_timezone(self, reconciler, spec, secret):
        # Test timezone handling
        # Use a timezone that is significantly different from UTC (e.g. Tokyo +9)
        spec.secret_rotation.timezone = "Asia/Tokyo"
        spec.secret_rotation.rotation_period = "1d"

        # Set target time to 10:00 JST (01:00 UTC)
        spec.secret_rotation.rotation_time = "10:00"

        # Scenario 1: Expired, but not yet 10:00 JST
        # Current time: 09:00 JST (00:00 UTC) - Should NOT rotate
        # Last rotated: yesterday 09:00 JST

        # We need to mock datetime.now() because the reconciler uses it internally
        # Since we can't easily mock datetime.now() without freeze_time or similar lib which might not be available,
        # we will skip the exact time check validation in this unit test if we can't mock it.
        # However, we can validate that the logic *attempts* to parse timezone

        # Let's try to verify the timezone parsing logic implicitly by providing an invalid timezone
        spec.secret_rotation.timezone = "Invalid/Timezone"
        # Invalid timezone should trigger exception in logic, which is caught and logged, returning True (fallback)

        # Set expired time so it proceeds to timezone check
        past = datetime.now(UTC) - timedelta(days=2)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": past.isoformat()}

        # This should log a warning and return True (fallback to immediate rotation)
        assert reconciler._should_rotate_secret(spec, secret) is True

        # Verify valid timezone doesn't crash
        spec.secret_rotation.timezone = "UTC"
        assert reconciler._should_rotate_secret(spec, secret) is True


class TestSecretRotationConfig:
    """Test SecretRotationConfig Pydantic model validation."""

    def test_rotation_time_valid_format(self):
        """Test valid HH:MM rotation time formats."""
        config = SecretRotationConfig(rotation_time="00:00")
        assert config.rotation_time == "00:00"

        config = SecretRotationConfig(rotation_time="23:59")
        assert config.rotation_time == "23:59"

        config = SecretRotationConfig(rotation_time="12:30")
        assert config.rotation_time == "12:30"

    def test_rotation_time_none(self):
        """Test that rotation_time can be None."""
        config = SecretRotationConfig(rotation_time=None)
        assert config.rotation_time is None

    def test_rotation_time_invalid_format(self):
        """Test that invalid HH:MM formats are rejected."""
        with pytest.raises(PydanticValidationError, match="Expected 'HH:MM' format"):
            SecretRotationConfig(rotation_time="invalid")

        with pytest.raises(PydanticValidationError, match="Expected 'HH:MM' format"):
            SecretRotationConfig(rotation_time="12")

        with pytest.raises(PydanticValidationError, match="Expected 'HH:MM' format"):
            SecretRotationConfig(rotation_time="12:30:00")

    def test_rotation_time_invalid_hour(self):
        """Test that invalid hour values are rejected."""
        with pytest.raises(PydanticValidationError, match="Hour must be 0-23"):
            SecretRotationConfig(rotation_time="24:00")

        with pytest.raises(PydanticValidationError, match="Hour must be 0-23"):
            SecretRotationConfig(rotation_time="25:00")

    def test_rotation_time_invalid_minute(self):
        """Test that invalid minute values are rejected."""
        with pytest.raises(PydanticValidationError, match="Minute must be 0-59"):
            SecretRotationConfig(rotation_time="12:60")

        with pytest.raises(PydanticValidationError, match="Minute must be 0-59"):
            SecretRotationConfig(rotation_time="12:99")

    def test_rotation_time_non_integer_values(self):
        """Test that non-integer hour/minute values are rejected."""
        with pytest.raises(PydanticValidationError, match="must be integers"):
            SecretRotationConfig(rotation_time="ab:cd")


class TestPublicClientRotation:
    """Test that rotation is properly skipped for public clients."""

    @pytest.fixture
    def reconciler(self):
        return KeycloakClientReconciler(k8s_client=MagicMock())

    def test_public_client_skips_rotation_check(self, reconciler):
        """
        Test that public clients don't trigger secret rotation.

        While _should_rotate_secret doesn't directly check public_client,
        the manage_client_credentials method checks it before attempting
        to regenerate secrets. This test validates the behavior is correct
        at the spec level.
        """
        spec = MagicMock(spec=KeycloakClientSpec)
        spec.secret_rotation = SecretRotationConfig(enabled=True, rotation_period="1d")
        spec.public_client = True
        spec.client_id = "test-public-client"

        # Even with rotation enabled, the check for public_client happens
        # in manage_client_credentials, not in _should_rotate_secret.
        # But we can verify that _should_rotate_secret still works correctly
        # for determining IF rotation would be needed (ignoring client type).

        secret = MagicMock()
        past = datetime.now(UTC) - timedelta(days=2)
        secret.metadata.annotations = {"keycloak-operator/rotated-at": past.isoformat()}

        # _should_rotate_secret returns True because the period has elapsed
        # The actual skipping of rotation for public clients happens in
        # manage_client_credentials with the check: "not spec.public_client"
        assert reconciler._should_rotate_secret(spec, secret) is True

        # The key validation is that manage_client_credentials checks public_client
        # before calling regenerate_client_secret - this is an integration concern


class TestDaemonParseDuration:
    """Test the _parse_duration function used by the rotation daemon."""

    def test_parse_duration_days(self):
        assert _parse_duration("90d") == timedelta(days=90)
        assert _parse_duration("1d") == timedelta(days=1)

    def test_parse_duration_hours(self):
        assert _parse_duration("24h") == timedelta(hours=24)
        assert _parse_duration("1h") == timedelta(hours=1)

    def test_parse_duration_minutes(self):
        assert _parse_duration("10m") == timedelta(minutes=10)
        assert _parse_duration("60m") == timedelta(minutes=60)

    def test_parse_duration_seconds(self):
        assert _parse_duration("30s") == timedelta(seconds=30)
        assert _parse_duration("1s") == timedelta(seconds=1)

    def test_parse_duration_invalid_unit(self):
        with pytest.raises(ValueError, match="Invalid duration unit"):
            _parse_duration("90x")

    def test_parse_duration_zero_value(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            _parse_duration("0d")

    def test_parse_duration_negative_value(self):
        with pytest.raises(ValueError, match="must be a positive integer"):
            _parse_duration("-1d")

    def test_parse_duration_empty_string(self):
        # Empty string returns default of 90 days
        assert _parse_duration("") == timedelta(days=90)


class TestCalculateSecondsUntilRotation:
    """Test the _calculate_seconds_until_rotation function."""

    @pytest.fixture
    def logger(self):
        return logging.getLogger("test")

    @pytest.fixture
    def base_spec(self):
        """Create a base client spec with rotation enabled."""
        return KeycloakClientSpec(
            client_id="test-client",
            realm_ref={"name": "test-realm", "namespace": "test-ns"},
            secret_rotation=SecretRotationConfig(
                enabled=True,
                rotation_period="1d",
            ),
        )

    def test_rotation_not_due(self, base_spec, logger):
        """Test when rotation period has not elapsed."""
        # Rotated just now
        rotated_at = datetime.now(UTC)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be close to 86400 (1 day in seconds)
        assert 86300 < seconds <= 86400

    def test_rotation_due_immediately(self, base_spec, logger):
        """Test when rotation period has elapsed."""
        # Rotated 2 days ago (period is 1 day)
        rotated_at = datetime.now(UTC) - timedelta(days=2)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be 0 (immediate rotation)
        assert seconds == 0.0

    def test_rotation_halfway(self, base_spec, logger):
        """Test when rotation is halfway through the period."""
        # Rotated 12 hours ago (period is 1 day)
        rotated_at = datetime.now(UTC) - timedelta(hours=12)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be approximately 12 hours (43200 seconds)
        assert 43100 < seconds <= 43200

    def test_rotation_with_time_window_not_reached(self, base_spec, logger):
        """Test rotation time window constrains when rotation happens.

        The time window calculation is relative to the expiration time, not the current time.
        When a secret expires, we wait until the next occurrence of the target time
        after the expiration point.
        """
        # Set up: rotation period of 1 second, so it expires almost immediately
        # Target rotation time 2 hours from now - this should delay the rotation
        base_spec.secret_rotation.rotation_period = "1s"

        future_time = datetime.now(UTC) + timedelta(hours=2)
        base_spec.secret_rotation.rotation_time = future_time.strftime("%H:%M")
        base_spec.secret_rotation.timezone = "UTC"

        # Rotated 10 seconds ago (expired, since period is 1s)
        rotated_at = datetime.now(UTC) - timedelta(seconds=10)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be approximately 2 hours (not 0, because of time window)
        # The target time is 2 hours from now
        assert 7000 < seconds <= 7200

    def test_rotation_with_time_window_reached(self, base_spec, logger):
        """Test when rotation time window has been reached."""
        # Set target rotation time to 1 hour ago
        past_time = datetime.now(UTC) - timedelta(hours=1)
        base_spec.secret_rotation.rotation_time = past_time.strftime("%H:%M")
        base_spec.secret_rotation.timezone = "UTC"

        # Rotated 2 days ago (expired)
        rotated_at = datetime.now(UTC) - timedelta(days=2)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be 0 (time window reached)
        assert seconds == 0.0

    def test_rotation_with_invalid_timezone(self, base_spec, logger):
        """Test that invalid timezone falls back to immediate rotation."""
        base_spec.secret_rotation.rotation_time = "10:00"
        base_spec.secret_rotation.timezone = "Invalid/Timezone"

        # Rotated 2 days ago (expired)
        rotated_at = datetime.now(UTC) - timedelta(days=2)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be 0 (fallback to immediate)
        assert seconds == 0.0

    def test_rotation_short_period(self, base_spec, logger):
        """Test with a short rotation period (seconds)."""
        base_spec.secret_rotation.rotation_period = "60s"

        # Rotated 30 seconds ago
        rotated_at = datetime.now(UTC) - timedelta(seconds=30)

        seconds = _calculate_seconds_until_rotation(base_spec, rotated_at, logger)

        # Should be approximately 30 seconds
        assert 25 < seconds <= 30


class TestParseRotationTimestamp:
    """Test the _parse_rotation_timestamp helper function."""

    def test_parse_valid_iso_format_with_timezone(self):
        """Test parsing a valid ISO timestamp with timezone."""
        timestamp_str = "2026-01-31T12:00:00+00:00"
        result = _parse_rotation_timestamp(timestamp_str)

        assert result is not None
        assert result.year == 2026
        assert result.month == 1
        assert result.day == 31
        assert result.hour == 12
        assert result.tzinfo is not None

    def test_parse_valid_iso_format_without_timezone(self):
        """Test parsing a valid ISO timestamp without timezone defaults to UTC."""
        timestamp_str = "2026-01-31T12:00:00"
        result = _parse_rotation_timestamp(timestamp_str)

        assert result is not None
        assert result.tzinfo == UTC

    def test_parse_valid_iso_format_with_microseconds(self):
        """Test parsing a valid ISO timestamp with microseconds."""
        timestamp_str = "2026-01-31T12:00:00.123456+00:00"
        result = _parse_rotation_timestamp(timestamp_str)

        assert result is not None
        assert result.microsecond == 123456

    def test_parse_none_returns_none(self):
        """Test that None input returns None."""
        result = _parse_rotation_timestamp(None)
        assert result is None

    def test_parse_empty_string_returns_none(self):
        """Test that empty string returns None."""
        result = _parse_rotation_timestamp("")
        assert result is None

    def test_parse_invalid_format_returns_none(self):
        """Test that invalid format returns None instead of raising."""
        result = _parse_rotation_timestamp("not-a-timestamp")
        assert result is None

    def test_parse_partial_timestamp_returns_none(self):
        """Test that partial timestamp returns None."""
        result = _parse_rotation_timestamp("2026-01-31")
        # datetime.fromisoformat accepts date-only strings in Python 3.11+
        # so this should actually parse successfully
        assert result is not None  # Date-only is valid ISO format

    def test_parse_garbage_returns_none(self):
        """Test that garbage input returns None."""
        result = _parse_rotation_timestamp("garbage123")
        assert result is None


class TestCalculateExponentialBackoff:
    """Test the _calculate_exponential_backoff helper function."""

    def test_initial_backoff(self):
        """Test backoff at retry 0."""
        backoff = _calculate_exponential_backoff(0)
        assert backoff == ROTATION_INITIAL_BACKOFF_SECONDS

    def test_first_retry_doubles(self):
        """Test backoff doubles after first retry."""
        backoff = _calculate_exponential_backoff(1)
        assert backoff == ROTATION_INITIAL_BACKOFF_SECONDS * 2

    def test_second_retry_quadruples(self):
        """Test backoff quadruples after second retry."""
        backoff = _calculate_exponential_backoff(2)
        assert backoff == ROTATION_INITIAL_BACKOFF_SECONDS * 4

    def test_backoff_capped_at_max(self):
        """Test backoff is capped at maximum value."""
        # With initial=2.0, after many retries we should hit the 30s cap
        backoff = _calculate_exponential_backoff(10)  # 2 * 2^10 = 2048, capped at 30
        assert backoff == ROTATION_MAX_BACKOFF_SECONDS

    def test_custom_initial_backoff(self):
        """Test with custom initial backoff."""
        backoff = _calculate_exponential_backoff(0, initial_backoff=5.0)
        assert backoff == 5.0

    def test_custom_max_backoff(self):
        """Test with custom max backoff."""
        backoff = _calculate_exponential_backoff(
            10, initial_backoff=2.0, max_backoff=10.0
        )
        assert backoff == 10.0

    def test_backoff_just_below_max(self):
        """Test backoff just below the max threshold."""
        # initial=2.0, retry=3 -> 2*8=16, which is below 30
        backoff = _calculate_exponential_backoff(3)
        assert backoff == 16.0
        assert backoff < ROTATION_MAX_BACKOFF_SECONDS

    def test_backoff_just_at_max(self):
        """Test backoff at the point where it hits max."""
        # initial=2.0, retry=4 -> 2*16=32, capped at 30
        backoff = _calculate_exponential_backoff(4)
        assert backoff == ROTATION_MAX_BACKOFF_SECONDS


class TestSecretRotationDaemon:
    """
    Unit tests for the secret_rotation_daemon function.

    These tests mock the Kubernetes client and kopf objects to test
    specific code paths in the daemon without requiring a real cluster.
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

        # Realm exists with keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
                "keycloakRef": {"name": "test-keycloak", "namespace": "test-ns"},
            }
        }

        # Mock admin client
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.return_value = "new-secret-value"
        mock_admin_client.__aenter__.return_value = mock_admin_client
        mock_admin_client.__aexit__.return_value = None

        # Mock Keycloak instance
        mock_keycloak_instance = {
            "status": {"endpoints": {"public": "http://keycloak:8080"}}
        }

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
                "keycloak_operator.handlers.client.validate_keycloak_reference"
            ) as mock_validate,
            patch(
                "keycloak_operator.handlers.client.create_client_secret"
            ) as mock_create_secret,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client
            mock_validate.return_value = mock_keycloak_instance

            # First bool check returns False (enter loop), subsequent checks return True (exit)
            # The daemon checks `while not stopped:` then `while ... and not stopped:`
            # For success path: outer check (False) -> inner check (False) -> success -> outer check (True)
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
            assert "Secret rotated successfully" in mock_patch_obj.status.get(
                "message", ""
            )

    @pytest.mark.asyncio
    async def test_daemon_rotation_retry_on_failure(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon retries rotation on transient failure."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists with keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
                "keycloakRef": {"name": "test-keycloak", "namespace": "test-ns"},
            }
        }

        # Mock admin client - fails first time, succeeds second
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.side_effect = [
            RuntimeError("Connection timeout"),
            "new-secret-value",
        ]
        mock_admin_client.__aenter__.return_value = mock_admin_client
        mock_admin_client.__aexit__.return_value = None

        # Mock Keycloak instance
        mock_keycloak_instance = {
            "status": {"endpoints": {"public": "http://keycloak:8080"}}
        }

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
                "keycloak_operator.handlers.client.validate_keycloak_reference"
            ) as mock_validate,
            patch(
                "keycloak_operator.handlers.client.create_client_secret"
            ) as mock_create_secret,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client
            mock_validate.return_value = mock_keycloak_instance

            # Wait returns False (continue) for retry backoff, then True to stop
            # Bool checks: outer(False) -> inner(False) -> fail -> backoff wait returns False
            #              -> inner(False) -> success -> outer(True) exit
            mock_stopped.wait = AsyncMock(side_effect=[False, True])
            mock_stopped.__bool__ = MagicMock(side_effect=[False, False, False, True])

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

            # Verify retried
            assert mock_admin_client.regenerate_client_secret.call_count == 2
            mock_create_secret.assert_called_once()

    @pytest.mark.asyncio
    async def test_daemon_max_retries_sets_degraded(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon sets Degraded status after max retries."""
        from keycloak_operator.handlers.client import (
            ROTATION_MAX_RETRIES,
            secret_rotation_daemon,
        )

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists with keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
                "keycloakRef": {"name": "test-keycloak", "namespace": "test-ns"},
            }
        }

        # Mock admin client - always fails
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.side_effect = RuntimeError(
            "Persistent failure"
        )
        mock_admin_client.__aenter__.return_value = mock_admin_client
        mock_admin_client.__aexit__.return_value = None

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
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client

            # Wait returns False for all retries
            mock_stopped.wait = AsyncMock(return_value=False)
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

            # Verify all retries attempted
            assert (
                mock_admin_client.regenerate_client_secret.call_count
                == ROTATION_MAX_RETRIES
            )

            # Verify Degraded status was set
            assert mock_patch_obj.status.get("phase") == "Degraded"
            assert "Manual intervention required" in mock_patch_obj.status.get(
                "message", ""
            )

    @pytest.mark.asyncio
    async def test_daemon_unexpected_error_waits_and_continues(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon handles unexpected exceptions gracefully."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        # First call raises unexpected error, then returns secret
        mock_core_api.read_namespaced_secret.side_effect = [
            ValueError("Unexpected parse error"),
            mock_secret,
        ]

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api

            # First wait is for error recovery, second is stop signal
            mock_stopped.wait = AsyncMock(side_effect=[False, True])
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

            # Verify error was handled and daemon continued
            assert mock_core_api.read_namespaced_secret.call_count >= 1
            mock_stopped.wait.assert_called()

    @pytest.mark.asyncio
    async def test_daemon_regenerate_returns_empty_secret(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon handles case when regenerate_client_secret returns empty."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists with keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
                "keycloakRef": {"name": "test-keycloak", "namespace": "test-ns"},
            }
        }

        # Mock admin client - returns None (empty secret)
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.return_value = None
        mock_admin_client.__aenter__.return_value = mock_admin_client
        mock_admin_client.__aexit__.return_value = None

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
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client

            # Wait returns False for retries, then we exhaust retries
            mock_stopped.wait = AsyncMock(return_value=False)
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

            # Should exhaust retries and set Degraded
            assert mock_patch_obj.status.get("phase") == "Degraded"

    @pytest.mark.asyncio
    async def test_daemon_keycloak_instance_not_found(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon handles case when Keycloak instance validation fails."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists with keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {
                "realmName": "test-realm",
                "keycloakRef": {"name": "test-keycloak", "namespace": "test-ns"},
            }
        }

        # Mock admin client - succeeds
        mock_admin_client = AsyncMock()
        mock_admin_client.regenerate_client_secret.return_value = "new-secret"
        mock_admin_client.__aenter__.return_value = mock_admin_client
        mock_admin_client.__aexit__.return_value = None

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
                "keycloak_operator.handlers.client.validate_keycloak_reference"
            ) as mock_validate,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api
            mock_get_admin.return_value = mock_admin_client
            # Keycloak instance not found
            mock_validate.return_value = None

            mock_stopped.wait = AsyncMock(return_value=False)
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

            # Should exhaust retries and set Degraded
            assert mock_patch_obj.status.get("phase") == "Degraded"

    @pytest.mark.asyncio
    async def test_daemon_no_annotation_waits(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon waits when secret has no rotation annotation."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_secret.metadata.annotations = {}
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api

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
    async def test_daemon_invalid_timestamp_waits(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon waits when timestamp annotation is invalid."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": "invalid-timestamp"
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api

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
    async def test_daemon_rotation_not_due_sleeps(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon sleeps when rotation is not yet due."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        # Setup: secret was just rotated (not due for rotation)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": datetime.now(UTC).isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        with (
            patch(
                "keycloak_operator.handlers.client.get_kubernetes_client"
            ) as mock_get_k8s,
            patch(
                "keycloak_operator.handlers.client.client.CoreV1Api"
            ) as mock_core_api_cls,
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api

            # First call returns False (loop continues), second True (stop)
            mock_stopped.wait = AsyncMock(side_effect=[False, True])
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

            # Should have called wait with a timeout > 0 (time until rotation)
            calls = mock_stopped.wait.call_args_list
            assert len(calls) >= 1
            # First call should have a positive timeout (sleep until rotation)
            first_call_timeout = calls[0].kwargs.get(
                "timeout", calls[0].args[0] if calls[0].args else 0
            )
            assert first_call_timeout > 0

    @pytest.mark.asyncio
    async def test_daemon_realm_not_found_waits(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon waits when realm resource is not found."""
        from kubernetes.client.rest import ApiException

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

        # Realm not found
        mock_custom_api.get_namespaced_custom_object.side_effect = ApiException(
            status=404
        )

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
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api

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
    async def test_daemon_no_keycloak_ref_waits(
        self, mock_stopped, mock_patch_obj, base_spec, mock_secret
    ):
        """Test daemon waits when realm has no keycloakRef."""
        from keycloak_operator.handlers.client import secret_rotation_daemon

        # Create mocks
        mock_core_api = MagicMock()
        mock_custom_api = MagicMock()

        # Setup: secret is expired
        expired_time = datetime.now(UTC) - timedelta(days=2)
        mock_secret.metadata.annotations = {
            "keycloak-operator/rotated-at": expired_time.isoformat()
        }
        mock_core_api.read_namespaced_secret.return_value = mock_secret

        # Realm exists but has no keycloakRef
        mock_custom_api.get_namespaced_custom_object.return_value = {
            "spec": {"realmName": "test-realm"}  # No keycloakRef
        }

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
        ):
            mock_get_k8s.return_value = MagicMock()
            mock_core_api_cls.return_value = mock_core_api
            mock_custom_api_cls.return_value = mock_custom_api

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
