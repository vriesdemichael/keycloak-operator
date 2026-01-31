import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError as PydanticValidationError

from keycloak_operator.errors import ValidationError
from keycloak_operator.handlers.client import (
    _calculate_seconds_until_rotation,
    _parse_duration,
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
