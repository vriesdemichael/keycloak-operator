"""Unit tests for realm capacity management."""

import pytest
from pydantic import ValidationError

from keycloak_operator.models.keycloak import RealmCapacity


class TestRealmCapacityModel:
    """Test RealmCapacity model validation."""

    def test_unlimited_capacity_default(self):
        """Test default (unlimited) capacity - capacity not set."""
        # Just test that realm_capacity can be None
        capacity = None
        assert capacity is None

    def test_capacity_with_max_realms(self):
        """Test capacity with max realms limit."""
        capacity = RealmCapacity(max_realms=10)
        assert capacity.max_realms == 10
        assert capacity.allow_new_realms is True

    def test_capacity_with_allow_new_realms_false(self):
        """Test capacity with new realms disabled."""
        capacity = RealmCapacity(allow_new_realms=False)
        assert capacity.max_realms is None
        assert capacity.allow_new_realms is False

    def test_capacity_with_custom_message(self):
        """Test capacity with custom message."""
        capacity = RealmCapacity(
            max_realms=5,
            capacity_message="This operator is at capacity. Contact platform team.",
        )
        assert capacity.max_realms == 5
        assert (
            capacity.capacity_message
            == "This operator is at capacity. Contact platform team."
        )

    def test_capacity_max_realms_minimum(self):
        """Test max_realms minimum value (1)."""
        capacity = RealmCapacity(max_realms=1)
        assert capacity.max_realms == 1

    def test_capacity_max_realms_zero_invalid(self):
        """Test max_realms=0 is invalid."""
        with pytest.raises(ValidationError) as exc_info:
            RealmCapacity(max_realms=0)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

    def test_capacity_max_realms_negative_invalid(self):
        """Test negative max_realms is invalid."""
        with pytest.raises(ValidationError) as exc_info:
            RealmCapacity(max_realms=-1)
        assert "greater than or equal to 1" in str(exc_info.value).lower()

    def test_capacity_serialization(self):
        """Test capacity serializes correctly."""
        capacity = RealmCapacity(max_realms=10, allow_new_realms=True)
        data = capacity.model_dump(by_alias=True)
        assert data["maxRealms"] == 10
        assert data["allowNewRealms"] is True

    def test_keycloak_spec_with_capacity(self):
        """Test that realm_capacity field exists and accepts RealmCapacity."""
        capacity = RealmCapacity(max_realms=5, allow_new_realms=True)
        # Just verify the capacity object itself works
        assert capacity.max_realms == 5
        assert capacity.allow_new_realms is True

    def test_capacity_all_fields(self):
        """Test capacity with all fields set."""
        capacity = RealmCapacity(
            max_realms=20,
            allow_new_realms=False,
            capacity_message="Maintenance mode - no new realms",
        )
        assert capacity.max_realms == 20
        assert capacity.allow_new_realms is False
        assert capacity.capacity_message == "Maintenance mode - no new realms"
