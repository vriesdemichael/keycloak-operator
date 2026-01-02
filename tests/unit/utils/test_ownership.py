"""
Unit tests for ownership tracking utilities.

These tests verify ownership attribute creation, validation, and
operator instance identification.
"""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from keycloak_operator.utils import ownership


class TestGetOperatorInstanceId:
    """Test cases for operator instance ID retrieval."""

    def test_get_instance_id_from_settings(self):
        """Test retrieving operator instance ID from settings."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"

            # Clear cache
            ownership._operator_instance_id_cache = None

            instance_id = ownership.get_operator_instance_id()

            assert instance_id == "keycloak-operator-prod"

    def test_get_instance_id_cached(self):
        """Test that instance ID is cached after first retrieval."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"

            # Clear cache and get first time
            ownership._operator_instance_id_cache = None
            first_call = ownership.get_operator_instance_id()

            # Change settings
            mock_settings.operator_instance_id = "different-operator"

            # Second call should return cached value
            second_call = ownership.get_operator_instance_id()

            assert first_call == second_call == "keycloak-operator-prod"

    def test_get_instance_id_not_configured_raises_error(self):
        """Test error when operator instance ID is not configured."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = None

            # Clear cache
            ownership._operator_instance_id_cache = None

            with pytest.raises(RuntimeError, match="OPERATOR_INSTANCE_ID is not set"):
                ownership.get_operator_instance_id()


class TestCreateOwnershipAttributes:
    """Test cases for ownership attribute creation."""

    def test_create_attributes_basic(self):
        """Test creating ownership attributes with basic info."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"
            ownership._operator_instance_id_cache = None

            attrs = ownership.create_ownership_attributes("my-namespace", "my-realm")

            assert attrs[ownership.ATTR_MANAGED_BY] == ownership.MANAGED_BY_VALUE
            assert attrs[ownership.ATTR_OPERATOR_INSTANCE] == "keycloak-operator-prod"
            assert attrs[ownership.ATTR_CR_NAMESPACE] == "my-namespace"
            assert attrs[ownership.ATTR_CR_NAME] == "my-realm"
            assert ownership.ATTR_CREATED_AT in attrs

            # Verify timestamp format
            datetime.fromisoformat(attrs[ownership.ATTR_CREATED_AT])

    def test_create_attributes_timestamp_format(self):
        """Test that created_at timestamp is in ISO format."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "test-operator"
            ownership._operator_instance_id_cache = None

            before = datetime.now(UTC)
            attrs = ownership.create_ownership_attributes("ns", "name")
            after = datetime.now(UTC)

            created_at = datetime.fromisoformat(attrs[ownership.ATTR_CREATED_AT])

            # Verify timestamp is between before and after
            assert before <= created_at <= after

    def test_create_attributes_different_cr_info(self):
        """Test creating attributes for different CRs."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "test-operator"
            ownership._operator_instance_id_cache = None

            attrs1 = ownership.create_ownership_attributes("namespace-1", "resource-1")
            attrs2 = ownership.create_ownership_attributes("namespace-2", "resource-2")

            assert attrs1[ownership.ATTR_CR_NAMESPACE] == "namespace-1"
            assert attrs1[ownership.ATTR_CR_NAME] == "resource-1"
            assert attrs2[ownership.ATTR_CR_NAMESPACE] == "namespace-2"
            assert attrs2[ownership.ATTR_CR_NAME] == "resource-2"


class TestIsOwnedByThisOperator:
    """Test cases for ownership verification."""

    def test_owned_by_this_operator(self):
        """Test detecting resource owned by this operator instance."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"
            ownership._operator_instance_id_cache = None

            attributes = {
                ownership.ATTR_MANAGED_BY: ownership.MANAGED_BY_VALUE,
                ownership.ATTR_OPERATOR_INSTANCE: "keycloak-operator-prod",
                ownership.ATTR_CR_NAMESPACE: "default",
                ownership.ATTR_CR_NAME: "my-realm",
            }

            assert ownership.is_owned_by_this_operator(attributes) is True

    def test_owned_by_different_operator(self):
        """Test detecting resource owned by different operator instance."""
        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"
            ownership._operator_instance_id_cache = None

            attributes = {
                ownership.ATTR_MANAGED_BY: ownership.MANAGED_BY_VALUE,
                ownership.ATTR_OPERATOR_INSTANCE: "keycloak-operator-staging",
                ownership.ATTR_CR_NAMESPACE: "default",
                ownership.ATTR_CR_NAME: "my-realm",
            }

            assert ownership.is_owned_by_this_operator(attributes) is False

    def test_not_managed_by_operator(self):
        """Test resource not managed by any operator."""
        attributes = {"some-other-key": "some-value"}

        assert ownership.is_owned_by_this_operator(attributes) is False

    def test_attributes_none(self):
        """Test handling of None attributes."""
        assert ownership.is_owned_by_this_operator(None) is False

    def test_attributes_empty(self):
        """Test handling of empty attributes."""
        assert ownership.is_owned_by_this_operator({}) is False

    def test_managed_by_operator_missing_instance_id(self):
        """Test resource managed by operator but missing instance ID."""
        attributes = {
            ownership.ATTR_MANAGED_BY: ownership.MANAGED_BY_VALUE,
            # Missing ATTR_OPERATOR_INSTANCE
        }

        assert ownership.is_owned_by_this_operator(attributes) is False

    def test_custom_operator_instance_id(self):
        """Test checking ownership against custom operator instance ID."""
        attributes = {
            ownership.ATTR_MANAGED_BY: ownership.MANAGED_BY_VALUE,
            ownership.ATTR_OPERATOR_INSTANCE: "custom-operator-id",
        }

        # Should match when we provide the same ID
        assert (
            ownership.is_owned_by_this_operator(
                attributes, operator_instance_id="custom-operator-id"
            )
            is True
        )

        # Should not match different ID
        assert (
            ownership.is_owned_by_this_operator(
                attributes, operator_instance_id="different-operator-id"
            )
            is False
        )

    def test_attributes_with_list_values(self):
        """Test handling attributes with list values (Keycloak format)."""
        attributes = {
            ownership.ATTR_MANAGED_BY: [ownership.MANAGED_BY_VALUE],
            ownership.ATTR_OPERATOR_INSTANCE: ["keycloak-operator-prod"],
        }

        with patch("keycloak_operator.utils.ownership.settings") as mock_settings:
            mock_settings.operator_instance_id = "keycloak-operator-prod"
            ownership._operator_instance_id_cache = None

            assert ownership.is_owned_by_this_operator(attributes) is True


class TestIsManagedByOperator:
    """Test cases for general operator management check."""

    def test_managed_by_operator(self):
        """Test detecting resource managed by operator (any instance)."""
        attributes = {
            ownership.ATTR_MANAGED_BY: ownership.MANAGED_BY_VALUE,
        }

        assert ownership.is_managed_by_operator(attributes) is True

    def test_not_managed_by_operator(self):
        """Test resource not managed by operator."""
        attributes = {
            ownership.ATTR_MANAGED_BY: "some-other-system",
        }

        assert ownership.is_managed_by_operator(attributes) is False

    def test_managed_by_operator_none_attributes(self):
        """Test handling of None attributes."""
        assert ownership.is_managed_by_operator(None) is False

    def test_managed_by_operator_empty_attributes(self):
        """Test handling of empty attributes."""
        assert ownership.is_managed_by_operator({}) is False

    def test_managed_by_operator_list_value(self):
        """Test handling managed-by attribute with list value."""
        attributes = {
            ownership.ATTR_MANAGED_BY: [ownership.MANAGED_BY_VALUE],
        }

        assert ownership.is_managed_by_operator(attributes) is True


class TestGetCrReference:
    """Test cases for extracting CR reference from attributes."""

    def test_get_cr_reference_valid(self):
        """Test extracting valid CR reference."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
            ownership.ATTR_CR_NAME: "my-realm",
        }

        namespace, name = ownership.get_cr_reference(attributes)  # type: ignore[misc]

        assert namespace == "production"
        assert name == "my-realm"

    def test_get_cr_reference_missing_namespace(self):
        """Test handling missing namespace in attributes."""
        attributes = {
            ownership.ATTR_CR_NAME: "my-realm",
        }

        result = ownership.get_cr_reference(attributes)

        # Function returns None when required fields are missing
        assert result is None

    def test_get_cr_reference_missing_name(self):
        """Test handling missing name in attributes."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
        }

        result = ownership.get_cr_reference(attributes)

        # Function returns None when required fields are missing
        assert result is None

    def test_get_cr_reference_none_attributes(self):
        """Test handling None attributes."""
        result = ownership.get_cr_reference(None)

        assert result is None

    def test_get_cr_reference_empty_attributes(self):
        """Test handling empty attributes."""
        result = ownership.get_cr_reference({})

        assert result is None

    def test_get_cr_reference_list_values(self):
        """Test extracting CR reference from list values."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: ["production"],
            ownership.ATTR_CR_NAME: ["my-realm"],
        }

        namespace, name = ownership.get_cr_reference(attributes)  # type: ignore[misc]

        assert namespace == "production"
        assert name == "my-realm"


class TestGetResourceAgeHours:
    """Test cases for calculating resource age."""

    def test_get_resource_age_hours(self):
        """Test calculating resource age from created_at attribute."""
        # Create timestamp 5 hours ago
        five_hours_ago = datetime.now(UTC).timestamp() - (5 * 3600)
        created_at = datetime.fromtimestamp(five_hours_ago, UTC).isoformat()

        attributes = {
            ownership.ATTR_CREATED_AT: created_at,
        }

        age_hours = ownership.get_resource_age_hours(attributes)

        assert age_hours is not None
        assert 4.9 < age_hours < 5.1
        assert 4.9 < age_hours < 5.1

    def test_get_resource_age_missing_timestamp(self):
        """Test handling missing created_at attribute."""
        attributes = {}

        age_hours = ownership.get_resource_age_hours(attributes)

        assert age_hours is None

    def test_get_resource_age_invalid_timestamp(self):
        """Test handling invalid timestamp format."""
        attributes = {
            ownership.ATTR_CREATED_AT: "invalid-timestamp",
        }

        age_hours = ownership.get_resource_age_hours(attributes)

        assert age_hours is None

    def test_get_resource_age_none_attributes(self):
        """Test handling None attributes."""
        age_hours = ownership.get_resource_age_hours(None)

        assert age_hours is None

    def test_get_resource_age_just_created(self):
        """Test age calculation for recently created resource."""
        created_at = datetime.now(UTC).isoformat()

        attributes = {
            ownership.ATTR_CREATED_AT: created_at,
        }

        age_hours = ownership.get_resource_age_hours(attributes)

        # Should be close to 0
        assert age_hours is not None
        assert age_hours < 0.01  # Less than 36 seconds

    def test_get_resource_age_old_resource(self):
        """Test age calculation for old resource (30 days)."""
        thirty_days_ago = datetime.now(UTC).timestamp() - (30 * 24 * 3600)
        created_at = datetime.fromtimestamp(thirty_days_ago, UTC).isoformat()

        attributes = {
            ownership.ATTR_CREATED_AT: created_at,
        }

        age_hours = ownership.get_resource_age_hours(attributes)

        assert age_hours is not None
        assert 719 < age_hours < 721  # Approximately 30 * 24 = 720 hours


class TestIsOwnedByCr:
    """Test cases for CR ownership verification during finalizer cleanup."""

    def test_owned_by_matching_cr(self):
        """Test returns True when CR namespace and name match."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
            ownership.ATTR_CR_NAME: "my-realm-cr",
        }

        assert ownership.is_owned_by_cr(attributes, "production", "my-realm-cr") is True

    def test_not_owned_by_different_namespace(self):
        """Test returns False when namespace doesn't match."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
            ownership.ATTR_CR_NAME: "my-realm-cr",
        }

        assert ownership.is_owned_by_cr(attributes, "staging", "my-realm-cr") is False

    def test_not_owned_by_different_name(self):
        """Test returns False when name doesn't match."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
            ownership.ATTR_CR_NAME: "my-realm-cr",
        }

        assert (
            ownership.is_owned_by_cr(attributes, "production", "other-realm-cr")
            is False
        )

    def test_not_owned_by_both_different(self):
        """Test returns False when both namespace and name don't match."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
            ownership.ATTR_CR_NAME: "my-realm-cr",
        }

        assert (
            ownership.is_owned_by_cr(attributes, "staging", "other-realm-cr") is False
        )

    def test_not_owned_when_attributes_none(self):
        """Test returns False when attributes is None."""
        assert ownership.is_owned_by_cr(None, "production", "my-realm-cr") is False

    def test_not_owned_when_attributes_empty(self):
        """Test returns False when attributes is empty."""
        assert ownership.is_owned_by_cr({}, "production", "my-realm-cr") is False

    def test_not_owned_when_missing_namespace(self):
        """Test returns False when namespace attribute is missing."""
        attributes = {
            ownership.ATTR_CR_NAME: "my-realm-cr",
        }

        assert (
            ownership.is_owned_by_cr(attributes, "production", "my-realm-cr") is False
        )

    def test_not_owned_when_missing_name(self):
        """Test returns False when name attribute is missing."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: "production",
        }

        assert (
            ownership.is_owned_by_cr(attributes, "production", "my-realm-cr") is False
        )

    def test_owned_with_list_values(self):
        """Test handles Keycloak's list attribute format."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: ["production"],
            ownership.ATTR_CR_NAME: ["my-realm-cr"],
        }

        assert ownership.is_owned_by_cr(attributes, "production", "my-realm-cr") is True

    def test_not_owned_with_list_values_mismatch(self):
        """Test handles list format with mismatched values."""
        attributes = {
            ownership.ATTR_CR_NAMESPACE: ["production"],
            ownership.ATTR_CR_NAME: ["my-realm-cr"],
        }

        assert ownership.is_owned_by_cr(attributes, "staging", "my-realm-cr") is False
