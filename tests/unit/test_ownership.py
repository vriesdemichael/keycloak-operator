"""
Unit tests for ownership tracking utilities.
"""

from datetime import UTC, datetime, timedelta

import pytest

from keycloak_operator.utils import ownership
from keycloak_operator.utils.ownership import (
    ATTR_CR_NAME,
    ATTR_CR_NAMESPACE,
    ATTR_CREATED_AT,
    ATTR_MANAGED_BY,
    ATTR_OPERATOR_INSTANCE,
    MANAGED_BY_VALUE,
    create_ownership_attributes,
    get_cr_reference,
    get_operator_instance_id,
    get_resource_age_hours,
    is_managed_by_operator,
    is_owned_by_this_operator,
)


@pytest.fixture(autouse=True)
def clear_instance_id_cache():
    """Clear the operator instance ID cache before each test."""
    ownership._operator_instance_id_cache = None
    yield
    ownership._operator_instance_id_cache = None


class TestGetOperatorInstanceId:
    """Test operator instance ID retrieval."""

    def test_get_operator_instance_id_success(self):
        """Test successful retrieval of operator instance ID."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "test-operator-production"
        ):
            assert get_operator_instance_id() == "test-operator-production"

    def test_get_operator_instance_id_missing(self):
        """Test error when OPERATOR_INSTANCE_ID is not set."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(settings_module.settings, "operator_instance_id", ""):
            with pytest.raises(RuntimeError, match="OPERATOR_INSTANCE_ID"):
                get_operator_instance_id()


class TestCreateOwnershipAttributes:
    """Test creation of ownership attributes."""

    def test_create_ownership_attributes(self):
        """Test that ownership attributes are created correctly."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "test-operator"
        ):
            attrs = create_ownership_attributes("my-namespace", "my-resource")

            assert attrs[ATTR_MANAGED_BY] == MANAGED_BY_VALUE
            assert attrs[ATTR_OPERATOR_INSTANCE] == "test-operator"
            assert attrs[ATTR_CR_NAMESPACE] == "my-namespace"
            assert attrs[ATTR_CR_NAME] == "my-resource"
            assert ATTR_CREATED_AT in attrs

            # Verify timestamp is recent (within 1 second)
            created_at = datetime.fromisoformat(attrs[ATTR_CREATED_AT])
            age = (datetime.now(UTC) - created_at).total_seconds()
            assert age < 1.0


class TestIsOwnedByThisOperator:
    """Test ownership checking."""

    def test_is_owned_by_this_operator_true(self):
        """Test when resource is owned by this operator."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "my-operator"
        ):
            attributes = {
                ATTR_MANAGED_BY: MANAGED_BY_VALUE,
                ATTR_OPERATOR_INSTANCE: "my-operator",
            }

            assert is_owned_by_this_operator(attributes) is True

    def test_is_owned_by_different_operator(self):
        """Test when resource is owned by a different operator."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "my-operator"
        ):
            attributes = {
                ATTR_MANAGED_BY: MANAGED_BY_VALUE,
                ATTR_OPERATOR_INSTANCE: "other-operator",
            }

            assert is_owned_by_this_operator(attributes) is False

    def test_is_owned_no_attributes(self):
        """Test when resource has no attributes."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "my-operator"
        ):
            assert is_owned_by_this_operator(None) is False
            assert is_owned_by_this_operator({}) is False

    def test_is_owned_list_value(self):
        """Test handling of list values (Keycloak sometimes uses lists)."""
        from unittest.mock import patch

        from keycloak_operator import settings as settings_module

        with patch.object(
            settings_module.settings, "operator_instance_id", "my-operator"
        ):
            # Keycloak may store attributes as lists
            attributes = {
                ATTR_MANAGED_BY: [MANAGED_BY_VALUE],
                ATTR_OPERATOR_INSTANCE: ["my-operator"],
            }

            assert is_owned_by_this_operator(attributes) is True


class TestIsManagedByOperator:
    """Test managed-by checking."""

    def test_is_managed_by_operator_true(self):
        """Test when resource is managed by any operator."""
        attributes = {
            ATTR_MANAGED_BY: MANAGED_BY_VALUE,
            ATTR_OPERATOR_INSTANCE: "some-operator",
        }

        assert is_managed_by_operator(attributes) is True

    def test_is_managed_by_operator_false(self):
        """Test when resource is not managed."""
        attributes = {
            "some-other-key": "value",
        }

        assert is_managed_by_operator(attributes) is False

    def test_is_managed_no_attributes(self):
        """Test when resource has no attributes."""
        assert is_managed_by_operator(None) is False
        assert is_managed_by_operator({}) is False

    def test_is_managed_list_value(self):
        """Test handling of list values."""
        attributes = {
            ATTR_MANAGED_BY: [MANAGED_BY_VALUE],
        }

        assert is_managed_by_operator(attributes) is True


class TestGetCrReference:
    """Test CR reference extraction."""

    def test_get_cr_reference_success(self):
        """Test successful CR reference extraction."""
        attributes = {
            ATTR_CR_NAMESPACE: "my-namespace",
            ATTR_CR_NAME: "my-resource",
        }

        result = get_cr_reference(attributes)
        assert result is not None
        namespace, name = result
        assert namespace == "my-namespace"
        assert name == "my-resource"

    def test_get_cr_reference_list_values(self):
        """Test CR reference extraction with list values."""
        attributes = {
            ATTR_CR_NAMESPACE: ["my-namespace"],
            ATTR_CR_NAME: ["my-resource"],
        }

        result = get_cr_reference(attributes)
        assert result is not None
        namespace, name = result
        assert namespace == "my-namespace"
        assert name == "my-resource"

    def test_get_cr_reference_missing(self):
        """Test when CR reference is missing."""
        assert get_cr_reference(None) is None
        assert get_cr_reference({}) is None

        # Missing namespace
        assert get_cr_reference({ATTR_CR_NAME: "name"}) is None

        # Missing name
        assert get_cr_reference({ATTR_CR_NAMESPACE: "namespace"}) is None


class TestGetResourceAgeHours:
    """Test resource age calculation."""

    def test_get_resource_age_hours_recent(self):
        """Test age calculation for recent resource."""
        # Created 2 hours ago
        created_at = datetime.now(UTC) - timedelta(hours=2)
        attributes = {
            ATTR_CREATED_AT: created_at.isoformat(),
        }

        age = get_resource_age_hours(attributes)
        assert age is not None
        assert 1.9 < age < 2.1  # Allow small margin

    def test_get_resource_age_hours_old(self):
        """Test age calculation for old resource."""
        # Created 48 hours ago
        created_at = datetime.now(UTC) - timedelta(hours=48)
        attributes = {
            ATTR_CREATED_AT: created_at.isoformat(),
        }

        age = get_resource_age_hours(attributes)
        assert age is not None
        assert 47.9 < age < 48.1

    def test_get_resource_age_hours_list_value(self):
        """Test age calculation with list value."""
        created_at = datetime.now(UTC) - timedelta(hours=1)
        attributes = {
            ATTR_CREATED_AT: [created_at.isoformat()],
        }

        age = get_resource_age_hours(attributes)
        assert age is not None
        assert 0.9 < age < 1.1

    def test_get_resource_age_hours_missing(self):
        """Test when created_at is missing."""
        assert get_resource_age_hours(None) is None
        assert get_resource_age_hours({}) is None

    def test_get_resource_age_hours_invalid_format(self):
        """Test with invalid timestamp format."""
        attributes = {
            ATTR_CREATED_AT: "invalid-timestamp",
        }

        age = get_resource_age_hours(attributes)
        assert age is None

    def test_get_resource_age_hours_with_z_suffix(self):
        """Test with Z suffix (UTC indicator)."""
        created_at = datetime.now(UTC) - timedelta(hours=3)
        # Replace +00:00 with Z
        timestamp = created_at.isoformat().replace("+00:00", "Z")
        attributes = {
            ATTR_CREATED_AT: timestamp,
        }

        age = get_resource_age_hours(attributes)
        assert age is not None
        assert 2.9 < age < 3.1
