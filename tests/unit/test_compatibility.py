"""
Unit tests for the Keycloak version compatibility layer.

Tests cover:
- Adapter factory and version selection
- URL path generation for different versions
- Version validation and warnings
- Model conversions between versions
"""

import pytest

from keycloak_operator.compatibility import (
    ValidationResult,
    VersionWarning,
    WarningLevel,
    get_adapter_for_version,
)
from keycloak_operator.compatibility.adapters import (
    V24Adapter,
    V25Adapter,
    V26Adapter,
)


class TestAdapterFactory:
    """Tests for the adapter factory function."""

    def test_get_adapter_for_version_v26(self):
        """Test that V26 adapter is returned for 26.x versions."""
        adapter = get_adapter_for_version("26.5.2")
        assert isinstance(adapter, V26Adapter)
        assert adapter.version == "26.5.2"
        assert adapter.version_tuple == (26, 5, 2)

    def test_get_adapter_for_version_v25(self):
        """Test that V25 adapter is returned for 25.x versions."""
        adapter = get_adapter_for_version("25.0.6")
        assert isinstance(adapter, V25Adapter)
        assert adapter.version == "25.0.6"

    def test_get_adapter_for_version_v24(self):
        """Test that V24 adapter is returned for 24.x versions."""
        adapter = get_adapter_for_version("24.0.5")
        assert isinstance(adapter, V24Adapter)
        assert adapter.version == "24.0.5"

    def test_get_adapter_unsupported_version(self):
        """Test that unsupported versions raise ValueError."""
        with pytest.raises(ValueError, match="not supported"):
            get_adapter_for_version("23.0.0")

        with pytest.raises(ValueError, match="not supported"):
            get_adapter_for_version("100.0.0")

    def test_get_adapter_invalid_version_string(self):
        """Test that invalid version strings raise ValueError."""
        with pytest.raises(ValueError, match="Invalid version string"):
            get_adapter_for_version("invalid")


class TestVersionParsing:
    """Tests for version parsing and comparison."""

    def test_version_parsing(self):
        """Test that versions are parsed correctly."""
        adapter = get_adapter_for_version("26.3.1")
        assert adapter.major_version == 26
        assert adapter.minor_version == 3
        assert adapter.patch_version == 1

    def test_version_at_least(self):
        """Test version_at_least comparisons."""
        adapter = get_adapter_for_version("26.3.0")

        assert adapter.version_at_least(26, 3, 0)
        assert adapter.version_at_least(26, 2, 0)
        assert adapter.version_at_least(26, 0, 0)
        assert adapter.version_at_least(25, 0, 0)

        assert not adapter.version_at_least(26, 4, 0)
        assert not adapter.version_at_least(27, 0, 0)

    def test_version_less_than(self):
        """Test version_less_than comparisons."""
        adapter = get_adapter_for_version("26.3.0")

        assert adapter.version_less_than(26, 4, 0)
        assert adapter.version_less_than(27, 0, 0)

        assert not adapter.version_less_than(26, 3, 0)
        assert not adapter.version_less_than(26, 2, 0)
        assert not adapter.version_less_than(25, 0, 0)


class TestPathResolution:
    """Tests for URL path generation."""

    def test_path_resolution_v26(self):
        """Test URL generation for V26."""
        adapter = get_adapter_for_version("26.5.2")

        assert adapter.get_realms_path() == "realms"
        assert adapter.get_realm_path("my-realm") == "realms/my-realm"
        assert adapter.get_clients_path("my-realm") == "realms/my-realm/clients"
        assert (
            adapter.get_client_path("my-realm", "123") == "realms/my-realm/clients/123"
        )
        assert (
            adapter.get_client_secret_path("my-realm", "123")
            == "realms/my-realm/clients/123/client-secret"
        )
        assert (
            adapter.get_realm_role_path("my-realm", "admin")
            == "realms/my-realm/roles/admin"
        )
        assert (
            adapter.get_identity_providers_path("my-realm")
            == "realms/my-realm/identity-provider/instances"
        )
        assert (
            adapter.get_authentication_flows_path("my-realm")
            == "realms/my-realm/authentication/flows"
        )
        assert (
            adapter.get_client_role_mapping_path("my-realm", "user-1", "client-uuid")
            == "realms/my-realm/users/user-1/role-mappings/clients/client-uuid"
        )

    def test_path_resolution_v25(self):
        """Test URL generation for V25 (should be same as V26)."""
        adapter = get_adapter_for_version("25.0.6")

        assert adapter.get_realms_path() == "realms"
        assert adapter.get_realm_path("my-realm") == "realms/my-realm"

    def test_path_resolution_v24(self):
        """Test URL generation for V24 (should be same as V26)."""
        adapter = get_adapter_for_version("24.0.5")

        assert adapter.get_realms_path() == "realms"
        assert adapter.get_realm_path("my-realm") == "realms/my-realm"


class TestVersionValidation:
    """Tests for version-specific validation."""

    def test_oauth2_device_fields_blocked_on_26_4(self):
        """Test that OAuth2 device fields are rejected on 26.4.0+."""
        adapter = get_adapter_for_version("26.4.0")

        spec = {
            "realm": "test",
            "oAuth2DeviceCodeLifespan": 600,
            "oAuth2DevicePollingInterval": 5,
        }

        result = adapter.validate_for_version(spec)

        assert not result.valid
        assert len(result.errors) == 1
        assert result.errors[0].code == "OAuth2DeviceFieldsUnsupported"
        assert "removed in 26.4.0" in result.errors[0].message

    def test_oauth2_device_fields_allowed_on_26_3(self):
        """Test that OAuth2 device fields are allowed on 26.3.x."""
        adapter = get_adapter_for_version("26.3.0")

        spec = {
            "realm": "test",
            "oAuth2DeviceCodeLifespan": 600,
        }

        result = adapter.validate_for_version(spec)

        # Should be valid (field not removed until 26.4.0)
        assert result.valid

    def test_organizations_blocked_on_v25(self):
        """Test that organizations feature is rejected on V25."""
        adapter = get_adapter_for_version("25.0.6")

        spec = {
            "realm": "test",
            "organizationsEnabled": True,
        }

        result = adapter.validate_for_version(spec)

        assert not result.valid
        assert len(result.errors) == 1
        assert result.errors[0].code == "OrganizationsNotSupported"
        assert "26.0.0" in result.errors[0].message

    def test_client_policy_warning_on_old_version(self):
        """Test that client policies get a warning on versions < 26.3.0."""
        adapter = get_adapter_for_version("26.2.0")

        spec = {
            "realm": "test",
            "clientPolicies": {
                "policies": [
                    {
                        "name": "test-policy",
                        "conditions": [{"condition": "test"}],
                    }
                ]
            },
        }

        result = adapter.validate_for_version(spec)

        # Should be valid (just a warning, not an error)
        assert result.valid
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "ClientPolicyConfigConverted"


class TestVersionWarning:
    """Tests for VersionWarning class."""

    def test_warning_to_condition(self):
        """Test converting warning to Kubernetes condition."""
        warning = VersionWarning(
            level=WarningLevel.WARNING,
            code="TestWarning",
            field_path="spec.field",
            message="This is a test warning",
            keycloak_version="26.2.0",
            min_version="26.3.0",
        )

        condition = warning.to_condition()

        assert condition["type"] == "VersionCompatibility/TestWarning"
        assert condition["status"] == "True"
        assert condition["reason"] == "TestWarning"
        assert condition["message"] == "This is a test warning"
        assert "lastTransitionTime" in condition

    def test_error_to_condition(self):
        """Test converting error to Kubernetes condition."""
        error = VersionWarning(
            level=WarningLevel.ERROR,
            code="TestError",
            field_path="spec.field",
            message="This is a test error",
            keycloak_version="26.4.0",
        )

        condition = error.to_condition()

        assert condition["type"] == "VersionCompatibility/TestError"
        assert condition["status"] == "False"  # False for errors
        assert condition["reason"] == "TestError"


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_valid_result(self):
        """Test a valid result with no issues."""
        result = ValidationResult(valid=True)

        assert result.valid
        assert not result.has_warnings
        assert not result.has_errors
        assert result.error_summary == ""

    def test_result_with_warnings(self):
        """Test result with warnings."""
        warning = VersionWarning(
            level=WarningLevel.WARNING,
            code="TestWarning",
            field_path="spec.field",
            message="Test warning",
            keycloak_version="26.2.0",
        )
        result = ValidationResult(valid=True, warnings=[warning])

        assert result.valid
        assert result.has_warnings
        assert not result.has_errors

    def test_result_with_errors(self):
        """Test result with errors."""
        error = VersionWarning(
            level=WarningLevel.ERROR,
            code="TestError",
            field_path="spec.field",
            message="Test error",
            keycloak_version="26.4.0",
        )
        result = ValidationResult(valid=False, errors=[error])

        assert not result.valid
        assert not result.has_warnings
        assert result.has_errors
        assert result.error_summary == "Test error"


class TestClientPolicyConversion:
    """Tests for ClientPolicy configuration type conversions."""

    def test_outbound_conversion_to_list_for_old_version(self):
        """Test that dict configuration is converted to list for <26.3.0."""
        adapter = get_adapter_for_version("26.2.0")

        data = {
            "name": "test-condition",
            "configuration": {"key1": "value1", "key2": ["item1", "item2"]},
        }

        result = adapter._apply_outbound_conversions(
            data, "ClientPolicyConditionRepresentation"
        )

        # Configuration should be converted to list
        assert isinstance(result["configuration"], list)

    def test_inbound_conversion_to_dict_for_old_version(self):
        """Test that list configuration is converted to dict for <26.3.0."""
        adapter = get_adapter_for_version("26.2.0")

        data = {
            "name": "test-condition",
            "configuration": [{"key1": "value1"}, {"key2": "value2"}],
        }

        result = adapter._apply_inbound_conversions(
            data, "ClientPolicyConditionRepresentation"
        )

        # Configuration should be converted to dict
        assert isinstance(result["configuration"], dict)
        assert result["configuration"]["key1"] == "value1"
        assert result["configuration"]["key2"] == "value2"

    def test_no_conversion_for_new_version(self):
        """Test that no conversion happens for >= 26.3.0."""
        adapter = get_adapter_for_version("26.3.0")

        data = {
            "name": "test-condition",
            "configuration": {"key1": "value1"},
        }

        result = adapter._apply_outbound_conversions(
            data, "ClientPolicyConditionRepresentation"
        )

        # Configuration should remain a dict
        assert isinstance(result["configuration"], dict)
        assert result["configuration"]["key1"] == "value1"


class TestWarningCollection:
    """Tests for warning/error collection in adapters."""

    def test_warnings_are_collected(self):
        """Test that warnings are collected and can be retrieved."""
        adapter = get_adapter_for_version("26.2.0")

        # Validate spec with client policies to trigger warning
        spec = {
            "realm": "test",
            "clientPolicies": {
                "policies": [{"name": "test"}],
            },
        }

        adapter.validate_for_version(spec)

        assert len(adapter.warnings) == 1
        assert adapter.warnings[0].code == "ClientPolicyConfigConverted"

    def test_get_status_conditions(self):
        """Test that conditions can be retrieved for CR status."""
        adapter = get_adapter_for_version("26.2.0")

        # Validate spec to trigger warning
        spec = {
            "realm": "test",
            "clientPolicies": {
                "policies": [{"name": "test"}],
            },
        }

        adapter.validate_for_version(spec)

        conditions = adapter.get_status_conditions()

        assert len(conditions) == 1
        assert (
            conditions[0]["type"] == "VersionCompatibility/ClientPolicyConfigConverted"
        )
        assert conditions[0]["status"] == "True"

    def test_warnings_cleared_between_validations(self):
        """Test that warnings are cleared for each validation."""
        adapter = get_adapter_for_version("26.2.0")

        # First validation
        spec1 = {
            "realm": "test",
            "clientPolicies": {"policies": [{"name": "test"}]},
        }
        adapter.validate_for_version(spec1)
        assert len(adapter.warnings) == 1

        # Second validation - warnings should be cleared first
        spec2 = {"realm": "test"}
        adapter.validate_for_version(spec2)
        assert len(adapter.warnings) == 0
