"""Unit tests for KeycloakPasswordPolicy model."""

import pytest

from keycloak_operator.models.realm import (
    KeycloakPasswordPolicy,
    KeycloakRealmSpec,
)


class TestPasswordPolicyModel:
    """Tests for KeycloakPasswordPolicy Pydantic model."""

    def test_empty_policy_string(self):
        """Empty policy generates empty string."""
        policy = KeycloakPasswordPolicy()
        assert policy.to_policy_string() == ""

    def test_single_policy_length(self):
        """Single length policy generates correct string."""
        policy = KeycloakPasswordPolicy(length=8)
        assert policy.to_policy_string() == "length(8)"

    def test_single_policy_uppercase(self):
        """Single upperCase policy generates correct string."""
        policy = KeycloakPasswordPolicy(upper_case=2)
        assert policy.to_policy_string() == "upperCase(2)"

    def test_multiple_policies_and_separated(self):
        """Multiple policies are separated with ' and '."""
        policy = KeycloakPasswordPolicy(
            length=12,
            upper_case=1,
            lower_case=1,
            digits=1,
        )
        result = policy.to_policy_string()
        assert "length(12)" in result
        assert "upperCase(1)" in result
        assert "lowerCase(1)" in result
        assert "digits(1)" in result
        # Verify "and" separation
        assert " and " in result
        parts = result.split(" and ")
        assert len(parts) == 4

    def test_boolean_policy_not_username(self):
        """notUsername boolean policy generates correct string."""
        policy = KeycloakPasswordPolicy(not_username=True)
        assert policy.to_policy_string() == "notUsername"

    def test_boolean_policy_not_email(self):
        """notEmail boolean policy generates correct string."""
        policy = KeycloakPasswordPolicy(not_email=True)
        assert policy.to_policy_string() == "notEmail"

    def test_boolean_policies_false_excluded(self):
        """False boolean policies are excluded."""
        policy = KeycloakPasswordPolicy(not_username=False, not_email=False)
        assert policy.to_policy_string() == ""

    def test_hash_iterations(self):
        """hashIterations policy generates correct string."""
        policy = KeycloakPasswordPolicy(hash_iterations=210000)
        assert policy.to_policy_string() == "hashIterations(210000)"

    def test_password_history(self):
        """passwordHistory policy generates correct string."""
        policy = KeycloakPasswordPolicy(password_history=5)
        assert policy.to_policy_string() == "passwordHistory(5)"

    def test_force_expired_password_change(self):
        """forceExpiredPasswordChange policy generates correct string."""
        policy = KeycloakPasswordPolicy(force_expired_password_change=90)
        assert policy.to_policy_string() == "forceExpiredPasswordChange(90)"

    def test_max_length(self):
        """maxLength policy generates correct string."""
        policy = KeycloakPasswordPolicy(max_length=128)
        assert policy.to_policy_string() == "maxLength(128)"

    def test_regex_pattern(self):
        """regexPattern policy generates correct string."""
        policy = KeycloakPasswordPolicy(regex_pattern="^[a-zA-Z0-9]+$")
        assert policy.to_policy_string() == "regexPattern(^[a-zA-Z0-9]+$)"

    def test_all_policies_combined(self):
        """All policies combined generate complete string."""
        policy = KeycloakPasswordPolicy(
            length=12,
            upper_case=1,
            lower_case=1,
            digits=1,
            special_chars=1,
            not_username=True,
            not_email=True,
            hash_iterations=210000,
            password_history=5,
            force_expired_password_change=90,
            max_length=128,
            regex_pattern="^[a-zA-Z0-9]+$",
        )
        result = policy.to_policy_string()
        assert "length(12)" in result
        assert "upperCase(1)" in result
        assert "lowerCase(1)" in result
        assert "digits(1)" in result
        assert "specialChars(1)" in result
        assert "notUsername" in result
        assert "notEmail" in result
        assert "hashIterations(210000)" in result
        assert "passwordHistory(5)" in result
        assert "forceExpiredPasswordChange(90)" in result
        assert "maxLength(128)" in result
        assert "regexPattern(^[a-zA-Z0-9]+$)" in result

    def test_validation_length_minimum(self):
        """Length must be at least 1."""
        with pytest.raises(ValueError):
            KeycloakPasswordPolicy(length=0)

    def test_validation_max_length_minimum(self):
        """maxLength must be at least 1."""
        with pytest.raises(ValueError):
            KeycloakPasswordPolicy(max_length=0)

    def test_validation_hash_iterations_minimum(self):
        """hashIterations must be at least 1."""
        with pytest.raises(ValueError):
            KeycloakPasswordPolicy(hash_iterations=0)

    def test_validation_uppercase_allows_zero(self):
        """upperCase allows 0 (explicitly disable)."""
        policy = KeycloakPasswordPolicy(upper_case=0)
        assert "upperCase(0)" in policy.to_policy_string()

    def test_validation_password_history_allows_zero(self):
        """passwordHistory allows 0 (disable history check)."""
        policy = KeycloakPasswordPolicy(password_history=0)
        assert "passwordHistory(0)" in policy.to_policy_string()

    def test_alias_mapping_camel_case(self):
        """Aliases work for camelCase input."""
        policy = KeycloakPasswordPolicy.model_validate(
            {
                "upperCase": 2,
                "lowerCase": 2,
                "specialChars": 1,
                "notUsername": True,
                "notEmail": True,
                "hashIterations": 100000,
                "passwordHistory": 3,
                "forceExpiredPasswordChange": 30,
                "maxLength": 64,
                "regexPattern": ".*",
            }
        )
        assert policy.upper_case == 2
        assert policy.lower_case == 2
        assert policy.special_chars == 1
        assert policy.not_username is True
        assert policy.not_email is True
        assert policy.hash_iterations == 100000
        assert policy.password_history == 3
        assert policy.force_expired_password_change == 30
        assert policy.max_length == 64
        assert policy.regex_pattern == ".*"

    def test_policy_order_is_consistent(self):
        """Policy string order is consistent for same input."""
        policy = KeycloakPasswordPolicy(
            length=8,
            upper_case=1,
            digits=1,
            not_username=True,
        )
        result1 = policy.to_policy_string()
        result2 = policy.to_policy_string()
        assert result1 == result2


class TestRealmSpecWithPasswordPolicy:
    """Tests for KeycloakRealmSpec with password policy."""

    def test_to_keycloak_config_includes_policy(self):
        """to_keycloak_config() includes passwordPolicy."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
            password_policy=KeycloakPasswordPolicy(length=12, upper_case=1),
        )
        config = spec.to_keycloak_config()
        assert "passwordPolicy" in config
        assert "length(12)" in config["passwordPolicy"]
        assert "upperCase(1)" in config["passwordPolicy"]

    def test_to_keycloak_config_omits_empty_policy(self):
        """to_keycloak_config() omits passwordPolicy when empty."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
            password_policy=KeycloakPasswordPolicy(),
        )
        config = spec.to_keycloak_config()
        assert "passwordPolicy" not in config

    def test_to_keycloak_config_no_policy_field(self):
        """to_keycloak_config() omits passwordPolicy when not set."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
        )
        config = spec.to_keycloak_config()
        assert "passwordPolicy" not in config

    def test_realm_spec_password_policy_alias(self):
        """KeycloakRealmSpec accepts passwordPolicy alias."""
        spec = KeycloakRealmSpec.model_validate(
            {
                "realmName": "test-realm",
                "operatorRef": {"namespace": "keycloak"},
                "passwordPolicy": {
                    "length": 10,
                    "notUsername": True,
                },
            }
        )
        assert spec.password_policy is not None
        assert spec.password_policy.length == 10
        assert spec.password_policy.not_username is True

    def test_comprehensive_policy_in_realm_config(self):
        """Comprehensive password policy is correctly included in realm config."""
        spec = KeycloakRealmSpec(
            realm_name="secure-realm",
            operator_ref={"namespace": "keycloak"},
            password_policy=KeycloakPasswordPolicy(
                length=12,
                upper_case=1,
                lower_case=1,
                digits=1,
                special_chars=1,
                not_username=True,
                hash_iterations=210000,
                password_history=5,
            ),
        )
        config = spec.to_keycloak_config()
        policy = config["passwordPolicy"]

        # Verify all components are present
        assert "length(12)" in policy
        assert "upperCase(1)" in policy
        assert "lowerCase(1)" in policy
        assert "digits(1)" in policy
        assert "specialChars(1)" in policy
        assert "notUsername" in policy
        assert "hashIterations(210000)" in policy
        assert "passwordHistory(5)" in policy
