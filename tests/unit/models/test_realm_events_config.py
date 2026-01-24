"""Unit tests for KeycloakEventsConfig model."""

import pytest

from keycloak_operator.models.realm import KeycloakEventsConfig, KeycloakRealmSpec


class TestEventsConfigModel:
    """Tests for KeycloakEventsConfig Pydantic model."""

    def test_defaults(self):
        """Default values are correct.

        Note: admin_events_enabled and admin_events_details_enabled default to True
        because they are required for drift detection to work properly.
        """
        config = KeycloakEventsConfig()
        assert config.events_enabled is False
        assert config.admin_events_enabled is True  # Required for drift detection
        assert (
            config.admin_events_details_enabled is True
        )  # Required for drift detection
        assert config.events_listeners == []
        assert config.enabled_event_types == []
        assert config.events_expiration is None

    def test_all_fields_set(self):
        """All fields can be set."""
        config = KeycloakEventsConfig(
            events_enabled=True,
            events_listeners=["jboss-logging", "email"],
            enabled_event_types=["LOGIN", "LOGOUT", "REGISTER"],
            events_expiration=86400,
            admin_events_enabled=True,
            admin_events_details_enabled=True,
        )
        assert config.events_enabled is True
        assert config.admin_events_enabled is True
        assert config.admin_events_details_enabled is True
        assert len(config.events_listeners) == 2
        assert "jboss-logging" in config.events_listeners
        assert "email" in config.events_listeners
        assert len(config.enabled_event_types) == 3
        assert config.events_expiration == 86400

    def test_events_expiration_minimum_validation(self):
        """events_expiration must be at least 1."""
        with pytest.raises(ValueError):
            KeycloakEventsConfig(events_expiration=0)

    def test_events_expiration_negative_validation(self):
        """events_expiration cannot be negative."""
        with pytest.raises(ValueError):
            KeycloakEventsConfig(events_expiration=-1)

    def test_alias_mapping_camel_case(self):
        """Aliases work for camelCase input."""
        config = KeycloakEventsConfig.model_validate(
            {
                "eventsEnabled": True,
                "adminEventsEnabled": True,
                "adminEventsDetailsEnabled": True,
                "eventsListeners": ["jboss-logging"],
                "enabledEventTypes": ["LOGIN"],
                "eventsExpiration": 3600,
            }
        )
        assert config.events_enabled is True
        assert config.admin_events_enabled is True
        assert config.admin_events_details_enabled is True
        assert config.events_listeners == ["jboss-logging"]
        assert config.enabled_event_types == ["LOGIN"]
        assert config.events_expiration == 3600

    def test_partial_configuration(self):
        """Partial configuration works correctly.

        Note: admin_events_enabled defaults to True for drift detection.
        """
        config = KeycloakEventsConfig(
            events_enabled=True,
            events_listeners=["jboss-logging"],
        )
        assert config.events_enabled is True
        assert (
            config.admin_events_enabled is True
        )  # Defaults to True for drift detection
        assert config.events_listeners == ["jboss-logging"]
        assert config.enabled_event_types == []

    def test_empty_listeners_list(self):
        """Empty listeners list is valid."""
        config = KeycloakEventsConfig(events_enabled=True, events_listeners=[])
        assert config.events_listeners == []

    def test_multiple_event_types(self):
        """Multiple event types can be specified."""
        event_types = [
            "LOGIN",
            "LOGIN_ERROR",
            "LOGOUT",
            "REGISTER",
            "CODE_TO_TOKEN",
            "REFRESH_TOKEN",
        ]
        config = KeycloakEventsConfig(enabled_event_types=event_types)
        assert config.enabled_event_types == event_types
        assert len(config.enabled_event_types) == 6


class TestRealmSpecWithEventsConfig:
    """Tests for KeycloakRealmSpec with events configuration."""

    def test_default_events_config(self):
        """Default events config is created.

        Note: admin_events_enabled defaults to True for drift detection.
        """
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
        )
        assert spec.events_config is not None
        assert spec.events_config.events_enabled is False
        assert (
            spec.events_config.admin_events_enabled is True
        )  # Required for drift detection

    def test_custom_events_config(self):
        """Custom events config is applied."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
            events_config=KeycloakEventsConfig(
                events_enabled=True,
                events_listeners=["jboss-logging"],
                admin_events_enabled=True,
            ),
        )
        assert spec.events_config.events_enabled is True
        assert "jboss-logging" in spec.events_config.events_listeners
        assert spec.events_config.admin_events_enabled is True

    def test_to_keycloak_config_includes_events(self):
        """to_keycloak_config() includes events configuration."""
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
            events_config=KeycloakEventsConfig(
                events_enabled=True,
                events_listeners=["jboss-logging", "email"],
                enabled_event_types=["LOGIN", "LOGOUT"],
                events_expiration=604800,
                admin_events_enabled=True,
                admin_events_details_enabled=True,
            ),
        )
        config = spec.to_keycloak_config()

        assert config["eventsEnabled"] is True
        assert config["eventsListeners"] == ["jboss-logging", "email"]
        assert config["enabledEventTypes"] == ["LOGIN", "LOGOUT"]
        assert config["eventsExpiration"] == 604800
        assert config["adminEventsEnabled"] is True
        assert config["adminEventsDetailsEnabled"] is True

    def test_to_keycloak_config_default_events(self):
        """to_keycloak_config() includes default events config.

        Note: admin events default to True for drift detection.
        """
        spec = KeycloakRealmSpec(
            realm_name="test-realm",
            operator_ref={"namespace": "keycloak"},
        )
        config = spec.to_keycloak_config()

        assert config["eventsEnabled"] is False
        assert config["eventsListeners"] == []
        assert config["enabledEventTypes"] == []
        assert config["eventsExpiration"] is None
        assert config["adminEventsEnabled"] is True  # Required for drift detection
        assert (
            config["adminEventsDetailsEnabled"] is True
        )  # Required for drift detection

    def test_events_config_alias_in_realm_spec(self):
        """KeycloakRealmSpec accepts eventsConfig alias."""
        spec = KeycloakRealmSpec.model_validate(
            {
                "realmName": "test-realm",
                "operatorRef": {"namespace": "keycloak"},
                "eventsConfig": {
                    "eventsEnabled": True,
                    "eventsListeners": ["jboss-logging"],
                    "adminEventsEnabled": True,
                },
            }
        )
        assert spec.events_config.events_enabled is True
        assert spec.events_config.events_listeners == ["jboss-logging"]
        assert spec.events_config.admin_events_enabled is True
