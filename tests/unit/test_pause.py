"""
Unit tests for the reconciliation pause feature.

Tests the pause utility functions, settings integration, and
the BaseReconciler.update_status_paused() method.
"""

from unittest.mock import patch

import pytest

from keycloak_operator.services.base_reconciler import BaseReconciler


class MockStatus:
    """Mock status object that allows dynamic attribute assignment."""

    def __init__(self):
        self.phase = None
        self.message = None
        self.observedGeneration = None
        self.conditions = []

    def __setattr__(self, name: str, value) -> None:
        self.__dict__[name] = value

    def __getattr__(self, name: str):
        return self.__dict__.get(name)


class ConcreteReconciler(BaseReconciler):
    """Concrete implementation of BaseReconciler for testing."""

    async def do_reconcile(self, spec, name, namespace, status, **kwargs):
        return {"test": "success"}


class TestPauseUtility:
    """Test the pause utility functions from keycloak_operator.utils.pause."""

    def test_is_keycloak_paused_default(self):
        """Default is not paused."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_keycloak = False
            from keycloak_operator.utils.pause import is_keycloak_paused

            # Re-import after patching won't help since the function references
            # the module-level settings; we patch where it's looked up
            assert is_keycloak_paused() is False

    def test_is_keycloak_paused_enabled(self):
        """Returns True when setting is enabled."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_keycloak = True
            from keycloak_operator.utils.pause import is_keycloak_paused

            assert is_keycloak_paused() is True

    def test_is_realms_paused_default(self):
        """Default is not paused."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_realms = False
            from keycloak_operator.utils.pause import is_realms_paused

            assert is_realms_paused() is False

    def test_is_realms_paused_enabled(self):
        """Returns True when setting is enabled."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_realms = True
            from keycloak_operator.utils.pause import is_realms_paused

            assert is_realms_paused() is True

    def test_is_clients_paused_default(self):
        """Default is not paused."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_clients = False
            from keycloak_operator.utils.pause import is_clients_paused

            assert is_clients_paused() is False

    def test_is_clients_paused_enabled(self):
        """Returns True when setting is enabled."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_clients = True
            from keycloak_operator.utils.pause import is_clients_paused

            assert is_clients_paused() is True

    def test_get_pause_message_default(self):
        """Returns the default pause message."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_message = (
                "Reconciliation paused by operator configuration"
            )
            from keycloak_operator.utils.pause import get_pause_message

            assert (
                get_pause_message() == "Reconciliation paused by operator configuration"
            )

    def test_get_pause_message_custom(self):
        """Returns a custom pause message when configured."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_message = (
                "Maintenance window: KC 25.0 upgrade"
            )
            from keycloak_operator.utils.pause import get_pause_message

            assert get_pause_message() == "Maintenance window: KC 25.0 upgrade"

    def test_individual_cr_types_independent(self):
        """Each CR type pause flag is independent of others."""
        with patch("keycloak_operator.utils.pause.settings") as mock_settings:
            mock_settings.reconcile_pause_keycloak = True
            mock_settings.reconcile_pause_realms = False
            mock_settings.reconcile_pause_clients = True

            from keycloak_operator.utils.pause import (
                is_clients_paused,
                is_keycloak_paused,
                is_realms_paused,
            )

            assert is_keycloak_paused() is True
            assert is_realms_paused() is False
            assert is_clients_paused() is True


class TestPauseSettings:
    """Test that pause settings are properly loaded from environment variables."""

    def test_pause_settings_defaults(self):
        """All pause settings default to False/default message."""
        from keycloak_operator.settings import Settings

        s = Settings(
            _env_file=None,
            OPERATOR_NAMESPACE="test",
        )
        assert s.reconcile_pause_keycloak is False
        assert s.reconcile_pause_realms is False
        assert s.reconcile_pause_clients is False
        assert (
            s.reconcile_pause_message
            == "Reconciliation paused by operator configuration"
        )

    def test_pause_settings_from_env(self):
        """Pause settings are loaded from environment variables."""
        from keycloak_operator.settings import Settings

        s = Settings(
            _env_file=None,
            OPERATOR_NAMESPACE="test",
            RECONCILE_PAUSE_KEYCLOAK="true",
            RECONCILE_PAUSE_REALMS="true",
            RECONCILE_PAUSE_CLIENTS="false",
            RECONCILE_PAUSE_MESSAGE="Maintenance: KC upgrade",
        )
        assert s.reconcile_pause_keycloak is True
        assert s.reconcile_pause_realms is True
        assert s.reconcile_pause_clients is False
        assert s.reconcile_pause_message == "Maintenance: KC upgrade"

    def test_pause_settings_case_insensitive_bool(self):
        """Boolean env vars handle various casing."""
        from keycloak_operator.settings import Settings

        s = Settings(
            _env_file=None,
            OPERATOR_NAMESPACE="test",
            RECONCILE_PAUSE_KEYCLOAK="True",
            RECONCILE_PAUSE_REALMS="FALSE",
            RECONCILE_PAUSE_CLIENTS="1",
        )
        assert s.reconcile_pause_keycloak is True
        assert s.reconcile_pause_realms is False
        assert s.reconcile_pause_clients is True


class TestUpdateStatusPaused:
    """Test the BaseReconciler.update_status_paused() method."""

    @pytest.fixture
    def reconciler(self):
        return ConcreteReconciler()

    @pytest.fixture
    def status(self):
        return MockStatus()

    def test_paused_sets_phase_and_message(self, reconciler, status):
        """Sets phase to Paused and the configured message."""
        reconciler.update_status_paused(status, "Maintenance window", 5)

        assert status.phase == "Paused"
        assert status.message == "Maintenance window"
        assert status.observedGeneration == 5
        assert status.lastUpdated is not None

    def test_paused_adds_reconciliation_paused_condition(self, reconciler, status):
        """Adds ReconciliationPaused=True condition."""
        reconciler.update_status_paused(status, "Paused for upgrade", 3)

        paused_condition = next(
            c for c in status.conditions if c["type"] == "ReconciliationPaused"
        )
        assert paused_condition["status"] == "True"
        assert paused_condition["reason"] == "OperatorPauseConfigured"
        assert paused_condition["message"] == "Paused for upgrade"
        assert paused_condition["observedGeneration"] == 3

    def test_paused_sets_ready_false(self, reconciler, status):
        """Sets Ready=False when paused."""
        reconciler.update_status_paused(status, "Maintenance", 1)

        ready_condition = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_condition["status"] == "False"
        assert ready_condition["reason"] == "ReconciliationPaused"
        assert "Maintenance" in ready_condition["message"]

    def test_paused_removes_transient_conditions(self, reconciler, status):
        """Removes Reconciling, Progressing, and Degraded conditions."""
        # Pre-populate with conditions that should be removed
        status.conditions = [
            {
                "type": "Reconciling",
                "status": "True",
                "reason": "Test",
                "message": "test",
                "lastTransitionTime": "2025-01-01T00:00:00",
                "observedGeneration": 1,
            },
            {
                "type": "Progressing",
                "status": "True",
                "reason": "Test",
                "message": "test",
                "lastTransitionTime": "2025-01-01T00:00:00",
                "observedGeneration": 1,
            },
            {
                "type": "Degraded",
                "status": "True",
                "reason": "Test",
                "message": "test",
                "lastTransitionTime": "2025-01-01T00:00:00",
                "observedGeneration": 1,
            },
        ]

        reconciler.update_status_paused(status, "Paused", 2)

        condition_types = [c["type"] for c in status.conditions]
        assert "Reconciling" not in condition_types
        assert "Progressing" not in condition_types
        assert "Degraded" not in condition_types
        assert "ReconciliationPaused" in condition_types
        assert "Ready" in condition_types

    def test_paused_from_ready_state(self, reconciler, status):
        """Transition from Ready to Paused replaces Ready=True with Ready=False."""
        # Start in Ready state
        reconciler.update_status_ready(status, "All good", 1)
        assert status.phase == "Ready"
        ready_cond = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_cond["status"] == "True"

        # Pause
        reconciler.update_status_paused(status, "Maintenance", 2)

        assert status.phase == "Paused"
        ready_cond = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_cond["status"] == "False"
        paused_cond = next(
            c for c in status.conditions if c["type"] == "ReconciliationPaused"
        )
        assert paused_cond["status"] == "True"

    def test_paused_default_generation_is_zero(self, reconciler, status):
        """Generation defaults to 0 if not provided."""
        reconciler.update_status_paused(status, "Paused")

        assert status.observedGeneration == 0


class TestAnnotationConstant:
    """Test the force-reconcile annotation constant rename."""

    def test_annotation_constant_value(self):
        """ANNOTATION_RECONCILE_FORCE has the new naming convention."""
        from keycloak_operator.constants import ANNOTATION_RECONCILE_FORCE

        assert ANNOTATION_RECONCILE_FORCE == "keycloak-operator/reconcile-force"

    def test_phase_paused_constant(self):
        """PHASE_PAUSED constant exists."""
        from keycloak_operator.constants import PHASE_PAUSED

        assert PHASE_PAUSED == "Paused"

    def test_condition_reconciliation_paused_constant(self):
        """CONDITION_RECONCILIATION_PAUSED constant exists."""
        from keycloak_operator.constants import CONDITION_RECONCILIATION_PAUSED

        assert CONDITION_RECONCILIATION_PAUSED == "ReconciliationPaused"
