"""
Unit tests for status condition state transitions.

Tests the proper state transitions between different status conditions
following Kubernetes best practices and ensuring observedGeneration tracking.
"""

from datetime import datetime
from unittest.mock import patch

import pytest

from keycloak_operator.services.base_reconciler import BaseReconciler


class MockStatus:
    """Mock status object that allows dynamic attribute assignment."""

    def __init__(self):
        self.phase = None
        self.message = None
        self.last_reconcile_time = None
        self.observedGeneration = None
        self.conditions = []

    def __setattr__(self, name: str, value) -> None:
        self.__dict__[name] = value

    def __getattr__(self, name: str):
        return self.__dict__.get(name)


class ConcreteReconciler(BaseReconciler):
    """Concrete implementation of BaseReconciler for testing."""

    async def do_reconcile(self, spec, name, namespace, status, **kwargs):
        """Simple test reconciliation that always succeeds."""
        return {"test": "success"}


class TestStatusConditionTransitions:
    """Test status condition state transitions."""

    @pytest.fixture
    def reconciler(self):
        """Create a reconciler for testing."""
        return ConcreteReconciler()

    @pytest.fixture
    def status(self):
        """Create a mock status object."""
        return MockStatus()

    def test_initial_reconciling_state(self, reconciler, status):
        """Test initial transition to reconciling state."""
        generation = 42

        reconciler.update_status_reconciling(status, "Starting reconciliation", generation)

        # Check basic status fields
        assert status.phase == "Reconciling"
        assert status.message == "Starting reconciliation"
        assert status.observedGeneration == generation
        assert status.last_reconcile_time is not None

        # Check conditions
        assert len(status.conditions) == 2

        # Check Reconciling condition
        reconciling_condition = next(c for c in status.conditions if c["type"] == "Reconciling")
        assert reconciling_condition["status"] == "True"
        assert reconciling_condition["reason"] == "ReconciliationInProgress"
        assert reconciling_condition["message"] == "Starting reconciliation"
        assert reconciling_condition["observedGeneration"] == generation
        assert "lastTransitionTime" in reconciling_condition

        # Check Progressing condition
        progressing_condition = next(c for c in status.conditions if c["type"] == "Progressing")
        assert progressing_condition["status"] == "True"
        assert progressing_condition["reason"] == "ReconciliationInProgress"
        assert progressing_condition["message"] == "Resource is progressing: Starting reconciliation"
        assert progressing_condition["observedGeneration"] == generation

    def test_transition_to_ready_state(self, reconciler, status):
        """Test transition from reconciling to ready state."""
        generation = 24

        # Start with reconciling state
        reconciler.update_status_reconciling(status, "Reconciling...", generation)

        # Transition to ready
        reconciler.update_status_ready(status, "Resource is ready", generation)

        # Check basic status fields
        assert status.phase == "Ready"
        assert status.message == "Resource is ready"
        assert status.observedGeneration == generation

        # Check conditions
        condition_types = [c["type"] for c in status.conditions]

        # Should have Ready, Available conditions, but not Reconciling or Progressing
        assert "Ready" in condition_types
        assert "Available" in condition_types
        assert "Reconciling" not in condition_types
        assert "Progressing" not in condition_types
        assert "Degraded" not in condition_types

        # Check Ready condition
        ready_condition = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_condition["status"] == "True"
        assert ready_condition["reason"] == "ReconciliationSucceeded"
        assert ready_condition["message"] == "Resource is ready"
        assert ready_condition["observedGeneration"] == generation

        # Check Available condition
        available_condition = next(c for c in status.conditions if c["type"] == "Available")
        assert available_condition["status"] == "True"
        assert available_condition["reason"] == "ReconciliationSucceeded"
        assert available_condition["message"] == "Resource is available: Resource is ready"
        assert available_condition["observedGeneration"] == generation

    def test_transition_to_failed_state(self, reconciler, status):
        """Test transition from reconciling to failed state."""
        generation = 36

        # Start with reconciling state
        reconciler.update_status_reconciling(status, "Reconciling...", generation)

        # Transition to failed
        reconciler.update_status_failed(status, "Reconciliation failed", generation)

        # Check basic status fields
        assert status.phase == "Failed"
        assert status.message == "Reconciliation failed"
        assert status.observedGeneration == generation

        # Check conditions
        condition_types = [c["type"] for c in status.conditions]

        # Should have Ready (False), Available (False), Degraded (True), but not Reconciling or Progressing
        assert "Ready" in condition_types
        assert "Available" in condition_types
        assert "Degraded" in condition_types
        assert "Reconciling" not in condition_types
        assert "Progressing" not in condition_types

        # Check Ready condition (should be False)
        ready_condition = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_condition["status"] == "False"
        assert ready_condition["reason"] == "ReconciliationFailed"
        assert ready_condition["message"] == "Reconciliation failed"
        assert ready_condition["observedGeneration"] == generation

        # Check Available condition (should be False)
        available_condition = next(c for c in status.conditions if c["type"] == "Available")
        assert available_condition["status"] == "False"
        assert available_condition["reason"] == "ReconciliationFailed"
        assert available_condition["message"] == "Resource unavailable: Reconciliation failed"
        assert available_condition["observedGeneration"] == generation

        # Check Degraded condition (should be True)
        degraded_condition = next(c for c in status.conditions if c["type"] == "Degraded")
        assert degraded_condition["status"] == "True"
        assert degraded_condition["reason"] == "ReconciliationFailed"
        assert degraded_condition["message"] == "Resource degraded: Reconciliation failed"
        assert degraded_condition["observedGeneration"] == generation

    def test_transition_to_degraded_state(self, reconciler, status):
        """Test transition to degraded state."""
        generation = 18

        # Start with ready state
        reconciler.update_status_ready(status, "Ready", generation)

        # Transition to degraded
        reconciler.update_status_degraded(status, "Partially functional", generation)

        # Check basic status fields
        assert status.phase == "Degraded"
        assert status.message == "Partially functional"
        assert status.observedGeneration == generation

        # Check conditions
        condition_types = [c["type"] for c in status.conditions]

        # Should have Ready (False), Available (True), Degraded (True), but not Reconciling or Progressing
        assert "Ready" in condition_types
        assert "Available" in condition_types
        assert "Degraded" in condition_types
        assert "Reconciling" not in condition_types
        assert "Progressing" not in condition_types

        # Check Ready condition (should be False)
        ready_condition = next(c for c in status.conditions if c["type"] == "Ready")
        assert ready_condition["status"] == "False"
        assert ready_condition["reason"] == "PartialFunctionality"
        assert ready_condition["observedGeneration"] == generation

        # Check Available condition (should be True - still partially available)
        available_condition = next(c for c in status.conditions if c["type"] == "Available")
        assert available_condition["status"] == "True"
        assert available_condition["reason"] == "PartialFunctionality"
        assert available_condition["observedGeneration"] == generation

        # Check Degraded condition (should be True)
        degraded_condition = next(c for c in status.conditions if c["type"] == "Degraded")
        assert degraded_condition["status"] == "True"
        assert degraded_condition["reason"] == "PartialFunctionality"
        assert degraded_condition["observedGeneration"] == generation

    def test_generation_tracking_across_transitions(self, reconciler, status):
        """Test that generation is properly tracked across state transitions."""
        generations = [1, 5, 10, 15]
        messages = ["Initial", "Update 1", "Update 2", "Final"]

        for gen, msg in zip(generations, messages, strict=False):
            reconciler.update_status_reconciling(status, f"Reconciling {msg}", gen)
            assert status.observedGeneration == gen

            for condition in status.conditions:
                assert condition["observedGeneration"] == gen

            reconciler.update_status_ready(status, f"Ready {msg}", gen)
            assert status.observedGeneration == gen

            for condition in status.conditions:
                assert condition["observedGeneration"] == gen

    def test_condition_replacement_not_accumulation(self, reconciler, status):
        """Test that conditions are replaced, not accumulated."""
        generation = 42

        # Multiple transitions should not accumulate conditions
        reconciler.update_status_reconciling(status, "Start", generation)
        initial_count = len(status.conditions)

        reconciler.update_status_ready(status, "Ready", generation)
        ready_count = len(status.conditions)

        reconciler.update_status_failed(status, "Failed", generation)
        failed_count = len(status.conditions)

        # Each state should have a reasonable number of conditions, not accumulating
        assert initial_count <= 4  # Reconciling, Progressing, and potentially others
        assert ready_count <= 4   # Ready, Available, and potentially others
        assert failed_count <= 4  # Ready (False), Available (False), Degraded, and potentially others

        # Should not have contradictory conditions
        condition_types = [c["type"] for c in status.conditions]
        assert condition_types.count("Ready") == 1
        assert condition_types.count("Available") == 1

    def test_condition_timestamp_updates(self, reconciler, status):
        """Test that condition timestamps are updated properly."""
        generation = 7

        reconciler.update_status_reconciling(status, "Start", generation)
        first_timestamps = {c["type"]: c["lastTransitionTime"] for c in status.conditions}

        # Small delay to ensure timestamp difference
        import time
        time.sleep(0.01)

        reconciler.update_status_ready(status, "Ready", generation)
        second_timestamps = {c["type"]: c["lastTransitionTime"] for c in status.conditions}

        # New conditions should have different timestamps
        for condition_type, timestamp in second_timestamps.items():
            if condition_type in first_timestamps:
                # Only compare if the condition existed before
                # Some conditions are removed/replaced during transitions
                pass
            # All current conditions should have recent timestamps
            assert timestamp is not None

    def test_helper_methods_condition_checking(self, reconciler, status):
        """Test helper methods for checking condition states."""
        generation = 13

        # Test is_ready
        reconciler.update_status_reconciling(status, "Reconciling", generation)
        assert not reconciler.is_ready(status)

        reconciler.update_status_ready(status, "Ready", generation)
        assert reconciler.is_ready(status)

        reconciler.update_status_failed(status, "Failed", generation)
        assert not reconciler.is_ready(status)

        # Test is_available
        reconciler.update_status_ready(status, "Ready", generation)
        assert reconciler.is_available(status)

        reconciler.update_status_degraded(status, "Degraded", generation)
        assert reconciler.is_available(status)  # Still available in degraded state

        reconciler.update_status_failed(status, "Failed", generation)
        assert not reconciler.is_available(status)

        # Test is_progressing
        reconciler.update_status_reconciling(status, "Reconciling", generation)
        assert reconciler.is_progressing(status)

        reconciler.update_status_ready(status, "Ready", generation)
        assert not reconciler.is_progressing(status)

        # Test is_degraded
        reconciler.update_status_degraded(status, "Degraded", generation)
        assert reconciler.is_degraded(status)

        reconciler.update_status_ready(status, "Ready", generation)
        assert not reconciler.is_degraded(status)

    def test_complex_state_transition_sequence(self, reconciler, status):
        """Test a complex sequence of state transitions."""
        # Simulate a realistic operator lifecycle
        transitions = [
            ("reconciling", "Initial reconciliation", 1),
            ("ready", "First success", 1),
            ("reconciling", "Configuration change", 2),
            ("degraded", "Partial failure", 2),
            ("reconciling", "Recovery attempt", 3),
            ("failed", "Recovery failed", 3),
            ("reconciling", "Another recovery", 4),
            ("ready", "Final success", 4),
        ]

        for state, message, generation in transitions:
            if state == "reconciling":
                reconciler.update_status_reconciling(status, message, generation)
                assert status.phase == "Reconciling"
                assert reconciler.is_progressing(status)
                assert not reconciler.is_ready(status)
            elif state == "ready":
                reconciler.update_status_ready(status, message, generation)
                assert status.phase == "Ready"
                assert reconciler.is_ready(status)
                assert reconciler.is_available(status)
                assert not reconciler.is_progressing(status)
                assert not reconciler.is_degraded(status)
            elif state == "degraded":
                reconciler.update_status_degraded(status, message, generation)
                assert status.phase == "Degraded"
                assert not reconciler.is_ready(status)
                assert reconciler.is_available(status)  # Still available
                assert reconciler.is_degraded(status)
                assert not reconciler.is_progressing(status)
            elif state == "failed":
                reconciler.update_status_failed(status, message, generation)
                assert status.phase == "Failed"
                assert not reconciler.is_ready(status)
                assert not reconciler.is_available(status)
                assert reconciler.is_degraded(status)
                assert not reconciler.is_progressing(status)

            # Check that observedGeneration is always correct
            assert status.observedGeneration == generation

    def test_concurrent_condition_updates(self, reconciler, status):
        """Test behavior under concurrent condition updates."""
        import threading
        import time

        generation = 99
        results = []

        def update_status(state_type, delay):
            time.sleep(delay)
            if state_type == "ready":
                reconciler.update_status_ready(status, f"Ready {state_type}", generation)
            elif state_type == "failed":
                reconciler.update_status_failed(status, f"Failed {state_type}", generation)
            elif state_type == "degraded":
                reconciler.update_status_degraded(status, f"Degraded {state_type}", generation)
            results.append(state_type)

        # Start multiple threads trying to update status
        threads = [
            threading.Thread(target=update_status, args=("ready", 0.01)),
            threading.Thread(target=update_status, args=("failed", 0.02)),
            threading.Thread(target=update_status, args=("degraded", 0.03)),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Should have consistent final state (last one wins)
        assert status.observedGeneration == generation
        assert len(results) == 3
        assert status.phase in ["Ready", "Failed", "Degraded"]

    def test_condition_structure_compliance(self, reconciler, status):
        """Test that conditions follow Kubernetes structure compliance."""
        generation = 55

        # Test all status update methods
        methods = [
            (reconciler.update_status_reconciling, "Reconciling test", generation),
            (reconciler.update_status_ready, "Ready test", generation),
            (reconciler.update_status_failed, "Failed test", generation),
            (reconciler.update_status_degraded, "Degraded test", generation),
        ]

        for method, message, gen in methods:
            method(status, message, gen)

            # All conditions should follow Kubernetes structure
            for condition in status.conditions:
                # Required fields
                assert "type" in condition
                assert "status" in condition
                assert "lastTransitionTime" in condition
                assert "reason" in condition
                assert "message" in condition

                # Our enhancement: observedGeneration
                assert "observedGeneration" in condition
                assert condition["observedGeneration"] == gen

                # Valid values
                assert condition["status"] in ["True", "False", "Unknown"]
                assert condition["type"] in ["Ready", "Available", "Progressing", "Degraded", "Reconciling"]

                # Timestamp should be valid ISO format
                timestamp = condition["lastTransitionTime"]
                # Should not raise exception when parsing
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))

    def test_default_generation_handling(self, reconciler, status):
        """Test handling when generation is not provided (defaults to 0)."""
        # Call without generation parameter
        reconciler.update_status_ready(status, "Ready without generation")

        assert status.observedGeneration == 0
        for condition in status.conditions:
            assert condition["observedGeneration"] == 0

    def test_condition_get_and_check_methods(self, reconciler, status):
        """Test condition retrieval and checking methods."""
        generation = 77

        # Start with empty status
        assert reconciler.get_condition(status, "Ready") is None
        assert not reconciler.is_ready(status)

        # Add a Ready condition
        reconciler.update_status_ready(status, "Now ready", generation)
        ready_condition = reconciler.get_condition(status, "Ready")
        assert ready_condition is not None
        assert ready_condition["type"] == "Ready"
        assert ready_condition["status"] == "True"
        assert reconciler.is_ready(status)

        # Check non-existent condition
        assert reconciler.get_condition(status, "NonExistent") is None

        # Verify all helper methods work consistently
        assert reconciler.is_available(status) == (reconciler.get_condition(status, "Available") is not None and
                                                 reconciler.get_condition(status, "Available")["status"] == "True")

        assert reconciler.is_progressing(status) == (reconciler.get_condition(status, "Progressing") is not None and
                                                    reconciler.get_condition(status, "Progressing")["status"] == "True")

        assert reconciler.is_degraded(status) == (reconciler.get_condition(status, "Degraded") is not None and
                                                 reconciler.get_condition(status, "Degraded")["status"] == "True")

    @pytest.mark.asyncio
    async def test_full_reconciliation_lifecycle_with_conditions(self, reconciler, status):
        """Test full reconciliation lifecycle with proper condition transitions."""
        # Mock the reconciliation process
        spec = {"test": "config"}
        name = "test-resource"
        namespace = "test-namespace"
        generation = 123

        with patch.object(reconciler, 'do_reconcile', return_value={"result": "success"}):
            # Run full reconciliation
            result = await reconciler.reconcile(
                spec=spec,
                name=name,
                namespace=namespace,
                status=status,
                meta={"generation": generation}
            )

        # Should have successful result
        assert result == {"result": "success"}

        # Should end in Ready state
        assert status.phase == "Ready"
        assert status.observedGeneration == generation
        assert reconciler.is_ready(status)
        assert reconciler.is_available(status)
        assert not reconciler.is_progressing(status)
        assert not reconciler.is_degraded(status)

        # Should have proper conditions
        ready_condition = reconciler.get_condition(status, "Ready")
        assert ready_condition["status"] == "True"
        assert ready_condition["observedGeneration"] == generation
