"""
Test ObservedGeneration tracking for GitOps compatibility.

This module tests that all reconcilers properly track the ObservedGeneration
field to enable GitOps tools like ArgoCD and Flux to detect drift and
determine sync status.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.services.base_reconciler import BaseReconciler
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler
from keycloak_operator.services.keycloak_reconciler import KeycloakInstanceReconciler
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler


class ConcreteReconciler(BaseReconciler):
    """Concrete implementation of BaseReconciler for testing."""

    async def do_reconcile(self, spec, name, namespace, status, **kwargs):
        """Simple test reconciliation that always succeeds."""
        return {"test": "success"}


class MockStatus:
    """Mock status object that tracks attribute assignments."""

    def __init__(self):
        self.attributes = {}

    def __setattr__(self, name, value):
        if name == "attributes":
            super().__setattr__(name, value)
        else:
            self.attributes[name] = value

    def __getattr__(self, name):
        if name in self.attributes:
            return self.attributes[name]
        raise AttributeError(name)


class TestBaseReconcilerGenerationTracking:
    """Test generation tracking in the base reconciler."""

    @pytest.fixture
    def base_reconciler(self):
        """Create a base reconciler for testing."""
        return ConcreteReconciler()

    def test_update_status_ready_with_generation(self, base_reconciler):
        """Test that update_status_ready sets observedGeneration."""
        status = MockStatus()
        generation = 42
        message = "Resource is ready"

        base_reconciler.update_status_ready(status, message, generation)

        assert status.observedGeneration == generation
        assert status.phase == "Ready"
        assert status.message == message
        assert status.lastUpdated is not None

    def test_update_status_reconciling_with_generation(self, base_reconciler):
        """Test that update_status_reconciling sets observedGeneration."""
        status = MockStatus()
        generation = 15
        message = "Starting reconciliation"

        base_reconciler.update_status_reconciling(status, message, generation)

        assert status.observedGeneration == generation
        assert status.phase == "Reconciling"
        assert status.message == message

    def test_update_status_failed_with_generation(self, base_reconciler):
        """Test that update_status_failed sets observedGeneration."""
        status = MockStatus()
        generation = 7
        message = "Reconciliation failed"

        base_reconciler.update_status_failed(status, message, generation)

        assert status.observedGeneration == generation
        assert status.phase == "Failed"
        assert status.message == message

    def test_update_status_degraded_with_generation(self, base_reconciler):
        """Test that update_status_degraded sets observedGeneration."""
        status = MockStatus()
        generation = 23
        message = "Resource is degraded"

        base_reconciler.update_status_degraded(status, message, generation)

        assert status.observedGeneration == generation
        assert status.phase == "Degraded"
        assert status.message == message

    def test_generation_defaults_to_zero(self, base_reconciler):
        """Test that generation defaults to 0 if not provided."""
        status = MockStatus()
        message = "Default generation test"

        # Test with default generation (should be 0)
        base_reconciler.update_status_ready(status, message)

        assert status.observedGeneration == 0
        assert status.phase == "Ready"

    def test_generation_preserves_existing_status_fields(self, base_reconciler):
        """Test that generation tracking doesn't overwrite other status fields."""
        status = MockStatus()
        status.custom_field = "preserved_value"
        status.another_field = 123

        generation = 5
        base_reconciler.update_status_ready(status, "Ready", generation)

        # New fields should be set
        assert status.observedGeneration == generation
        assert status.phase == "Ready"

        # Existing fields should be preserved
        assert status.custom_field == "preserved_value"
        assert status.another_field == 123


class TestKeycloakReconcilerGenerationTracking:
    """Test generation tracking in Keycloak instance reconciler."""

    @pytest.fixture
    def keycloak_reconciler(self):
        """Create a Keycloak reconciler for testing."""
        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            return KeycloakInstanceReconciler()

    @pytest.mark.asyncio
    async def test_do_reconcile_extracts_generation_from_kwargs(
        self, keycloak_reconciler
    ):
        """Test that do_reconcile extracts generation from kwargs metadata."""
        status = MockStatus()
        spec = {
            "image": "quay.io/keycloak/keycloak:23.0.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
            },
            "admin": {
                "username": "admin",
                "password_secret": {"name": "admin-secret", "key": "password"},
            },
        }

        # Mock metadata with generation
        kwargs = {"meta": {"generation": 42}}

        # Mock the methods that would be called during reconciliation
        with (
            patch.object(
                keycloak_reconciler,
                "validate_production_settings",
                new_callable=AsyncMock,
            ),
            patch.object(
                keycloak_reconciler, "ensure_admin_access", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler, "ensure_deployment", new_callable=AsyncMock
            ),
            patch.object(keycloak_reconciler, "ensure_service", new_callable=AsyncMock),
            patch.object(
                keycloak_reconciler, "ensure_persistence", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            await keycloak_reconciler.do_reconcile(
                spec=spec,
                name="test-keycloak",
                namespace="test-namespace",
                status=status,
                **kwargs,
            )

            # Verify generation was extracted and used
            assert status.observedGeneration == 42
            assert status.phase == "Ready"

    @pytest.mark.asyncio
    async def test_do_reconcile_handles_missing_generation(self, keycloak_reconciler):
        """Test that do_reconcile handles missing generation gracefully."""
        status = MockStatus()
        spec = {
            "image": "quay.io/keycloak/keycloak:23.0.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
            },
            "admin": {
                "username": "admin",
                "password_secret": {"name": "admin-secret", "key": "password"},
            },
        }

        # No meta or empty meta
        kwargs = {}

        with (
            patch.object(
                keycloak_reconciler,
                "validate_production_settings",
                new_callable=AsyncMock,
            ),
            patch.object(
                keycloak_reconciler, "ensure_admin_access", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler, "ensure_deployment", new_callable=AsyncMock
            ),
            patch.object(keycloak_reconciler, "ensure_service", new_callable=AsyncMock),
            patch.object(
                keycloak_reconciler, "ensure_persistence", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            await keycloak_reconciler.do_reconcile(
                spec=spec,
                name="test-keycloak",
                namespace="test-namespace",
                status=status,
                **kwargs,
            )

            # Should default to generation 0
            assert status.observedGeneration == 0
            assert status.phase == "Ready"

    @pytest.mark.asyncio
    async def test_do_reconcile_degraded_state_includes_generation(
        self, keycloak_reconciler
    ):
        """Test that degraded state also includes generation tracking."""
        status = MockStatus()
        spec = {
            "image": "quay.io/keycloak/keycloak:23.0.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
            },
            "admin": {
                "username": "admin",
                "password_secret": {"name": "admin-secret", "key": "password"},
            },
        }

        kwargs = {"meta": {"generation": 99}}

        with (
            patch.object(
                keycloak_reconciler,
                "validate_production_settings",
                new_callable=AsyncMock,
            ),
            patch.object(
                keycloak_reconciler, "ensure_admin_access", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler, "ensure_deployment", new_callable=AsyncMock
            ),
            patch.object(keycloak_reconciler, "ensure_service", new_callable=AsyncMock),
            patch.object(
                keycloak_reconciler, "ensure_persistence", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            await keycloak_reconciler.do_reconcile(
                spec=spec,
                name="test-keycloak",
                namespace="test-namespace",
                status=status,
                **kwargs,
            )

            # Should set degraded status with generation
            assert status.observedGeneration == 99
            assert status.phase == "Degraded"


class TestRealmReconcilerGenerationTracking:
    """Test generation tracking in Keycloak realm reconciler."""

    @pytest.fixture
    def realm_reconciler(self):
        """Create a Realm reconciler for testing."""
        return KeycloakRealmReconciler()

    @pytest.mark.asyncio
    async def test_realm_reconcile_sets_generation(self, realm_reconciler):
        """Test that realm reconciliation sets observedGeneration."""
        status = MockStatus()
        spec = {
            "realm_name": "test-realm",
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": "test-namespace",
            },
        }

        kwargs = {"meta": {"generation": 17}}

        # Mock the realm reconciliation methods
        with (
            patch.object(
                realm_reconciler,
                "validate_cross_namespace_access",
                new_callable=AsyncMock,
            ),
            patch.object(
                realm_reconciler, "ensure_realm_exists", new_callable=AsyncMock
            ),
            patch.object(
                realm_reconciler, "manage_realm_backup", new_callable=AsyncMock
            ),
            patch(
                "keycloak_operator.utils.kubernetes.validate_keycloak_reference",
                return_value=None,
            ),
        ):
            await realm_reconciler.do_reconcile(
                spec=spec,
                name="test-realm",
                namespace="test-namespace",
                status=status,
                **kwargs,
            )

            # Verify generation tracking
            assert status.observedGeneration == 17
            assert status.phase == "Ready"


class TestClientReconcilerGenerationTracking:
    """Test generation tracking in Keycloak client reconciler."""

    @pytest.fixture
    def client_reconciler(self):
        """Create a Client reconciler for testing."""
        return KeycloakClientReconciler()

    @pytest.mark.asyncio
    async def test_client_reconcile_sets_generation(self, client_reconciler):
        """Test that client reconciliation sets observedGeneration."""
        status = MockStatus()
        spec = {
            "client_id": "test-client",
            "realm": "test-realm",
            "keycloak_instance_ref": {
                "name": "test-keycloak",
                "namespace": "test-namespace",
            },
        }

        kwargs = {"meta": {"generation": 33}}

        # Mock the client reconciliation methods
        with (
            patch.object(
                client_reconciler,
                "validate_cross_namespace_access",
                new_callable=AsyncMock,
            ),
            patch.object(
                client_reconciler,
                "ensure_client_exists",
                new_callable=AsyncMock,
                return_value="client-uuid",
            ),
            patch.object(
                client_reconciler, "configure_oauth_settings", new_callable=AsyncMock
            ),
            patch.object(
                client_reconciler,
                "manage_client_credentials",
                new_callable=AsyncMock,
            ),
            patch.object(
                client_reconciler,
                "manage_service_account_roles",
                new_callable=AsyncMock,
            ),
            patch.object(
                client_reconciler,
                "keycloak_admin_factory",
                MagicMock(return_value=MagicMock()),
            ),
            patch(
                "keycloak_operator.utils.kubernetes.validate_keycloak_reference",
                return_value=None,
            ),
        ):
            await client_reconciler.do_reconcile(
                spec=spec,
                name="test-client",
                namespace="test-namespace",
                status=status,
                **kwargs,
            )

            # Verify generation tracking
            assert status.observedGeneration == 33
            assert status.phase == "Ready"


class TestGitOpsCompatibility:
    """Test GitOps compatibility scenarios."""

    @pytest.fixture
    def base_reconciler(self):
        """Create a base reconciler for testing."""
        return ConcreteReconciler()

    def test_generation_increment_detection(self, base_reconciler):
        """Test that generation increments are properly detected."""
        status = MockStatus()

        # Initial reconciliation with generation 1
        base_reconciler.update_status_ready(status, "Initial deployment", 1)
        assert status.observedGeneration == 1

        # Simulate spec change (generation increment)
        base_reconciler.update_status_reconciling(status, "Updating configuration", 2)
        assert status.observedGeneration == 2

        # Complete reconciliation
        base_reconciler.update_status_ready(status, "Update completed", 2)
        assert status.observedGeneration == 2

    def test_drift_detection_scenario(self, base_reconciler):
        """Test scenario where GitOps tool detects drift."""
        status = MockStatus()

        # GitOps tool applies resource with generation 5
        status.observedGeneration = 3  # Operator last observed generation 3

        # New reconciliation with generation 5
        base_reconciler.update_status_reconciling(
            status, "Detected drift, reconciling", 5
        )
        assert status.observedGeneration == 5

        # Drift resolved
        base_reconciler.update_status_ready(status, "Drift resolved", 5)
        assert status.observedGeneration == 5

    def test_sync_status_determination(self, base_reconciler):
        """Test how GitOps tools can determine sync status."""
        status = MockStatus()

        # Resource generation in K8s API: 10
        # ObservedGeneration in status: 8
        # This indicates the operator hasn't processed the latest changes

        current_generation = 10
        status.observedGeneration = 8

        # When operator reconciles, it should update to current generation
        base_reconciler.update_status_ready(
            status, "Synced to latest", current_generation
        )
        assert status.observedGeneration == current_generation

        # Now GitOps tool can see: generation == observedGeneration (synced)
        assert status.observedGeneration == current_generation

    def test_partial_reconciliation_tracking(self, base_reconciler):
        """Test that partial reconciliations still track generation."""
        status = MockStatus()
        generation = 42

        # Start reconciliation
        base_reconciler.update_status_reconciling(
            status, "Starting reconciliation", generation
        )
        assert status.observedGeneration == generation

        # Reconciliation fails partway through
        base_reconciler.update_status_failed(
            status, "Database connection failed", generation
        )
        assert status.observedGeneration == generation

        # Even failed reconciliations should track generation
        # This tells GitOps tools that the operator attempted to process this version


class TestGenerationTrackingEdgeCases:
    """Test edge cases in generation tracking."""

    @pytest.fixture
    def base_reconciler(self):
        """Create a base reconciler for testing."""
        return ConcreteReconciler()

    def test_generation_zero_is_valid(self, base_reconciler):
        """Test that generation 0 is handled correctly."""
        status = MockStatus()

        base_reconciler.update_status_ready(status, "Initial creation", 0)
        assert status.observedGeneration == 0
        assert status.phase == "Ready"

    def test_large_generation_numbers(self, base_reconciler):
        """Test that large generation numbers are handled correctly."""
        status = MockStatus()
        large_generation = 999999999

        base_reconciler.update_status_ready(
            status, "Large generation test", large_generation
        )
        assert status.observedGeneration == large_generation

    def test_generation_backward_compatibility(self, base_reconciler):
        """Test that generation tracking works when field doesn't exist initially."""
        status = MockStatus()

        # Initially no observedGeneration field
        assert not hasattr(status, "observedGeneration")

        # First reconciliation should set it
        base_reconciler.update_status_ready(status, "First reconciliation", 1)
        assert status.observedGeneration == 1

    def test_concurrent_generation_updates(self, base_reconciler):
        """Test that generation updates handle concurrent scenarios."""
        status = MockStatus()

        # Simulate rapid generation increments (e.g., fast kubectl apply operations)
        generations = [5, 6, 7, 8]

        for gen in generations:
            base_reconciler.update_status_reconciling(
                status, f"Processing generation {gen}", gen
            )
            assert status.observedGeneration == gen

            base_reconciler.update_status_ready(
                status, f"Completed generation {gen}", gen
            )
            assert status.observedGeneration == gen
