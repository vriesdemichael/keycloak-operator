"""
Test ObservedGeneration tracking for GitOps compatibility.

This module tests that all reconcilers properly track the ObservedGeneration
field to enable GitOps tools like ArgoCD and Flux to detect drift and
determine sync status.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from keycloak_operator.errors.operator_errors import TemporaryError
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
            "image": "quay.io/keycloak/keycloak:26.4.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
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
                keycloak_reconciler, "ensure_discovery_service", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=(True, None),
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
            "image": "quay.io/keycloak/keycloak:26.4.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
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
                keycloak_reconciler, "ensure_discovery_service", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=(True, None),
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
    async def test_do_reconcile_not_ready_raises_temporary_error(
        self, keycloak_reconciler
    ):
        """Test that deployment not ready raises TemporaryError for retry."""
        status = MockStatus()
        spec = {
            "image": "quay.io/keycloak/keycloak:26.4.0",
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "database": "keycloak",
                "username": "keycloak",
                "credentials_secret": "db-secret",
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
                keycloak_reconciler, "ensure_discovery_service", new_callable=AsyncMock
            ),
            patch.object(
                keycloak_reconciler,
                "wait_for_deployment_ready",
                new_callable=AsyncMock,
                return_value=(False, None),
            ),
        ):
            with pytest.raises(TemporaryError, match="not ready"):
                await keycloak_reconciler.do_reconcile(
                    spec=spec,
                    name="test-keycloak",
                    namespace="test-namespace",
                    status=status,
                    **kwargs,
                )


class TestRealmReconcilerGenerationTracking:
    """Test generation tracking in Keycloak realm reconciler."""

    @pytest.fixture
    def realm_reconciler(self):
        """Create a Realm reconciler for testing."""
        mock_factory = AsyncMock()
        mock_client = MagicMock()
        mock_factory.return_value = mock_client

        # Mock the adapter for version compatibility check
        mock_validation_result = MagicMock()
        mock_validation_result.valid = True
        mock_validation_result.warnings = []
        mock_validation_result.errors = []

        mock_client.adapter.validate_for_version.return_value = mock_validation_result

        return KeycloakRealmReconciler(keycloak_admin_factory=mock_factory)

    @pytest.mark.asyncio
    async def test_realm_reconcile_sets_generation(self, realm_reconciler):
        """Test that realm reconciliation sets observedGeneration."""
        status = MockStatus()
        spec = {
            "realm_name": "test-realm",
            "operator_ref": {
                "namespace": "test-namespace",
                "authorization_secret_ref": {"name": "operator-token"},
            },
        }

        kwargs = {"meta": {"generation": 17}}

        # Mock the realm reconciliation methods
        with (
            patch(
                "keycloak_operator.settings.settings.operator_namespace",
                "test-namespace",
            ),
            patch.object(
                realm_reconciler,
                "validate_cross_namespace_access",
                new_callable=AsyncMock,
            ),
            patch.object(
                realm_reconciler, "ensure_realm_exists", new_callable=AsyncMock
            ),
            patch.object(
                realm_reconciler, "configure_identity_providers", new_callable=AsyncMock
            ),
            patch.object(
                realm_reconciler, "configure_user_federation", new_callable=AsyncMock
            ),
            patch.object(
                realm_reconciler,
                "configure_client_profiles_and_policies",
                new_callable=AsyncMock,
            ),
            patch.object(
                realm_reconciler, "configure_organizations", new_callable=AsyncMock
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
        reconciler = KeycloakClientReconciler()
        # Mock _get_realm_info to return expected values without calling K8s API
        # Returns: (actual_realm_name, keycloak_namespace, keycloak_name, realm_resource)
        reconciler._get_realm_info = MagicMock(  # ty: ignore[invalid-assignment]
            return_value=("test-realm", "test-namespace", "keycloak", {})
        )
        return reconciler

    @pytest.mark.asyncio
    async def test_client_reconcile_sets_generation(self, client_reconciler):
        """Test that client reconciliation sets observedGeneration."""
        status = MockStatus()
        spec = {
            "client_id": "test-client",
            "realm_ref": {
                "name": "test-realm",
                "namespace": "test-namespace",
                "authorization_secret_ref": {"name": "realm-token"},
            },
        }

        kwargs = {"meta": {"generation": 33}}

        # Mock the client reconciliation methods
        with (
            patch(
                "keycloak_operator.settings.settings.operator_namespace",
                "test-namespace",
            ),
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


class TestGenerationBasedSkip:
    """Test generation-based skip optimization for operator restart efficiency."""

    @pytest.fixture
    def base_reconciler(self):
        """Create a base reconciler for testing."""
        return ConcreteReconciler()

    @pytest.fixture
    def ready_status(self):
        """Create a status object in Ready state with observedGeneration set."""
        status = MockStatus()
        status.phase = "Ready"
        status.observedGeneration = 5
        return status

    @pytest.mark.asyncio
    async def test_skip_when_generation_matches_and_ready(self, base_reconciler):
        """Test that reconciliation is skipped when generation matches and phase is Ready."""
        status = MockStatus()
        status.phase = "Ready"
        status.observedGeneration = 10

        # Mock the metrics collector at the import location
        mock_metrics = MagicMock()
        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 10},  # Same as observedGeneration
            )

            # Should return empty dict without calling do_reconcile
            assert result == {}

            # Should record the skip in metrics
            mock_metrics.record_reconciliation_skip.assert_called_once_with(
                resource_type="concrete", namespace="test-ns", name="test-resource"
            )

            # Should NOT call track_reconciliation (no actual reconciliation)
            mock_metrics.track_reconciliation.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_skip_when_generation_differs(self, base_reconciler):
        """Test that reconciliation proceeds when generation differs."""
        status = MockStatus()
        status.phase = "Ready"
        status.observedGeneration = 5

        mock_metrics = MagicMock()
        # Configure the async context manager
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 6},  # Different from observedGeneration (5)
            )

            # Should return result from do_reconcile
            assert result == {"test": "success"}

            # Should NOT record a skip
            mock_metrics.record_reconciliation_skip.assert_not_called()

            # Should track reconciliation (actual reconciliation happened)
            mock_metrics.track_reconciliation.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_skip_when_phase_is_failed(self, base_reconciler):
        """Test that reconciliation proceeds when phase is Failed even if generation matches."""
        status = MockStatus()
        status.phase = "Failed"
        status.observedGeneration = 10

        mock_metrics = MagicMock()
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 10},  # Same as observedGeneration
            )

            # Should still reconcile because phase is Failed
            assert result == {"test": "success"}
            mock_metrics.record_reconciliation_skip.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_skip_when_phase_is_degraded(self, base_reconciler):
        """Test that reconciliation proceeds when phase is Degraded even if generation matches."""
        status = MockStatus()
        status.phase = "Degraded"
        status.observedGeneration = 10

        mock_metrics = MagicMock()
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 10},
            )

            # Should still reconcile because phase is Degraded
            assert result == {"test": "success"}
            mock_metrics.record_reconciliation_skip.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_skip_when_phase_is_reconciling(self, base_reconciler):
        """Test that reconciliation proceeds when phase is Reconciling."""
        status = MockStatus()
        status.phase = "Reconciling"
        status.observedGeneration = 10

        mock_metrics = MagicMock()
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 10},
            )

            # Should still reconcile because phase is Reconciling
            assert result == {"test": "success"}
            mock_metrics.record_reconciliation_skip.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_skip_when_observed_generation_is_none(self, base_reconciler):
        """Test that reconciliation proceeds when observedGeneration is not set."""
        status = MockStatus()
        status.phase = "Ready"
        # observedGeneration is not set (None)

        mock_metrics = MagicMock()
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 1},
            )

            # Should reconcile because observedGeneration is None
            assert result == {"test": "success"}
            mock_metrics.record_reconciliation_skip.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_skip_when_phase_is_none(self, base_reconciler):
        """Test that reconciliation proceeds when phase is not set."""
        status = MockStatus()
        status.observedGeneration = 10
        # phase is not set (None)

        mock_metrics = MagicMock()
        mock_metrics.track_reconciliation.return_value.__aenter__ = AsyncMock()
        mock_metrics.track_reconciliation.return_value.__aexit__ = AsyncMock()

        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 10},
            )

            # Should reconcile because phase is None
            assert result == {"test": "success"}
            mock_metrics.record_reconciliation_skip.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_logs_debug_message(self, base_reconciler):
        """Test that skipped reconciliations log a debug message."""
        status = MockStatus()
        status.phase = "Ready"
        status.observedGeneration = 10

        mock_metrics = MagicMock()
        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            # Capture logger calls
            with patch.object(base_reconciler.logger, "debug") as mock_debug:
                await base_reconciler.reconcile(
                    spec={"test": "data"},
                    name="my-keycloak",
                    namespace="production",
                    status=status,
                    meta={"generation": 10},
                )

                # Should log debug message about skipping
                mock_debug.assert_called_once()
                call_args = mock_debug.call_args[0][0]
                assert "Skipping" in call_args
                assert "my-keycloak" in call_args
                assert "generation 10" in call_args
                assert "Ready" in call_args

    @pytest.mark.asyncio
    async def test_generation_zero_is_handled_correctly(self, base_reconciler):
        """Test that generation 0 is handled correctly (new resources)."""
        status = MockStatus()
        status.phase = "Ready"
        status.observedGeneration = 0

        mock_metrics = MagicMock()
        with patch(
            "keycloak_operator.observability.metrics.metrics_collector", mock_metrics
        ):
            result = await base_reconciler.reconcile(
                spec={"test": "data"},
                name="test-resource",
                namespace="test-ns",
                status=status,
                meta={"generation": 0},
            )

            # Generation 0 with Ready phase should still be skipped
            assert result == {}
            mock_metrics.record_reconciliation_skip.assert_called_once()
