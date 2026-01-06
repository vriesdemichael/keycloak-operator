"""
Unit tests for BaseReconciler cleanup functionality.

Tests the cleanup_with_timeout and related methods added for
robust finalizer handling.
"""

import asyncio
from unittest.mock import patch

import pytest

from keycloak_operator.errors import TemporaryError
from keycloak_operator.services.base_reconciler import BaseReconciler


class ConcreteReconciler(BaseReconciler):
    """Concrete implementation for testing."""

    async def do_reconcile(self, spec, name, namespace, status, **kwargs):
        return {}


@pytest.fixture
def reconciler():
    """Create a test reconciler instance."""
    return ConcreteReconciler()


class TestCleanupWithTimeout:
    """Tests for cleanup_with_timeout method."""

    @pytest.mark.asyncio
    async def test_successful_cleanup(self, reconciler):
        """Test that successful cleanup completes normally."""
        cleanup_called = False

        async def cleanup_func():
            nonlocal cleanup_called
            cleanup_called = True

        await reconciler.cleanup_with_timeout(
            cleanup_func=cleanup_func,
            resource_type="realm",
            name="test-realm",
            namespace="test-ns",
            timeout=10,
            retry_count=0,
        )

        assert cleanup_called

    @pytest.mark.asyncio
    async def test_cleanup_timeout_raises_temporary_error(self, reconciler):
        """Test that timeout raises TemporaryError."""

        async def slow_cleanup():
            await asyncio.sleep(10)  # This will timeout

        with pytest.raises(TemporaryError) as exc_info:
            await reconciler.cleanup_with_timeout(
                cleanup_func=slow_cleanup,
                resource_type="realm",
                name="test-realm",
                namespace="test-ns",
                timeout=0.1,  # Very short timeout
                retry_count=1,
            )

        assert "Cleanup timeout" in str(exc_info.value)
        assert "test-realm" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cleanup_exception_propagates(self, reconciler):
        """Test that exceptions from cleanup are propagated."""

        async def failing_cleanup():
            raise ValueError("Cleanup failed!")

        with pytest.raises(ValueError) as exc_info:
            await reconciler.cleanup_with_timeout(
                cleanup_func=failing_cleanup,
                resource_type="client",
                name="test-client",
                namespace="test-ns",
                timeout=10,
                retry_count=2,
            )

        assert "Cleanup failed!" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cleanup_logs_structured_context(self, reconciler):
        """Test that cleanup logs include structured context."""
        log_messages = []

        # Mock the logger to capture structured log calls
        original_info = reconciler.logger.info

        def capture_info(msg, *args, extra=None, **kwargs):
            log_messages.append({"msg": msg, "extra": extra})
            return original_info(msg, *args, **kwargs)

        with patch.object(reconciler.logger, "info", side_effect=capture_info):

            async def cleanup_func():
                pass

            await reconciler.cleanup_with_timeout(
                cleanup_func=cleanup_func,
                resource_type="realm",
                name="test-realm",
                namespace="test-ns",
                timeout=10,
                retry_count=3,
            )

        # Check that structured logs include expected fields
        assert len(log_messages) >= 2  # Started and completed

        started_log = log_messages[0]
        assert started_log["extra"] is not None
        assert started_log["extra"]["resource_type"] == "realm"
        assert started_log["extra"]["resource_name"] == "test-realm"
        assert started_log["extra"]["retry_count"] == 3
        assert started_log["extra"]["cleanup_phase"] == "started"

        completed_log = log_messages[1]
        assert completed_log["extra"]["cleanup_phase"] == "completed"
        assert "duration_seconds" in completed_log["extra"]


class TestLogCleanupStep:
    """Tests for log_cleanup_step method."""

    def test_log_cleanup_step_basic(self, reconciler):
        """Test basic cleanup step logging."""
        with patch.object(reconciler.logger, "info") as mock_info:
            reconciler.log_cleanup_step(
                step="Deleting Keycloak resource",
                resource_type="realm",
                name="test-realm",
                namespace="test-ns",
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "Deleting Keycloak resource" in call_args[0][0]
            assert call_args[1]["extra"]["cleanup_step"] == "Deleting Keycloak resource"
            assert call_args[1]["extra"]["resource_type"] == "realm"
            assert call_args[1]["extra"]["cleanup_phase"] == "in_progress"

    def test_log_cleanup_step_with_details(self, reconciler):
        """Test cleanup step logging with additional details."""
        with patch.object(reconciler.logger, "info") as mock_info:
            reconciler.log_cleanup_step(
                step="Deleting clients",
                resource_type="realm",
                name="test-realm",
                namespace="test-ns",
                details={"client_count": 5, "realm_name": "my-realm"},
            )

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert call_args[1]["extra"]["client_count"] == 5
            assert call_args[1]["extra"]["realm_name"] == "my-realm"
