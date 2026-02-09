"""
Unit tests for rate limiter module.

Tests the token bucket algorithm, two-level rate limiting,
and concurrent access patterns.
"""

import asyncio
import contextlib
import time
from unittest.mock import MagicMock, patch

import pytest

from keycloak_operator.utils.rate_limiter import RateLimiter, TokenBucket


class TestTokenBucket:
    """Test token bucket implementation."""

    @pytest.mark.asyncio
    async def test_token_bucket_initialization(self):
        """Test token bucket initializes with correct capacity."""
        bucket = TokenBucket(rate=10.0, capacity=20)

        assert bucket.rate == 10.0
        assert bucket.capacity == 20
        assert bucket.tokens == 20  # Starts full

    @pytest.mark.asyncio
    async def test_token_bucket_acquire_single(self):
        """Test acquiring a single token."""
        bucket = TokenBucket(rate=10.0, capacity=20)

        # Should succeed immediately
        result = await bucket.acquire(timeout=1.0)
        assert result is True
        assert bucket.tokens == 19  # One token consumed

    @pytest.mark.asyncio
    async def test_token_bucket_acquire_depletes_tokens(self):
        """Test that acquiring tokens depletes the bucket."""
        bucket = TokenBucket(rate=10.0, capacity=5)

        # Acquire all tokens
        for i in range(5):
            result = await bucket.acquire(timeout=0.1)
            assert result is True
            # Tokens may refill slightly between iterations due to timing
            assert bucket.tokens < 5 - i

        # Bucket should be nearly empty (allow for tiny refill)
        assert bucket.tokens < 0.1

    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test that tokens refill over time."""
        bucket = TokenBucket(rate=10.0, capacity=10)  # 10 tokens/second

        # Consume some tokens but not all
        for _ in range(5):
            result = await bucket.acquire(timeout=0.1)
            assert result is True

        # Check available tokens method
        available_before = bucket.available_tokens()

        # Wait for refill (200ms = 2 tokens at 10/s)
        await asyncio.sleep(0.25)

        # Check available tokens after wait
        available_after = bucket.available_tokens()

        # Should have gained at least 2 tokens
        tokens_gained = available_after - available_before
        assert tokens_gained >= 1.5, (
            f"Expected >= 1.5 tokens gained, got {tokens_gained}"
        )

    @pytest.mark.asyncio
    async def test_token_bucket_timeout(self):
        """Test that acquire times out when no tokens available."""
        bucket = TokenBucket(rate=1.0, capacity=1)  # Very slow refill

        # Acquire the only token
        await bucket.acquire(timeout=0.1)
        assert bucket.tokens == 0

        # Second acquire should timeout
        start_time = time.monotonic()
        result = await bucket.acquire(timeout=0.2)
        elapsed = time.monotonic() - start_time

        assert result is False
        assert elapsed >= 0.19  # Should wait full timeout
        assert elapsed <= 0.3  # Allow some overhead

    @pytest.mark.asyncio
    async def test_token_bucket_burst_capacity(self):
        """Test that tokens don't exceed burst capacity."""
        bucket = TokenBucket(rate=100.0, capacity=10)

        # Wait for potential overflow
        await asyncio.sleep(0.2)  # Would generate 20 tokens without cap

        # Tokens should be capped at burst
        assert bucket.tokens <= 10

    @pytest.mark.asyncio
    async def test_token_bucket_concurrent_access(self):
        """Test concurrent token acquisition."""
        bucket = TokenBucket(rate=10.0, capacity=20)

        results = []

        async def acquire_token():
            result = await bucket.acquire(timeout=1.0)
            results.append(result)

        # Launch 20 concurrent acquisitions (exactly burst capacity)
        tasks = [acquire_token() for _ in range(20)]
        await asyncio.gather(*tasks)

        # All should succeed
        assert all(results)
        assert len(results) == 20
        # Bucket should be nearly empty (allow for tiny refill during execution)
        assert bucket.tokens < 0.5

    @pytest.mark.asyncio
    async def test_token_bucket_concurrent_timeout(self):
        """Test concurrent access beyond capacity."""
        bucket = TokenBucket(rate=1.0, capacity=5)

        results = []

        async def acquire_token():
            result = await bucket.acquire(timeout=0.1)
            results.append(result)

        # Try to acquire 10 tokens but only 5 available
        tasks = [acquire_token() for _ in range(10)]
        await asyncio.gather(*tasks)

        # First 5 should succeed, rest should timeout
        successful = sum(1 for r in results if r)
        failed = sum(1 for r in results if not r)

        assert successful == 5
        assert failed == 5


class TestRateLimiter:
    """Test RateLimiter with two-level rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limiter_initialization(self):
        """Test rate limiter initializes correctly."""
        limiter = RateLimiter(
            global_rate=50.0,
            global_burst=100,
            namespace_rate=5.0,
            namespace_burst=10,
        )

        assert limiter.global_bucket.rate == 50.0
        assert limiter.global_bucket.capacity == 100
        assert limiter.namespace_rate == 5.0
        assert limiter.namespace_burst == 10
        assert len(limiter.namespace_buckets) == 0

    @pytest.mark.asyncio
    async def test_rate_limiter_acquire_single_namespace(self):
        """Test acquiring tokens for a single namespace."""
        limiter = RateLimiter(
            global_rate=50.0,
            global_burst=100,
            namespace_rate=5.0,
            namespace_burst=10,
        )

        # Should succeed
        await limiter.acquire("test-namespace", timeout=1.0)

        # Namespace bucket should be created
        assert "test-namespace" in limiter.namespace_buckets

    @pytest.mark.asyncio
    async def test_rate_limiter_namespace_isolation(self):
        """Test that different namespaces have separate rate limits."""
        limiter = RateLimiter(
            global_rate=100.0,  # High global limit
            global_burst=200,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        # Deplete namespace-a
        for _ in range(5):
            await limiter.acquire("namespace-a", timeout=0.1)

        # namespace-b should still have tokens
        await limiter.acquire("namespace-b", timeout=0.1)

        # namespace-a should timeout
        with pytest.raises(TimeoutError):
            await limiter.acquire("namespace-a", timeout=0.1)

    @pytest.mark.asyncio
    async def test_rate_limiter_global_limit_enforcement(self):
        """Test that global rate limit is enforced across namespaces."""
        limiter = RateLimiter(
            global_rate=5.0,  # Lower rate for more predictable timeout
            global_burst=10,
            namespace_rate=20.0,  # Higher namespace limit
            namespace_burst=20,
        )

        # Use multiple namespaces to hit global limit
        namespaces = [f"ns-{i}" for i in range(5)]

        # Acquire 2 tokens from each namespace (10 total = global burst)
        for ns in namespaces:
            await limiter.acquire(ns, timeout=0.1)
            await limiter.acquire(ns, timeout=0.1)

        # Global bucket is now depleted (10 tokens used, capacity=10)
        # Next acquisition should timeout immediately
        with pytest.raises(TimeoutError):
            await limiter.acquire("ns-0", timeout=0.05)

    @pytest.mark.asyncio
    async def test_rate_limiter_timeout_error(self):
        """Test that timeout raises TimeoutError."""
        limiter = RateLimiter(
            global_rate=1.0,
            global_burst=1,
            namespace_rate=1.0,
            namespace_burst=1,
        )

        # First acquire succeeds
        await limiter.acquire("test", timeout=1.0)

        # Second should timeout
        with pytest.raises(TimeoutError) as exc_info:
            await limiter.acquire("test", timeout=0.1)

        assert "rate limit timeout" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_rate_limiter_cleanup_idle_buckets(self):
        """Test that idle namespace buckets are cleaned up."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,  # Very short for testing
        )

        # Create buckets for multiple namespaces
        await limiter.acquire("ns-1", timeout=1.0)
        await limiter.acquire("ns-2", timeout=1.0)
        await limiter.acquire("ns-3", timeout=1.0)

        assert len(limiter.namespace_buckets) == 3

        # Manually set last_update to simulate idle time (4000 seconds ago)
        import time

        old_time = time.monotonic() - 4000
        limiter.namespace_buckets["ns-2"].last_update = old_time
        limiter.namespace_buckets["ns-3"].last_update = old_time

        # Keep one namespace active
        await limiter.acquire("ns-1", timeout=1.0)

        # Trigger cleanup with 3600s threshold
        removed = await limiter.cleanup_idle_buckets(idle_threshold=3600.0)

        # Should have removed idle buckets
        assert removed >= 2
        assert "ns-1" in limiter.namespace_buckets  # Still active

    @pytest.mark.asyncio
    async def test_rate_limiter_concurrent_namespace_access(self):
        """Test concurrent access to same namespace."""
        limiter = RateLimiter(
            global_rate=100.0,
            global_burst=100,
            namespace_rate=10.0,
            namespace_burst=10,
        )

        results = []

        async def acquire():
            try:
                # Use very short timeout to minimize refill during execution
                await limiter.acquire("shared-ns", timeout=0.05)
                results.append(True)
            except TimeoutError:
                results.append(False)

        # Launch 15 concurrent acquisitions
        tasks = [acquire() for _ in range(15)]
        await asyncio.gather(*tasks)

        successful = sum(1 for r in results if r)

        # Burst is 10, so approximately 10 should succeed
        # Allow some variance for timing/refill (8-12 range)
        assert 8 <= successful <= 12
        assert len(results) == 15

    @pytest.mark.asyncio
    @patch("keycloak_operator.utils.rate_limiter.logger")
    async def test_rate_limiter_logging(self, mock_logger):
        """Test that rate limiter logs appropriately."""
        limiter = RateLimiter(
            global_rate=1.0,
            global_burst=1,
            namespace_rate=1.0,
            namespace_burst=1,
        )

        # Acquire token
        await limiter.acquire("test-ns", timeout=0.5)

        # Verify debug log was called
        mock_logger.debug.assert_called()

        # Try to acquire when depleted
        with contextlib.suppress(TimeoutError):
            await limiter.acquire("test-ns", timeout=0.1)

        # Verify warning was logged
        mock_logger.warning.assert_called()


class TestRateLimiterMetrics:
    """Test rate limiter metrics integration."""

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.observability.metrics.RATE_LIMIT_WAIT_SECONDS", MagicMock()
    )
    @patch(
        "keycloak_operator.observability.metrics.RATE_LIMIT_ACQUIRED_TOTAL", MagicMock()
    )
    async def test_rate_limiter_records_metrics(self):
        """Test that metrics are recorded on acquisition."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        # Acquire token
        await limiter.acquire("test-ns", timeout=1.0)

        # Metrics should have been called (verify via mock if needed)
        # This is a smoke test that metrics integration doesn't break

    @pytest.mark.asyncio
    @patch(
        "keycloak_operator.observability.metrics.RATE_LIMIT_TIMEOUTS_TOTAL", MagicMock()
    )
    async def test_rate_limiter_records_timeout_metrics(self):
        """Test that timeout metrics are recorded."""
        limiter = RateLimiter(
            global_rate=1.0,
            global_burst=1,
            namespace_rate=1.0,
            namespace_burst=1,
        )

        # Deplete tokens
        await limiter.acquire("test-ns", timeout=0.5)

        # Timeout
        with contextlib.suppress(TimeoutError):
            await limiter.acquire("test-ns", timeout=0.1)

        # Timeout metric should have been recorded


class TestRateLimiterEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_rate_limiter_zero_timeout(self):
        """Test behavior with zero timeout."""
        limiter = RateLimiter(
            global_rate=1.0,
            global_burst=1,
            namespace_rate=1.0,
            namespace_burst=1,
        )

        # First acquire should succeed even with zero timeout
        # (tokens available immediately)
        await limiter.acquire("test", timeout=0.0)

        # Second should fail immediately
        with pytest.raises(TimeoutError):
            await limiter.acquire("test", timeout=0.0)

    @pytest.mark.asyncio
    async def test_rate_limiter_very_high_rate(self):
        """Test with very high rate limits."""
        limiter = RateLimiter(
            global_rate=1000.0,
            global_burst=2000,
            namespace_rate=1000.0,
            namespace_burst=2000,
        )

        # Should handle many rapid acquisitions
        for _ in range(100):
            await limiter.acquire("test", timeout=0.1)

    @pytest.mark.asyncio
    async def test_rate_limiter_special_namespace_names(self):
        """Test with special namespace names."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        # Test various namespace names
        special_names = [
            "default",
            "kube-system",
            "namespace-with-dashes",
            "namespace_with_underscores",
            "namespace123",
            "very-long-namespace-name-that-exceeds-normal-length-limits",
        ]

        for ns in special_names:
            await limiter.acquire(ns, timeout=0.5)
            assert ns in limiter.namespace_buckets

    @pytest.mark.asyncio
    async def test_token_bucket_negative_tokens(self):
        """Test that tokens don't go negative."""
        bucket = TokenBucket(rate=1.0, capacity=1)

        # Acquire the only token
        await bucket.acquire(timeout=0.1)

        # Tokens should be 0, not negative
        assert bucket.tokens >= 0

    @pytest.mark.asyncio
    async def test_rate_limiter_refill_during_wait(self):
        """Test that tokens refill while waiting."""
        limiter = RateLimiter(
            global_rate=10.0,  # 10 tokens/second = 1 token every 100ms
            global_burst=2,
            namespace_rate=10.0,
            namespace_burst=2,
        )

        # Acquire 2 tokens (deplete)
        await limiter.acquire("test", timeout=0.1)
        await limiter.acquire("test", timeout=0.1)

        # Wait for refill and acquire again
        # Should succeed after ~100ms refill
        await limiter.acquire("test", timeout=0.5)


class TestRecordBudget:
    """Test _record_budget per-namespace token reporting."""

    @pytest.mark.asyncio
    async def test_record_budget_uses_namespace_bucket(self):
        """_record_budget reads available_tokens from the namespace bucket."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        # Acquire a token to create the namespace bucket
        await limiter.acquire("my-ns", timeout=1.0)

        with patch(
            "keycloak_operator.observability.metrics.RATE_LIMIT_BUDGET_AVAILABLE"
        ) as mock_budget:
            limiter._record_budget("my-ns")

            mock_budget.labels.assert_called_with(namespace="my-ns")
            # The set call should receive the available_tokens value
            set_args = mock_budget.labels().set.call_args
            assert set_args is not None
            recorded_value = set_args[0][0]
            # After one acquisition from a 5-capacity bucket, should be ~4
            assert 3.5 < recorded_value <= 5.0

    @pytest.mark.asyncio
    async def test_record_budget_missing_namespace_returns_early(self):
        """_record_budget returns early if namespace bucket doesn't exist."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        with patch(
            "keycloak_operator.observability.metrics.RATE_LIMIT_BUDGET_AVAILABLE"
        ) as mock_budget:
            limiter._record_budget("nonexistent-ns")

            # Should not call .labels() because bucket is None
            mock_budget.labels.assert_not_called()

    @pytest.mark.asyncio
    async def test_record_budget_exception_swallowed(self):
        """_record_budget swallows exceptions gracefully."""
        limiter = RateLimiter(
            global_rate=10.0,
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        await limiter.acquire("my-ns", timeout=1.0)

        with patch(
            "keycloak_operator.observability.metrics.RATE_LIMIT_BUDGET_AVAILABLE"
        ) as mock_budget:
            mock_budget.labels.side_effect = RuntimeError("metric broken")
            # Should not raise
            limiter._record_budget("my-ns")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
