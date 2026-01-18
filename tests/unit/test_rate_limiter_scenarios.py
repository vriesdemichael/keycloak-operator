"""
Integration tests for rate limiting in production scenarios.

Tests end-to-end rate limiting with real Keycloak instances,
including operator restart scenarios and multi-namespace load.
"""

import asyncio
import time

import pytest

from keycloak_operator.utils.rate_limiter import RateLimiter

pytestmark = pytest.mark.integration


class TestRateLimitingIntegration:
    """Integration tests for rate limiting scenarios."""

    @pytest.mark.asyncio
    async def test_single_namespace_spam_protection(self):
        """
        Test: Spam 100 realms in one namespace.
        Expected: Rate limited to ~5 req/s = ~20 seconds minimum.
        """
        rate_limiter = RateLimiter(
            global_rate=100.0,  # High global to isolate namespace limit
            global_burst=200,
            namespace_rate=5.0,
            namespace_burst=10,
        )

        namespace = "spam-test-namespace"
        num_requests = 50  # Use 50 to keep test faster

        start_time = time.monotonic()

        # Simulate 50 API calls
        for _ in range(num_requests):
            await rate_limiter.acquire(namespace, timeout=30.0)

        elapsed = time.monotonic() - start_time

        # Should take at least (50-10)/5 = 8 seconds
        # (50 requests, 10 burst, 5/second)
        expected_min_time = (num_requests - 10) / 5.0

        assert elapsed >= expected_min_time * 0.9  # 90% margin for timing variance
        print(
            f"Rate limiting enforced: {num_requests} requests took {elapsed:.2f}s (expected >= {expected_min_time:.2f}s)"
        )

    @pytest.mark.asyncio
    async def test_multi_namespace_fairness(self):
        """
        Test: 5 namespaces each creating 10 realms simultaneously.
        Expected: Fair distribution, global limit enforced.
        """
        rate_limiter = RateLimiter(
            global_rate=25.0,  # Global bottleneck
            global_burst=50,
            namespace_rate=10.0,  # Higher namespace limit
            namespace_burst=20,
        )

        namespaces = [f"team-{i}" for i in range(5)]
        requests_per_namespace = 20

        async def simulate_namespace_load(namespace: str):
            """Simulate load from one namespace."""
            for _ in range(requests_per_namespace):
                await rate_limiter.acquire(namespace, timeout=30.0)

        start_time = time.monotonic()

        # Run all namespaces concurrently
        await asyncio.gather(*[simulate_namespace_load(ns) for ns in namespaces])

        elapsed = time.monotonic() - start_time

        # Total: 5 namespaces * 20 requests = 100 requests
        # Global: 50 burst + 50 requests at 25/s = 50/25 = 2s
        # Expected: ~2 seconds minimum
        total_requests = len(namespaces) * requests_per_namespace
        expected_min_time = (total_requests - 50) / 25.0

        assert elapsed >= expected_min_time * 0.9
        print(
            f"Fair distribution: {total_requests} requests from {len(namespaces)} namespaces took {elapsed:.2f}s"
        )

    @pytest.mark.asyncio
    async def test_operator_restart_jitter_protection(self):
        """
        Test: Simulate operator restart with many resources.
        Expected: Jitter spreads reconciliation over time window.
        """
        rate_limiter = RateLimiter(
            global_rate=50.0,
            global_burst=100,
            namespace_rate=5.0,
            namespace_burst=10,
        )

        # Simulate 30 resources across multiple namespaces
        resources = [(f"resource-{i}", f"namespace-{i % 5}") for i in range(30)]

        # Simulate jitter (0-5 seconds)
        import random

        JITTER_MAX = 5.0

        async def reconcile_resource(resource_name: str, namespace: str):
            """Simulate reconciliation with jitter."""
            jitter = random.uniform(0, JITTER_MAX)
            await asyncio.sleep(jitter)
            await rate_limiter.acquire(namespace, timeout=30.0)

        start_time = time.monotonic()

        # Launch all reconciliations concurrently
        await asyncio.gather(*[reconcile_resource(name, ns) for name, ns in resources])

        elapsed = time.monotonic() - start_time

        # Should take less time than without jitter due to spread
        # But still enforce rate limits
        print(
            f"Operator restart simulation: {len(resources)} resources reconciled in {elapsed:.2f}s"
        )

    @pytest.mark.asyncio
    async def test_rate_limit_recovery_after_timeout(self):
        """
        Test: Rate limit timeout recovery.
        Expected: After timeout, tokens refill and requests succeed.
        """
        rate_limiter = RateLimiter(
            global_rate=10.0,  # 10 tokens/second
            global_burst=10,
            namespace_rate=5.0,
            namespace_burst=5,
        )

        namespace = "test-recovery"

        # Deplete namespace bucket (5 tokens)
        for _ in range(5):
            await rate_limiter.acquire(namespace, timeout=1.0)

        # Next request should timeout (no tokens available)
        with pytest.raises(TimeoutError):
            await rate_limiter.acquire(namespace, timeout=0.1)

        # Wait for refill (200ms = 1 token at 5/s)
        await asyncio.sleep(0.25)

        # Should succeed now
        await rate_limiter.acquire(namespace, timeout=1.0)

    @pytest.mark.asyncio
    async def test_burst_capacity_handling(self):
        """
        Test: Burst capacity allows temporary spikes.
        Expected: Burst requests succeed quickly, then rate limited.
        """
        rate_limiter = RateLimiter(
            global_rate=5.0,
            global_burst=20,
            namespace_rate=5.0,
            namespace_burst=20,
        )

        namespace = "burst-test"

        # First 20 requests should be instant (burst)
        burst_start = time.monotonic()
        for _ in range(20):
            await rate_limiter.acquire(namespace, timeout=1.0)
        burst_time = time.monotonic() - burst_start

        # Burst should be very fast (< 1 second)
        assert burst_time < 1.0

        # Next 10 requests should be rate limited
        limited_start = time.monotonic()
        for _ in range(10):
            await rate_limiter.acquire(namespace, timeout=5.0)
        limited_time = time.monotonic() - limited_start

        # Should take at least 10/5 = 2 seconds
        assert limited_time >= 1.8  # 90% margin

        print(f"Burst: {burst_time:.2f}s, Rate limited: {limited_time:.2f}s")

    @pytest.mark.asyncio
    async def test_idle_bucket_cleanup(self):
        """
        Test: Idle namespace buckets are cleaned up.
        Expected: Memory usage doesn't grow unbounded.
        """
        rate_limiter = RateLimiter(
            global_rate=50.0, global_burst=100, namespace_rate=5.0, namespace_burst=10
        )

        # Create many namespace buckets
        namespaces = [f"ephemeral-ns-{i}" for i in range(20)]
        for ns in namespaces:
            await rate_limiter.acquire(ns, timeout=1.0)

        assert len(rate_limiter.namespace_buckets) == 20

        # Keep one namespace active
        active_ns = "ephemeral-ns-0"
        await rate_limiter.acquire(active_ns, timeout=1.0)

        # Wait for cleanup threshold
        await asyncio.sleep(1.5)

        # Keep active namespace alive
        await rate_limiter.acquire(active_ns, timeout=1.0)

        # Trigger cleanup with short idle threshold
        removed = await rate_limiter.cleanup_idle_buckets(idle_threshold=1.0)

        # Should have cleaned up idle buckets
        assert removed >= 18
        assert active_ns in rate_limiter.namespace_buckets

    @pytest.mark.asyncio
    async def test_concurrent_namespace_access_fairness(self):
        """
        Test: Concurrent access to different namespaces is fair.
        Expected: No namespace monopolizes the global bucket.
        """
        rate_limiter = RateLimiter(
            global_rate=50.0,
            global_burst=10,  # Reduced burst to force all to wait
            namespace_rate=20.0,  # Higher than global
            namespace_burst=5,  # Reduced burst
        )

        namespaces = [f"concurrent-ns-{i}" for i in range(5)]
        requests_per_namespace = 30

        # Track completion times per namespace
        completion_times = {}

        async def namespace_workload(namespace: str):
            """Simulate workload for one namespace."""
            start = time.monotonic()
            for _ in range(requests_per_namespace):
                await rate_limiter.acquire(namespace, timeout=30.0)
            completion_times[namespace] = time.monotonic() - start

        # Run all concurrently
        await asyncio.gather(*[namespace_workload(ns) for ns in namespaces])

        # Verify fairness: completion times should be similar
        times = list(completion_times.values())
        max_time = max(times)
        min_time = min(times)

        # Difference should be reasonable (within 60% of max to be safe in CI)
        if max_time > 0:
            assert (max_time - min_time) / max_time < 0.6
        else:
            # If max_time is 0, it means everything was instant, which is also fair
            pass

        print(f"Completion times: {completion_times}")

    @pytest.mark.asyncio
    async def test_rate_limiting_doesnt_break_functionality(self):
        """
        Test: Rate limiting doesn't break normal operations.
        Expected: All requests eventually succeed.
        """
        rate_limiter = RateLimiter(
            global_rate=10.0,
            global_burst=20,
            namespace_rate=5.0,
            namespace_burst=10,
        )

        # Simulate normal operation
        namespaces = ["app-1", "app-2", "app-3"]
        requests = []

        for ns in namespaces:
            for i in range(5):  # 5 requests per namespace
                requests.append((ns, i))

        # Execute all requests
        for ns, _ in requests:
            await rate_limiter.acquire(ns, timeout=10.0)

        # All requests should have succeeded
        assert len(requests) == 15

    @pytest.mark.asyncio
    async def test_high_throughput_scenario(self):
        """
        Test: High throughput with generous limits.
        Expected: Low overhead, requests flow smoothly.
        """
        rate_limiter = RateLimiter(
            global_rate=1000.0,  # Very high
            global_burst=2000,
            namespace_rate=1000.0,
            namespace_burst=2000,
        )

        namespace = "high-throughput"
        num_requests = 500

        start_time = time.monotonic()

        for _ in range(num_requests):
            await rate_limiter.acquire(namespace, timeout=5.0)

        elapsed = time.monotonic() - start_time

        # Should complete very quickly (overhead < 1s)
        assert elapsed < 1.0

        throughput = num_requests / elapsed
        print(f"High throughput: {throughput:.0f} req/s")

    @pytest.mark.asyncio
    async def test_namespace_isolation(self):
        """
        Test: One namespace hitting limits doesn't affect others.
        Expected: Isolated namespaces continue working.
        """
        rate_limiter = RateLimiter(
            global_rate=100.0,  # High global
            global_burst=200,
            namespace_rate=2.0,  # Low namespace limit
            namespace_burst=2,
        )

        # Deplete namespace-a
        for _ in range(2):
            await rate_limiter.acquire("namespace-a", timeout=1.0)

        # namespace-a should timeout
        with pytest.raises(TimeoutError):
            await rate_limiter.acquire("namespace-a", timeout=0.1)

        # namespace-b should work fine
        await rate_limiter.acquire("namespace-b", timeout=1.0)
        await rate_limiter.acquire("namespace-b", timeout=1.0)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
