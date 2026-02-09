"""
Rate limiting utilities for Keycloak API calls.

Implements a two-level rate limiting strategy:
1. Global rate limit: Protects Keycloak from total overload
2. Per-namespace rate limit: Ensures fair access across teams/namespaces

This prevents:
- Operator restart causing API flood (jitter + global limit)
- Single namespace spamming realms/clients (namespace limit)
- Multiple teams overwhelming Keycloak (global limit)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """
    Async token bucket implementation for rate limiting.

    Uses the token bucket algorithm with continuous token refill.
    Thread-safe via asyncio locks.
    """

    rate: float  # tokens per second
    capacity: int  # maximum burst capacity
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        """Initialize token bucket to full capacity."""
        self.tokens = float(self.capacity)
        self.last_update = time.monotonic()

    async def acquire(self, timeout: float | None = None) -> bool:
        """
        Acquire a token, waiting if necessary.

        Args:
            timeout: Maximum time to wait for token (seconds). None = wait forever.

        Returns:
            True if token acquired, False if timeout reached

        Raises:
            asyncio.TimeoutError: If timeout exceeded (when timeout is set)
        """
        start_time = time.monotonic()

        async with self.lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update

                # Refill tokens based on elapsed time
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_update = now

                # If we have a token, consume it and return
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

                # Calculate wait time for next token
                wait_time = (1.0 - self.tokens) / self.rate

                # Check timeout
                if timeout is not None:
                    elapsed_total = time.monotonic() - start_time
                    remaining = timeout - elapsed_total
                    if remaining <= 0:
                        return False
                    wait_time = min(wait_time, remaining)

                # Wait for token to be available
                await asyncio.sleep(wait_time)

    def available_tokens(self) -> float:
        """Get current number of available tokens (not thread-safe)."""
        now = time.monotonic()
        elapsed = now - self.last_update
        return min(self.capacity, self.tokens + elapsed * self.rate)


class RateLimiter:
    """
    Two-level rate limiter for Keycloak API calls.

    Enforces:
    1. Global rate limit across all namespaces
    2. Per-namespace rate limit for fairness

    Example:
        rate_limiter = RateLimiter(
            global_rate=50.0,  # 50 req/s total
            global_burst=100,
            namespace_rate=5.0,  # 5 req/s per namespace
            namespace_burst=10,
        )

        # In handler
        await rate_limiter.acquire(namespace="team-a")
    """

    def __init__(
        self,
        global_rate: float,
        global_burst: int,
        namespace_rate: float,
        namespace_burst: int,
    ):
        """
        Initialize rate limiter.

        Args:
            global_rate: Global requests per second
            global_burst: Global burst capacity
            namespace_rate: Per-namespace requests per second
            namespace_burst: Per-namespace burst capacity
        """
        self.global_bucket = TokenBucket(global_rate, global_burst)
        self.namespace_buckets: dict[str, TokenBucket] = {}
        self.namespace_rate = namespace_rate
        self.namespace_burst = namespace_burst
        self._namespace_lock = asyncio.Lock()

        logger.info(
            f"Rate limiter initialized: "
            f"global={global_rate} TPS (burst={global_burst}), "
            f"namespace={namespace_rate} TPS (burst={namespace_burst})"
        )

    async def _get_namespace_bucket(self, namespace: str) -> TokenBucket:
        """Get or create token bucket for namespace."""
        # Fast path: bucket already exists
        if namespace in self.namespace_buckets:
            return self.namespace_buckets[namespace]

        # Slow path: create new bucket
        async with self._namespace_lock:
            # Double-check after acquiring lock
            if namespace not in self.namespace_buckets:
                self.namespace_buckets[namespace] = TokenBucket(
                    self.namespace_rate,
                    self.namespace_burst,
                )
                logger.debug(
                    f"Created rate limit bucket for namespace '{namespace}': "
                    f"{self.namespace_rate} TPS"
                )
            return self.namespace_buckets[namespace]

    async def acquire(self, namespace: str, timeout: float = 30.0) -> None:
        """
        Acquire rate limit tokens for both global and namespace buckets.

        This method blocks until tokens are available in BOTH buckets.
        Namespace token is acquired first (more restrictive), then global.

        Args:
            namespace: Origin namespace of the request
            timeout: Maximum time to wait for tokens (seconds)

        Raises:
            TimeoutError: If tokens cannot be acquired within timeout
        """
        start_time = time.monotonic()

        # Acquire namespace token first (more restrictive)
        namespace_bucket = await self._get_namespace_bucket(namespace)
        namespace_start = time.monotonic()
        namespace_acquired = await namespace_bucket.acquire(timeout=timeout)
        namespace_wait = time.monotonic() - namespace_start

        if not namespace_acquired:
            elapsed = time.monotonic() - start_time
            logger.warning(
                f"Namespace rate limit timeout for '{namespace}' after {elapsed:.2f}s"
            )
            # Record timeout metric
            self._record_timeout(namespace, "namespace")
            raise TimeoutError(
                f"Namespace rate limit timeout for '{namespace}' "
                f"(limit: {self.namespace_rate} req/s)"
            )

        # Record namespace wait time
        self._record_wait_time(namespace, "namespace", namespace_wait)
        self._record_acquisition(namespace, "namespace")

        # Calculate remaining timeout
        elapsed = time.monotonic() - start_time
        remaining_timeout = max(0.1, timeout - elapsed)

        # Acquire global token
        global_start = time.monotonic()
        global_acquired = await self.global_bucket.acquire(timeout=remaining_timeout)
        global_wait = time.monotonic() - global_start

        if not global_acquired:
            elapsed = time.monotonic() - start_time
            logger.warning(
                f"Global rate limit timeout after {elapsed:.2f}s "
                f"(namespace: {namespace})"
            )
            # Record timeout metric
            self._record_timeout(namespace, "global")
            raise TimeoutError(
                f"Global rate limit timeout (limit: {self.global_bucket.rate} req/s)"
            )

        # Record global wait time
        self._record_wait_time(namespace, "global", global_wait)
        self._record_acquisition(namespace, "global")

        # Both tokens acquired successfully
        logger.debug(f"Rate limit tokens acquired for namespace '{namespace}'")

        # Record remaining budget for observability
        self._record_budget(namespace)

    def get_metrics(self) -> dict:
        """
        Get current rate limiter state for metrics/observability.

        Returns:
            Dictionary with current state including available tokens
        """
        return {
            "global_tokens": self.global_bucket.available_tokens(),
            "global_rate": self.global_bucket.rate,
            "global_capacity": self.global_bucket.capacity,
            "namespace_count": len(self.namespace_buckets),
            "namespace_rate": self.namespace_rate,
            "namespace_capacity": self.namespace_burst,
            "namespaces": {
                ns: {
                    "tokens": bucket.available_tokens(),
                    "rate": bucket.rate,
                    "capacity": bucket.capacity,
                }
                for ns, bucket in self.namespace_buckets.items()
            },
        }

    async def cleanup_idle_buckets(self, idle_threshold: float = 3600.0) -> int:
        """
        Clean up namespace buckets that haven't been used recently.

        Call this periodically to prevent memory growth from short-lived namespaces.

        Args:
            idle_threshold: Remove buckets idle for this many seconds (default: 1 hour)

        Returns:
            Number of buckets removed
        """
        now = time.monotonic()
        removed = 0

        async with self._namespace_lock:
            to_remove = [
                ns
                for ns, bucket in self.namespace_buckets.items()
                if (now - bucket.last_update) > idle_threshold
            ]

            for ns in to_remove:
                del self.namespace_buckets[ns]
                removed += 1

            if removed > 0:
                logger.info(
                    f"Cleaned up {removed} idle namespace rate limit buckets "
                    f"(threshold: {idle_threshold}s)"
                )

        return removed

    def _record_wait_time(
        self, namespace: str, limit_type: str, duration: float
    ) -> None:
        """Record wait time metric."""
        try:
            from keycloak_operator.observability.metrics import RATE_LIMIT_WAIT_SECONDS

            RATE_LIMIT_WAIT_SECONDS.labels(
                namespace=namespace, limit_type=limit_type
            ).observe(duration)
        except Exception:
            pass  # Metrics are optional - gracefully handle import or recording errors

    def _record_acquisition(self, namespace: str, limit_type: str) -> None:
        """Record successful token acquisition."""
        try:
            from keycloak_operator.observability.metrics import (
                RATE_LIMIT_ACQUIRED_TOTAL,
            )

            RATE_LIMIT_ACQUIRED_TOTAL.labels(
                namespace=namespace, limit_type=limit_type
            ).inc()
        except Exception:
            pass  # Metrics are optional - gracefully handle errors

    def _record_timeout(self, namespace: str, limit_type: str) -> None:
        """Record rate limit timeout."""
        try:
            from keycloak_operator.observability.metrics import (
                RATE_LIMIT_TIMEOUTS_TOTAL,
            )

            RATE_LIMIT_TIMEOUTS_TOTAL.labels(
                namespace=namespace, limit_type=limit_type
            ).inc()
        except Exception:
            pass  # Metrics are optional - gracefully handle errors

    def _record_budget(self, namespace: str) -> None:
        """Record remaining rate limit budget after acquisition."""
        try:
            from keycloak_operator.observability.metrics import (
                RATE_LIMIT_BUDGET_AVAILABLE,
            )

            RATE_LIMIT_BUDGET_AVAILABLE.labels(
                namespace=namespace,
            ).set(self.global_bucket.available_tokens())
        except Exception:
            pass  # Metrics are optional
