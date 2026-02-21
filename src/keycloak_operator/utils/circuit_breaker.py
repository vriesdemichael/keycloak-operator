"""
Circuit breaker implementation for Keycloak API calls.

This module provides a wrapper around aiobreaker to protect the operator
from overloaded Keycloak instances. It integrates with Prometheus metrics
to track the circuit state.
"""

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any, TypeVar

import aiobreaker
from aiobreaker.state import CircuitHalfOpenState, CircuitOpenState
from opentelemetry import trace

from keycloak_operator.observability.metrics import CIRCUIT_BREAKER_STATE

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

T = TypeVar("T")


class KeycloakCircuitBreaker:
    """
    Circuit breaker wrapper for Keycloak Admin API client.

    Wraps aiobreaker.CircuitBreaker and updates Prometheus metrics
    on state changes.
    """

    def __init__(
        self,
        name: str,
        namespace: str,
        fail_max: int,
        timeout_duration: int,
    ):
        """
        Initialize circuit breaker.

        Args:
            name: Keycloak instance name
            namespace: Keycloak instance namespace
            fail_max: Number of failures before opening the circuit
            timeout_duration: Seconds to wait before attempting recovery (half-open)
        """
        self.name = name
        self.namespace = namespace

        # Define state listener to update metrics
        class MetricsListener(aiobreaker.CircuitBreakerListener):
            def state_change(self, breaker, old, new):
                try:
                    # Robustly get state name for logging
                    old_name = getattr(old, "name", type(old).__name__)
                    new_name = getattr(new, "name", type(new).__name__)

                    logger.warning(
                        f"Circuit breaker state changed: {old_name} -> {new_name} "
                        f"(instance={name}, namespace={namespace})"
                    )

                    # Map state to metric value
                    # 0 = Closed (Healthy)
                    # 1 = Open (Broken)
                    # 2 = Half-Open (Recovering)
                    state_value = 0

                    if (
                        isinstance(new, CircuitOpenState)
                        or getattr(new, "name", "").lower() == "open"
                    ):
                        state_value = 1
                    elif (
                        isinstance(new, CircuitHalfOpenState)
                        or getattr(new, "name", "").lower() == "half-open"
                    ):
                        state_value = 2

                    CIRCUIT_BREAKER_STATE.labels(
                        keycloak_instance=name,
                        keycloak_namespace=namespace,
                    ).set(state_value)
                except Exception as e:
                    # Log error but don't crash
                    logger.error(f"Error in circuit breaker listener: {e}")

        self._breaker = aiobreaker.CircuitBreaker(
            fail_max=fail_max,
            timeout_duration=timedelta(seconds=timeout_duration),
            listeners=[MetricsListener()],
        )

        # Initialize metric
        CIRCUIT_BREAKER_STATE.labels(
            keycloak_instance=name,
            keycloak_namespace=namespace,
        ).set(0)

    async def call(self, func: Callable[..., Any], *args, **kwargs) -> Any:
        """
        Call a function with circuit breaker protection.

        Args:
            func: Async function to call
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            Result of the function call

        Raises:
            aiobreaker.CircuitBreakerError: If the circuit is open
            Exception: Whatever the function raises
        """
        with tracer.start_as_current_span("circuit_breaker_call") as span:
            span.set_attribute("circuit_breaker.name", self.name)
            span.set_attribute("circuit_breaker.state", self.current_state)

            try:
                return await self._breaker.call_async(func, *args, **kwargs)
            except aiobreaker.CircuitBreakerError:
                span.set_attribute("error", True)
                span.set_attribute("circuit_breaker.error", "open")
                raise
            except Exception as e:
                span.set_attribute("error", True)
                span.record_exception(e)
                raise

    @property
    def current_state(self) -> str:
        """Get current state name (lowercase)."""
        return self._breaker.current_state.name.lower()
