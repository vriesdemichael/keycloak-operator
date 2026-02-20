import asyncio

import pytest
from aiobreaker import CircuitBreakerError

from keycloak_operator.observability.metrics import CIRCUIT_BREAKER_STATE
from keycloak_operator.utils.circuit_breaker import KeycloakCircuitBreaker


@pytest.mark.asyncio
async def test_circuit_breaker_state_transitions():
    """Test circuit breaker state transitions and metrics updates."""

    # Custom exception for testing
    class TestException(Exception):
        pass

    # Setup
    name = "test-instance"
    namespace = "test-namespace"
    fail_max = 2
    timeout_duration = 0.1  # Fast recovery for test

    cb = KeycloakCircuitBreaker(
        name=name,
        namespace=namespace,
        fail_max=fail_max,
        timeout_duration=timeout_duration,
    )

    # Verify initial state (Closed = 0)
    assert cb.current_state == "closed"
    metrics = list(CIRCUIT_BREAKER_STATE.collect())
    sample_value = None
    for metric in metrics:
        for sample in metric.samples:
            if (
                sample.labels["keycloak_instance"] == name
                and sample.labels["keycloak_namespace"] == namespace
            ):
                sample_value = sample.value
                break
    assert sample_value == 0

    # Failing function
    async def failing_func():
        raise TestException("Failed!")

    # Trigger failures to open circuit
    for i in range(fail_max):
        # On the last failure that trips the breaker, it raises CircuitBreakerError
        # wrapping the original exception
        expected_exc = (
            (TestException, CircuitBreakerError) if i == fail_max - 1 else TestException
        )
        with pytest.raises(expected_exc):
            await cb.call(failing_func)

    # Should now be open
    assert cb.current_state == "open"

    # Metric check
    metrics = list(CIRCUIT_BREAKER_STATE.collect())
    sample_value = None
    for metric in metrics:
        for sample in metric.samples:
            if (
                sample.labels["keycloak_instance"] == name
                and sample.labels["keycloak_namespace"] == namespace
            ):
                sample_value = sample.value
                break
    assert sample_value == 1

    # Call should raise CircuitBreakerError immediately
    with pytest.raises(CircuitBreakerError):
        await cb.call(failing_func)

    # Wait for recovery timeout
    await asyncio.sleep(timeout_duration + 0.1)

    # Should be half-open (metric updates on next call attempt)
    # Note: aiobreaker transitions to half-open lazily on next call

    # Successful function
    async def success_func():
        return "Success"

    # Next call should succeed and close circuit
    result = await cb.call(success_func)
    assert result == "Success"

    assert cb.current_state == "closed"

    metrics = list(CIRCUIT_BREAKER_STATE.collect())
    sample_value = None
    for metric in metrics:
        for sample in metric.samples:
            if (
                sample.labels["keycloak_instance"] == name
                and sample.labels["keycloak_namespace"] == namespace
            ):
                sample_value = sample.value
                break
    assert sample_value == 0


@pytest.mark.asyncio
async def test_circuit_breaker_passthrough():
    """Test that circuit breaker passes return values and exceptions."""
    cb = KeycloakCircuitBreaker("test", "ns", 5, 1)

    # Test return value
    async def ok_func():
        return "OK"

    assert await cb.call(ok_func) == "OK"

    # Test exception passthrough
    async def err_func():
        raise ValueError("Error")

    with pytest.raises(ValueError):
        await cb.call(err_func)
