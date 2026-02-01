"""
Observability utilities for the Keycloak operator.

This module provides metrics, health checks, structured logging,
and distributed tracing capabilities for production monitoring
and troubleshooting.
"""

from .health import HealthChecker
from .logging import OperatorLogger, setup_structured_logging
from .metrics import MetricsServer, get_metrics_registry
from .tracing import (
    _reset_for_testing,
    get_tracer,
    is_tracing_enabled,
    setup_tracing,
    shutdown_tracing,
    traced_handler,
)

__all__ = [
    # Metrics
    "MetricsServer",
    "get_metrics_registry",
    # Health
    "HealthChecker",
    # Logging
    "OperatorLogger",
    "setup_structured_logging",
    # Tracing
    "setup_tracing",
    "shutdown_tracing",
    "get_tracer",
    "traced_handler",
    "is_tracing_enabled",
    "_reset_for_testing",
]
