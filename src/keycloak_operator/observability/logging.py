"""
Structured logging utilities for the Keycloak operator.

This module provides correlation ID tracking, structured log formatting,
and audit logging capabilities for better production troubleshooting.
"""

import logging
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variable for tracking correlation IDs across async operations
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

# Paths that should be filtered from access logs (health probes)
HEALTH_PROBE_PATHS = frozenset({"/healthz", "/health", "/ready", "/metrics"})


class HealthProbeFilter(logging.Filter):
    """
    Logging filter that suppresses health probe and metrics endpoint logs.

    These endpoints are hit frequently by Kubernetes probes and monitoring
    systems, generating excessive noise in logs during debugging.
    """

    def __init__(self, suppress_health_logs: bool = True):
        """
        Initialize health probe filter.

        Args:
            suppress_health_logs: If True, filter out health probe logs
        """
        super().__init__()
        self.suppress_health_logs = suppress_health_logs

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter out health probe related log messages.

        Args:
            record: The log record to process

        Returns:
            False to suppress the record, True to allow it
        """
        if not self.suppress_health_logs:
            return True

        # Check if the message contains health probe paths
        message = record.getMessage()
        return all(path not in message for path in HEALTH_PROBE_PATHS)


class CorrelationIDFilter(logging.Filter):
    """Logging filter that adds correlation ID to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Add correlation ID to the log record.

        Args:
            record: The log record to process

        Returns:
            True to allow the record to be processed
        """
        # Get correlation ID from context, or generate a new one
        current_correlation_id = correlation_id.get()
        if not current_correlation_id:
            current_correlation_id = generate_correlation_id()
            correlation_id.set(current_correlation_id)

        record.correlation_id = current_correlation_id
        return True


class StructuredFormatter(logging.Formatter):
    """
    Structured JSON formatter for logs with correlation ID support.

    Formats log records as structured JSON for better parsing and analysis
    in production monitoring systems.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record as structured JSON.

        Args:
            record: The log record to format

        Returns:
            JSON-formatted log message
        """
        import json

        # Base log structure
        log_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", ""),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields from the log record
        # Note: extra fields are added as attributes to the record, not as an 'extra' dict
        # We'll handle them in the structured_fields section below

        # Add specific structured fields if present
        structured_fields = [
            "resource_type",
            "resource_name",
            "namespace",
            "operation",
            "duration",
            "error_type",
            "audit",
            "database_type",
            "cluster_name",
            "payload_preview",
            "keycloak_instance",
            "realm_name",
            "http_status",
            "response_body",
        ]

        for field in structured_fields:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)

        return json.dumps(log_data)


def generate_correlation_id() -> str:
    """
    Generate a new correlation ID.

    Returns:
        Unique correlation ID string
    """
    return str(uuid.uuid4())[:8]  # Short 8-character ID for readability


def set_correlation_id(corr_id: str) -> str:
    """
    Set the correlation ID for the current context.

    Args:
        corr_id: Correlation ID to set

    Returns:
        The correlation ID that was set
    """
    correlation_id.set(corr_id)
    return corr_id


def get_correlation_id() -> str:
    """
    Get the current correlation ID.

    Returns:
        Current correlation ID, or empty string if none set
    """
    return correlation_id.get("")


def setup_structured_logging(
    log_level: str = "INFO",
    enable_json_formatting: bool = True,
    correlation_id_enabled: bool = True,
    log_health_probes: bool = False,
    webhook_log_level: str = "WARNING",
) -> None:
    """
    Set up structured logging for the operator.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        enable_json_formatting: Whether to use JSON formatting
        correlation_id_enabled: Whether to enable correlation ID tracking
        log_health_probes: Whether to log health probe requests (default: False)
        webhook_log_level: Log level for webhook-related loggers
    """
    # Get root logger
    root_logger = logging.getLogger()

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create new handler
    handler = logging.StreamHandler()

    if enable_json_formatting:
        # Use structured JSON formatter
        formatter = StructuredFormatter()
    else:
        # Use standard formatter with correlation ID
        if correlation_id_enabled:
            formatter = logging.Formatter(
                "%(asctime)s - %(correlation_id)s - %(name)s - %(levelname)s - %(message)s"
            )
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

    handler.setFormatter(formatter)

    # Add correlation ID filter if enabled
    if correlation_id_enabled:
        handler.addFilter(CorrelationIDFilter())

    # Add health probe filter to suppress noisy probe logs
    if not log_health_probes:
        handler.addFilter(HealthProbeFilter(suppress_health_logs=True))

    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Set specific logger levels for third-party libraries
    logging.getLogger("kopf").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("kubernetes").setLevel(logging.WARNING)

    # Suppress aiohttp access logs which spam with probe requests
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.server").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.web").setLevel(logging.WARNING)

    # Set webhook log level (for admission webhook handlers)
    webhook_level = getattr(logging, webhook_log_level.upper(), logging.WARNING)
    logging.getLogger("keycloak_operator.webhooks").setLevel(webhook_level)
    logging.getLogger("keycloak_operator.webhooks.client").setLevel(webhook_level)
    logging.getLogger("keycloak_operator.webhooks.realm").setLevel(webhook_level)
    logging.getLogger("keycloak_operator.webhooks.keycloak").setLevel(webhook_level)


class OperatorLogger:
    """
    Enhanced logger for operator operations with structured logging support.

    Provides convenient methods for logging common operator events
    with proper correlation ID tracking and structured data.
    """

    def __init__(self, name: str):
        """
        Initialize operator logger.

        Args:
            name: Logger name (usually the class name)
        """
        self.logger = logging.getLogger(name)

    def log_reconciliation_start(
        self,
        resource_type: str,
        resource_name: str,
        namespace: str,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log the start of a reconciliation operation.

        Args:
            resource_type: Type of resource being reconciled
            resource_name: Name of the resource
            namespace: Namespace of the resource
            correlation_id: Optional correlation ID (will generate if not provided)

        Returns:
            The correlation ID used for this operation
        """
        if correlation_id is None:
            correlation_id = generate_correlation_id()

        set_correlation_id(correlation_id)

        self.logger.info(
            f"Starting reconciliation for {resource_type} {resource_name}",
            extra={
                "resource_type": resource_type,
                "resource_name": resource_name,
                "namespace": namespace,
                "operation": "reconcile_start",
            },
        )

        return correlation_id

    def log_reconciliation_success(
        self, resource_type: str, resource_name: str, namespace: str, duration: float
    ) -> None:
        """
        Log successful reconciliation completion.

        Args:
            resource_type: Type of resource
            resource_name: Name of the resource
            namespace: Namespace of the resource
            duration: Reconciliation duration in seconds
        """
        self.logger.info(
            f"Reconciliation completed successfully for {resource_type} {resource_name}",
            extra={
                "resource_type": resource_type,
                "resource_name": resource_name,
                "namespace": namespace,
                "operation": "reconcile_success",
                "duration": duration,
            },
        )

    def log_reconciliation_error(
        self,
        resource_type: str,
        resource_name: str,
        namespace: str,
        error: Exception,
        duration: float,
    ) -> None:
        """
        Log reconciliation error.

        Args:
            resource_type: Type of resource
            resource_name: Name of the resource
            namespace: Namespace of the resource
            error: The error that occurred
            duration: Reconciliation duration in seconds
        """
        self.logger.error(
            f"Reconciliation failed for {resource_type} {resource_name}: {str(error)}",
            extra={
                "resource_type": resource_type,
                "resource_name": resource_name,
                "namespace": namespace,
                "operation": "reconcile_error",
                "error_type": type(error).__name__,
                "duration": duration,
            },
            exc_info=True,
        )

    def log_database_operation(
        self,
        operation: str,
        database_type: str,
        resource_name: str,
        namespace: str,
        success: bool,
        duration: float | None = None,
        error: str | None = None,
    ) -> None:
        """
        Log database operations.

        Args:
            operation: Database operation (connect, test, migrate, etc.)
            database_type: Type of database
            resource_name: Name of the Keycloak resource
            namespace: Namespace
            success: Whether the operation succeeded
            duration: Operation duration in seconds
            error: Error message if operation failed
        """
        level = logging.INFO if success else logging.ERROR
        message = f"Database {operation} {'succeeded' if success else 'failed'} for {resource_name}"

        extra_data = {
            "resource_name": resource_name,
            "namespace": namespace,
            "operation": f"database_{operation}",
            "database_type": database_type,
            "success": success,
        }

        if duration is not None:
            extra_data["duration"] = duration

        if error:
            extra_data["error"] = error

        self.logger.log(level, message, extra=extra_data)

    def log_rbac_audit(
        self,
        operation: str,
        source_namespace: str,
        target_namespace: str,
        resource_name: str,
        success: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Log RBAC audit events.

        Args:
            operation: RBAC operation being performed
            source_namespace: Source namespace
            target_namespace: Target namespace
            resource_name: Name of the resource being accessed
            success: Whether the operation was allowed
            details: Additional audit details
        """
        level = logging.INFO if success else logging.WARNING
        message = f"RBAC {operation} {'allowed' if success else 'denied'}: {source_namespace} -> {target_namespace}"

        audit_data = {
            "audit_event": "rbac_validation",
            "operation": operation,
            "source_namespace": source_namespace,
            "target_namespace": target_namespace,
            "resource_name": resource_name,
            "success": success,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        if details:
            audit_data.update(details)

        self.logger.log(level, message, extra={"audit": audit_data})

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with extra data."""
        self.logger.debug(message, extra=kwargs)

    def info(self, message: str, **kwargs) -> None:
        """Log info message with extra data."""
        self.logger.info(message, extra=kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with extra data."""
        self.logger.warning(message, extra=kwargs)

    def error(self, message: str, exc_info: bool = False, **kwargs) -> None:
        """Log error message with extra data."""
        self.logger.error(message, exc_info=exc_info, extra=kwargs)
