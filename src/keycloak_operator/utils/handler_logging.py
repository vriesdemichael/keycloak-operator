"""Shared logging utilities for kopf handlers.

This module provides common logging functions used across all handler modules
to ensure consistent logging format and behavior.
"""

import logging
from typing import Any

from keycloak_operator.constants import HANDLER_ENTRY_LOG_LEVEL

logger = logging.getLogger(__name__)


def log_handler_entry(
    handler_type: str,
    resource_type: str,
    name: str,
    namespace: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Log handler invocation at configurable level.

    This provides visibility into which handlers are being called,
    useful for debugging issues where handlers appear to not be invoked.

    The log level is controlled by the HANDLER_ENTRY_LOG_LEVEL environment
    variable (default: INFO). Set to DEBUG to reduce noise in production.

    Args:
        handler_type: Type of handler (create, update, delete, resume, create/resume)
        resource_type: Type of resource (keycloakrealm, keycloakclient, keycloak)
        name: Resource name
        namespace: Resource namespace
        extra: Additional context to include in structured log
    """
    log_extra = {
        "handler_type": handler_type,
        "resource_type": resource_type,
        "resource_name": name,
        "namespace": namespace,
        "handler_phase": "invoked",
    }
    if extra:
        log_extra.update(extra)

    logger.log(
        HANDLER_ENTRY_LOG_LEVEL,
        f"Handler invoked: {handler_type} {resource_type}/{name} in {namespace}",
        extra=log_extra,
    )
