import logging

from .adapters import AdapterV24, AdapterV25, AdapterV26
from .base import KeycloakAdapter

logger = logging.getLogger(__name__)


def get_adapter(version: str) -> KeycloakAdapter:
    """
    Factory to get the correct adapter for a Keycloak version.

    Args:
        version: Version string (e.g. "24.0.5", "26.5.2")

    Returns:
        KeycloakAdapter instance
    """
    major = int(version.split(".")[0])

    if major >= 26:
        logger.info(f"Using Keycloak v26 adapter for version {version}")
        return AdapterV26(version)
    elif major == 25:
        logger.info(f"Using Keycloak v25 adapter for version {version}")
        return AdapterV25(version)
    elif major == 24:
        logger.info(f"Using Keycloak v24 adapter for version {version}")
        return AdapterV24(version)
    else:
        logger.warning(
            f"Unsupported Keycloak version {version}. Defaulting to v26 adapter. "
            "Some features may not work."
        )
        return AdapterV26(version)
