"""
OIDC endpoint discovery utilities.

This module provides utilities for constructing standard OIDC/OAuth2 endpoints
for Keycloak realms based on the Keycloak instance's base URL.
"""

import logging

from ..models.keycloak import Keycloak

logger = logging.getLogger(__name__)


def construct_oidc_endpoints(base_url: str, realm_name: str) -> dict[str, str]:
    """
    Construct OIDC endpoint URLs for a Keycloak realm.

    Generates all standard OIDC discovery endpoints based on Keycloak's
    URL structure for the specified realm.

    Args:
        base_url: Base URL of the Keycloak instance (e.g., "https://keycloak.example.com")
        realm_name: Name of the realm

    Returns:
        Dictionary with OIDC endpoint URLs:
        - issuer: OpenID Connect issuer identifier
        - auth: Authorization endpoint
        - token: Token endpoint
        - userinfo: UserInfo endpoint
        - jwks: JSON Web Key Set (JWKS) endpoint
        - endSession: End session (logout) endpoint
        - registration: Dynamic client registration endpoint

    Example:
        >>> construct_oidc_endpoints("https://keycloak.example.com", "my-realm")
        {
            "issuer": "https://keycloak.example.com/realms/my-realm",
            "auth": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/auth",
            ...
        }
    """
    # Remove trailing slash from base URL if present
    base_url = base_url.rstrip("/")

    # Construct the realm base path
    realm_base = f"{base_url}/realms/{realm_name}"
    oidc_base = f"{realm_base}/protocol/openid-connect"

    return {
        "issuer": realm_base,
        "auth": f"{oidc_base}/auth",
        "token": f"{oidc_base}/token",
        "userinfo": f"{oidc_base}/userinfo",
        "jwks": f"{oidc_base}/certs",
        "endSession": f"{oidc_base}/logout",
        "registration": f"{oidc_base}/registrations",
    }


def get_keycloak_base_url(keycloak: Keycloak) -> str:
    """
    Get Keycloak base URL from Keycloak instance CR.

    Extracts the base URL from the Keycloak instance's status endpoints.
    Falls back to service DNS if endpoints aren't configured yet.

    Args:
        keycloak: Keycloak instance Pydantic model

    Returns:
        Base URL string

    Example:
        >>> get_keycloak_base_url(keycloak_instance)
        "https://keycloak.example.com"
    """
    # Extract metadata for fallback
    namespace = keycloak.metadata.get("namespace", "default")
    name = keycloak.metadata.get("name", "keycloak")

    # Check if status exists
    if not keycloak.status:
        logger.debug(
            f"Keycloak instance {name} has no status yet, using service DNS fallback"
        )
        return f"http://{name}.{namespace}.svc.cluster.local:8080"

    # Priority 1: Use public endpoint (from ingress/route)
    if keycloak.status.endpoints and keycloak.status.endpoints.public:
        return keycloak.status.endpoints.public

    # Priority 2: Use internal cluster endpoint
    if keycloak.status.endpoints and keycloak.status.endpoints.internal:
        return keycloak.status.endpoints.internal

    # Priority 3: Construct from service DNS (fallback)
    logger.debug(
        f"Keycloak instance {name} has no configured endpoints yet, using service DNS"
    )
    return f"http://{name}.{namespace}.svc.cluster.local:8080"
