"""
Keycloak Admin API client utilities.

This module provides a high-level interface to the Keycloak Admin REST API
for managing Keycloak instances, realms, clients, and other resources.

The client handles:
- Authentication with Keycloak admin credentials
- Session management and token refresh
- Error handling and retry logic
- Type-safe API interactions
- Rate limiting for API protection
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from functools import wraps

# Import RateLimiter - use TYPE_CHECKING to avoid circular import
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel

from keycloak_operator.models.keycloak_api import (
    AdminEventRepresentation,
    AuthenticationExecutionInfoRepresentation,
    AuthenticationFlowRepresentation,
    AuthenticatorConfigRepresentation,
    ClientRepresentation,
    ClientScopeRepresentation,
    ComponentRepresentation,
    GroupRepresentation,
    IdentityProviderMapperRepresentation,
    IdentityProviderRepresentation,
    ProtocolMapperRepresentation,
    RealmRepresentation,
    RequiredActionProviderRepresentation,
    RoleRepresentation,
    UserRepresentation,
)

if TYPE_CHECKING:
    from keycloak_operator.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

# Type variables for decorators
P = ParamSpec("P")
T = TypeVar("T")


# =============================================================================
# API Error Handling Decorators
# =============================================================================
# These decorators centralize error handling patterns for Keycloak API methods,
# ensuring consistent logging and behavior while reducing code duplication.


def api_get_single(
    resource_name: str,
) -> Callable[[Callable[P, Awaitable[T | None]]], Callable[P, Awaitable[T | None]]]:
    """
    Decorator for GET single resource operations.

    Handles common error cases:
    - Returns None on any exception (resource not found or error)
    - Logs errors with consistent format

    Args:
        resource_name: Human-readable resource name for logging (e.g., "client scope")
    """

    def decorator(
        func: Callable[P, Awaitable[T | None]],
    ) -> Callable[P, Awaitable[T | None]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Failed to get {resource_name}: {e}")
                return None

        return wrapper

    return decorator


def api_get_list(
    resource_name: str,
) -> Callable[[Callable[P, Awaitable[list[T]]]], Callable[P, Awaitable[list[T]]]]:
    """
    Decorator for GET list operations.

    Handles common error cases:
    - Returns empty list on any exception
    - Logs errors with consistent format

    Args:
        resource_name: Human-readable resource name for logging (e.g., "client scopes")
    """

    def decorator(
        func: Callable[P, Awaitable[list[T]]],
    ) -> Callable[P, Awaitable[list[T]]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> list[T]:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Failed to get {resource_name}: {e}")
                return []

        return wrapper

    return decorator


def api_create(
    resource_name: str,
    conflict_is_success: bool = True,
) -> Callable[[Callable[P, Awaitable[str | None]]], Callable[P, Awaitable[str | None]]]:
    """
    Decorator for CREATE operations.

    Handles common error cases:
    - 409 Conflict: Optionally treated as success (resource exists)
    - Other errors: Returns None

    Args:
        resource_name: Human-readable resource name for logging
        conflict_is_success: If True, 409 returns None gracefully (idempotent create)
    """

    def decorator(
        func: Callable[P, Awaitable[str | None]],
    ) -> Callable[P, Awaitable[str | None]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> str | None:
            try:
                return await func(*args, **kwargs)
            except KeycloakAdminError as e:
                if e.status_code == 409 and conflict_is_success:
                    logger.warning(f"{resource_name} already exists")
                    return None  # Caller should look up existing resource if needed
                logger.error(f"Failed to create {resource_name}: {e}")
                return None
            except Exception as e:
                logger.error(f"Failed to create {resource_name}: {e}")
                return None

        return wrapper

    return decorator


def api_update(
    resource_name: str,
    conflict_is_success: bool = False,
) -> Callable[[Callable[P, Awaitable[bool]]], Callable[P, Awaitable[bool]]]:
    """
    Decorator for UPDATE operations.

    Handles common error cases:
    - 409 Conflict: Optionally treated as success (idempotent add)
    - Other errors: Returns False
    - Logs errors with consistent format

    Args:
        resource_name: Human-readable resource name for logging
        conflict_is_success: If True, treat 409 Conflict as success (already exists)
    """

    def decorator(func: Callable[P, Awaitable[bool]]) -> Callable[P, Awaitable[bool]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> bool:
            try:
                return await func(*args, **kwargs)
            except KeycloakAdminError as e:
                if e.status_code == 409 and conflict_is_success:
                    logger.warning(f"{resource_name} already exists/assigned")
                    return True  # Idempotent success
                logger.error(f"Failed to update {resource_name}: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to update {resource_name}: {e}")
                return False

        return wrapper

    return decorator


def api_delete(
    resource_name: str,
    not_found_is_success: bool = True,
) -> Callable[[Callable[P, Awaitable[bool]]], Callable[P, Awaitable[bool]]]:
    """
    Decorator for DELETE operations.

    Handles common error cases:
    - 404 Not Found: Optionally treated as success (idempotent delete)
    - Other errors: Returns False

    Args:
        resource_name: Human-readable resource name for logging
        not_found_is_success: If True, 404 returns True (idempotent delete)
    """

    def decorator(func: Callable[P, Awaitable[bool]]) -> Callable[P, Awaitable[bool]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> bool:
            try:
                return await func(*args, **kwargs)
            except KeycloakAdminError as e:
                if e.status_code == 404 and not_found_is_success:
                    logger.warning(f"{resource_name} not found, already deleted")
                    return True
                logger.error(f"Failed to delete {resource_name}: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to delete {resource_name}: {e}")
                return False

        return wrapper

    return decorator


# Global cache for httpx clients - one per Keycloak instance
# Key: (server_url, verify_ssl), Value: (httpx.AsyncClient, event_loop_id)
# We track the event loop ID to detect when a client was created in a different loop
_httpx_client_cache: dict[tuple[str, bool], tuple[httpx.AsyncClient, int]] = {}
_cache_lock = asyncio.Lock()


class KeycloakAdminError(Exception):
    """Base exception for Keycloak Admin API errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body

    def body_preview(self, limit: int = 2048) -> str | None:
        """Return a truncated preview of the response body for logging."""

        if self.response_body is None:
            return None

        if len(self.response_body) <= limit:
            return self.response_body

        return f"{self.response_body[:limit]}...<truncated>"


class KeycloakAdminClient:
    """
        High-level client for Keycloak Admin API operations.

        This client provides methods for managing Keycloak resources including
        realms, clients, users, and configuration. It handles authentication,
        session management, and provides a clean interface for the operator.

    This client provides comprehensive Keycloak Admin API operations with
        authentication, error handling, and retry logic.
    """

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        realm: str = "master",
        client_id: str = "admin-cli",
        verify_ssl: bool = True,
        timeout: int = 60,
        rate_limiter: "RateLimiter | None" = None,
    ) -> None:
        """
        Initialize Keycloak Admin client.

        Args:
            server_url: Base URL of the Keycloak server
            username: Admin username
            password: Admin password
            realm: Admin realm (default: master)
            client_id: Client ID for admin API access
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            rate_limiter: Optional rate limiter for API call throttling
        """
        self.server_url = server_url.rstrip("/")
        self.username = username
        self.password = password
        self.admin_realm = realm
        self.client_id = client_id
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.rate_limiter = rate_limiter

        # Authentication state
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expires_at: float | None = None

        logger.info(f"Initialized Keycloak Admin client for {server_url}")

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx client (lazy initialization with caching).

        The client is cached per (server_url, verify_ssl) combination.
        We also track the event loop ID to detect when a cached client was
        created in a different event loop (which can happen in tests).
        """
        cache_key = (self.server_url, self.verify_ssl)
        current_loop_id = id(asyncio.get_running_loop())

        # Check if we have a cached client
        async with _cache_lock:
            if cache_key in _httpx_client_cache:
                cached_client, loop_id = _httpx_client_cache[cache_key]
                # Reuse client only if it's not closed AND was created in the same event loop
                if not cached_client.is_closed and loop_id == current_loop_id:
                    return cached_client
                else:
                    # Client is closed or from a different event loop - remove from cache
                    # Don't try to close it as that might fail if the loop is closed
                    del _httpx_client_cache[cache_key]
                    logger.debug(
                        f"Discarding stale httpx client for {self.server_url} "
                        f"(closed={cached_client.is_closed}, loop_mismatch={loop_id != current_loop_id})"
                    )

            # Create new httpx client with connection pooling and timeouts
            client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(
                    max_connections=100,  # Global connection pool
                    max_keepalive_connections=20,  # Keepalive pool
                ),
                headers={
                    "Content-Type": "application/json",
                },
                follow_redirects=False,
            )

            # Cache the client with the current event loop ID
            _httpx_client_cache[cache_key] = (client, current_loop_id)
            logger.debug(f"Created and cached httpx client for {self.server_url}")
            return client

    async def close(self) -> None:
        """
        Close method for compatibility with async context manager.

        Note: With the caching strategy, we don't actually close the httpx client
        here as it's shared across multiple KeycloakAdminClient instances.
        The cached client will be reused until the operator shuts down.
        """
        # Clear authentication tokens but don't close the shared httpx client
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None

    async def __aenter__(self) -> "KeycloakAdminClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit - ensures session cleanup."""
        await self.close()

    async def authenticate(self) -> None:
        """
        Authenticate with Keycloak and obtain access tokens.

        Uses username/password grant to obtain access and refresh tokens.
        """
        auth_url = (
            f"{self.server_url}/realms/{self.admin_realm}/protocol/openid-connect/token"
        )

        auth_data = {
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
            "client_id": self.client_id,
        }

        try:
            client = await self._get_client()

            # Make authentication request
            # Use data parameter for form-urlencoded data
            response = await client.post(
                auth_url,
                data=auth_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            # Store tokens
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")

            # Calculate expiration time
            self.token_expires_at = time.time() + token_data.get("expires_in", 300)

            logger.debug("Successfully authenticated with Keycloak")

        except httpx.HTTPError as e:
            logger.error(f"Failed to authenticate with Keycloak: {e}")
            raise KeycloakAdminError(f"Authentication failed: {e}") from e

    async def _ensure_authenticated(self) -> None:
        """
        Ensure we have a valid access token, refreshing if necessary.
        """
        # If no token or token is expired (with 30s buffer)
        if not self.access_token or (
            self.token_expires_at and time.time() >= self.token_expires_at - 30
        ):
            if self.refresh_token:
                try:
                    # Try to refresh token
                    await self._refresh_token()
                except KeycloakAdminError:
                    # Refresh failed, re-authenticate
                    await self.authenticate()
            else:
                # No refresh token, re-authenticate
                await self.authenticate()

    async def _refresh_token(self) -> None:
        """
        Refresh the access token using the refresh token.
        """
        if not self.refresh_token:
            raise KeycloakAdminError("No refresh token available")

        auth_url = (
            f"{self.server_url}/realms/{self.admin_realm}/protocol/openid-connect/token"
        )

        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
        }

        try:
            client = await self._get_client()

            # Use data parameter for form-urlencoded data
            response = await client.post(
                auth_url,
                data=refresh_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            # Update tokens and expiration
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data.get("refresh_token")
            self.token_expires_at = time.time() + token_data.get("expires_in", 300)

            logger.debug("Successfully refreshed access token")

        except httpx.HTTPError as e:
            logger.error(f"Failed to refresh token: {e}")
            raise KeycloakAdminError(f"Token refresh failed: {e}") from e

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        namespace: str,
        data: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """
        Make an authenticated request to the Keycloak Admin API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to admin base)
            namespace: Origin namespace for rate limiting
            data: Request body data (deprecated, use json parameter)
            json: JSON request body data
            params: Query parameters

        Returns:
            Response object (httpx.Response) with body already buffered

        Raises:
            KeycloakAdminError: On API errors or rate limit timeouts
        """
        # Apply rate limiting before making request
        if self.rate_limiter:
            try:
                await self.rate_limiter.acquire(namespace)
            except TimeoutError as e:
                logger.warning(f"Rate limit timeout for namespace '{namespace}': {e}")
                raise KeycloakAdminError(
                    f"Rate limit timeout: {e}",
                    status_code=429,
                ) from e

        # Ensure we have valid authentication
        await self._ensure_authenticated()

        url = urljoin(f"{self.server_url}/admin/", endpoint.lstrip("/"))
        logger.debug(
            f"URL construction: server_url={self.server_url}, endpoint={endpoint}, url={url}"
        )
        client = await self._get_client()

        try:
            # Prepare headers with auth token
            headers = {"Authorization": f"Bearer {self.access_token}"}

            # Make the request (httpx buffers response automatically)
            response = await client.request(
                method=method,
                url=url,
                json=json if json else data if data else None,
                params=params,
                headers=headers,
            )

            # Handle 401 - token might be expired
            if response.status_code == 401:
                logger.warning("Received 401, attempting re-authentication")
                await self.authenticate()

                # Retry with new token
                headers = {"Authorization": f"Bearer {self.access_token}"}
                response = await client.request(
                    method=method,
                    url=url,
                    json=json if json else data if data else None,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                return response

            response.raise_for_status()
            return response

        except httpx.HTTPStatusError as e:
            # HTTP error with response
            status_code = e.response.status_code
            response_body: str | None = None

            try:
                response_body = e.response.text or "<no content>"
            except Exception:  # pragma: no cover
                response_body = "<unavailable>"

            body_preview = (
                response_body[:1024] + "...<truncated>"
                if len(response_body) > 1024
                else response_body
            )

            logger.error(
                f"Request failed: {method} {url} - {e}",
                extra={
                    "http_status": status_code,
                    "response_body": body_preview,
                },
            )
            raise KeycloakAdminError(
                f"API request failed: {e}",
                status_code=status_code,
                response_body=response_body,
            ) from e

        except httpx.HTTPError as e:
            # Other HTTP errors (connection, timeout, etc.)
            logger.error(f"Request failed: {method} {url} - {e}")
            raise KeycloakAdminError(
                f"API request failed: {e}",
                status_code=None,
            ) from e

    async def _make_validated_request(
        self,
        method: str,
        endpoint: str,
        namespace: str,
        request_model: BaseModel | None = None,
        response_model: type[BaseModel] | None = None,
        **kwargs: Any,
    ) -> Any:
        """
        Make an authenticated request with automatic Pydantic validation.

        This method wraps _make_request to provide automatic validation of
        request and response data using Pydantic models.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (relative to admin base)
            namespace: Origin namespace for rate limiting
            request_model: Pydantic model instance to serialize as request body
            response_model: Pydantic model class to validate response data
            **kwargs: Additional arguments passed to _make_request

        Returns:
            Validated response model instance if response_model is provided,
            otherwise the raw Response object

        Raises:
            KeycloakAdminError: If the API request fails
            ValidationError: If response data doesn't match the expected model
        """
        # Validate and serialize request payload
        if request_model is not None:
            # Convert Pydantic model to JSON-compatible dict
            # exclude_none: Don't send null values to API
            # by_alias: Use camelCase field names for API
            # mode='json': Serialize Enums and other types properly
            kwargs["json"] = request_model.model_dump(
                exclude_none=True, by_alias=True, mode="json"
            )

        # Make the HTTP request
        response = await self._make_request(method, endpoint, namespace, **kwargs)

        # Validate and parse response
        if response_model is not None and response.status_code < 300:
            # Parse response JSON and validate against model (httpx buffers automatically)
            response_data = response.json()
            return response_model.model_validate(response_data)

        return response

    # Realm Management Methods

    async def create_realm(
        self, realm_config: RealmRepresentation | dict[str, Any], namespace: str
    ) -> RealmRepresentation:
        """
        Create a new realm in Keycloak.

        Args:
            realm_config: Realm configuration as RealmRepresentation or dict
            namespace: Origin namespace for rate limiting

        Returns:
            Created realm information as RealmRepresentation

        Raises:
            KeycloakAdminError: If realm creation fails
        """
        # Convert dict to model if needed
        if isinstance(realm_config, dict):
            realm_config = RealmRepresentation.model_validate(realm_config)

        logger.info(f"Creating realm: {realm_config.realm or 'unknown'}")

        # Use validated request
        response = await self._make_validated_request(
            "POST", "realms", namespace, request_model=realm_config
        )

        if response.status_code == 201:
            logger.info("Realm created successfully")
            # Return the realm config as validated model
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to create realm: {response.status_code}",
                response.status_code,
            )

    async def get_realm(
        self, realm_name: str, namespace: str
    ) -> RealmRepresentation | None:
        """
        Get realm configuration from Keycloak.

        Args:
            realm_name: Name of the realm to retrieve
            namespace: Origin namespace for rate limiting

        Returns:
            Realm configuration as RealmRepresentation or None if not found

        Raises:
            KeycloakAdminError: If the request fails (except 404)
        """
        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}",
                namespace,
                response_model=RealmRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                return None
            raise

    async def export_realm(
        self, realm_name: str, namespace: str
    ) -> RealmRepresentation | None:
        """
        Export realm configuration from Keycloak.

        Based on OpenAPI spec: GET /admin/realms/{realm}
        Returns the complete realm representation.

        Args:
            realm_name: Name of the realm to export
            namespace: Origin namespace for rate limiting

        Returns:
            Complete realm configuration as RealmRepresentation or None if not found

        Example:
            realm = await client.export_realm("my-realm", "default")
            if realm:
                print(f"Realm {realm.realm} has {len(realm.clients or [])} clients")
        """
        logger.info(f"Exporting realm '{realm_name}'")

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}",
                namespace,
                response_model=RealmRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(f"Realm '{realm_name}' not found for export")
                return None
            logger.error(f"Failed to export realm '{realm_name}': {e}")
            return None

    async def get_realms(
        self, namespace: str, brief_representation: bool = False
    ) -> list[RealmRepresentation] | None:
        """
        Get all accessible realms from Keycloak.

        Based on OpenAPI spec: GET /admin/realms
        Returns a list of accessible realms filtered by what the caller is allowed to view.

        Args:
            namespace: Origin namespace for rate limiting
            brief_representation: If True, return brief representation of realms

        Returns:
            List of realm configurations as RealmRepresentation or None on error

        Example:
            realms = await client.get_realms("default")
            for realm in realms:
                print(f"Realm: {realm.realm}, Enabled: {realm.enabled}")
        """
        logger.debug("Fetching all accessible realms")

        try:
            params = {}
            if brief_representation:
                params["briefRepresentation"] = "true"

            response = await self._make_request(
                "GET", "realms", namespace, params=params
            )

            if response.status_code == 200:
                realms_data = response.json()
                # Validate each realm with Pydantic
                return [
                    RealmRepresentation.model_validate(realm) for realm in realms_data
                ]
            else:
                logger.error(f"Failed to get realms: HTTP {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to get realms: {e}")
            return None

    async def update_realm(
        self,
        realm_name: str,
        realm_config: RealmRepresentation | dict[str, Any],
        namespace: str,
    ) -> RealmRepresentation:
        """
        Update realm configuration.

        Args:
            realm_name: Name of the realm to update
            realm_config: Updated realm configuration as RealmRepresentation or dict
            namespace: Origin namespace for rate limiting

        Returns:
            Updated realm configuration as RealmRepresentation

        Raises:
            KeycloakAdminError: If realm update fails
        """
        # Convert dict to model if needed
        if isinstance(realm_config, dict):
            realm_config = RealmRepresentation.model_validate(realm_config)

        logger.info(f"Updating realm: {realm_name}")

        # Use validated request
        response = await self._make_validated_request(
            "PUT", f"realms/{realm_name}", namespace, request_model=realm_config
        )

        if response.status_code == 204:  # No content on successful update
            # Return the updated config
            return realm_config
        else:
            raise KeycloakAdminError(
                f"Failed to update realm: {response.status_code}",
                response.status_code,
            )

    async def create_identity_provider(
        self,
        realm_name: str,
        idp_config: dict[str, Any],
        namespace: str,
    ) -> str | None:
        """
        Create a new identity provider.

        Args:
            realm_name: Name of the realm
            idp_config: Identity provider configuration
            namespace: Origin namespace for rate limiting

        Returns:
            ID of the created identity provider or None if failed
        """
        logger.info(
            f"Creating identity provider '{idp_config.get('alias')}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/identity-provider/instances",
                namespace,
                json=idp_config,
            )

            if response.status_code == 201:
                logger.info(
                    f"Successfully created identity provider '{idp_config.get('alias')}'"
                )

                # Try to extract ID from Location header if available
                location = response.headers.get("Location")
                if location:
                    return location.split("/")[-1]

                return idp_config.get("alias")
            else:
                logger.error(
                    f"Failed to create identity provider: {response.status_code}",
                    extra={"response_body": response.text},
                )
                return None

        except Exception as e:
            logger.error(f"Failed to create identity provider: {e}")
            return None

    async def get_identity_providers(
        self, realm_name: str, namespace: str
    ) -> list[IdentityProviderRepresentation]:
        """
        Get all identity providers in a realm.

        Args:
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            List of identity providers
        """
        logger.debug(f"Getting identity providers for realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET", f"realms/{realm_name}/identity-provider/instances", namespace
            )

            if response.status_code == 200:
                idps_data = response.json()
                return [
                    IdentityProviderRepresentation.model_validate(idp)
                    for idp in idps_data
                ]
            else:
                logger.warning(
                    f"Failed to get identity providers: {response.status_code}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to get identity providers: {e}")
            return []

    async def get_admin_events(
        self,
        realm_name: str,
        namespace: str,
        date_from: str | None = None,
        date_to: str | None = None,
        operation_types: list[str] | None = None,
        resource_types: list[str] | None = None,
        resource_path: str | None = None,
        max_results: int | None = None,
        first_result: int | None = None,
    ) -> list[AdminEventRepresentation]:
        """
        Get admin events from Keycloak.

        Based on OpenAPI spec: GET /admin/realms/{realm}/admin-events

        Args:
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting
            date_from: Filter events after this date (format: yyyy-MM-dd)
            date_to: Filter events before this date (format: yyyy-MM-dd)
            operation_types: Filter by operation types (CREATE, UPDATE, DELETE, ACTION)
            resource_types: Filter by resource types (REALM, CLIENT, USER, etc.)
            resource_path: Filter by resource path (e.g. 'users/123')
            max_results: Maximum number of results to return
            first_result: Offset for pagination

        Returns:
            List of AdminEventRepresentation objects
        """
        logger.debug(f"Fetching admin events for realm '{realm_name}'")

        try:
            params = {}
            if date_from:
                params["dateFrom"] = date_from
            if date_to:
                params["dateTo"] = date_to
            if operation_types:
                params["operationTypes"] = operation_types
            if resource_types:
                params["resourceTypes"] = resource_types
            if resource_path:
                params["resourcePath"] = resource_path
            if max_results is not None:
                params["max"] = max_results
            if first_result is not None:
                params["first"] = first_result

            response = await self._make_request(
                "GET", f"realms/{realm_name}/admin-events", namespace, params=params
            )

            if response.status_code == 200:
                events_data = response.json()
                return [
                    AdminEventRepresentation.model_validate(event)
                    for event in events_data
                ]
            else:
                logger.error(
                    f"Failed to get admin events: HTTP {response.status_code}",
                    extra={"response_body": response.text},
                )
                return []

        except Exception as e:
            logger.error(f"Failed to get admin events: {e}")
            return []

    # Resource type constants for drift detection filtering
    # These are config-changing events that should trigger reconciliation
    REALM_CONFIG_RESOURCE_TYPES = [
        "REALM",
        "REALM_ROLE",
        "REALM_SCOPE_MAPPING",
        "AUTH_FLOW",
        "AUTH_EXECUTION",
        "AUTH_EXECUTION_FLOW",
        "AUTHENTICATOR_CONFIG",
        "REQUIRED_ACTION",
        "IDENTITY_PROVIDER",
        "IDENTITY_PROVIDER_MAPPER",
        "CLIENT_SCOPE",  # Realm-level client scopes
        "USER_FEDERATION_PROVIDER",
        "USER_FEDERATION_MAPPER",
        "COMPONENT",
        "CLIENT_INITIAL_ACCESS_MODEL",
    ]

    CLIENT_CONFIG_RESOURCE_TYPES = [
        "CLIENT",
        "CLIENT_ROLE",
        "CLIENT_SCOPE_MAPPING",
        "PROTOCOL_MAPPER",
    ]

    async def get_latest_admin_event_time(
        self,
        realm_name: str,
        namespace: str,
        scope: str = "realm",
        client_uuid: str | None = None,
        since_timestamp: int | None = None,
    ) -> int | None:
        """
        Get the timestamp of the latest config-changing admin event.

        This method is used for drift detection to determine if any configuration
        changes have been made since the last reconciliation.

        Args:
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting
            scope: Either "realm" or "client" - determines which resource types to filter
            client_uuid: Required when scope="client" - the client UUID to filter events for
            since_timestamp: Optional timestamp (Unix ms) to filter events after this time

        Returns:
            The timestamp (Unix ms) of the latest matching event, or None if no events found

        Examples:
            # Get latest realm config event
            ts = await client.get_latest_admin_event_time("my-realm", "default", scope="realm")

            # Get latest client config event
            ts = await client.get_latest_admin_event_time(
                "my-realm", "default", scope="client", client_uuid="abc-123"
            )

            # Check for events since last reconcile
            ts = await client.get_latest_admin_event_time(
                "my-realm", "default", since_timestamp=last_reconcile_time
            )
        """
        logger.debug(
            f"Getting latest admin event time for {scope} in realm '{realm_name}'"
        )

        try:
            # Determine resource types based on scope
            if scope == "realm":
                resource_types = self.REALM_CONFIG_RESOURCE_TYPES
            elif scope == "client":
                if not client_uuid:
                    logger.error("client_uuid required when scope='client'")
                    return None
                resource_types = self.CLIENT_CONFIG_RESOURCE_TYPES
            else:
                logger.error(f"Invalid scope: {scope}")
                return None

            # Build query parameters
            params: dict[str, Any] = {
                # Only config-changing operations, not ACTION (login events, etc.)
                "operationTypes": ["CREATE", "UPDATE", "DELETE"],
                "resourceTypes": resource_types,
                # We only need the most recent event
                "max": 1,
                "first": 0,
            }

            # Convert since_timestamp to date string for API
            # Note: Keycloak API only supports date filtering (yyyy-MM-dd), not precise timestamps
            # We'll filter more precisely after fetching

            response = await self._make_request(
                "GET", f"realms/{realm_name}/admin-events", namespace, params=params
            )

            if response.status_code != 200:
                logger.error(
                    f"Failed to get admin events: HTTP {response.status_code}",
                    extra={"response_body": response.text},
                )
                return None

            events_data = response.json()

            if not events_data:
                logger.debug(
                    f"No admin events found for {scope} in realm '{realm_name}'"
                )
                return None

            # Parse events and filter
            events = [
                AdminEventRepresentation.model_validate(event) for event in events_data
            ]

            # For client scope, filter by resource_path containing the client UUID
            if scope == "client" and client_uuid:
                events = [
                    e
                    for e in events
                    if e.resource_path and client_uuid in e.resource_path
                ]

            # For realm scope, exclude events that are client-specific
            # (resource_path starting with "clients/")
            if scope == "realm":
                events = [
                    e
                    for e in events
                    if not (e.resource_path and e.resource_path.startswith("clients/"))
                ]

            # Filter by since_timestamp if provided
            if since_timestamp is not None:
                events = [e for e in events if e.time and e.time > since_timestamp]

            if not events:
                logger.debug(
                    f"No matching admin events found for {scope} in realm '{realm_name}'"
                )
                return None

            # Get the latest event timestamp
            latest_event = max(events, key=lambda e: e.time or 0)
            latest_time = latest_event.time

            logger.debug(
                f"Latest {scope} admin event in realm '{realm_name}': "
                f"type={latest_event.resource_type}, op={latest_event.operation_type}, "
                f"time={latest_time}"
            )

            return latest_time

        except Exception as e:
            logger.error(f"Failed to get latest admin event time: {e}")
            return None

    # Client Management Methods

    async def get_client_by_name(
        self, client_id: str, realm_name: str, namespace: str
    ) -> ClientRepresentation | None:
        """
        Get a client by its client ID in the specified realm.

        Args:
            client_id: The client ID to search for
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client data as ClientRepresentation if found, None otherwise

        Example:
            client = await admin_client.get_client_by_name("my-client", "my-realm", "default")
            if client:
                print(f"Client UUID: {client.id}, Enabled: {client.enabled}")
        """
        logger.info(f"Looking up client '{client_id}' in realm '{realm_name}'")

        try:
            # Get all clients in the realm
            response = await self._make_request(
                "GET", f"realms/{realm_name}/clients", namespace
            )
            clients_data = response.json()

            # Find client by clientId and validate
            for client_data in clients_data:
                if client_data.get("clientId") == client_id:
                    logger.info(
                        f"Found client '{client_id}' with ID: {client_data['id']}"
                    )
                    return ClientRepresentation.model_validate(client_data)

            logger.info(f"Client '{client_id}' not found in realm '{realm_name}'")
            return None

        except Exception as e:
            logger.error(f"Failed to get client '{client_id}': {e}")
            return None

    async def get_client_uuid(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Get client UUID by client ID in the specified realm.

        Args:
            client_id: The client ID to search for
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client UUID if found, None otherwise
        """
        client = await self.get_client_by_name(client_id, realm_name, namespace)
        if client:
            return client.id
        return None

    async def create_client(
        self,
        client_config: ClientRepresentation | dict[str, Any],
        realm_name: str,
        namespace: str,
    ) -> str | None:
        """
        Create a new client in the specified realm.

        Args:
            client_config: Client configuration as ClientRepresentation or dict
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Client UUID if successful, None otherwise

        Raises:
            KeycloakAdminError: If client creation fails
        """
        # Convert dict to model if needed
        if isinstance(client_config, dict):
            client_config = ClientRepresentation.model_validate(client_config)

        client_id = client_config.client_id or "unknown"
        logger.info(f"Creating client '{client_id}' in realm '{realm_name}'")

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/clients",
                namespace,
                request_model=client_config,
            )

            if response.status_code == 201:
                # Get the created client UUID from Location header
                location = response.headers.get("Location", "")
                created_client_uuid = location.split("/")[-1] if location else None
                logger.info(
                    f"Successfully created client '{client_id}' with UUID: {created_client_uuid}"
                )
                return created_client_uuid
            else:
                logger.error(
                    f"Failed to create client '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to create client '{client_id}': {e}")
            return None

    async def update_client(
        self,
        client_uuid: str,
        client_config: ClientRepresentation | dict[str, Any],
        realm_name: str,
        namespace: str,
    ) -> bool:
        """
        Update an existing client configuration.

        Args:
            client_uuid: The UUID of the client to update
            client_config: Updated client configuration as ClientRepresentation or dict
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful

        Raises:
            KeycloakAdminError: If client update fails
        """
        # Convert dict to model if needed
        if isinstance(client_config, dict):
            client_config = ClientRepresentation.model_validate(client_config)

        client_id = client_config.client_id or "unknown"
        logger.info(
            f"Updating client '{client_id}' (UUID: {client_uuid}) in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/clients/{client_uuid}",
                namespace,
                request_model=client_config,
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated client '{client_id}'")
                return True
            else:
                error_msg = f"Failed to update client '{client_id}': HTTP {response.status_code}"
                logger.error(error_msg)
                raise KeycloakAdminError(error_msg, response.status_code)

        except KeycloakAdminError:
            raise
        except Exception as e:
            error_msg = f"Failed to update client '{client_id}': {e}"
            logger.error(error_msg)
            raise KeycloakAdminError(error_msg) from e

    async def get_client_secret(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Get the client secret for a confidential client.

        Args:
            client_id: The client ID
            realm_name: Name of the realm (defaults to "master")

        Returns:
            Client secret if found, None otherwise
        """
        logger.info(f"Getting client secret for '{client_id}' in realm '{realm_name}'")

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.error(f"Client '{client_id}' not found")
                return None

            client_uuid = client.id

            # Get the client secret
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/client-secret",
                namespace,
            )

            if response.status_code == 200:
                secret_data = response.json()
                secret = secret_data.get("value")
                if secret:
                    logger.info(
                        f"Successfully retrieved client secret for '{client_id}'"
                    )
                    return secret
                else:
                    logger.warning(f"No secret found for client '{client_id}'")
                    return None
            else:
                logger.error(
                    f"Failed to get client secret for '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to get client secret for '{client_id}': {e}")
            return None

    async def get_service_account_user(
        self, client_uuid: str, realm_name: str, namespace: str
    ) -> UserRepresentation:
        """Get the service account user for a client.

        Based on OpenAPI spec: GET /admin/realms/{realm}/clients/{id}/service-account-user

        Args:
            client_uuid: Client UUID in Keycloak
            realm_name: Target realm name
            namespace: Origin namespace for rate limiting

        Returns:
            Service account user representation as UserRepresentation

        Raises:
            KeycloakAdminError: If retrieval fails or service account is disabled

        Example:
            user = await admin_client.get_service_account_user(client_uuid, "my-realm", "default")
            print(f"Service account user: {user.username}, ID: {user.id}")
        """
        logger.debug(
            f"Fetching service account user for client {client_uuid} in realm {realm_name}"
        )

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/service-account-user",
                namespace,
                response_model=UserRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                raise KeycloakAdminError(
                    (
                        f"Service account user not found for client {client_uuid}. "
                        "Ensure service_accounts_enabled is true."
                    ),
                    status_code=404,
                ) from e
            raise

    async def get_realm_role(
        self, role_name: str, realm_name: str, namespace: str
    ) -> RoleRepresentation | None:
        """Get a realm role by name.

        Args:
            role_name: Name of the role to retrieve
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Role representation as RoleRepresentation or None if not found

        Example:
            role = await admin_client.get_realm_role("admin", "my-realm", "default")
            if role:
                print(f"Role: {role.name}, ID: {role.id}")
        """
        logger.debug(f"Fetching realm role '{role_name}' in realm '{realm_name}'")

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/roles/{role_name}",
                namespace,
                response_model=RoleRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(
                    f"Realm role '{role_name}' not found in realm '{realm_name}'"
                )
                return None
            raise

    async def get_client_role(
        self, client_uuid: str, role_name: str, realm_name: str, namespace: str
    ) -> RoleRepresentation | None:
        """Get a client role by name.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to retrieve
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            Role representation as RoleRepresentation or None if not found

        Example:
            role = await admin_client.get_client_role(client_uuid, "admin", "my-realm", "default")
            if role:
                print(f"Client role: {role.name}, ID: {role.id}")
        """
        logger.debug(
            f"Fetching client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        try:
            return await self._make_validated_request(
                "GET",
                f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}",
                namespace,
                response_model=RoleRepresentation,
            )
        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(
                    f"Client role '{role_name}' not found for client '{client_uuid}'"
                )
                return None
            raise

    async def assign_realm_roles_to_user(
        self, user_id: str, role_names: list[str], realm_name: str, namespace: str
    ) -> None:
        """Assign realm-level roles to a user.

        Args:
            user_id: UUID of the user in Keycloak
            role_names: List of role names to assign
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Raises:
            KeycloakAdminError: If assignment fails

        Example:
            await admin_client.assign_realm_roles_to_user(
                user_id="123-456-789",
                role_names=["admin", "user"],
                realm_name="my-realm",
                namespace="default"
            )
        """
        logger.info(f"Assigning realm roles to user {user_id} in realm '{realm_name}'")

        roles: list[RoleRepresentation] = []
        for role_name in role_names:
            role = await self.get_realm_role(role_name, realm_name, namespace)
            if not role:
                logger.warning(
                    f"Realm role '{role_name}' not found in realm '{realm_name}', skipping"
                )
                continue
            roles.append(role)

        if not roles:
            logger.info(f"No valid realm roles to assign to user {user_id}")
            return

        # Serialize roles to dict for API
        roles_data = [
            role.model_dump(by_alias=True, exclude_none=True, mode="json")
            for role in roles
        ]

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/users/{user_id}/role-mappings/realm",
                namespace,
                json=roles_data,
            )

            if response.status_code not in (200, 204):
                raise KeycloakAdminError(
                    f"Failed to assign realm roles to user: {response.text}",
                    status_code=response.status_code,
                )

            logger.info(
                f"Successfully assigned {len(roles)} realm roles to user {user_id}"
            )
        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to assign realm roles to user {user_id}: {e}")
            raise KeycloakAdminError(f"Failed to assign realm roles: {e}") from e

    async def assign_client_roles_to_user(
        self,
        user_id: str,
        client_uuid: str,
        role_names: list[str],
        realm_name: str,
        namespace: str,
    ) -> None:
        """Assign client-level roles to a user.

        Args:
            user_id: UUID of the user in Keycloak
            client_uuid: UUID of the client in Keycloak
            role_names: List of role names to assign
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Raises:
            KeycloakAdminError: If assignment fails

        Example:
            await admin_client.assign_client_roles_to_user(
                user_id="123-456-789",
                client_uuid="abc-def-ghi",
                role_names=["admin", "user"],
                realm_name="my-realm",
                namespace="default"
            )
        """
        logger.info(
            f"Assigning client roles to user {user_id} for client {client_uuid} in realm '{realm_name}'"
        )

        roles: list[RoleRepresentation] = []
        for role_name in role_names:
            role = await self.get_client_role(
                client_uuid, role_name, realm_name, namespace
            )
            if not role:
                logger.warning(
                    f"Client role '{role_name}' not found for client '{client_uuid}', skipping"
                )
                continue
            roles.append(role)

        if not roles:
            logger.info(f"No valid client roles to assign to user {user_id}")
            return

        # Serialize roles to dict for API
        roles_data = [
            role.model_dump(by_alias=True, exclude_none=True, mode="json")
            for role in roles
        ]

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/users/{user_id}/role-mappings/clients/{client_uuid}",
                namespace,
                json=roles_data,
            )

            if response.status_code not in (200, 204):
                raise KeycloakAdminError(
                    f"Failed to assign client roles to user: {response.text}",
                    status_code=response.status_code,
                )

            logger.info(
                f"Successfully assigned {len(roles)} client roles to user {user_id}"
            )
        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to assign client roles to user {user_id}: {e}")
            raise KeycloakAdminError(f"Failed to assign client roles: {e}") from e

    async def delete_client(
        self, client_id: str, realm_name: str, namespace: str
    ) -> bool:
        """
        Delete a client from the specified realm.

        Args:
            client_id: The client ID to delete
            realm_name: Name of the realm (defaults to "master")

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting client '{client_id}' from realm '{realm_name}'")

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.warning(f"Client '{client_id}' not found, nothing to delete")
                return True  # Consider this successful

            client_uuid = client.id

            response = await self._make_request(
                "DELETE", f"realms/{realm_name}/clients/{client_uuid}", namespace
            )

            if response.status_code == 204:
                logger.info(f"Successfully deleted client '{client_id}'")
                return True
            else:
                logger.error(
                    f"Failed to delete client '{client_id}': {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete client '{client_id}': {e}")
            return False

    async def regenerate_client_secret(
        self, client_id: str, realm_name: str, namespace: str
    ) -> str | None:
        """
        Regenerate the client secret for a confidential client.

        Args:
            client_id: The client ID
            realm_name: Name of the realm (defaults to "master")

        Returns:
            New client secret if successful, None otherwise
        """
        logger.info(
            f"Regenerating client secret for '{client_id}' in realm '{realm_name}'"
        )

        try:
            # First get the client UUID
            client = await self.get_client_by_name(client_id, realm_name, namespace)
            if not client:
                logger.error(f"Client '{client_id}' not found")
                return None

            client_uuid = client.id

            # Regenerate the client secret
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/clients/{client_uuid}/client-secret",
                namespace,
            )

            if response.status_code == 200:
                secret_data = response.json()
                new_secret = secret_data.get("value")
                if new_secret:
                    logger.info(
                        f"Successfully regenerated client secret for '{client_id}'"
                    )
                    return new_secret
                else:
                    logger.error(f"No secret returned for client '{client_id}'")
                    return None
            else:
                logger.error(
                    f"Failed to regenerate client secret for '{client_id}': {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to regenerate client secret for '{client_id}': {e}")
            return None

    # Realm Management Methods

    async def delete_realm(self, realm_name: str, namespace: str) -> bool:
        """
        Delete a realm from Keycloak.

        Args:
            realm_name: Name of the realm to delete

        Returns:
            True if successful, False otherwise
        """
        if realm_name == "master":
            logger.error("Cannot delete the master realm")
            return False

        logger.info(f"Deleting realm '{realm_name}'")

        try:
            response = await self._make_request(
                "DELETE", f"realms/{realm_name}", namespace
            )

            if response.status_code == 204:
                logger.info(f"Successfully deleted realm '{realm_name}'")
                return True
            else:
                logger.error(
                    f"Failed to delete realm '{realm_name}': {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete realm '{realm_name}': {e}")
            return False

    async def get_realm_clients(
        self, realm_name: str, namespace: str
    ) -> list[ClientRepresentation]:
        """
        Get all clients in a realm.

        Args:
            realm_name: Name of the realm

        Returns:
            List of client configurations as ClientRepresentation

        Example:
            clients = admin_client.get_realm_clients("my-realm")
            for client in clients:
                print(f"Client: {client.client_id}, Enabled: {client.enabled}")
        """
        logger.info(f"Getting all clients in realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET", f"realms/{realm_name}/clients", namespace
            )

            if response.status_code == 200:
                clients_data = response.json()
                logger.info(
                    f"Found {len(clients_data)} clients in realm '{realm_name}'"
                )
                # Validate each client with Pydantic
                return [
                    ClientRepresentation.model_validate(client)
                    for client in clients_data
                ]
            else:
                logger.error(
                    f"Failed to get clients for realm '{realm_name}': {response.status_code}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to get clients for realm '{realm_name}': {e}")
            return []

    async def update_realm_themes(
        self, realm_name: str, themes: dict[str, Any], namespace: str
    ) -> bool:
        """
        Update realm theme configuration.

        Args:
            realm_name: Name of the realm
            themes: Theme configuration

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Updating themes for realm '{realm_name}'")

        try:
            realm_config = {
                "loginTheme": themes.get("login"),
                "accountTheme": themes.get("account"),
                "adminTheme": themes.get("admin"),
                "emailTheme": themes.get("email"),
            }

            # Remove None values
            realm_config = {k: v for k, v in realm_config.items() if v is not None}

            response = await self._make_request(
                "PUT", f"realms/{realm_name}", namespace, json=realm_config
            )

            if response.status_code == 204:
                logger.info(f"Successfully updated themes for realm '{realm_name}'")
                return True
            else:
                logger.error(f"Failed to update themes: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Failed to update realm themes: {e}")
            return False

    # =========================================================================
    # Authentication Flow Management Methods
    # =========================================================================

    async def get_authentication_flows(
        self,
        realm_name: str,
        namespace: str,
    ) -> list[AuthenticationFlowRepresentation]:
        """
        Get all authentication flows for a realm.

        Args:
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            List of authentication flows
        """
        logger.debug(f"Getting authentication flows for realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/authentication/flows",
                namespace,
            )

            if response.status_code == 200:
                flows_data = response.json()
                return [
                    AuthenticationFlowRepresentation.model_validate(flow)
                    for flow in flows_data
                ]
            else:
                logger.warning(
                    f"Failed to get authentication flows: {response.status_code}"
                )
                return []

        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to get authentication flows: {e}")
            return []

    async def get_authentication_flow_by_alias(
        self,
        realm_name: str,
        flow_alias: str,
        namespace: str,
    ) -> AuthenticationFlowRepresentation | None:
        """
        Get a specific authentication flow by alias.

        Args:
            realm_name: Name of the realm
            flow_alias: Alias of the flow
            namespace: Origin namespace for rate limiting

        Returns:
            Authentication flow or None if not found
        """
        logger.debug(
            f"Getting authentication flow '{flow_alias}' for realm '{realm_name}'"
        )

        flows = await self.get_authentication_flows(realm_name, namespace)
        for flow in flows:
            if flow.alias == flow_alias:
                return flow
        return None

    async def create_authentication_flow(
        self,
        realm_name: str,
        flow_config: AuthenticationFlowRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Create a new authentication flow for a realm.

        Args:
            realm_name: Name of the realm
            flow_config: Authentication flow configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if the flow was created successfully.
            False if the flow already exists (409 conflict) or creation failed.
            For idempotent operations, callers should check if the flow exists
            separately when False is returned, as the flow may already be present.
        """
        if isinstance(flow_config, dict):
            flow_config = AuthenticationFlowRepresentation.model_validate(flow_config)

        flow_alias = flow_config.alias or "unknown"
        logger.info(
            f"Creating authentication flow '{flow_alias}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/authentication/flows",
                namespace,
                request_model=flow_config,
            )

            if response.status_code in [201, 204]:
                logger.info(f"Successfully created authentication flow '{flow_alias}'")
                return True
            else:
                logger.error(
                    f"Failed to create authentication flow: {response.status_code}"
                )
                return False

        except KeycloakAdminError as e:
            if e.status_code == 409:
                logger.warning(f"Authentication flow '{flow_alias}' already exists")
                return False
            raise
        except Exception as e:
            logger.error(f"Failed to create authentication flow: {e}")
            return False

    async def delete_authentication_flow(
        self,
        realm_name: str,
        flow_id: str,
        namespace: str,
    ) -> bool:
        """
        Delete an authentication flow.

        Args:
            realm_name: Name of the realm
            flow_id: ID of the flow to delete
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Deleting authentication flow '{flow_id}' from realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "DELETE",
                f"realms/{realm_name}/authentication/flows/{flow_id}",
                namespace,
            )

            if response.status_code in [204, 200]:
                logger.info(f"Successfully deleted authentication flow '{flow_id}'")
                return True
            else:
                logger.error(
                    f"Failed to delete authentication flow: {response.status_code}"
                )
                return False

        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(f"Authentication flow '{flow_id}' not found")
                return True  # Already deleted
            raise
        except Exception as e:
            logger.error(f"Failed to delete authentication flow: {e}")
            return False

    async def copy_authentication_flow(
        self,
        realm_name: str,
        source_flow_alias: str,
        new_flow_alias: str,
        namespace: str,
    ) -> bool:
        """
        Copy an existing authentication flow under a new name.

        Args:
            realm_name: Name of the realm
            source_flow_alias: Alias of the flow to copy
            new_flow_alias: Alias for the new flow
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Copying authentication flow '{source_flow_alias}' "
            f"to '{new_flow_alias}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/authentication/flows/{source_flow_alias}/copy",
                namespace,
                json={"newName": new_flow_alias},
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully copied authentication flow to '{new_flow_alias}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to copy authentication flow: {response.status_code}"
                )
                return False

        except KeycloakAdminError as e:
            if e.status_code == 409:
                logger.warning(f"Authentication flow '{new_flow_alias}' already exists")
                return False
            raise
        except Exception as e:
            logger.error(f"Failed to copy authentication flow: {e}")
            return False

    async def get_flow_executions(
        self,
        realm_name: str,
        flow_alias: str,
        namespace: str,
    ) -> list[AuthenticationExecutionInfoRepresentation]:
        """
        Get all executions for an authentication flow.

        Args:
            realm_name: Name of the realm
            flow_alias: Alias of the flow
            namespace: Origin namespace for rate limiting

        Returns:
            List of execution info representations
        """
        logger.debug(
            f"Getting executions for flow '{flow_alias}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/authentication/flows/{flow_alias}/executions",
                namespace,
            )

            if response.status_code == 200:
                executions_data = response.json()
                return [
                    AuthenticationExecutionInfoRepresentation.model_validate(ex)
                    for ex in executions_data
                ]
            else:
                logger.warning(f"Failed to get flow executions: {response.status_code}")
                return []

        except KeycloakAdminError:
            raise
        except Exception as e:
            logger.error(f"Failed to get flow executions: {e}")
            return []

    async def add_execution_to_flow(
        self,
        realm_name: str,
        flow_alias: str,
        provider_id: str,
        namespace: str,
    ) -> str | None:
        """
        Add a new authenticator execution to a flow.

        Args:
            realm_name: Name of the realm
            flow_alias: Alias of the parent flow
            provider_id: Authenticator provider ID (e.g., 'auth-cookie')
            namespace: Origin namespace for rate limiting

        Returns:
            Execution ID if successful, None otherwise
        """
        logger.info(
            f"Adding execution '{provider_id}' to flow '{flow_alias}' "
            f"in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/authentication/flows/{flow_alias}/executions/execution",
                namespace,
                json={"provider": provider_id},
            )

            if response.status_code in [201, 204]:
                # Extract execution ID from Location header
                location = response.headers.get("Location", "")
                execution_id = location.rsplit("/", 1)[-1] if location else None
                logger.info(f"Successfully added execution '{provider_id}'")
                return execution_id
            else:
                logger.error(f"Failed to add execution: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to add execution to flow: {e}")
            return None

    async def add_subflow_to_flow(
        self,
        realm_name: str,
        parent_flow_alias: str,
        subflow_alias: str,
        provider_id: str,
        description: str | None,
        namespace: str,
    ) -> str | None:
        """
        Add a new sub-flow execution to a flow.

        Args:
            realm_name: Name of the realm
            parent_flow_alias: Alias of the parent flow
            subflow_alias: Alias for the new sub-flow
            provider_id: Flow provider ('basic-flow' or 'client-flow')
            description: Description for the sub-flow
            namespace: Origin namespace for rate limiting

        Returns:
            Execution ID if successful, None otherwise
        """
        logger.info(
            f"Adding sub-flow '{subflow_alias}' to flow '{parent_flow_alias}' "
            f"in realm '{realm_name}'"
        )

        try:
            payload = {
                "alias": subflow_alias,
                "type": provider_id,
                "provider": "registration-page-form",
            }
            if description:
                payload["description"] = description

            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/authentication/flows/{parent_flow_alias}/executions/flow",
                namespace,
                json=payload,
            )

            if response.status_code in [201, 204]:
                location = response.headers.get("Location", "")
                execution_id = location.rsplit("/", 1)[-1] if location else None
                logger.info(f"Successfully added sub-flow '{subflow_alias}'")
                return execution_id
            else:
                logger.error(f"Failed to add sub-flow: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to add sub-flow to flow: {e}")
            return None

    async def update_execution_requirement(
        self,
        realm_name: str,
        flow_alias: str,
        execution_id: str,
        requirement: str,
        namespace: str,
    ) -> bool:
        """
        Update the requirement level of an execution.

        Args:
            realm_name: Name of the realm
            flow_alias: Alias of the parent flow
            execution_id: ID of the execution to update
            requirement: New requirement level (REQUIRED, ALTERNATIVE, DISABLED, CONDITIONAL)
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Updating execution '{execution_id}' requirement to '{requirement}' "
            f"in flow '{flow_alias}'"
        )

        try:
            # First get current execution info
            executions = await self.get_flow_executions(
                realm_name, flow_alias, namespace
            )
            current_execution = None
            for ex in executions:
                if ex.id == execution_id:
                    current_execution = ex
                    break

            if not current_execution:
                logger.error(f"Execution '{execution_id}' not found in flow")
                return False

            # Update the requirement
            update_payload = {
                "id": execution_id,
                "requirement": requirement,
            }

            response = await self._make_request(
                "PUT",
                f"realms/{realm_name}/authentication/flows/{flow_alias}/executions",
                namespace,
                json=update_payload,
            )

            if response.status_code in [200, 202, 204]:
                logger.info(
                    f"Successfully updated execution requirement to '{requirement}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to update execution requirement: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to update execution requirement: {e}")
            return False

    async def delete_execution(
        self,
        realm_name: str,
        execution_id: str,
        namespace: str,
    ) -> bool:
        """
        Delete an execution from a flow.

        Args:
            realm_name: Name of the realm
            execution_id: ID of the execution to delete
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting execution '{execution_id}' from realm '{realm_name}'")

        try:
            response = await self._make_request(
                "DELETE",
                f"realms/{realm_name}/authentication/executions/{execution_id}",
                namespace,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted execution '{execution_id}'")
                return True
            else:
                logger.error(f"Failed to delete execution: {response.status_code}")
                return False

        except KeycloakAdminError as e:
            if e.status_code == 404:
                logger.warning(f"Execution '{execution_id}' not found")
                return True  # Already deleted
            raise
        except Exception as e:
            logger.error(f"Failed to delete execution: {e}")
            return False

    async def get_authenticator_config(
        self,
        realm_name: str,
        config_id: str,
        namespace: str,
    ) -> AuthenticatorConfigRepresentation | None:
        """
        Get authenticator configuration by ID.

        Args:
            realm_name: Name of the realm
            config_id: ID of the authenticator config
            namespace: Origin namespace for rate limiting

        Returns:
            Authenticator config or None if not found
        """
        logger.debug(
            f"Getting authenticator config '{config_id}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/authentication/config/{config_id}",
                namespace,
            )

            if response.status_code == 200:
                return AuthenticatorConfigRepresentation.model_validate(response.json())
            else:
                return None

        except KeycloakAdminError as e:
            if e.status_code == 404:
                return None
            raise
        except Exception as e:
            logger.error(f"Failed to get authenticator config: {e}")
            return None

    async def create_authenticator_config(
        self,
        realm_name: str,
        execution_id: str,
        config: AuthenticatorConfigRepresentation | dict[str, Any],
        namespace: str,
    ) -> str | None:
        """
        Create a new authenticator configuration for an execution.

        Args:
            realm_name: Name of the realm
            execution_id: ID of the execution to configure
            config: Authenticator configuration
            namespace: Origin namespace for rate limiting

        Returns:
            Config ID if successful, None otherwise
        """
        if isinstance(config, dict):
            config = AuthenticatorConfigRepresentation.model_validate(config)

        config_alias = config.alias or "unknown"
        logger.info(
            f"Creating authenticator config '{config_alias}' for execution "
            f"'{execution_id}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/authentication/executions/{execution_id}/config",
                namespace,
                request_model=config,
            )

            if response.status_code in [201, 204]:
                # Extract config ID from Location header
                location = response.headers.get("Location", "")
                config_id = location.rsplit("/", 1)[-1] if location else None
                logger.info(
                    f"Successfully created authenticator config '{config_alias}'"
                )
                return config_id
            else:
                logger.error(
                    f"Failed to create authenticator config: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to create authenticator config: {e}")
            return None

    async def update_authenticator_config(
        self,
        realm_name: str,
        config_id: str,
        config: AuthenticatorConfigRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Update an authenticator configuration.

        Args:
            realm_name: Name of the realm
            config_id: ID of the config to update
            config: Updated authenticator configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(config, dict):
            config = AuthenticatorConfigRepresentation.model_validate(config)

        logger.info(
            f"Updating authenticator config '{config_id}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/authentication/config/{config_id}",
                namespace,
                request_model=config,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully updated authenticator config '{config_id}'")
                return True
            else:
                logger.error(
                    f"Failed to update authenticator config: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to update authenticator config: {e}")
            return False

    # =========================================================================
    # Required Actions Management Methods
    # =========================================================================

    async def get_required_actions(
        self,
        realm_name: str,
        namespace: str,
    ) -> list[RequiredActionProviderRepresentation]:
        """
        Get all required actions for a realm.

        Args:
            realm_name: Name of the realm
            namespace: Origin namespace for rate limiting

        Returns:
            List of required action provider representations
        """
        logger.debug(f"Getting required actions for realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/authentication/required-actions",
                namespace,
            )

            if response.status_code == 200:
                actions_data = response.json()
                return [
                    RequiredActionProviderRepresentation.model_validate(action)
                    for action in actions_data
                ]
            else:
                logger.warning(
                    f"Failed to get required actions: {response.status_code}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to get required actions: {e}")
            return []

    async def get_required_action(
        self,
        realm_name: str,
        action_alias: str,
        namespace: str,
    ) -> RequiredActionProviderRepresentation | None:
        """
        Get a specific required action by alias.

        Args:
            realm_name: Name of the realm
            action_alias: Alias of the required action
            namespace: Origin namespace for rate limiting

        Returns:
            Required action provider or None if not found
        """
        logger.debug(
            f"Getting required action '{action_alias}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/authentication/required-actions/{action_alias}",
                namespace,
            )

            if response.status_code == 200:
                return RequiredActionProviderRepresentation.model_validate(
                    response.json()
                )
            else:
                return None

        except KeycloakAdminError as e:
            if e.status_code == 404:
                return None
            raise
        except Exception as e:
            logger.error(f"Failed to get required action: {e}")
            return None

    async def update_required_action(
        self,
        realm_name: str,
        action_alias: str,
        action_config: RequiredActionProviderRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Update a required action configuration.

        Args:
            realm_name: Name of the realm
            action_alias: Alias of the required action to update
            action_config: Updated action configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(action_config, dict):
            action_config = RequiredActionProviderRepresentation.model_validate(
                action_config
            )

        logger.info(
            f"Updating required action '{action_alias}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/authentication/required-actions/{action_alias}",
                namespace,
                request_model=action_config,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully updated required action '{action_alias}'")
                return True
            else:
                logger.error(
                    f"Failed to update required action: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to update required action: {e}")
            return False

    async def register_required_action(
        self,
        realm_name: str,
        provider_id: str,
        name: str,
        namespace: str,
    ) -> bool:
        """
        Register a new required action provider.

        Args:
            realm_name: Name of the realm
            provider_id: Provider ID for the required action
            name: Display name for the action
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Registering required action '{provider_id}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/authentication/register-required-action",
                namespace,
                json={"providerId": provider_id, "name": name},
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully registered required action '{provider_id}'")
                return True
            else:
                logger.error(
                    f"Failed to register required action: {response.status_code}"
                )
                return False

        except KeycloakAdminError as e:
            if e.status_code == 409:
                logger.warning(f"Required action '{provider_id}' already registered")
                return True  # Already exists is OK
            raise
        except Exception as e:
            logger.error(f"Failed to register required action: {e}")
            return False

    async def get_identity_provider(
        self,
        realm_name: str,
        alias: str,
        namespace: str,
    ) -> IdentityProviderRepresentation | None:
        """
        Get an identity provider by alias.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            namespace: Origin namespace for rate limiting

        Returns:
            IdentityProviderRepresentation if found, None otherwise

        Example:
            idp = await admin_client.get_identity_provider("my-realm", "github", "default")
            if idp:
                print(f"IdP: {idp.alias}, Enabled: {idp.enabled}")
        """
        logger.debug(f"Looking up identity provider '{alias}' in realm '{realm_name}'")

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/identity-provider/instances/{alias}",
                namespace,
            )

            if response.status_code == 200:
                return IdentityProviderRepresentation.model_validate(response.json())
            elif response.status_code == 404:
                logger.debug(f"Identity provider '{alias}' not found")
                return None
            else:
                logger.warning(
                    f"Unexpected response getting identity provider: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to get identity provider '{alias}': {e}")
            return None

    async def update_identity_provider(
        self,
        realm_name: str,
        alias: str,
        provider_config: IdentityProviderRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Update an existing identity provider.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            provider_config: Updated identity provider configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise

        Example:
            idp = await admin_client.get_identity_provider("my-realm", "github", "default")
            idp.enabled = False
            success = await admin_client.update_identity_provider(
                "my-realm", "github", idp, "default"
            )
        """
        # Convert dict to model if needed
        if isinstance(provider_config, dict):
            provider_config = IdentityProviderRepresentation.model_validate(
                provider_config
            )

        logger.info(f"Updating identity provider '{alias}' in realm '{realm_name}'")

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/identity-provider/instances/{alias}",
                namespace,
                request_model=provider_config,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully updated identity provider '{alias}'")
                return True
            else:
                logger.error(
                    f"Failed to update identity provider: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to update identity provider '{alias}': {e}")
            return False

    async def configure_identity_provider(
        self,
        realm_name: str,
        provider_config: IdentityProviderRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Configure identity provider for a realm (create or update).

        This method checks if the identity provider already exists:
        - If it exists, updates it using PUT
        - If it doesn't exist, creates it using POST

        Args:
            realm_name: Name of the realm
            provider_config: Identity provider configuration as IdentityProviderRepresentation or dict
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import IdentityProviderRepresentation

            provider = IdentityProviderRepresentation(
                alias="google",
                provider_id="google",
                enabled=True
            )
            success = await admin_client.configure_identity_provider("my-realm", provider, "my-namespace")
        """
        # Convert dict to model if needed
        if isinstance(provider_config, dict):
            provider_config = IdentityProviderRepresentation.model_validate(
                provider_config
            )

        provider_alias = provider_config.alias or "unknown"
        logger.info(
            f"Configuring identity provider '{provider_alias}' for realm '{realm_name}'"
        )

        # Check if identity provider already exists
        existing_idp = await self.get_identity_provider(
            realm_name, provider_alias, namespace
        )

        if existing_idp:
            # Update existing identity provider
            logger.info(f"Identity provider '{provider_alias}' exists, updating")
            return await self.update_identity_provider(
                realm_name, provider_alias, provider_config, namespace
            )

        # Create new identity provider
        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/identity-provider/instances",
                namespace,
                request_model=provider_config,
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully created identity provider '{provider_alias}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to create identity provider: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to create identity provider: {e}")
            return False

    async def delete_identity_provider(
        self,
        realm_name: str,
        alias: str,
        namespace: str,
    ) -> bool:
        """
        Delete an identity provider by alias.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful or not found, False on error

        Example:
            success = await admin_client.delete_identity_provider("my-realm", "github", "default")
        """
        logger.info(f"Deleting identity provider '{alias}' from realm '{realm_name}'")

        try:
            response = await self._make_request(
                "DELETE",
                f"realms/{realm_name}/identity-provider/instances/{alias}",
                namespace,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted identity provider '{alias}'")
                return True
            elif response.status_code == 404:
                logger.debug(
                    f"Identity provider '{alias}' not found, nothing to delete"
                )
                return True
            else:
                logger.error(
                    f"Failed to delete identity provider: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete identity provider '{alias}': {e}")
            return False

    async def get_identity_provider_mappers(
        self,
        realm_name: str,
        alias: str,
        namespace: str,
    ) -> list[IdentityProviderMapperRepresentation]:
        """
        Get all mappers for an identity provider.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            namespace: Origin namespace for rate limiting

        Returns:
            List of IdentityProviderMapperRepresentation objects

        Example:
            mappers = await admin_client.get_identity_provider_mappers(
                "my-realm", "github", "default"
            )
            for mapper in mappers:
                print(f"Mapper: {mapper.name}, Type: {mapper.identity_provider_mapper}")
        """
        logger.debug(
            f"Listing mappers for identity provider '{alias}' in realm '{realm_name}'"
        )

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/identity-provider/instances/{alias}/mappers",
                namespace,
            )

            if response.status_code == 200:
                return [
                    IdentityProviderMapperRepresentation.model_validate(mapper)
                    for mapper in response.json()
                ]
            else:
                logger.warning(
                    f"Failed to list identity provider mappers: {response.status_code}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to list identity provider mappers: {e}")
            return []

    async def get_identity_provider_mapper(
        self,
        realm_name: str,
        alias: str,
        mapper_id: str,
        namespace: str,
    ) -> IdentityProviderMapperRepresentation | None:
        """
        Get a specific mapper by ID.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            mapper_id: Mapper ID
            namespace: Origin namespace for rate limiting

        Returns:
            IdentityProviderMapperRepresentation if found, None otherwise
        """
        logger.debug(f"Getting mapper '{mapper_id}' for identity provider '{alias}'")

        try:
            response = await self._make_request(
                "GET",
                f"realms/{realm_name}/identity-provider/instances/{alias}/mappers/{mapper_id}",
                namespace,
            )

            if response.status_code == 200:
                return IdentityProviderMapperRepresentation.model_validate(
                    response.json()
                )
            elif response.status_code == 404:
                return None
            else:
                logger.warning(
                    f"Failed to get identity provider mapper: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Failed to get identity provider mapper: {e}")
            return None

    async def create_identity_provider_mapper(
        self,
        realm_name: str,
        alias: str,
        mapper: IdentityProviderMapperRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Create a mapper for an identity provider.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            mapper: Mapper configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise

        Example:
            mapper = IdentityProviderMapperRepresentation(
                name="email-mapper",
                identity_provider_alias="github",
                identity_provider_mapper="hardcoded-user-session-attribute-idp-mapper",
                config={"attribute": "email", "attribute.value": "${CLAIM.email}"}
            )
            success = await admin_client.create_identity_provider_mapper(
                "my-realm", "github", mapper, "default"
            )
        """
        if isinstance(mapper, dict):
            mapper = IdentityProviderMapperRepresentation.model_validate(mapper)

        mapper_name = mapper.name or "unknown"
        logger.info(f"Creating mapper '{mapper_name}' for identity provider '{alias}'")

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/identity-provider/instances/{alias}/mappers",
                namespace,
                request_model=mapper,
            )

            if response.status_code in [201, 204]:
                logger.info(f"Successfully created mapper '{mapper_name}'")
                return True
            else:
                logger.error(
                    f"Failed to create identity provider mapper: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to create identity provider mapper: {e}")
            return False

    async def update_identity_provider_mapper(
        self,
        realm_name: str,
        alias: str,
        mapper_id: str,
        mapper: IdentityProviderMapperRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Update an existing mapper.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            mapper_id: Mapper ID
            mapper: Updated mapper configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(mapper, dict):
            mapper = IdentityProviderMapperRepresentation.model_validate(mapper)

        mapper_name = mapper.name or mapper_id
        logger.info(f"Updating mapper '{mapper_name}' for identity provider '{alias}'")

        try:
            response = await self._make_validated_request(
                "PUT",
                f"realms/{realm_name}/identity-provider/instances/{alias}/mappers/{mapper_id}",
                namespace,
                request_model=mapper,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully updated mapper '{mapper_name}'")
                return True
            else:
                logger.error(
                    f"Failed to update identity provider mapper: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to update identity provider mapper: {e}")
            return False

    async def delete_identity_provider_mapper(
        self,
        realm_name: str,
        alias: str,
        mapper_id: str,
        namespace: str,
    ) -> bool:
        """
        Delete a mapper from an identity provider.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            mapper_id: Mapper ID
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful or not found, False on error
        """
        logger.info(f"Deleting mapper '{mapper_id}' from identity provider '{alias}'")

        try:
            response = await self._make_request(
                "DELETE",
                f"realms/{realm_name}/identity-provider/instances/{alias}/mappers/{mapper_id}",
                namespace,
            )

            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted mapper '{mapper_id}'")
                return True
            elif response.status_code == 404:
                logger.debug(f"Mapper '{mapper_id}' not found, nothing to delete")
                return True
            else:
                logger.error(
                    f"Failed to delete identity provider mapper: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to delete identity provider mapper: {e}")
            return False

    async def configure_identity_provider_mapper(
        self,
        realm_name: str,
        alias: str,
        mapper: IdentityProviderMapperRepresentation | dict[str, Any],
        namespace: str,
    ) -> bool:
        """
        Configure an identity provider mapper (create or update).

        This method finds existing mappers by name and updates them,
        or creates new ones if they don't exist.

        Args:
            realm_name: Name of the realm
            alias: Identity provider alias
            mapper: Mapper configuration
            namespace: Origin namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(mapper, dict):
            mapper = IdentityProviderMapperRepresentation.model_validate(mapper)

        mapper_name = mapper.name or "unknown"
        logger.info(
            f"Configuring mapper '{mapper_name}' for identity provider '{alias}'"
        )

        # Get existing mappers to find by name
        existing_mappers = await self.get_identity_provider_mappers(
            realm_name, alias, namespace
        )

        # Find existing mapper by name
        existing_mapper = next(
            (m for m in existing_mappers if m.name == mapper_name),
            None,
        )

        if existing_mapper and existing_mapper.id:
            # Update existing mapper - ensure ID is set
            mapper.id = existing_mapper.id
            return await self.update_identity_provider_mapper(
                realm_name, alias, existing_mapper.id, mapper, namespace
            )
        else:
            # Create new mapper
            return await self.create_identity_provider_mapper(
                realm_name, alias, mapper, namespace
            )

    async def configure_user_federation(
        self,
        realm_name: str,
        federation_config: ComponentRepresentation | dict[str, Any],
    ) -> bool:
        """
        Configure user federation for a realm.

        Args:
            realm_name: Name of the realm
            federation_config: User federation configuration as ComponentRepresentation or dict

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import ComponentRepresentation

            federation = ComponentRepresentation(
                name="ldap",
                provider_id="ldap"
            )
            success = admin_client.configure_user_federation("my-realm", federation)
        """
        # Convert dict to model if needed
        if isinstance(federation_config, dict):
            federation_config = ComponentRepresentation.model_validate(
                federation_config
            )

        federation_name = federation_config.name or "unknown"
        logger.info(
            f"Configuring user federation '{federation_name}' for realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/components",
                request_model=federation_config,
            )

            if response.status_code in [201, 204]:
                logger.info(
                    f"Successfully configured user federation '{federation_name}'"
                )
                return True
            else:
                logger.error(
                    f"Failed to configure user federation: {response.status_code}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to configure user federation: {e}")
            return False

    # =========================================================================
    # User Federation Provider CRUD Operations
    # =========================================================================

    async def get_user_federation_providers(
        self,
        realm_name: str,
        namespace: str = "default",
    ) -> list[ComponentRepresentation]:
        """
        Get all user federation providers for a realm.

        Args:
            realm_name: Name of the realm
            namespace: Kubernetes namespace (for logging)

        Returns:
            List of user federation provider configurations

        Example:
            providers = await admin_client.get_user_federation_providers("my-realm")
            for provider in providers:
                print(f"Provider: {provider.name}, Type: {provider.provider_id}")
        """
        logger.debug(f"Fetching user federation providers for realm '{realm_name}'")

        # Note: Keycloak's ?type= filter may not immediately reflect newly created
        # components. As a workaround, we fetch all components and filter client-side.
        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/components",
            namespace,
        )

        logger.debug(
            f"get_user_federation_providers: status={response.status_code}, "
            f"realm={realm_name}"
        )

        if response.status_code == 200:
            all_components = response.json()
            # Filter client-side for UserStorageProvider type
            providers = [
                c
                for c in all_components
                if c.get("providerType") == "org.keycloak.storage.UserStorageProvider"
            ]
            logger.debug(
                f"get_user_federation_providers: found {len(providers)} providers "
                f"(filtered from {len(all_components)} total components)"
            )
            return [ComponentRepresentation.model_validate(p) for p in providers]
        elif response.status_code == 404:
            logger.warning(f"Realm {realm_name} not found")
            return []
        else:
            raise KeycloakAdminError(
                f"Failed to get user federation providers: {response.status_code}",
                status_code=response.status_code,
            )

    async def get_user_federation_provider(
        self,
        realm_name: str,
        provider_id: str,
        namespace: str = "default",
    ) -> ComponentRepresentation | None:
        """
        Get a specific user federation provider by ID.

        Args:
            realm_name: Name of the realm
            provider_id: ID of the federation provider component
            namespace: Kubernetes namespace (for logging)

        Returns:
            Federation provider configuration or None if not found
        """
        logger.debug(
            f"Fetching user federation provider '{provider_id}' for realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/components/{provider_id}",
            namespace,
        )

        if response.status_code == 200:
            return ComponentRepresentation.model_validate(response.json())
        elif response.status_code == 404:
            return None
        else:
            raise KeycloakAdminError(
                f"Failed to get user federation provider: {response.status_code}",
                status_code=response.status_code,
            )

    async def get_user_federation_provider_by_name(
        self,
        realm_name: str,
        provider_name: str,
        namespace: str = "default",
    ) -> ComponentRepresentation | None:
        """
        Get a user federation provider by its display name.

        Args:
            realm_name: Name of the realm
            provider_name: Display name of the federation provider
            namespace: Kubernetes namespace (for logging)

        Returns:
            Federation provider configuration or None if not found
        """
        providers = await self.get_user_federation_providers(realm_name, namespace)
        for provider in providers:
            if provider.name == provider_name:
                return provider
        return None

    async def create_user_federation_provider(
        self,
        realm_name: str,
        federation_config: ComponentRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a new user federation provider.

        Args:
            realm_name: Name of the realm
            federation_config: Federation provider configuration
            namespace: Kubernetes namespace (for logging)

        Returns:
            ID of the created provider, or None on failure

        Example:
            config = ComponentRepresentation(
                name="corporate-ldap",
                provider_id="ldap",
                provider_type="org.keycloak.storage.UserStorageProvider",
                config={
                    "connectionUrl": ["ldap://ldap.example.com:389"],
                    "usersDn": ["ou=People,dc=example,dc=org"],
                    "bindDn": ["cn=admin,dc=example,dc=org"],
                    "bindCredential": ["secret"],
                    "vendor": ["other"],
                }
            )
            provider_id = await admin_client.create_user_federation_provider(
                "my-realm", config
            )
        """
        if isinstance(federation_config, dict):
            federation_config = ComponentRepresentation.model_validate(
                federation_config
            )

        # Ensure provider_type is set for user storage
        if not federation_config.provider_type:
            federation_config.provider_type = "org.keycloak.storage.UserStorageProvider"

        federation_name = federation_config.name or "unknown"
        logger.info(
            f"Creating user federation provider '{federation_name}' in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "POST",
            f"realms/{realm_name}/components",
            namespace,
            request_model=federation_config,
        )

        if response.status_code in [201, 204]:
            # Extract ID from Location header
            location = response.headers.get("Location", "")
            provider_id = location.split("/")[-1] if location else None
            logger.info(
                f"Successfully created user federation provider '{federation_name}' "
                f"with ID: {provider_id}"
            )
            return provider_id
        else:
            logger.error(
                f"Failed to create user federation provider: {response.status_code}"
            )
            return None

    async def update_user_federation_provider(
        self,
        realm_name: str,
        provider_id: str,
        federation_config: ComponentRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Update an existing user federation provider.

        Args:
            realm_name: Name of the realm
            provider_id: ID of the federation provider to update
            federation_config: Updated federation configuration
            namespace: Kubernetes namespace (for logging)

        Returns:
            True if successful, False otherwise
        """
        if isinstance(federation_config, dict):
            federation_config = ComponentRepresentation.model_validate(
                federation_config
            )

        # Ensure ID is set
        federation_config.id = provider_id

        federation_name = federation_config.name or provider_id
        logger.info(
            f"Updating user federation provider '{federation_name}' in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "PUT",
            f"realms/{realm_name}/components/{provider_id}",
            namespace,
            request_model=federation_config,
        )

        if response.status_code in [200, 204]:
            logger.info(
                f"Successfully updated user federation provider '{federation_name}'"
            )
            return True
        else:
            logger.error(
                f"Failed to update user federation provider: {response.status_code}"
            )
            return False

    async def delete_user_federation_provider(
        self,
        realm_name: str,
        provider_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Delete a user federation provider.

        Args:
            realm_name: Name of the realm
            provider_id: ID of the federation provider to delete
            namespace: Kubernetes namespace (for logging)

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Deleting user federation provider '{provider_id}' from realm '{realm_name}'"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/components/{provider_id}",
            namespace,
        )

        if response.status_code in [200, 204, 404]:
            logger.info(
                f"Successfully deleted user federation provider '{provider_id}'"
            )
            return True
        else:
            logger.error(
                f"Failed to delete user federation provider: {response.status_code}"
            )
            return False

    # =========================================================================
    # User Federation Mapper Operations
    # =========================================================================

    async def get_user_federation_mappers(
        self,
        realm_name: str,
        parent_id: str,
        namespace: str = "default",
    ) -> list[ComponentRepresentation]:
        """
        Get all mappers for a user federation provider.

        Args:
            realm_name: Name of the realm
            parent_id: ID of the parent federation provider
            namespace: Kubernetes namespace (for logging)

        Returns:
            List of mapper configurations
        """
        logger.debug(
            f"Fetching mappers for federation provider '{parent_id}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/components",
            namespace,
            params={
                "parent": parent_id,
                "type": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
            },
        )

        if response.status_code == 200:
            mappers = response.json()
            return [ComponentRepresentation.model_validate(m) for m in mappers]
        elif response.status_code == 404:
            return []
        else:
            raise KeycloakAdminError(
                f"Failed to get federation mappers: {response.status_code}",
                status_code=response.status_code,
            )

    async def create_user_federation_mapper(
        self,
        realm_name: str,
        parent_id: str,
        mapper_config: ComponentRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a mapper for a user federation provider.

        Args:
            realm_name: Name of the realm
            parent_id: ID of the parent federation provider
            mapper_config: Mapper configuration
            namespace: Kubernetes namespace (for logging)

        Returns:
            ID of the created mapper, or None on failure

        Example:
            mapper = ComponentRepresentation(
                name="email",
                provider_id="user-attribute-ldap-mapper",
                provider_type="org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                parent_id=federation_id,
                config={
                    "ldap.attribute": ["mail"],
                    "user.model.attribute": ["email"],
                    "read.only": ["true"],
                }
            )
            mapper_id = await admin_client.create_user_federation_mapper(
                "my-realm", federation_id, mapper
            )
        """
        if isinstance(mapper_config, dict):
            mapper_config = ComponentRepresentation.model_validate(mapper_config)

        # Set parent and provider type
        mapper_config.parent_id = parent_id
        if not mapper_config.provider_type:
            mapper_config.provider_type = (
                "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
            )

        mapper_name = mapper_config.name or "unknown"
        logger.info(
            f"Creating federation mapper '{mapper_name}' for provider '{parent_id}'"
        )

        response = await self._make_validated_request(
            "POST",
            f"realms/{realm_name}/components",
            namespace,
            request_model=mapper_config,
        )

        if response.status_code in [201, 204]:
            location = response.headers.get("Location", "")
            mapper_id = location.split("/")[-1] if location else None
            logger.info(f"Successfully created federation mapper '{mapper_name}'")
            return mapper_id
        else:
            logger.error(f"Failed to create federation mapper: {response.status_code}")
            return None

    async def delete_user_federation_mapper(
        self,
        realm_name: str,
        mapper_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Delete a user federation mapper.

        Args:
            realm_name: Name of the realm
            mapper_id: ID of the mapper to delete
            namespace: Kubernetes namespace (for logging)

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Deleting federation mapper '{mapper_id}' from realm '{realm_name}'"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/components/{mapper_id}",
            namespace,
        )

        if response.status_code in [200, 204, 404]:
            logger.info(f"Successfully deleted federation mapper '{mapper_id}'")
            return True
        else:
            logger.error(f"Failed to delete federation mapper: {response.status_code}")
            return False

    # =========================================================================
    # User Federation Sync Operations
    # =========================================================================

    async def trigger_user_federation_sync(
        self,
        realm_name: str,
        provider_id: str,
        full_sync: bool = False,
        namespace: str = "default",
    ) -> dict[str, Any]:
        """
        Trigger synchronization for a user federation provider.

        Args:
            realm_name: Name of the realm
            provider_id: ID of the federation provider
            full_sync: If True, perform full sync; otherwise, sync only changed users
            namespace: Kubernetes namespace (for logging)

        Returns:
            Dictionary with sync results (added, updated, removed, failed counts)

        Example:
            result = await admin_client.trigger_user_federation_sync(
                "my-realm", provider_id, full_sync=True
            )
            print(f"Added: {result.get('added')}, Updated: {result.get('updated')}")
        """
        action = "triggerFullSync" if full_sync else "triggerChangedUsersSync"
        logger.info(
            f"Triggering {'full' if full_sync else 'changed users'} sync "
            f"for provider '{provider_id}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/user-storage/{provider_id}/sync",
            namespace,
            params={"action": action},
        )

        if response.status_code == 200:
            result = response.json()
            logger.info(
                f"Sync completed: added={result.get('added', 0)}, "
                f"updated={result.get('updated', 0)}, "
                f"removed={result.get('removed', 0)}, "
                f"failed={result.get('failed', 0)}"
            )
            return result
        else:
            logger.error(f"Failed to trigger sync: {response.status_code}")
            raise KeycloakAdminError(
                f"Sync failed: {response.status_code}",
                status_code=response.status_code,
            )

    async def test_ldap_connection(
        self,
        realm_name: str,
        connection_config: dict[str, Any],
        namespace: str = "default",
    ) -> dict[str, Any]:
        """
        Test LDAP connection settings before creating a provider.

        Args:
            realm_name: Name of the realm
            connection_config: LDAP connection configuration to test
            namespace: Kubernetes namespace (for logging)

        Returns:
            Dictionary with test results

        Example:
            result = await admin_client.test_ldap_connection(
                "my-realm",
                {
                    "connectionUrl": "ldap://ldap.example.com:389",
                    "bindDn": "cn=admin,dc=example,dc=org",
                    "bindCredential": "secret",
                }
            )
            if result.get("status") == "success":
                print("Connection successful!")
        """
        logger.info(f"Testing LDAP connection for realm '{realm_name}'")

        # Keycloak expects the config in a specific format
        test_config = {
            "action": "testConnection",
            **connection_config,
        }

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/testLDAPConnection",
            namespace,
            json=test_config,
        )

        if response.status_code == 204:
            logger.info("LDAP connection test successful")
            return {"status": "success", "message": "Connection successful"}
        else:
            error_msg = response.text if response.text else "Connection failed"
            logger.error(f"LDAP connection test failed: {error_msg}")
            return {"status": "failed", "message": error_msg}

    async def test_ldap_authentication(
        self,
        realm_name: str,
        connection_config: dict[str, Any],
        namespace: str = "default",
    ) -> dict[str, Any]:
        """
        Test LDAP authentication (bind) settings.

        Args:
            realm_name: Name of the realm
            connection_config: LDAP connection configuration with bind credentials
            namespace: Kubernetes namespace (for logging)

        Returns:
            Dictionary with test results
        """
        logger.info(f"Testing LDAP authentication for realm '{realm_name}'")

        test_config = {
            "action": "testAuthentication",
            **connection_config,
        }

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/testLDAPConnection",
            namespace,
            json=test_config,
        )

        if response.status_code == 204:
            logger.info("LDAP authentication test successful")
            return {"status": "success", "message": "Authentication successful"}
        else:
            error_msg = response.text if response.text else "Authentication failed"
            logger.error(f"LDAP authentication test failed: {error_msg}")
            return {"status": "failed", "message": error_msg}

    # Protocol Mappers API methods
    @api_get_list("client protocol mappers")
    async def get_client_protocol_mappers(
        self, client_uuid: str, realm_name: str = "master", namespace: str = "default"
    ) -> list[ProtocolMapperRepresentation]:
        """
        Get all protocol mappers for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            realm_name: Name of the realm

        Returns:
            List of protocol mapper configurations as ProtocolMapperRepresentation

        Example:
            mappers = admin_client.get_client_protocol_mappers(client_uuid, "my-realm")
            for mapper in mappers:
                print(f"Mapper: {mapper.name}, Protocol: {mapper.protocol}")
        """
        logger.debug(
            f"Fetching protocol mappers for client {client_uuid} in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models",
            namespace,
        )

        if response.status_code == 200:
            mappers_data = response.json()
            return [
                ProtocolMapperRepresentation.model_validate(mapper)
                for mapper in mappers_data
            ]
        elif response.status_code == 404:
            logger.warning(f"Client {client_uuid} not found in realm {realm_name}")
            return []
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_single("client protocol mapper")
    async def create_client_protocol_mapper(
        self,
        client_uuid: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> ProtocolMapperRepresentation | None:
        """
        Create a protocol mapper for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_config: Protocol mapper configuration as ProtocolMapperRepresentation or dict
            realm_name: Name of the realm

        Returns:
            Created mapper configuration as ProtocolMapperRepresentation or None on error

        Example:
            from keycloak_operator.models.keycloak_api import ProtocolMapperRepresentation

            mapper = ProtocolMapperRepresentation(
                name="email",
                protocol="openid-connect",
                protocol_mapper="oidc-usermodel-property-mapper"
            )
            created = admin_client.create_client_protocol_mapper(
                client_uuid, mapper, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name or "unknown"
        logger.info(
            f"Creating protocol mapper '{mapper_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "POST",
            f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models",
            request_model=mapper_config,
        )

        if response.status_code == 201:
            logger.info(f"Successfully created protocol mapper '{mapper_name}'")
            return mapper_config
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client protocol mapper")
    async def update_client_protocol_mapper(
        self,
        client_uuid: str,
        mapper_id: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Update a protocol mapper for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_id: ID of the protocol mapper
            mapper_config: Updated protocol mapper configuration as ProtocolMapperRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            mappers = admin_client.get_client_protocol_mappers(client_uuid, "my-realm")
            mapper = mappers[0]
            mapper.protocol = "saml"
            success = admin_client.update_client_protocol_mapper(
                client_uuid, mapper.id, mapper, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name or "unknown"
        logger.info(
            f"Updating protocol mapper '{mapper_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "PUT",
            f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}",
            request_model=mapper_config,
        )

        if response.status_code == 204:
            logger.info(f"Successfully updated protocol mapper '{mapper_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("client protocol mapper")
    async def delete_client_protocol_mapper(
        self,
        client_uuid: str,
        mapper_id: str,
        realm_name: str = "master",
        namespace: str = "default",
    ) -> bool:
        """
        Delete a protocol mapper from a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            mapper_id: ID of the protocol mapper
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise
        """
        await self._ensure_authenticated()
        endpoint = f"realms/{realm_name}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}"

        response = await self._make_request("DELETE", endpoint, namespace)
        if response.status_code == 204:
            logger.info(f"Successfully deleted protocol mapper {mapper_id}")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # Client Roles API methods
    @api_get_list("client roles")
    async def get_client_roles(
        self, client_uuid: str, realm_name: str = "master", namespace: str = "default"
    ) -> list[RoleRepresentation]:
        """
        Get all roles for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            realm_name: Name of the realm

        Returns:
            List of client role configurations as RoleRepresentation

        Example:
            roles = admin_client.get_client_roles(client_uuid, "my-realm")
            for role in roles:
                print(f"Role: {role.name}, ID: {role.id}")
        """
        logger.debug(f"Fetching roles for client {client_uuid} in realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/clients/{client_uuid}/roles", namespace
        )

        if response.status_code == 200:
            roles_data = response.json()
            return [RoleRepresentation.model_validate(role) for role in roles_data]
        elif response.status_code == 404:
            logger.warning(f"Client {client_uuid} not found in realm {realm_name}")
            return []
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client role")
    async def create_client_role(
        self,
        client_uuid: str,
        role_config: RoleRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Create a role for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_config: Role configuration as RoleRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            from keycloak_operator.models.keycloak_api import RoleRepresentation

            role = RoleRepresentation(
                name="admin",
                description="Administrator role"
            )
            success = admin_client.create_client_role(client_uuid, role, "my-realm")
        """
        # Convert dict to model if needed
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        role_name = role_config.name or "unknown"
        logger.info(
            f"Creating client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "POST",
            f"realms/{realm_name}/clients/{client_uuid}/roles",
            request_model=role_config,
        )

        if response.status_code == 201:
            logger.info(f"Successfully created client role '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client role")
    async def update_client_role(
        self,
        client_uuid: str,
        role_name: str,
        role_config: RoleRepresentation | dict[str, Any],
        realm_name: str = "master",
    ) -> bool:
        """
        Update a role for a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to update
            role_config: Updated role configuration as RoleRepresentation or dict
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise

        Example:
            role = admin_client.get_client_role(client_uuid, "admin", "my-realm")
            role.description = "Updated description"
            success = admin_client.update_client_role(
                client_uuid, "admin", role, "my-realm"
            )
        """
        # Convert dict to model if needed
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        logger.info(
            f"Updating client role '{role_name}' for client {client_uuid} in realm '{realm_name}'"
        )

        response = await self._make_validated_request(
            "PUT",
            f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}",
            request_model=role_config,
        )

        if response.status_code == 204:
            logger.info(f"Successfully updated client role '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("client role")
    async def delete_client_role(
        self,
        client_uuid: str,
        role_name: str,
        realm_name: str = "master",
        namespace: str = "default",
    ) -> bool:
        """
        Delete a role from a client.

        Args:
            client_uuid: UUID of the client in Keycloak
            role_name: Name of the role to delete
            realm_name: Name of the realm

        Returns:
            True if successful, False otherwise
        """
        await self._ensure_authenticated()
        endpoint = f"realms/{realm_name}/clients/{client_uuid}/roles/{role_name}"

        response = await self._make_request("DELETE", endpoint, namespace)
        if response.status_code == 204:
            logger.info(f"Successfully deleted client role '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Realm Roles API methods
    # =========================================================================

    @api_get_list("realm roles")
    async def get_realm_roles(
        self, realm_name: str, namespace: str = "default"
    ) -> list[RoleRepresentation]:
        """
        Get all realm-level roles.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting

        Returns:
            List of realm role configurations as RoleRepresentation
        """
        logger.debug(f"Fetching realm roles for realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/roles", namespace
        )

        if response.status_code == 200:
            roles_data = response.json()
            return [RoleRepresentation.model_validate(role) for role in roles_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_single("realm role")
    async def get_realm_role_by_name(
        self, realm_name: str, role_name: str, namespace: str = "default"
    ) -> RoleRepresentation | None:
        """
        Get a specific realm role by name.

        Args:
            realm_name: Name of the realm
            role_name: Name of the role
            namespace: Namespace for rate limiting

        Returns:
            RoleRepresentation if found, None otherwise
        """
        logger.debug(f"Fetching realm role '{role_name}' in realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/roles/{role_name}", namespace
        )

        if response.status_code == 200:
            return RoleRepresentation.model_validate(response.json())
        elif response.status_code == 404:
            return None
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    async def create_realm_role(
        self,
        realm_name: str,
        role_config: RoleRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Create a realm-level role.

        Args:
            realm_name: Name of the realm
            role_config: Role configuration as RoleRepresentation or dict
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        role_name = role_config.name or "unknown"
        logger.info(f"Creating realm role '{role_name}' in realm '{realm_name}'")

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/roles",
                namespace,
                request_model=role_config,
            )

            if response.status_code == 201:
                logger.info(f"Successfully created realm role '{role_name}'")
                return True
            elif response.status_code == 409:
                logger.info(f"Realm role '{role_name}' already exists")
                return True
            else:
                logger.error(f"Failed to create realm role: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to create realm role: {e}")
            return False

    @api_update("realm role")
    async def update_realm_role(
        self,
        realm_name: str,
        role_name: str,
        role_config: RoleRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Update an existing realm-level role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the existing role
            role_config: Updated role configuration
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(role_config, dict):
            role_config = RoleRepresentation.model_validate(role_config)

        logger.info(f"Updating realm role '{role_name}' in realm '{realm_name}'")

        response = await self._make_validated_request(
            "PUT",
            f"realms/{realm_name}/roles/{role_name}",
            namespace,
            request_model=role_config,
        )

        if response.status_code in (200, 204):
            logger.info(f"Successfully updated realm role '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("realm role")
    async def delete_realm_role(
        self, realm_name: str, role_name: str, namespace: str = "default"
    ) -> bool:
        """
        Delete a realm-level role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the role to delete
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting realm role '{role_name}' in realm '{realm_name}'")

        response = await self._make_request(
            "DELETE", f"realms/{realm_name}/roles/{role_name}", namespace
        )

        if response.status_code == 204:
            logger.info(f"Successfully deleted realm role '{role_name}'")
            return True
        elif response.status_code == 404:
            logger.info(f"Realm role '{role_name}' not found (already deleted)")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("realm role composites")
    async def get_realm_role_composites(
        self, realm_name: str, role_name: str, namespace: str = "default"
    ) -> list[RoleRepresentation]:
        """
        Get composite roles (child roles) of a realm role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the composite role
            namespace: Namespace for rate limiting

        Returns:
            List of child role configurations
        """
        logger.debug(
            f"Fetching composite roles for realm role '{role_name}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET", f"realms/{realm_name}/roles/{role_name}/composites", namespace
        )

        if response.status_code == 200:
            roles_data = response.json()
            return [RoleRepresentation.model_validate(role) for role in roles_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("realm role composites")
    async def add_realm_role_composites(
        self,
        realm_name: str,
        role_name: str,
        child_roles: list[RoleRepresentation] | list[dict[str, Any]],
        namespace: str = "default",
    ) -> bool:
        """
        Add composite (child) roles to a realm role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the parent role
            child_roles: List of roles to add as composites
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Adding {len(child_roles)} composite roles to realm role '{role_name}'"
        )

        roles_data = []
        for role in child_roles:
            if isinstance(role, dict):
                roles_data.append(role)
            else:
                roles_data.append(role.model_dump(by_alias=True, exclude_none=True))

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/roles/{role_name}/composites",
            namespace,
            json=roles_data,
        )

        if response.status_code == 204:
            logger.info(f"Successfully added composite roles to '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("realm role composites")
    async def remove_realm_role_composites(
        self,
        realm_name: str,
        role_name: str,
        child_roles: list[RoleRepresentation] | list[dict[str, Any]],
        namespace: str = "default",
    ) -> bool:
        """
        Remove composite (child) roles from a realm role.

        Args:
            realm_name: Name of the realm
            role_name: Name of the parent role
            child_roles: List of roles to remove from composites
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing {len(child_roles)} composite roles from realm role '{role_name}'"
        )

        roles_data = []
        for role in child_roles:
            if isinstance(role, dict):
                roles_data.append(role)
            else:
                roles_data.append(role.model_dump(by_alias=True, exclude_none=True))

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/roles/{role_name}/composites",
            namespace,
            json=roles_data,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed composite roles from '{role_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Client Scopes API methods
    # =========================================================================

    @api_get_list("client scopes")
    async def get_client_scopes(
        self, realm_name: str, namespace: str = "default"
    ) -> list[ClientScopeRepresentation]:
        """
        Get all client scopes in a realm.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting

        Returns:
            List of client scopes as ClientScopeRepresentation
        """
        logger.debug(f"Fetching client scopes for realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/client-scopes", namespace
        )

        if response.status_code == 200:
            scopes_data = response.json()
            return [
                ClientScopeRepresentation.model_validate(scope) for scope in scopes_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_single("client scope by name")
    async def get_client_scope_by_name(
        self, realm_name: str, scope_name: str, namespace: str = "default"
    ) -> ClientScopeRepresentation | None:
        """
        Get a specific client scope by name.

        Args:
            realm_name: Name of the realm
            scope_name: Name of the client scope
            namespace: Namespace for rate limiting

        Returns:
            ClientScopeRepresentation if found, None otherwise
        """
        logger.debug(f"Fetching client scope '{scope_name}' in realm '{realm_name}'")

        scopes = await self.get_client_scopes(realm_name, namespace)
        for scope in scopes:
            if scope.name == scope_name:
                return scope
        return None

    async def create_client_scope(
        self,
        realm_name: str,
        scope_config: ClientScopeRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a new client scope.

        Args:
            realm_name: Name of the realm
            scope_config: Client scope configuration
            namespace: Namespace for rate limiting

        Returns:
            ID of the created client scope, or None if creation failed
        """
        if isinstance(scope_config, dict):
            scope_config = ClientScopeRepresentation.model_validate(scope_config)

        scope_name = scope_config.name
        logger.info(f"Creating client scope '{scope_name}' in realm '{realm_name}'")

        try:
            payload = scope_config.model_dump(by_alias=True, exclude_none=True)
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/client-scopes",
                namespace,
                json=payload,
            )

            if response.status_code == 201:
                # Extract ID from Location header
                location = response.headers.get("Location", "")
                scope_id = location.split("/")[-1] if location else None
                logger.info(f"Successfully created client scope '{scope_name}'")
                return scope_id
            else:
                logger.error(f"Failed to create client scope: {response.status_code}")
                return None
        except KeycloakAdminError as e:
            if e.status_code == 409:
                logger.warning(f"Client scope '{scope_name}' already exists")
                # Return existing scope ID
                existing = await self.get_client_scope_by_name(
                    realm_name, scope_name or "", namespace
                )
                return existing.id if existing else None
            logger.error(f"Failed to create client scope: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create client scope: {e}")
            return None

    @api_update("client scope")
    async def update_client_scope(
        self,
        realm_name: str,
        scope_id: str,
        scope_config: ClientScopeRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Update an existing client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to update
            scope_config: Updated client scope configuration
            namespace: Namespace for rate limiting

        Returns:
            True if update successful, False otherwise
        """
        if isinstance(scope_config, dict):
            scope_config = ClientScopeRepresentation.model_validate(scope_config)

        scope_name = scope_config.name
        logger.info(f"Updating client scope '{scope_name}' in realm '{realm_name}'")

        payload = scope_config.model_dump(by_alias=True, exclude_none=True)
        # Ensure ID is included in payload
        payload["id"] = scope_id

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/client-scopes/{scope_id}",
            namespace,
            json=payload,
        )

        if response.status_code == 204:
            logger.info(f"Successfully updated client scope '{scope_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("client scope")
    async def delete_client_scope(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> bool:
        """
        Delete a client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to delete
            namespace: Namespace for rate limiting

        Returns:
            True if deletion successful, False otherwise
        """
        logger.info(f"Deleting client scope '{scope_id}' from realm '{realm_name}'")

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully deleted client scope '{scope_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Realm Default/Optional Client Scopes API methods
    # =========================================================================

    @api_get_list("realm default client scopes")
    async def get_realm_default_client_scopes(
        self, realm_name: str, namespace: str = "default"
    ) -> list[ClientScopeRepresentation]:
        """
        Get realm default client scopes.

        These scopes are assigned to all new clients by default.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting

        Returns:
            List of default client scopes
        """
        logger.debug(f"Fetching realm default client scopes for '{realm_name}'")

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/default-default-client-scopes",
            namespace,
        )

        if response.status_code == 200:
            scopes_data = response.json()
            return [
                ClientScopeRepresentation.model_validate(scope) for scope in scopes_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("realm default client scope", conflict_is_success=True)
    async def add_realm_default_client_scope(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> bool:
        """
        Add a client scope to realm default client scopes.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to add
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Adding scope '{scope_id}' to realm default scopes in '{realm_name}'"
        )

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/default-default-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully added default client scope '{scope_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("realm default client scope")
    async def remove_realm_default_client_scope(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> bool:
        """
        Remove a client scope from realm default client scopes.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to remove
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing scope '{scope_id}' from realm default scopes in '{realm_name}'"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/default-default-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed default client scope '{scope_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("realm optional client scopes")
    async def get_realm_optional_client_scopes(
        self, realm_name: str, namespace: str = "default"
    ) -> list[ClientScopeRepresentation]:
        """
        Get realm optional client scopes.

        These scopes are available for clients to request optionally.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting

        Returns:
            List of optional client scopes
        """
        logger.debug(f"Fetching realm optional client scopes for '{realm_name}'")

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/default-optional-client-scopes",
            namespace,
        )

        if response.status_code == 200:
            scopes_data = response.json()
            return [
                ClientScopeRepresentation.model_validate(scope) for scope in scopes_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("realm optional client scope", conflict_is_success=True)
    async def add_realm_optional_client_scope(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> bool:
        """
        Add a client scope to realm optional client scopes.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to add
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Adding scope '{scope_id}' to realm optional scopes in '{realm_name}'"
        )

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/default-optional-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully added optional client scope '{scope_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("realm optional client scope")
    async def remove_realm_optional_client_scope(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> bool:
        """
        Remove a client scope from realm optional client scopes.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope to remove
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing scope '{scope_id}' from realm optional scopes in '{realm_name}'"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/default-optional-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed optional client scope '{scope_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Client-level Default/Optional Client Scopes API methods
    # =========================================================================

    @api_get_list("client default scopes")
    async def get_client_default_scopes(
        self, realm_name: str, client_uuid: str, namespace: str = "default"
    ) -> list[ClientScopeRepresentation]:
        """
        Get default client scopes assigned to a specific client.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            namespace: Namespace for rate limiting

        Returns:
            List of default client scopes for this client
        """
        logger.debug(
            f"Fetching default scopes for client '{client_uuid}' in '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/clients/{client_uuid}/default-client-scopes",
            namespace,
        )

        if response.status_code == 200:
            scopes_data = response.json()
            return [
                ClientScopeRepresentation.model_validate(scope) for scope in scopes_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client default scope", conflict_is_success=True)
    async def add_client_default_scope(
        self,
        realm_name: str,
        client_uuid: str,
        scope_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Add a client scope to a client's default scopes.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            scope_id: ID of the client scope to add
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Adding scope '{scope_id}' to client '{client_uuid}' default scopes"
        )

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/clients/{client_uuid}/default-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully added default scope '{scope_id}' to client")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("client default scope")
    async def remove_client_default_scope(
        self,
        realm_name: str,
        client_uuid: str,
        scope_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Remove a client scope from a client's default scopes.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            scope_id: ID of the client scope to remove
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing scope '{scope_id}' from client '{client_uuid}' default scopes"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/clients/{client_uuid}/default-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed default scope '{scope_id}' from client")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("client optional scopes")
    async def get_client_optional_scopes(
        self, realm_name: str, client_uuid: str, namespace: str = "default"
    ) -> list[ClientScopeRepresentation]:
        """
        Get optional client scopes assigned to a specific client.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            namespace: Namespace for rate limiting

        Returns:
            List of optional client scopes for this client
        """
        logger.debug(
            f"Fetching optional scopes for client '{client_uuid}' in '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/clients/{client_uuid}/optional-client-scopes",
            namespace,
        )

        if response.status_code == 200:
            scopes_data = response.json()
            return [
                ClientScopeRepresentation.model_validate(scope) for scope in scopes_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client optional scope", conflict_is_success=True)
    async def add_client_optional_scope(
        self,
        realm_name: str,
        client_uuid: str,
        scope_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Add a client scope to a client's optional scopes.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            scope_id: ID of the client scope to add
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Adding scope '{scope_id}' to client '{client_uuid}' optional scopes"
        )

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/clients/{client_uuid}/optional-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully added optional scope '{scope_id}' to client")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("client optional scope")
    async def remove_client_optional_scope(
        self,
        realm_name: str,
        client_uuid: str,
        scope_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Remove a client scope from a client's optional scopes.

        Args:
            realm_name: Name of the realm
            client_uuid: UUID of the client
            scope_id: ID of the client scope to remove
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing scope '{scope_id}' from client '{client_uuid}' optional scopes"
        )

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/clients/{client_uuid}/optional-client-scopes/{scope_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed optional scope '{scope_id}' from client")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Client Scope Protocol Mappers API methods
    # =========================================================================

    @api_get_list("scope protocol mappers")
    async def get_client_scope_protocol_mappers(
        self, realm_name: str, scope_id: str, namespace: str = "default"
    ) -> list[ProtocolMapperRepresentation]:
        """
        Get protocol mappers for a client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope
            namespace: Namespace for rate limiting

        Returns:
            List of protocol mappers
        """
        logger.debug(
            f"Fetching protocol mappers for scope '{scope_id}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/client-scopes/{scope_id}/protocol-mappers/models",
            namespace,
        )

        if response.status_code == 200:
            mappers_data = response.json()
            return [
                ProtocolMapperRepresentation.model_validate(mapper)
                for mapper in mappers_data
            ]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    async def create_client_scope_protocol_mapper(
        self,
        realm_name: str,
        scope_id: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a protocol mapper in a client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope
            mapper_config: Protocol mapper configuration
            namespace: Namespace for rate limiting

        Returns:
            ID of the created mapper, or None if creation failed
        """
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name
        logger.info(f"Creating protocol mapper '{mapper_name}' in scope '{scope_id}'")

        try:
            payload = mapper_config.model_dump(by_alias=True, exclude_none=True)
            response = await self._make_request(
                "POST",
                f"realms/{realm_name}/client-scopes/{scope_id}/protocol-mappers/models",
                namespace,
                json=payload,
            )

            if response.status_code == 201:
                location = response.headers.get("Location", "")
                mapper_id = location.split("/")[-1] if location else None
                logger.info(f"Successfully created protocol mapper '{mapper_name}'")
                return mapper_id
            else:
                logger.error(
                    f"Failed to create protocol mapper: {response.status_code}"
                )
                return None
        except KeycloakAdminError as e:
            if e.status_code == 409:
                logger.warning(f"Protocol mapper '{mapper_name}' already exists")
                # Find and return existing mapper ID
                mappers = await self.get_client_scope_protocol_mappers(
                    realm_name, scope_id, namespace
                )
                for mapper in mappers:
                    if mapper.name == mapper_name:
                        return mapper.id
                return None
            logger.error(f"Failed to create protocol mapper: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create protocol mapper: {e}")
            return None

    @api_update("scope protocol mapper")
    async def update_client_scope_protocol_mapper(
        self,
        realm_name: str,
        scope_id: str,
        mapper_id: str,
        mapper_config: ProtocolMapperRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Update a protocol mapper in a client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope
            mapper_id: ID of the mapper to update
            mapper_config: Updated protocol mapper configuration
            namespace: Namespace for rate limiting

        Returns:
            True if update successful, False otherwise
        """
        if isinstance(mapper_config, dict):
            mapper_config = ProtocolMapperRepresentation.model_validate(mapper_config)

        mapper_name = mapper_config.name
        logger.info(f"Updating protocol mapper '{mapper_name}' in scope '{scope_id}'")

        payload = mapper_config.model_dump(by_alias=True, exclude_none=True)
        payload["id"] = mapper_id

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/client-scopes/{scope_id}/protocol-mappers/models/{mapper_id}",
            namespace,
            json=payload,
        )

        if response.status_code == 204:
            logger.info(f"Successfully updated protocol mapper '{mapper_name}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("scope protocol mapper")
    async def delete_client_scope_protocol_mapper(
        self,
        realm_name: str,
        scope_id: str,
        mapper_id: str,
        namespace: str = "default",
    ) -> bool:
        """
        Delete a protocol mapper from a client scope.

        Args:
            realm_name: Name of the realm
            scope_id: ID of the client scope
            mapper_id: ID of the mapper to delete
            namespace: Namespace for rate limiting

        Returns:
            True if deletion successful, False otherwise
        """
        logger.info(f"Deleting protocol mapper '{mapper_id}' from scope '{scope_id}'")

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/client-scopes/{scope_id}/protocol-mappers/models/{mapper_id}",
            namespace,
        )

        if response.status_code == 204:
            logger.info(f"Successfully deleted protocol mapper '{mapper_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    # =========================================================================
    # Groups API methods
    # =========================================================================

    @api_get_list("groups")
    async def get_groups(
        self,
        realm_name: str,
        namespace: str = "default",
        brief_representation: bool = False,
    ) -> list[GroupRepresentation]:
        """
        Get all top-level groups in a realm.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting
            brief_representation: If true, returns only basic group info

        Returns:
            List of group configurations
        """
        logger.debug(f"Fetching groups for realm '{realm_name}'")

        params = {"briefRepresentation": str(brief_representation).lower()}
        response = await self._make_request(
            "GET", f"realms/{realm_name}/groups", namespace, params=params
        )

        if response.status_code == 200:
            groups_data = response.json()
            return [GroupRepresentation.model_validate(group) for group in groups_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_single("group")
    async def get_group_by_id(
        self, realm_name: str, group_id: str, namespace: str = "default"
    ) -> GroupRepresentation | None:
        """
        Get a specific group by its ID.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            namespace: Namespace for rate limiting

        Returns:
            GroupRepresentation if found, None otherwise
        """
        logger.debug(f"Fetching group '{group_id}' in realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/groups/{group_id}", namespace
        )

        if response.status_code == 200:
            return GroupRepresentation.model_validate(response.json())
        elif response.status_code == 404:
            return None
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_single("group by path")
    async def get_group_by_path(
        self, realm_name: str, path: str, namespace: str = "default"
    ) -> GroupRepresentation | None:
        """
        Get a group by its path (e.g., /parent/child).

        Args:
            realm_name: Name of the realm
            path: Group path (e.g., "/parent/child")
            namespace: Namespace for rate limiting

        Returns:
            GroupRepresentation if found, None otherwise
        """
        logger.debug(f"Fetching group by path '{path}' in realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/group-by-path/{path}", namespace
        )

        if response.status_code == 200:
            return GroupRepresentation.model_validate(response.json())
        elif response.status_code == 404:
            return None
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    async def create_group(
        self,
        realm_name: str,
        group_config: GroupRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a top-level group.

        Args:
            realm_name: Name of the realm
            group_config: Group configuration
            namespace: Namespace for rate limiting

        Returns:
            Group ID if successful, None otherwise
        """
        if isinstance(group_config, dict):
            group_config = GroupRepresentation.model_validate(group_config)

        group_name = group_config.name or "unknown"
        logger.info(f"Creating group '{group_name}' in realm '{realm_name}'")

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/groups",
                namespace,
                request_model=group_config,
            )

            if response.status_code == 201:
                # Extract group ID from Location header
                location = response.headers.get("Location", "")
                group_id = location.split("/")[-1] if location else None
                logger.info(
                    f"Successfully created group '{group_name}' with ID {group_id}"
                )
                return group_id
            elif response.status_code == 409:
                logger.info(f"Group '{group_name}' already exists")
                # Try to find the existing group
                existing_group = await self.get_group_by_path(
                    realm_name, f"/{group_name}", namespace
                )
                return existing_group.id if existing_group else None
            else:
                logger.error(f"Failed to create group: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to create group: {e}")
            return None

    async def create_subgroup(
        self,
        realm_name: str,
        parent_group_id: str,
        group_config: GroupRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> str | None:
        """
        Create a subgroup under a parent group.

        Args:
            realm_name: Name of the realm
            parent_group_id: ID of the parent group
            group_config: Subgroup configuration
            namespace: Namespace for rate limiting

        Returns:
            Subgroup ID if successful, None otherwise
        """
        if isinstance(group_config, dict):
            group_config = GroupRepresentation.model_validate(group_config)

        group_name = group_config.name or "unknown"
        logger.info(
            f"Creating subgroup '{group_name}' under parent '{parent_group_id}' "
            f"in realm '{realm_name}'"
        )

        try:
            response = await self._make_validated_request(
                "POST",
                f"realms/{realm_name}/groups/{parent_group_id}/children",
                namespace,
                request_model=group_config,
            )

            if response.status_code == 201:
                location = response.headers.get("Location", "")
                group_id = location.split("/")[-1] if location else None
                logger.info(
                    f"Successfully created subgroup '{group_name}' with ID {group_id}"
                )
                return group_id
            elif response.status_code == 409:
                logger.info(f"Subgroup '{group_name}' already exists")
                return None
            else:
                logger.error(f"Failed to create subgroup: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to create subgroup: {e}")
            return None

    @api_update("group")
    async def update_group(
        self,
        realm_name: str,
        group_id: str,
        group_config: GroupRepresentation | dict[str, Any],
        namespace: str = "default",
    ) -> bool:
        """
        Update an existing group.

        Note: Keycloak's PUT endpoint ignores subGroups - they must be managed
        separately via create_subgroup(). Read-only fields (path, subGroupCount,
        access) are excluded from the update payload to prevent 500 errors.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group to update
            group_config: Updated group configuration
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        if isinstance(group_config, dict):
            group_config = GroupRepresentation.model_validate(group_config)

        logger.info(f"Updating group '{group_id}' in realm '{realm_name}'")

        # Build update payload excluding:
        # - Read-only fields (path, sub_group_count, access) that cause 500 errors
        # - sub_groups: Keycloak ignores these in PUT; use /children endpoint instead
        update_payload = group_config.model_dump(
            exclude_none=True,
            by_alias=True,
            mode="json",
            exclude={"sub_group_count", "sub_groups", "access", "path"},
        )

        response = await self._make_request(
            "PUT",
            f"realms/{realm_name}/groups/{group_id}",
            namespace,
            json=update_payload,
        )

        if response.status_code in (200, 204):
            logger.info(f"Successfully updated group '{group_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("group")
    async def delete_group(
        self, realm_name: str, group_id: str, namespace: str = "default"
    ) -> bool:
        """
        Delete a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group to delete
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Deleting group '{group_id}' in realm '{realm_name}'")

        response = await self._make_request(
            "DELETE", f"realms/{realm_name}/groups/{group_id}", namespace
        )

        if response.status_code == 204:
            logger.info(f"Successfully deleted group '{group_id}'")
            return True
        elif response.status_code == 404:
            logger.info(f"Group '{group_id}' not found (already deleted)")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("group realm role mappings")
    async def get_group_realm_role_mappings(
        self, realm_name: str, group_id: str, namespace: str = "default"
    ) -> list[RoleRepresentation]:
        """
        Get realm role mappings for a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            namespace: Namespace for rate limiting

        Returns:
            List of assigned realm roles
        """
        logger.debug(
            f"Fetching realm role mappings for group '{group_id}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/groups/{group_id}/role-mappings/realm",
            namespace,
        )

        if response.status_code == 200:
            roles_data = response.json()
            return [RoleRepresentation.model_validate(role) for role in roles_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("realm roles to group", conflict_is_success=True)
    async def assign_realm_roles_to_group(
        self,
        realm_name: str,
        group_id: str,
        roles: list[RoleRepresentation] | list[dict[str, Any]],
        namespace: str = "default",
    ) -> bool:
        """
        Assign realm roles to a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            roles: List of roles to assign
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Assigning {len(roles)} realm roles to group '{group_id}' "
            f"in realm '{realm_name}'"
        )

        roles_data = []
        for role in roles:
            if isinstance(role, dict):
                roles_data.append(role)
            else:
                roles_data.append(role.model_dump(by_alias=True, exclude_none=True))

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/groups/{group_id}/role-mappings/realm",
            namespace,
            json=roles_data,
        )

        if response.status_code == 204:
            logger.info(f"Successfully assigned realm roles to group '{group_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("realm roles from group")
    async def remove_realm_roles_from_group(
        self,
        realm_name: str,
        group_id: str,
        roles: list[RoleRepresentation] | list[dict[str, Any]],
        namespace: str = "default",
    ) -> bool:
        """
        Remove realm roles from a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            roles: List of roles to remove
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing {len(roles)} realm roles from group '{group_id}' "
            f"in realm '{realm_name}'"
        )

        roles_data = []
        for role in roles:
            if isinstance(role, dict):
                roles_data.append(role)
            else:
                roles_data.append(role.model_dump(by_alias=True, exclude_none=True))

        response = await self._make_request(
            "DELETE",
            f"realms/{realm_name}/groups/{group_id}/role-mappings/realm",
            namespace,
            json=roles_data,
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed realm roles from group '{group_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("group client role mappings")
    async def get_group_client_role_mappings(
        self,
        realm_name: str,
        group_id: str,
        client_uuid: str,
        namespace: str = "default",
    ) -> list[RoleRepresentation]:
        """
        Get client role mappings for a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            client_uuid: UUID of the client
            namespace: Namespace for rate limiting

        Returns:
            List of assigned client roles
        """
        logger.debug(
            f"Fetching client role mappings for group '{group_id}' "
            f"and client '{client_uuid}' in realm '{realm_name}'"
        )

        response = await self._make_request(
            "GET",
            f"realms/{realm_name}/groups/{group_id}/role-mappings/clients/{client_uuid}",
            namespace,
        )

        if response.status_code == 200:
            roles_data = response.json()
            return [RoleRepresentation.model_validate(role) for role in roles_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("client roles to group", conflict_is_success=True)
    async def assign_client_roles_to_group(
        self,
        realm_name: str,
        group_id: str,
        client_uuid: str,
        roles: list[RoleRepresentation] | list[dict[str, Any]],
        namespace: str = "default",
    ) -> bool:
        """
        Assign client roles to a group.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group
            client_uuid: UUID of the client
            roles: List of roles to assign
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Assigning {len(roles)} client roles to group '{group_id}' "
            f"for client '{client_uuid}' in realm '{realm_name}'"
        )

        roles_data = []
        for role in roles:
            if isinstance(role, dict):
                roles_data.append(role)
            else:
                roles_data.append(role.model_dump(by_alias=True, exclude_none=True))

        response = await self._make_request(
            "POST",
            f"realms/{realm_name}/groups/{group_id}/role-mappings/clients/{client_uuid}",
            namespace,
            json=roles_data,
        )

        if response.status_code == 204:
            logger.info(f"Successfully assigned client roles to group '{group_id}'")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_get_list("default groups")
    async def get_default_groups(
        self, realm_name: str, namespace: str = "default"
    ) -> list[GroupRepresentation]:
        """
        Get the default groups for a realm.

        Default groups are automatically assigned to new users.

        Args:
            realm_name: Name of the realm
            namespace: Namespace for rate limiting

        Returns:
            List of default groups
        """
        logger.debug(f"Fetching default groups for realm '{realm_name}'")

        response = await self._make_request(
            "GET", f"realms/{realm_name}/default-groups", namespace
        )

        if response.status_code == 200:
            groups_data = response.json()
            return [GroupRepresentation.model_validate(group) for group in groups_data]
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_update("default group", conflict_is_success=True)
    async def add_default_group(
        self, realm_name: str, group_id: str, namespace: str = "default"
    ) -> bool:
        """
        Add a group to the default groups.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group to add as default
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Adding group '{group_id}' as default in realm '{realm_name}'")

        response = await self._make_request(
            "PUT", f"realms/{realm_name}/default-groups/{group_id}", namespace
        )

        if response.status_code in (200, 204):
            logger.info(f"Successfully added group '{group_id}' as default")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )

    @api_delete("default group")
    async def remove_default_group(
        self, realm_name: str, group_id: str, namespace: str = "default"
    ) -> bool:
        """
        Remove a group from the default groups.

        Args:
            realm_name: Name of the realm
            group_id: ID of the group to remove from defaults
            namespace: Namespace for rate limiting

        Returns:
            True if successful, False otherwise
        """
        logger.info(
            f"Removing group '{group_id}' from defaults in realm '{realm_name}'"
        )

        response = await self._make_request(
            "DELETE", f"realms/{realm_name}/default-groups/{group_id}", namespace
        )

        if response.status_code == 204:
            logger.info(f"Successfully removed group '{group_id}' from defaults")
            return True
        elif response.status_code == 404:
            logger.info(f"Group '{group_id}' was not a default group (already removed)")
            return True
        else:
            raise KeycloakAdminError(
                f"Unexpected status code: {response.status_code}",
                status_code=response.status_code,
            )


async def get_keycloak_admin_client(
    keycloak_name: str,
    namespace: str,
    rate_limiter: "RateLimiter | None" = None,
    verify_ssl: bool = False,
) -> KeycloakAdminClient:
    """
    Factory function to create KeycloakAdminClient for a specific instance.

    This function handles:
    - Looking up Keycloak instance details from Kubernetes
    - Retrieving admin credentials from secrets
    - Creating configured admin client with rate limiting

    Args:
        keycloak_name: Name of the Keycloak instance
        namespace: Namespace where the Keycloak instance exists
        rate_limiter: Optional rate limiter for API throttling
        verify_ssl: Whether to verify SSL certificates (default: False for development)

    Returns:
        Configured KeycloakAdminClient instance
    """
    from kubernetes import client as k8s_client

    from keycloak_operator.utils.kubernetes import get_kubernetes_client

    logger.info(f"Creating admin client for Keycloak {keycloak_name} in {namespace}")

    try:
        # Get Keycloak instance details
        k8s = get_kubernetes_client()
        custom_api = k8s_client.CustomObjectsApi(k8s)

        # Get Keycloak instance
        keycloak_instance = custom_api.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=namespace,
            plural="keycloaks",
            name=keycloak_name,
        )

        # Get server URL from instance status
        server_url = (
            keycloak_instance.get("status", {}).get("endpoints", {}).get("admin")
        )
        if not server_url:
            raise KeycloakAdminError(
                f"Keycloak instance {keycloak_name} does not have admin endpoint ready"
            )

        # Get admin credentials from secret
        core_api = k8s_client.CoreV1Api(k8s)
        admin_secret_name = f"{keycloak_name}-admin-credentials"

        try:
            secret = core_api.read_namespaced_secret(
                name=admin_secret_name, namespace=namespace
            )

            # Decode credentials from secret
            import base64

            username = base64.b64decode(secret.data["username"]).decode("utf-8")
            password = base64.b64decode(secret.data["password"]).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to retrieve admin credentials: {e}")
            raise KeycloakAdminError(
                f"Could not retrieve admin credentials for {keycloak_name}"
            ) from e

        # Create and return admin client
        admin_client = KeycloakAdminClient(
            server_url=server_url,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            rate_limiter=rate_limiter,
        )

        # Test authentication
        await admin_client.authenticate()

        logger.info(f"Successfully created admin client for {keycloak_name}")
        return admin_client

    except Exception as e:
        logger.error(f"Failed to create admin client: {e}")
        raise KeycloakAdminError(f"Admin client creation failed: {e}") from e
