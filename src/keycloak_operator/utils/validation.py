"""
Validation utilities for the Keycloak operator.

This module provides validation functions for Keycloak resources,
configurations, and operator settings. It includes:

- Resource specification validation
- Configuration consistency checks
- Security and best practice validations
- Cross-resource dependency validation
"""

import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Exception raised for validation failures."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


def validate_resource_name(name: str, resource_type: str = "resource") -> None:
    """
    Validate Kubernetes resource name according to DNS-1123 subdomain rules.

    Args:
        name: Resource name to validate
        resource_type: Type of resource for error messages

    Raises:
        ValidationError: If name is invalid

    TODO: Implement the following validation:
    1. Check length limits (1-253 characters)
    2. Check allowed characters (lowercase letters, numbers, hyphens)
    3. Check start/end characters (must be alphanumeric)
    4. Check for consecutive hyphens
    5. Provide clear error messages
    """
    if not name:
        raise ValidationError(f"{resource_type} name cannot be empty")

    if len(name) > 253:
        raise ValidationError(
            f"{resource_type} name '{name}' is too long (max 253 characters)"
        )

    if len(name) < 1:
        raise ValidationError(f"{resource_type} name cannot be empty")

    # DNS-1123 subdomain rules
    pattern = r"^[a-z0-9]([a-z0-9\-]{0,251}[a-z0-9])?$"
    if not re.match(pattern, name):
        raise ValidationError(
            f"{resource_type} name '{name}' is invalid. "
            "Must contain only lowercase letters, numbers, and hyphens, "
            "and must start and end with an alphanumeric character"
        )

    logger.debug(f"Validated {resource_type} name: {name}")


def validate_namespace_name(namespace: str) -> None:
    """
    Validate Kubernetes namespace name.

    Args:
        namespace: Namespace name to validate

    Raises:
        ValidationError: If namespace name is invalid
    """
    validate_resource_name(namespace, "namespace")

    # Additional namespace-specific validations
    reserved_namespaces = {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "default",
    }

    if namespace in reserved_namespaces:
        logger.warning(
            f"Using reserved namespace '{namespace}' - ensure this is intentional"
        )


def validate_client_id(client_id: str) -> None:
    """
    Validate Keycloak client ID format.

    Args:
        client_id: Client ID to validate

    Raises:
        ValidationError: If client ID is invalid

    TODO: Implement validation for:
    1. Length limits
    2. Allowed characters
    3. Reserved client IDs
    4. Best practice recommendations
    """
    if not client_id:
        raise ValidationError("Client ID cannot be empty")

    if len(client_id) > 255:
        raise ValidationError(
            f"Client ID '{client_id}' is too long (max 255 characters)"
        )

    # Check for problematic characters
    problematic_chars = [" ", "\t", "\n", "\r"]
    for char in problematic_chars:
        if char in client_id:
            raise ValidationError(
                f"Client ID '{client_id}' contains invalid whitespace"
            )

    # Reserved client IDs in Keycloak
    reserved_clients = {
        "admin-cli",
        "account",
        "account-console",
        "broker",
        "realm-management",
        "security-admin-console",
    }

    if client_id in reserved_clients:
        raise ValidationError(f"Client ID '{client_id}' is reserved by Keycloak")

    logger.debug(f"Validated client ID: {client_id}")


def validate_realm_name(realm_name: str) -> None:
    """
    Validate Keycloak realm name format.

    Args:
        realm_name: Realm name to validate

    Raises:
        ValidationError: If realm name is invalid

    TODO: Implement validation for:
    1. Length limits
    2. Allowed characters (similar to DNS but more permissive)
    3. Reserved realm names
    4. Best practice recommendations
    """
    if not realm_name:
        raise ValidationError("Realm name cannot be empty")

    if len(realm_name) > 255:
        raise ValidationError(
            f"Realm name '{realm_name}' is too long (max 255 characters)"
        )

    # Check for problematic characters
    invalid_chars = ["/", "\\", "?", "#", "%", "&", "=", "+", " "]
    for char in invalid_chars:
        if char in realm_name:
            raise ValidationError(
                f"Realm name '{realm_name}' contains invalid character: '{char}'"
            )

    # Reserved realm names
    if realm_name == "master":
        logger.warning("Using 'master' realm - ensure this is intentional")

    logger.debug(f"Validated realm name: {realm_name}")


def validate_url(url: str, url_type: str = "URL") -> None:
    """
    Validate URL format and basic security checks.

    Args:
        url: URL to validate
        url_type: Type of URL for error messages

    Raises:
        ValidationError: If URL is invalid

    TODO: Implement validation for:
    1. URL format and parsing
    2. Allowed schemes (http, https)
    3. Security checks (no localhost in production)
    4. Reachability checks (optional)
    """
    if not url:
        raise ValidationError(f"{url_type} cannot be empty")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid {url_type} format: {e}") from e

    # Check scheme
    if parsed.scheme not in ["http", "https"]:
        raise ValidationError(
            f"{url_type} must use http or https scheme, got: {parsed.scheme}"
        )

    # Check hostname
    if not parsed.hostname:
        raise ValidationError(f"{url_type} must have a valid hostname")

    # Security warnings
    if parsed.hostname in ["localhost", "127.0.0.1", "::1"]:
        logger.warning(
            f"{url_type} uses localhost - this may not work in a cluster environment"
        )

    if parsed.scheme == "http" and parsed.hostname != "localhost":
        logger.warning(
            f"{url_type} uses unencrypted HTTP - consider using HTTPS for security"
        )

    logger.debug(f"Validated {url_type}: {url}")


def validate_redirect_uris(redirect_uris: list[str]) -> None:
    """
    Validate OAuth2 redirect URIs.

    Args:
        redirect_uris: List of redirect URIs to validate

    Raises:
        ValidationError: If any URI is invalid

    TODO: Implement validation for:
    1. URI format validation
    2. Security checks (no wildcards, proper schemes)
    3. Best practice recommendations
    4. Platform-specific URI schemes (mobile apps)
    """
    if not redirect_uris:
        return  # Empty list is valid

    for i, uri in enumerate(redirect_uris):
        if not uri:
            raise ValidationError(f"Redirect URI at index {i} cannot be empty")

        # Basic URI validation
        try:
            parsed = urlparse(uri)
        except Exception as e:
            raise ValidationError(f"Invalid redirect URI at index {i}: {e}") from e

        # Check for wildcards (security risk)
        if "*" in uri:
            raise ValidationError(
                f"Wildcard characters not allowed in redirect URI: {uri}"
            )

        # Allow various schemes for different client types
        allowed_schemes = {
            "http",
            "https",
            "urn",  # For SAML
            "custom",  # Custom mobile app schemes
        }

        # If it looks like a custom scheme, allow it
        if (
            "://" in uri
            and parsed.scheme not in allowed_schemes
            and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", uri)
        ):
            raise ValidationError(f"Invalid URI scheme in redirect URI: {uri}")

        logger.debug(f"Validated redirect URI: {uri}")


def validate_resource_limits(resources: dict[str, Any]) -> None:
    """
    Validate Kubernetes resource limits and requests.

    Args:
        resources: Resource specification dictionary

    Raises:
        ValidationError: If resource specification is invalid

    TODO: Implement validation for:
    1. Valid resource names (cpu, memory, storage)
    2. Valid quantity formats
    3. Logical constraints (requests <= limits)
    4. Best practice recommendations
    """
    if not resources:
        return

    valid_resources = {"cpu", "memory", "storage", "ephemeral-storage"}

    for section in ["requests", "limits"]:
        if section not in resources:
            continue

        resource_section = resources[section]
        if not isinstance(resource_section, dict):
            raise ValidationError(f"Resources {section} must be a dictionary")

        for resource_name, quantity in resource_section.items():
            if resource_name not in valid_resources:
                logger.warning(f"Unknown resource type: {resource_name}")

            # TODO: Validate quantity format (e.g., "100m", "1Gi", "2")
            if not isinstance(quantity, (str, int, float)):
                raise ValidationError(
                    f"Resource quantity for {resource_name} must be a string or number"
                )

    # TODO: Validate that requests <= limits
    requests = resources.get("requests", {})
    limits = resources.get("limits", {})

    for resource_name in requests:
        if resource_name in limits:
            # TODO: Parse and compare quantities
            # This is complex due to different units (m, Mi, Gi, etc.)
            pass

    logger.debug("Validated resource limits")


def validate_image_reference(image: str) -> None:
    """
    Validate container image reference format.

    Args:
        image: Container image reference

    Raises:
        ValidationError: If image reference is invalid

    TODO: Implement validation for:
    1. Image reference format (registry/repo:tag)
    2. Tag validation (no 'latest' in production)
    3. Registry accessibility checks
    4. Security scanning recommendations
    """
    if not image:
        raise ValidationError("Image reference cannot be empty")

    # Basic format validation
    if " " in image:
        raise ValidationError("Image reference cannot contain spaces")

    # Check for tag
    if ":" not in image:
        logger.warning(f"Image '{image}' has no explicit tag - 'latest' will be used")
    elif image.endswith(":latest"):
        logger.warning(
            f"Image '{image}' uses 'latest' tag - consider using specific versions"
        )

    # TODO: Validate registry format
    # TODO: Check for digest format (@sha256:...)

    logger.debug(f"Validated image reference: {image}")


def validate_environment_variables(env_vars: dict[str, Any]) -> None:
    """
    Validate environment variable configuration.

    Args:
        env_vars: Environment variables dictionary

    Raises:
        ValidationError: If environment variable configuration is invalid

    TODO: Implement validation for:
    1. Valid environment variable names
    2. Security checks (no hardcoded secrets)
    3. Value format validation
    4. Best practice recommendations
    """
    if not env_vars:
        return

    for name, value in env_vars.items():
        # Validate environment variable name
        if not re.match(r"^[A-Z_][A-Z0-9_]*$", name):
            logger.warning(
                f"Environment variable '{name}' doesn't follow naming conventions"
            )

        # Check for potential secrets
        sensitive_patterns = [
            r"password",
            r"secret",
            r"key",
            r"token",
            r"credential",
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, name.lower()) and isinstance(value, str):
                logger.warning(
                    f"Environment variable '{name}' may contain sensitive data - "
                    "consider using secrets instead"
                )
                break

    logger.debug("Validated environment variables")


def validate_cross_resource_references(
    resource_spec: dict[str, Any],
    resource_type: str,
    namespace: str,
) -> list[tuple[str, str, str]]:
    """
    Validate cross-resource references and return list of dependencies.

    Args:
        resource_spec: Resource specification
        resource_type: Type of the resource being validated
        namespace: Current namespace

    Returns:
        List of (resource_type, name, namespace) tuples for dependencies

    TODO: Implement validation for:
    1. Keycloak instance references
    2. Secret references
    3. ConfigMap references
    4. Cross-namespace reference validation
    5. Circular dependency detection
    """
    dependencies: list[tuple[str, str, str]] = []

    if resource_type == "KeycloakClient":
        # Validate Keycloak instance reference
        keycloak_ref = resource_spec.get("keycloakInstanceRef")
        if not keycloak_ref:
            raise ValidationError("KeycloakClient must specify keycloakInstanceRef")

        keycloak_name = keycloak_ref.get("name")
        keycloak_namespace = keycloak_ref.get("namespace", namespace)

        if not keycloak_name:
            raise ValidationError("keycloakInstanceRef must specify name")

        validate_resource_name(keycloak_name, "Keycloak instance")
        validate_namespace_name(keycloak_namespace)

        dependencies.append(("Keycloak", keycloak_name, keycloak_namespace))

    elif resource_type == "KeycloakRealm":
        # Validate Keycloak instance reference
        keycloak_ref = resource_spec.get("keycloakInstanceRef")
        if not keycloak_ref:
            raise ValidationError("KeycloakRealm must specify keycloakInstanceRef")

        keycloak_name = keycloak_ref.get("name")
        keycloak_namespace = keycloak_ref.get("namespace", namespace)

        if not keycloak_name:
            raise ValidationError("keycloakInstanceRef must specify name")

        dependencies.append(("Keycloak", keycloak_name, keycloak_namespace))

    # TODO: Validate secret references
    # TODO: Validate configmap references

    logger.debug(f"Found {len(dependencies)} dependencies for {resource_type}")
    return dependencies


def validate_security_settings(spec: dict[str, Any], resource_type: str) -> None:
    """
    Validate security-related settings and provide recommendations.

    Args:
        spec: Resource specification
        resource_type: Type of resource being validated

    TODO: Implement security validation for:
    1. TLS/SSL configuration
    2. Authentication requirements
    3. Authorization settings
    4. Network policies
    5. Security best practices
    """
    # TODO: Check for TLS configuration
    if resource_type == "Keycloak":
        tls_enabled = spec.get("tls", {}).get("enabled", False)
        if not tls_enabled:
            logger.warning(
                "TLS is not enabled - consider enabling TLS for production deployments"
            )

        # Check admin access restrictions
        admin_access = spec.get("adminAccess", {})
        if not admin_access.get("restrictToNamespace", False):
            logger.warning(
                "Admin access is not restricted to namespace - "
                "consider enabling namespace restrictions"
            )

    elif resource_type == "KeycloakClient":
        # Check for public clients with sensitive scopes
        public_client = spec.get("publicClient", False)
        scopes = spec.get("scopes", [])

        if public_client and "offline_access" in scopes:
            logger.warning(
                "Public client with offline_access scope - "
                "consider using confidential client for refresh tokens"
            )

        # Validate redirect URIs for security
        redirect_uris = spec.get("redirectUris", [])
        validate_redirect_uris(redirect_uris)

    logger.debug(f"Validated security settings for {resource_type}")


def validate_complete_resource(
    resource: dict[str, Any],
    resource_type: str,
    namespace: str,
) -> list[tuple[str, str, str]]:
    """
    Perform complete validation of a resource specification.

    Args:
        resource: Complete resource definition
        resource_type: Type of resource
        namespace: Target namespace

    Returns:
        List of dependencies found during validation

    Raises:
        ValidationError: If resource is invalid

    TODO: Coordinate all validation functions:
    1. Basic structure validation
    2. Field-specific validation
    3. Cross-resource validation
    4. Security validation
    5. Best practice recommendations
    """
    logger.info(f"Validating {resource_type} resource")

    # Validate basic structure
    if "metadata" not in resource:
        raise ValidationError("Resource must have metadata section")

    if "spec" not in resource:
        raise ValidationError("Resource must have spec section")

    metadata = resource["metadata"]
    spec = resource["spec"]

    # Validate metadata
    name = metadata.get("name")
    if not name:
        raise ValidationError("Resource must have a name")

    validate_resource_name(name, resource_type)

    # Validate namespace if specified
    resource_namespace = metadata.get("namespace", namespace)
    validate_namespace_name(resource_namespace)

    # Validate resource-specific fields
    if resource_type == "KeycloakClient":
        client_id = spec.get("clientId")
        if not client_id:
            raise ValidationError("KeycloakClient must specify clientId")
        validate_client_id(client_id)

        realm = spec.get("realm")
        if realm:
            validate_realm_name(realm)

    elif resource_type == "KeycloakRealm":
        realm_name = spec.get("realmName")
        if not realm_name:
            raise ValidationError("KeycloakRealm must specify realmName")
        validate_realm_name(realm_name)

    elif resource_type == "Keycloak":
        image = spec.get("image")
        if image:
            validate_image_reference(image)

        resources = spec.get("resources")
        if resources:
            validate_resource_limits(resources)

    # Perform cross-resource validation
    dependencies = validate_cross_resource_references(
        spec, resource_type, resource_namespace
    )

    # Perform security validation
    validate_security_settings(spec, resource_type)

    logger.info(f"Successfully validated {resource_type} resource: {name}")
    return dependencies
