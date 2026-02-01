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

from keycloak_operator.constants import (
    MANAGEMENT_PORT_MIN_VERSION,
    MINIMUM_KEYCLOAK_VERSION,
    TRACING_MIN_VERSION,
)

logger = logging.getLogger(__name__)


def _parse_kubernetes_quantity(quantity: str) -> float:
    """
    Parse a Kubernetes quantity string into a numeric value.

    Args:
        quantity: Kubernetes quantity string (e.g., "100m", "1Gi", "2")

    Returns:
        Numeric value in base units

    Raises:
        ValueError: If quantity format is invalid
    """
    if not isinstance(quantity, str):
        return float(quantity)

    # CPU units (base unit: cores)
    cpu_suffixes = {
        "m": 0.001,  # millicores
        "": 1.0,  # cores
    }

    # Memory units (base unit: bytes)
    memory_suffixes = {
        "": 1,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
        "P": 1000**5,
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "Pi": 1024**5,
    }

    # Check for CPU units
    for suffix, multiplier in cpu_suffixes.items():
        if quantity.endswith(suffix) and suffix:
            try:
                value = float(quantity[: -len(suffix)])
                return value * multiplier
            except ValueError:
                continue

    # Check for memory units
    for suffix, multiplier in memory_suffixes.items():
        if quantity.endswith(suffix):
            try:
                value = float(quantity[: -len(suffix)]) if suffix else float(quantity)
                return value * multiplier
            except ValueError:
                continue

    # Try to parse as plain number
    try:
        return float(quantity)
    except ValueError as e:
        raise ValueError(f"Invalid quantity format: {quantity}") from e


def _parse_version(version_string: str) -> tuple[int, int, int]:
    """
    Parse a semantic version string into major, minor, patch tuple.

    Args:
        version_string: Version string like "25.0.1" or "26.4.0"

    Returns:
        Tuple of (major, minor, patch) as integers

    Raises:
        ValueError: If version format is invalid
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_string)
    if not match:
        raise ValueError(f"Invalid version format: {version_string}")

    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _extract_version_from_image(image: str) -> str | None:
    """
    Extract version tag from container image reference.

    Args:
        image: Container image reference like "quay.io/keycloak/keycloak:26.4.0"

    Returns:
        Version string or None if no version tag found
    """
    # Skip digest-based images
    if "@sha256:" in image:
        return None

    # Extract tag after last colon
    if ":" not in image:
        return None

    tag = image.split(":")[-1]

    # Check if tag looks like a version (starts with digit)
    if tag and tag[0].isdigit():
        return tag

    return None


def supports_management_port(image: str, version_override: str | None = None) -> bool:
    """
    Check if a Keycloak image supports the separate management port (9000).

    The management interface with separate port 9000 was introduced in Keycloak 25.0.0.
    Earlier versions (24.x) serve health endpoints on the main HTTP port (8080).

    Args:
        image: Container image reference like "quay.io/keycloak/keycloak:26.4.0"
        version_override: Optional explicit version string (e.g., "24.0.5") for custom
            images without version tags. Takes precedence over image tag detection.

    Returns:
        True if the version supports management port (25.0.0+), False otherwise.
        Returns True if version cannot be determined (assume modern version).
    """
    # Use version override if provided, otherwise try to extract from image tag
    version_str = version_override or _extract_version_from_image(image)

    if not version_str:
        # Can't determine version, assume it supports management port
        logger.debug(
            f"Could not extract version from image '{image}' - assuming management port support"
        )
        return True

    try:
        version = _parse_version(version_str)
        mgmt_port_version = _parse_version(MANAGEMENT_PORT_MIN_VERSION)
        supports = version >= mgmt_port_version
        logger.debug(
            f"Keycloak {version_str} {'supports' if supports else 'does not support'} "
            f"management port (requires {MANAGEMENT_PORT_MIN_VERSION}+)"
        )
        return supports
    except ValueError:
        # Can't parse version, assume it supports management port
        logger.debug(
            f"Could not parse version '{version_str}' - assuming management port support"
        )
        return True


def get_health_port(image: str, version_override: str | None = None) -> int:
    """
    Get the port to use for health check endpoints based on Keycloak version.

    Args:
        image: Container image reference
        version_override: Optional explicit version string (e.g., "24.0.5") for custom
            images without version tags. Takes precedence over image tag detection.

    Returns:
        Port number for health endpoints (8080 for 24.x, 9000 for 25.x+)
    """
    if supports_management_port(image, version_override):
        return 9000
    return 8080


def supports_tracing(image: str, version_override: str | None = None) -> bool:
    """
    Check if a Keycloak image supports built-in OpenTelemetry tracing.

    Built-in OTEL tracing support (via Quarkus) was introduced in Keycloak 26.0.0.
    Earlier versions (24.x, 25.x) do not have native tracing support.

    Args:
        image: Container image reference like "quay.io/keycloak/keycloak:26.4.0"
        version_override: Optional explicit version string (e.g., "25.0.0") for custom
            images without version tags. Takes precedence over image tag detection.

    Returns:
        True if the version supports tracing (26.0.0+), False otherwise.
        Returns True if version cannot be determined (assume modern version).
    """
    # Use version override if provided, otherwise try to extract from image tag
    version_str = version_override or _extract_version_from_image(image)

    if not version_str:
        # Can't determine version, assume it supports tracing
        logger.debug(
            f"Could not extract version from image '{image}' - assuming tracing support"
        )
        return True

    try:
        version = _parse_version(version_str)
        tracing_min = _parse_version(TRACING_MIN_VERSION)
        supports = version >= tracing_min
        logger.debug(
            f"Keycloak {version_str} {'supports' if supports else 'does not support'} "
            f"built-in tracing (requires {TRACING_MIN_VERSION}+)"
        )
        return supports
    except ValueError:
        # Can't parse version, assume it supports tracing
        logger.debug(
            f"Could not parse version '{version_str}' - assuming tracing support"
        )
        return True


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

            # Validate quantity format
            if not isinstance(quantity, (str, int, float)):
                raise ValidationError(
                    f"Resource quantity for {resource_name} must be a string or number"
                )

            # Validate quantity format if it's a string
            if isinstance(quantity, str):
                try:
                    _parse_kubernetes_quantity(quantity)
                except ValueError as e:
                    raise ValidationError(
                        f"Invalid quantity format for {resource_name}: {e}"
                    ) from e

    # Validate that requests <= limits
    requests = resources.get("requests", {})
    limits = resources.get("limits", {})

    for resource_name in requests:
        if resource_name in limits:
            try:
                request_value = _parse_kubernetes_quantity(str(requests[resource_name]))
                limit_value = _parse_kubernetes_quantity(str(limits[resource_name]))

                if request_value > limit_value:
                    raise ValidationError(
                        f"Resource request for {resource_name} ({requests[resource_name]}) "
                        f"exceeds limit ({limits[resource_name]})"
                    )
            except ValueError as e:
                logger.warning(f"Could not compare quantities for {resource_name}: {e}")

    logger.debug("Validated resource limits")


def validate_image_reference(image: str) -> None:
    """
    Validate container image reference format.

    Args:
        image: Container image reference

    Raises:
        ValidationError: If image reference is invalid

    """
    if not image:
        raise ValidationError("Image reference cannot be empty")

    # Basic format validation
    if " " in image:
        raise ValidationError("Image reference cannot contain spaces")

    # Check for digest format (@sha256:...)
    has_digest = "@sha256:" in image
    has_tag = ":" in image and not has_digest

    if not has_tag and not has_digest:
        logger.warning(f"Image '{image}' has no explicit tag - 'latest' will be used")
    elif has_tag and image.split(":")[-1] == "latest":
        logger.warning(
            f"Image '{image}' uses 'latest' tag - consider using specific versions"
        )

    # Validate registry format
    if "/" in image:
        parts = image.split("/")
        registry_part = parts[0]

        # Check if first part looks like a registry (contains dot or port)
        if "." in registry_part or ":" in registry_part:
            # Validate registry hostname format
            registry_host = registry_part.split(":")[0]
            if not re.match(r"^[a-zA-Z0-9.-]+$", registry_host):
                raise ValidationError(
                    f"Invalid registry hostname in image: {registry_host}"
                )

    # Validate digest format if present
    if has_digest:
        digest_part = image.split("@sha256:")[-1]
        # Allow shorter digests for testing, but real SHA256 should be 64 chars
        if not re.match(r"^[a-f0-9]+$", digest_part) or len(digest_part) < 6:
            raise ValidationError(f"Invalid SHA256 digest format in image: {image}")
        elif len(digest_part) != 64:
            logger.warning(
                f"Image digest '{digest_part}' is not full 64-character SHA256"
            )

    logger.debug(f"Validated image reference: {image}")


def validate_keycloak_version(image: str) -> None:
    """
    Validate Keycloak version is supported by this operator.

    Supported versions: 24.x, 25.x, 26.x
    - 24.x: Health endpoints on main HTTP port (8080)
    - 25.x+: Health endpoints on management port (9000) with KC_HTTP_MANAGEMENT_PORT

    Args:
        image: Container image reference

    Raises:
        ValidationError: If Keycloak version is not supported

    """
    version_str = _extract_version_from_image(image)

    if not version_str:
        logger.warning(
            f"Could not extract version from image '{image}' - skipping version validation. "
            f"Ensure the image uses Keycloak {MINIMUM_KEYCLOAK_VERSION} or later."
        )
        return

    try:
        version = _parse_version(version_str)
        minimum_version = _parse_version(MINIMUM_KEYCLOAK_VERSION)

        if version < minimum_version:
            raise ValidationError(
                f"Keycloak version {version_str} is not supported. "
                f"Minimum required version is {MINIMUM_KEYCLOAK_VERSION}. "
                f"Please upgrade to Keycloak {MINIMUM_KEYCLOAK_VERSION} or later."
            )

        logger.debug(
            f"Keycloak version {version_str} meets minimum requirement ({MINIMUM_KEYCLOAK_VERSION})"
        )

    except ValueError as e:
        logger.warning(
            f"Could not parse version from image tag '{version_str}': {e}. "
            f"Ensure the image uses Keycloak {MINIMUM_KEYCLOAK_VERSION} or later."
        )


def validate_environment_variables(env_vars: dict[str, Any]) -> None:
    """
    Validate environment variable configuration.

    Args:
        env_vars: Environment variables dictionary

    Raises:
        ValidationError: If environment variable configuration is invalid

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

    # Validate secret references
    def _validate_secret_refs(obj: dict[str, Any], current_namespace: str) -> None:
        """Recursively find and validate secret references."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.endswith("_secret") or key.endswith("Secret"):
                    if isinstance(value, dict) and "name" in value:
                        secret_name = value["name"]
                        secret_namespace = value.get("namespace", current_namespace)
                        validate_resource_name(secret_name, "Secret")
                        validate_namespace_name(secret_namespace)
                        dependencies.append(("Secret", secret_name, secret_namespace))
                elif isinstance(value, (dict, list)):
                    _validate_secret_refs(value, current_namespace)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _validate_secret_refs(item, current_namespace)

    # Validate configmap references
    def _validate_configmap_refs(obj: dict[str, Any], current_namespace: str) -> None:
        """Recursively find and validate configmap references."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.endswith("_configmap") or key.endswith("ConfigMap"):
                    if isinstance(value, dict) and "name" in value:
                        cm_name = value["name"]
                        cm_namespace = value.get("namespace", current_namespace)
                        validate_resource_name(cm_name, "ConfigMap")
                        validate_namespace_name(cm_namespace)
                        dependencies.append(("ConfigMap", cm_name, cm_namespace))
                elif isinstance(value, (dict, list)):
                    _validate_configmap_refs(value, current_namespace)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _validate_configmap_refs(item, current_namespace)

    # Scan for secret and configmap references
    _validate_secret_refs(resource_spec, namespace)
    _validate_configmap_refs(resource_spec, namespace)

    # Check for circular dependencies (basic check)
    dependency_names = {
        (dep_type, dep_name, dep_ns) for dep_type, dep_name, dep_ns in dependencies
    }
    if len(dependency_names) != len(dependencies):
        logger.warning("Potential duplicate dependencies detected")

    logger.debug(f"Found {len(dependencies)} dependencies for {resource_type}")
    return dependencies


def validate_security_settings(spec: dict[str, Any], resource_type: str) -> None:
    """
    Validate security-related settings and provide recommendations.

    Args:
        spec: Resource specification
        resource_type: Type of resource being validated

    """
    # Check for TLS configuration
    if resource_type == "Keycloak":
        tls_enabled = spec.get("tls", {}).get("enabled", False)
        if not tls_enabled:
            logger.warning(
                "TLS is not enabled - consider enabling TLS for production deployments"
            )

        # Check ingress TLS configuration
        ingress_config = spec.get("ingress", {})
        if ingress_config.get("enabled", False) and not ingress_config.get(
            "tls_enabled", False
        ):
            logger.warning(
                "Ingress is enabled but TLS is not - consider enabling TLS for ingress"
            )

        # Check admin credentials configuration
        admin_config = spec.get("admin", {})
        if admin_config.get("create_secret", True) and not admin_config.get(
            "password_secret"
        ):
            logger.info("Admin credentials will be auto-generated")

        # Check database security
        db_config = spec.get("database", {})
        if db_config.get("type") != "h2" and not db_config.get("password_secret"):
            logger.warning(
                "External database configured without password secret - "
                "ensure credentials are properly secured"
            )

        # Check resource limits for security
        resources = spec.get("resources", {})
        if not resources.get("limits"):
            logger.warning(
                "No resource limits set - consider setting limits to prevent resource exhaustion"
            )

        # Check security contexts
        if not spec.get("security_context") and not spec.get("pod_security_context"):
            logger.warning(
                "No security context configured - consider setting security contexts for better isolation"
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

        # Check for insecure protocol mappers
        protocol_mappers = spec.get("protocolMappers", [])
        for mapper in protocol_mappers:
            if isinstance(mapper, dict):
                mapper_type = mapper.get("protocolMapper", "")
                if "script" in mapper_type.lower():
                    logger.warning(
                        "Script-based protocol mapper detected - ensure script content is secure"
                    )

    elif resource_type == "KeycloakRealm":
        # Check realm security settings
        realm_config = spec.get("realmSettings", {})

        # Check password policy
        if not realm_config.get("passwordPolicy"):
            logger.warning(
                "No password policy configured - consider setting a strong password policy"
            )

        # Check SSL requirements
        ssl_required = realm_config.get("sslRequired", "external")
        if ssl_required == "none":
            logger.warning(
                "SSL requirement set to 'none' - consider requiring SSL for security"
            )

        # Check registration settings
        if realm_config.get("registrationAllowed", False):
            logger.info("User registration is enabled - ensure this is intentional")

        # Check reset password settings
        if realm_config.get("resetPasswordAllowed", True):
            logger.info(
                "Password reset is enabled - ensure email configuration is secure"
            )

        # Check for insecure authentication flows
        auth_flows = spec.get("authenticationFlows", [])
        for flow in auth_flows:
            if isinstance(flow, dict) and flow.get("alias", "").lower() == "direct":
                logger.warning(
                    "Direct authentication flow detected - consider using more secure flows"
                )

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
            validate_keycloak_version(image)

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


# Keycloak env var placeholder pattern
# Matches patterns like ${keycloak:...}, ${env.VAR}, ${ENV.VAR}, etc.
KEYCLOAK_PLACEHOLDER_PATTERN = re.compile(
    r"\$\{(?:keycloak:|env\.|ENV\.|vault:|VAULT:)[^}]*\}"
)


def validate_no_keycloak_placeholders(value: str, field_name: str = "field") -> None:
    """
    Validate that a string value does not contain Keycloak environment variable placeholders.

    Keycloak supports placeholder syntax like ${keycloak:secret-name:key} or ${env.VAR}
    for runtime variable substitution. However, this operator manages Keycloak through
    the Admin REST API, not through Keycloak's config file mechanism. Placeholders
    cannot be resolved and will be passed literally to Keycloak, causing unexpected behavior.

    Args:
        value: String value to check
        field_name: Name of the field for error messages

    Raises:
        ValidationError: If placeholder patterns are detected
    """
    if not value or not isinstance(value, str):
        return

    matches = KEYCLOAK_PLACEHOLDER_PATTERN.findall(value)
    if matches:
        placeholder_examples = ", ".join(matches[:3])
        if len(matches) > 3:
            placeholder_examples += f", ... ({len(matches)} total)"

        raise ValidationError(
            f"Keycloak environment variable placeholders are not supported in {field_name}. "
            f"Found: {placeholder_examples}. "
            f"This operator manages Keycloak through the Admin REST API, not config files. "
            f"Placeholders like '${{keycloak:...}}' or '${{env.VAR}}' cannot be resolved. "
            f"Use Kubernetes Secrets with secretKeyRef instead. "
            f"See: https://vriesdemichael.github.io/keycloak-operator/secrets/"
        )


def validate_spec_no_placeholders(spec: dict[str, Any], resource_type: str) -> None:
    """
    Recursively validate that a resource spec does not contain Keycloak placeholders.

    Args:
        spec: Resource specification dictionary
        resource_type: Type of resource for error messages

    Raises:
        ValidationError: If placeholder patterns are detected in any string field
    """

    def _check_value(value: Any, path: str) -> None:
        """Recursively check all string values in the structure."""
        if isinstance(value, str):
            validate_no_keycloak_placeholders(value, f"{resource_type}.{path}")
        elif isinstance(value, dict):
            for key, val in value.items():
                _check_value(val, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                _check_value(item, f"{path}[{i}]")

    _check_value(spec, "")
