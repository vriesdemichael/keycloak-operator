"""
Authorization utilities for token-based authentication.

This module provides functions for generating and validating authorization tokens
used in the operator's authentication flow. The token system enables secure
delegation of permissions from the operator to realms and from realms to clients.
"""

import base64
import binascii
import logging
import secrets
from typing import TYPE_CHECKING

from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import ALLOW_OPERATOR_READ_LABEL

if TYPE_CHECKING:
    from keycloak_operator.models.common import AuthorizationSecretRef

logger = logging.getLogger(__name__)


def generate_token(length: int = 32) -> str:
    """
    Generate a secure, URL-safe random token.

    Args:
        length: Length of the token in bytes (default: 32 bytes = 256 bits)

    Returns:
        A URL-safe base64-encoded token string

    Example:
        >>> token = generate_token()
        >>> len(token)  # Will vary, but typically around 43 characters
        43
    """
    return secrets.token_urlsafe(length)


def validate_authorization(
    secret_ref: "AuthorizationSecretRef | dict[str, str] | None",
    secret_namespace: str,
    expected_token: str,
    k8s_client: client.CoreV1Api,
) -> bool:
    """
    Validate an authorization token from a referenced secret.

    This function retrieves a secret from Kubernetes, validates it has the required
    RBAC label, and compares its token value against an expected token using
    constant-time comparison to prevent timing attacks.

    Args:
        secret_ref: AuthorizationSecretRef object or dict with 'name' and optional 'key', or None
        secret_namespace: Namespace where the secret is located
        expected_token: The token value to compare against
        k8s_client: Kubernetes CoreV1Api client instance

    Returns:
        True if the token matches and has required label, False otherwise

    Example:
        >>> from keycloak_operator.models.common import AuthorizationSecretRef
        >>> secret_ref = AuthorizationSecretRef(name="my-token", key="token")
        >>> is_valid = validate_authorization(
        ...     secret_ref=secret_ref,
        ...     secret_namespace="default",
        ...     expected_token="abc123...",
        ...     k8s_client=core_v1_client
        ... )
    """
    # Import here to avoid circular dependency
    from keycloak_operator.models.common import AuthorizationSecretRef

    # Handle None secret_ref - authorization is mandatory
    if secret_ref is None:
        logger.warning(
            "Authorization secret reference is required but was not provided"
        )
        return False

    # Convert dict to AuthorizationSecretRef if needed
    if isinstance(secret_ref, dict):
        secret_ref = AuthorizationSecretRef(**secret_ref)

    try:
        secret = k8s_client.read_namespaced_secret(
            name=secret_ref.name,
            namespace=secret_namespace,
        )

        # Validate RBAC label is present
        if not secret.metadata or not secret.metadata.labels:
            logger.warning(
                f"Secret '{secret_ref.name}' in namespace '{secret_namespace}' "
                f"has no labels - missing required RBAC label"
            )
            return False

        if secret.metadata.labels.get(ALLOW_OPERATOR_READ_LABEL) != "true":
            logger.warning(
                f"Secret '{secret_ref.name}' in namespace '{secret_namespace}' "
                f"is missing required label {ALLOW_OPERATOR_READ_LABEL}=true"
            )
            return False

        token_key = secret_ref.key

        if token_key not in secret.data:
            logger.warning(
                f"Key '{token_key}' not found in secret '{secret_ref.name}' "
                f"in namespace '{secret_namespace}'"
            )
            return False

        # Decode the base64-encoded token from the secret
        encoded_token = secret.data[token_key]
        decoded_token = base64.b64decode(encoded_token).decode("utf-8")

        # Use constant-time comparison to prevent timing attacks
        result = secrets.compare_digest(decoded_token, expected_token)

        if not result:
            logger.warning(
                f"Token mismatch for secret '{secret_ref.name}' in namespace '{secret_namespace}'. "
                f"Expected token length: {len(expected_token)}, Decoded token length: {len(decoded_token)}"
            )

        return result

    except ApiException as e:
        if e.status == 404:
            logger.warning(
                f"Authorization secret '{secret_ref.name}' not found "
                f"in namespace '{secret_namespace}'"
            )
        else:
            logger.error(
                f"Cannot read authorization secret '{secret_ref.name}' "
                f"in namespace '{secret_namespace}': {e}"
            )
        return False
    except (binascii.Error, UnicodeDecodeError) as e:
        logger.error(
            f"Failed to decode token from secret '{secret_ref.name}' "
            f"in namespace '{secret_namespace}': {e}"
        )
        return False
    except Exception as e:
        logger.error(
            f"Unexpected error validating authorization secret '{secret_ref.name}' "
            f"in namespace '{secret_namespace}': {e}"
        )
        return False
