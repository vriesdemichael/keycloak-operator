"""
RBAC utilities for namespace access control and secret validation.

This module provides functions to:
- Check if operator has access to a namespace
- Validate secrets have required labels before reading
- Perform SubjectAccessReview checks
"""

import base64
import logging
import os
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.constants import (
    ALLOW_OPERATOR_READ_LABEL,
    ERROR_NAMESPACE_ACCESS_DENIED,
    ERROR_SECRET_NOT_LABELED,
)

logger = logging.getLogger(__name__)


async def check_namespace_access(
    namespace: str, operator_namespace: str
) -> tuple[bool, str | None]:
    """
    Check if the operator has access to read secrets in a namespace.

    Performs a SubjectAccessReview to verify the operator service account
    has permission to read secrets in the target namespace.

    Args:
        namespace: Target namespace to check access for
        operator_namespace: Namespace where the operator is running

    Returns:
        Tuple of (has_access, error_message)
        - has_access: True if operator has access, False otherwise
        - error_message: Detailed error message if access denied, None if allowed

    """
    try:
        auth_api = client.AuthorizationV1Api()

        # Get service account name from environment or use default
        # Chart sets SERVICE_ACCOUNT_NAME env var
        service_account_name = os.getenv(
            "SERVICE_ACCOUNT_NAME", f"keycloak-operator-{operator_namespace}"
        )

        sar = client.V1SubjectAccessReview(
            spec=client.V1SubjectAccessReviewSpec(
                resource_attributes=client.V1ResourceAttributes(
                    namespace=namespace,
                    verb="get",
                    group="",
                    resource="secrets",
                ),
                user=f"system:serviceaccount:{operator_namespace}:{service_account_name}",
            )
        )

        # Create the SubjectAccessReview
        result = auth_api.create_subject_access_review(body=sar)

        # Check the status
        allowed = result.status.allowed

        if not allowed:
            reason = result.status.reason or "Unknown reason"
            error_msg = ERROR_NAMESPACE_ACCESS_DENIED.format(
                namespace, operator_namespace, operator_namespace, namespace
            )
            logger.warning(
                f"Namespace access denied for {namespace}: {reason}. "
                f"RoleBinding may be missing."
            )
            return False, error_msg

        logger.debug(f"Namespace access verified for {namespace}")
        return True, None

    except ApiException as e:
        if e.status == 403:
            error_msg = ERROR_NAMESPACE_ACCESS_DENIED.format(
                namespace, operator_namespace, operator_namespace, namespace
            )
            logger.error(
                f"HTTP 403 when checking namespace access for {namespace}: {e}"
            )
            return False, error_msg
        logger.error(f"API error checking namespace access for {namespace}: {e}")
        return False, f"API error checking namespace access: {e}"
    except Exception as e:
        logger.error(f"Unexpected error checking namespace access for {namespace}: {e}")
        return False, f"Unexpected error checking namespace access: {e}"


async def validate_secret_label(
    secret_name: str, namespace: str, operator_namespace: str | None = None
) -> tuple[bool, str | None]:
    """
    Validate that a secret has the required label for operator access.

    The operator requires secrets to have the label:
    vriesdemichael.github.io/keycloak-allow-operator-read=true

    This provides an explicit opt-in mechanism where users must label
    secrets before the operator can read them.

    Args:
        secret_name: Name of the secret to validate
        namespace: Namespace containing the secret
        operator_namespace: Namespace where operator is running (for error messages)

    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if secret has required label, False otherwise
        - error_message: Detailed error message if label missing, None if valid

    """
    try:
        core_api = client.CoreV1Api()
        secret = core_api.read_namespaced_secret(name=secret_name, namespace=namespace)
        labels = secret.metadata.labels or {}

        # Check for the required label
        label_value = labels.get(ALLOW_OPERATOR_READ_LABEL)

        if label_value != "true":
            error_msg = ERROR_SECRET_NOT_LABELED.format(
                secret_name, namespace, ALLOW_OPERATOR_READ_LABEL
            )
            logger.warning(
                f"Secret {secret_name} in {namespace} is missing required label "
                f"{ALLOW_OPERATOR_READ_LABEL}=true"
            )
            return False, error_msg

        logger.debug(
            f"Secret {secret_name} in {namespace} has required label, access allowed"
        )
        return True, None

    except ApiException as e:
        if e.status == 404:
            logger.error(f"Secret {secret_name} not found in namespace {namespace}")
            return False, f"Secret '{secret_name}' not found in namespace '{namespace}'"
        elif e.status == 403:
            # Use operator_namespace if provided, otherwise use generic placeholder
            op_ns = operator_namespace or "keycloak-system"
            error_msg = ERROR_NAMESPACE_ACCESS_DENIED.format(
                namespace, op_ns, op_ns, namespace
            )
            logger.error(
                f"HTTP 403 when accessing secret {secret_name} in {namespace}: {e}"
            )
            return False, error_msg
        logger.error(f"API error validating secret {secret_name} in {namespace}: {e}")
        return False, f"API error validating secret: {e}"
    except Exception as e:
        logger.error(
            f"Unexpected error validating secret {secret_name} in {namespace}: {e}"
        )
        return False, f"Unexpected error validating secret: {e}"


async def get_secret_with_validation(
    secret_name: str,
    namespace: str,
    operator_namespace: str,
    key: str | None = None,
) -> tuple[str | dict[str, Any] | None, str | None]:
    """
    Get a secret value after validating RBAC and label requirements.

    This function performs a complete validation workflow:
    1. Check namespace access via SubjectAccessReview (if not operator namespace)
    2. Validate secret has required label
    3. Read and return secret data

    Args:
        secret_name: Name of the secret to read
        namespace: Namespace containing the secret
        operator_namespace: Namespace where the operator is running
        key: Optional key to extract from secret data. If None, returns all data

    Returns:
        Tuple of (secret_value, error_message)
        - secret_value: Secret data (string if key specified, dict if not)
        - error_message: Detailed error message if validation fails

    """
    # Skip namespace access check if reading from operator's own namespace
    if namespace != operator_namespace:
        has_access, error_msg = await check_namespace_access(
            namespace, operator_namespace
        )
        if not has_access:
            return None, error_msg

    # Validate secret has required label
    is_valid, error_msg = await validate_secret_label(secret_name, namespace)
    if not is_valid:
        return None, error_msg

    # Read the secret
    try:
        core_api = client.CoreV1Api()
        secret = core_api.read_namespaced_secret(name=secret_name, namespace=namespace)
        data = secret.data or {}

        if key:
            if key not in data:
                error_msg = f"Key '{key}' not found in secret '{secret_name}'"
                logger.error(f"{error_msg} in namespace {namespace}")
                return None, error_msg
            # Decode base64 data
            value = base64.b64decode(data[key]).decode("utf-8")
            return value, None
        else:
            # Return all decoded data
            decoded_data = {
                k: base64.b64decode(v).decode("utf-8") for k, v in data.items()
            }
            return decoded_data, None

    except ApiException as e:
        logger.error(f"API error reading secret {secret_name} in {namespace}: {e}")
        return None, f"API error reading secret: {e}"
    except Exception as e:
        logger.error(
            f"Unexpected error reading secret {secret_name} in {namespace}: {e}"
        )
        return None, f"Unexpected error reading secret: {e}"
