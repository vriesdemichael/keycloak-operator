"""
Token management utilities for authorization tokens.

This module handles token generation, validation, rotation, and metadata storage.
Tokens are stored as SHA-256 hashes in a ConfigMap for persistence and security.
"""

import hashlib
import json
import logging
import secrets
from datetime import UTC, datetime, timedelta

from kubernetes import client
from kubernetes.client.rest import ApiException

from ..errors import ConfigurationError, KubernetesAPIError
from ..models.common import TokenMetadata

logger = logging.getLogger(__name__)

# ConfigMap for token metadata storage
TOKEN_METADATA_CONFIGMAP = "keycloak-operator-token-metadata"
TOKEN_VALIDITY_DAYS = 90
GRACE_PERIOD_DAYS = 7


def _get_operator_namespace() -> str:
    """Get the operator's namespace from environment or default."""
    import os

    return os.environ.get("OPERATOR_NAMESPACE", "keycloak-system")


def _hash_token(token: str) -> str:
    """Create SHA-256 hash of a token."""
    return hashlib.sha256(token.encode()).hexdigest()


async def store_token_metadata(metadata: TokenMetadata) -> None:
    """
    Store token metadata in ConfigMap.

    Args:
        metadata: Token metadata to store

    Raises:
        KubernetesAPIError: If ConfigMap operations fail
    """
    v1 = client.CoreV1Api()
    operator_namespace = _get_operator_namespace()

    try:
        # Get existing ConfigMap or create new one
        try:
            cm = v1.read_namespaced_config_map(
                name=TOKEN_METADATA_CONFIGMAP, namespace=operator_namespace
            )
            data = cm.data or {}
        except ApiException as e:
            if e.status == 404:
                # Create new ConfigMap
                data = {}
            else:
                raise KubernetesAPIError(
                    f"Failed to read token metadata ConfigMap: {e.reason}",
                    reason=e.reason,
                )

        # Store metadata as JSON under token hash key
        data[metadata.token_hash] = json.dumps(
            {
                "namespace": metadata.namespace,
                "token_type": metadata.token_type,
                "issued_at": metadata.issued_at.isoformat(),
                "valid_until": metadata.valid_until.isoformat(),
                "version": metadata.version,
                "created_by_realm": metadata.created_by_realm,
                "revoked": metadata.revoked,
                "revoked_at": metadata.revoked_at.isoformat()
                if metadata.revoked_at
                else None,
            }
        )

        # Create or update ConfigMap
        if "cm" in locals():
            # Update existing
            cm.data = data
            v1.replace_namespaced_config_map(
                name=TOKEN_METADATA_CONFIGMAP, namespace=operator_namespace, body=cm
            )
        else:
            # Create new
            v1.create_namespaced_config_map(
                namespace=operator_namespace,
                body={
                    "metadata": {
                        "name": TOKEN_METADATA_CONFIGMAP,
                        "labels": {
                            "app.kubernetes.io/name": "keycloak-operator",
                            "app.kubernetes.io/component": "token-metadata",
                        },
                    },
                    "data": data,
                },
            )

        logger.debug(
            f"Stored token metadata for namespace={metadata.namespace}, "
            f"type={metadata.token_type}, version={metadata.version}"
        )

    except ApiException as e:
        raise KubernetesAPIError(
            f"Failed to store token metadata: {e.reason}", reason=e.reason
        )


async def get_token_metadata(token_hash: str) -> TokenMetadata | None:
    """
    Retrieve token metadata by hash.

    Args:
        token_hash: SHA-256 hash of the token

    Returns:
        TokenMetadata if found, None otherwise

    Raises:
        KubernetesAPIError: If ConfigMap read fails
    """
    v1 = client.CoreV1Api()
    operator_namespace = _get_operator_namespace()

    try:
        cm = v1.read_namespaced_config_map(
            name=TOKEN_METADATA_CONFIGMAP, namespace=operator_namespace
        )

        if not cm.data or token_hash not in cm.data:
            return None

        data = json.loads(cm.data[token_hash])

        return TokenMetadata(
            namespace=data["namespace"],
            token_hash=token_hash,
            token_type=data["token_type"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            valid_until=datetime.fromisoformat(data["valid_until"]),
            version=data["version"],
            created_by_realm=data.get("created_by_realm"),
            revoked=data.get("revoked", False),
            revoked_at=datetime.fromisoformat(data["revoked_at"])
            if data.get("revoked_at")
            else None,
        )

    except ApiException as e:
        if e.status == 404:
            return None
        raise KubernetesAPIError(
            f"Failed to read token metadata: {e.reason}", reason=e.reason
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.error(f"Failed to parse token metadata: {e}")
        return None


async def list_tokens_for_namespace(namespace: str) -> list[TokenMetadata]:
    """
    List all tokens for a specific namespace.

    Args:
        namespace: Namespace to list tokens for

    Returns:
        List of TokenMetadata for the namespace

    Raises:
        KubernetesAPIError: If ConfigMap read fails
    """
    v1 = client.CoreV1Api()
    operator_namespace = _get_operator_namespace()

    try:
        cm = v1.read_namespaced_config_map(
            name=TOKEN_METADATA_CONFIGMAP, namespace=operator_namespace
        )

        if not cm.data:
            return []

        tokens = []
        for token_hash, json_data in cm.data.items():
            try:
                data = json.loads(json_data)
                if data["namespace"] == namespace:
                    tokens.append(
                        TokenMetadata(
                            namespace=data["namespace"],
                            token_hash=token_hash,
                            token_type=data["token_type"],
                            issued_at=datetime.fromisoformat(data["issued_at"]),
                            valid_until=datetime.fromisoformat(data["valid_until"]),
                            version=data["version"],
                            created_by_realm=data.get("created_by_realm"),
                            revoked=data.get("revoked", False),
                            revoked_at=datetime.fromisoformat(data["revoked_at"])
                            if data.get("revoked_at")
                            else None,
                        )
                    )
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning(f"Skipping invalid token metadata: {e}")
                continue

        return tokens

    except ApiException as e:
        if e.status == 404:
            return []
        raise KubernetesAPIError(
            f"Failed to list token metadata: {e.reason}", reason=e.reason
        )


async def validate_token(token: str, namespace: str) -> TokenMetadata | None:
    """
    Validate a token and return its metadata if valid.

    Args:
        token: Token to validate
        namespace: Expected namespace for the token

    Returns:
        TokenMetadata if valid, None if invalid
    """
    token_hash = _hash_token(token)
    metadata = await get_token_metadata(token_hash)

    if not metadata:
        logger.debug(f"Token not found in metadata store (hash={token_hash[:8]}...)")
        return None

    # Check namespace match
    if metadata.namespace != namespace:
        logger.warning(
            f"Token namespace mismatch: expected={namespace}, got={metadata.namespace}"
        )
        return None

    # Check revocation
    if metadata.revoked:
        logger.warning(
            f"Token revoked at {metadata.revoked_at} for namespace={namespace}"
        )
        return None

    # Check expiry
    if datetime.now(UTC) > metadata.valid_until:
        logger.warning(
            f"Token expired at {metadata.valid_until} for namespace={namespace}"
        )
        return None

    logger.debug(
        f"Token validated: namespace={namespace}, type={metadata.token_type}, "
        f"version={metadata.version}, expires={metadata.valid_until}"
    )

    return metadata


async def invalidate_token(token_hash: str) -> None:
    """
    Mark a token as revoked.

    Args:
        token_hash: SHA-256 hash of token to revoke

    Raises:
        KubernetesAPIError: If ConfigMap operations fail
    """
    metadata = await get_token_metadata(token_hash)

    if not metadata:
        logger.warning(f"Attempted to revoke non-existent token: {token_hash[:8]}...")
        return

    metadata.revoked = True
    metadata.revoked_at = datetime.now(UTC)

    await store_token_metadata(metadata)

    logger.info(
        f"Token revoked: namespace={metadata.namespace}, type={metadata.token_type}"
    )


async def generate_operational_token(
    namespace: str, created_by_realm: str | None = None
) -> tuple[str, TokenMetadata]:
    """
    Generate a new operational token for a namespace.

    Args:
        namespace: Namespace the token is for
        created_by_realm: Optional realm name that triggered creation

    Returns:
        Tuple of (token, metadata)
    """
    # Generate cryptographically secure token (256 bits entropy)
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)

    # Create metadata
    now = datetime.now(UTC)
    metadata = TokenMetadata(
        namespace=namespace,
        token_hash=token_hash,
        token_type="operational",
        issued_at=now,
        valid_until=now + timedelta(days=TOKEN_VALIDITY_DAYS),
        version=1,
        created_by_realm=created_by_realm,
    )

    # Store metadata
    await store_token_metadata(metadata)

    logger.info(
        f"Generated operational token: namespace={namespace}, "
        f"version={metadata.version}, expires={metadata.valid_until}"
    )

    return token, metadata


async def validate_admission_token(token: str, namespace: str) -> bool:
    """
    Validate an admission token.

    Admission tokens can be used to bootstrap operational tokens.
    They are validated against the operator's master admission token list.

    Args:
        token: Admission token to validate
        namespace: Namespace requesting validation

    Returns:
        True if valid, False otherwise
    """
    token_hash = _hash_token(token)
    metadata = await get_token_metadata(token_hash)

    if not metadata:
        logger.debug(f"Admission token not found in metadata (namespace={namespace})")
        return False

    if metadata.token_type != "admission":
        logger.warning(
            f"Token is not an admission token (type={metadata.token_type}, "
            f"namespace={namespace})"
        )
        return False

    # Check revocation
    if metadata.revoked:
        logger.warning(f"Admission token revoked for namespace={namespace}")
        return False

    # Check expiry
    if datetime.now(UTC) > metadata.valid_until:
        logger.warning(f"Admission token expired for namespace={namespace}")
        return False

    # Check namespace match
    if metadata.namespace != namespace:
        logger.warning(
            f"Admission token namespace mismatch: expected={namespace}, "
            f"got={metadata.namespace}"
        )
        return False

    logger.debug(f"Admission token validated for namespace={namespace}")
    return True


async def rotate_operational_token(
    namespace: str, current_metadata: TokenMetadata
) -> tuple[str, TokenMetadata]:
    """
    Rotate an operational token.

    Generates new token while keeping track of the previous version
    for grace period support.

    Args:
        namespace: Namespace the token is for
        current_metadata: Metadata of the current token

    Returns:
        Tuple of (new_token, new_metadata)
    """
    if current_metadata.token_type != "operational":
        raise ConfigurationError(
            f"Cannot rotate non-operational token: type={current_metadata.token_type}"
        )

    # Generate new token
    new_token = secrets.token_urlsafe(32)
    new_token_hash = _hash_token(new_token)

    # Create new metadata with incremented version
    now = datetime.now(UTC)
    new_metadata = TokenMetadata(
        namespace=namespace,
        token_hash=new_token_hash,
        token_type="operational",
        issued_at=now,
        valid_until=now + timedelta(days=TOKEN_VALIDITY_DAYS),
        version=current_metadata.version + 1,
        created_by_realm=current_metadata.created_by_realm,
    )

    # Store new metadata
    await store_token_metadata(new_metadata)

    logger.info(
        f"Rotated operational token: namespace={namespace}, "
        f"version={current_metadata.version} → {new_metadata.version}, "
        f"new_expiry={new_metadata.valid_until}"
    )

    return new_token, new_metadata
