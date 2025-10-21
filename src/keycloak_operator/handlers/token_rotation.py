"""
Token rotation handlers - Automatic token lifecycle management.

This module implements Kopf timer handlers for automatic token rotation:
1. Daily rotation check - Rotates tokens 7 days before expiry
2. Hourly grace period cleanup - Removes old tokens after grace period
3. Orphaned token detection - Cleans up tokens without owners

These handlers ensure zero-downtime token rotation without manual intervention.
"""

import logging
from datetime import UTC, datetime

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


@kopf.timer(
    "v1",
    "secrets",
    field='metadata.labels["keycloak.mdvr.nl/token-type"]=="operational"',
    interval=86400,  # Daily check
    idle=300,  # Wait 5 minutes before first check
)
async def rotate_operational_tokens_before_expiry(
    spec, meta, namespace, **kwargs
) -> None:
    """
    Rotate operational tokens 7 days before expiry.

    This handler runs daily to check all operational token secrets.
    If a token expires in less than 7 days, it triggers rotation with
    a grace period (dual token support).

    Args:
        spec: Secret specification
        meta: Secret metadata
        namespace: Secret namespace
        **kwargs: Additional handler arguments
    """
    from ..utils.secret_manager import SecretManager
    from ..utils.token_manager import (
        get_token_metadata,
        rotate_operational_token,
    )

    secret_name = meta.get("name")
    if not secret_name:
        return

    # Check valid-until annotation
    annotations = meta.get("annotations", {})
    valid_until_str = annotations.get("keycloak.mdvr.nl/valid-until")

    if not valid_until_str:
        logger.warning(
            f"Operational token secret {namespace}/{secret_name} "
            f"missing valid-until annotation"
        )
        return

    try:
        valid_until = datetime.fromisoformat(valid_until_str)
    except ValueError as e:
        logger.error(f"Invalid valid-until timestamp in {namespace}/{secret_name}: {e}")
        return

    # Calculate days remaining
    now = datetime.now(UTC)
    days_remaining = (valid_until - now).days

    logger.debug(f"Token {namespace}/{secret_name} expires in {days_remaining} days")

    # Rotate if < 7 days remaining
    if days_remaining <= 7:
        logger.info(
            f"Rotating operational token {namespace}/{secret_name} "
            f"(expires in {days_remaining} days)"
        )

        try:
            # Get current token metadata
            import base64

            current_token = base64.b64decode(spec["data"]["token"]).decode()
            token_hash = (
                __import__("hashlib").sha256(current_token.encode()).hexdigest()
            )

            current_metadata = await get_token_metadata(token_hash)

            if not current_metadata:
                logger.error(
                    f"Cannot rotate {namespace}/{secret_name}: "
                    f"metadata not found in ConfigMap"
                )
                return

            # Generate new token
            new_token, new_metadata = await rotate_operational_token(
                namespace=namespace, current_metadata=current_metadata
            )

            # Update secret with dual tokens (grace period)
            secret_manager = SecretManager()
            v1 = client.CoreV1Api()
            secret = v1.read_namespaced_secret(name=secret_name, namespace=namespace)

            await secret_manager.update_secret_with_rotation(
                secret=secret,
                new_token=new_token,
                new_version=new_metadata.version,
                new_valid_until=new_metadata.valid_until,
            )

            # Emit Kubernetes event
            from ..observability.metrics import metrics_collector

            metrics_collector.token_rotations.labels(namespace=namespace).inc()

            logger.info(
                f"✅ Rotated token {namespace}/{secret_name} "
                f"from version {current_metadata.version} to {new_metadata.version}"
            )

        except Exception as e:
            logger.error(
                f"Failed to rotate token {namespace}/{secret_name}: {e}",
                exc_info=True,
            )
            # Don't raise - will retry on next interval


@kopf.timer(
    "v1",
    "secrets",
    field='metadata.labels["keycloak.mdvr.nl/token-type"]=="operational"',
    interval=3600,  # Hourly check
    idle=600,  # Wait 10 minutes before first check
)
async def cleanup_expired_grace_periods(spec, meta, namespace, **kwargs) -> None:
    """
    Remove token-previous after grace period expires.

    This handler runs hourly to check operational secrets for expired
    grace periods. After 7 days, the previous token is no longer needed
    and is removed from the secret.

    Args:
        spec: Secret specification
        meta: Secret metadata
        namespace: Secret namespace
        **kwargs: Additional handler arguments
    """
    from ..utils.secret_manager import SecretManager

    secret_name = meta.get("name")
    if not secret_name:
        return

    # Check if token-previous exists
    if "token-previous" not in spec.get("data", {}):
        return  # Nothing to clean up

    # Check grace-period-ends annotation
    annotations = meta.get("annotations", {})
    grace_period_end_str = annotations.get("keycloak.mdvr.nl/grace-period-ends")

    if not grace_period_end_str:
        return  # No grace period set

    try:
        grace_period_end = datetime.fromisoformat(grace_period_end_str)
    except ValueError as e:
        logger.error(
            f"Invalid grace-period-ends timestamp in {namespace}/{secret_name}: {e}"
        )
        return

    # Check if grace period has expired
    now = datetime.now(UTC)
    if now < grace_period_end:
        days_remaining = (grace_period_end - now).days
        logger.debug(
            f"Grace period for {namespace}/{secret_name} "
            f"expires in {days_remaining} days"
        )
        return  # Grace period still active

    # Grace period expired, clean up previous token
    logger.info(f"Cleaning up expired grace period for {namespace}/{secret_name}")

    try:
        secret_manager = SecretManager()
        v1 = client.CoreV1Api()
        secret = v1.read_namespaced_secret(name=secret_name, namespace=namespace)

        await secret_manager.cleanup_previous_token(secret)

        logger.info(f"✅ Cleaned up previous token from {namespace}/{secret_name}")

    except Exception as e:
        logger.error(
            f"Failed to cleanup previous token {namespace}/{secret_name}: {e}",
            exc_info=True,
        )
        # Don't raise - will retry on next interval


@kopf.daemon(
    "v1",
    "secrets",
    field='metadata.labels["keycloak.mdvr.nl/token-type"]=="operational"',
)
async def detect_orphaned_tokens(spec, meta, namespace, stopped, **kwargs) -> None:
    """
    Detect and log orphaned operational tokens.

    This daemon watches operational token secrets and checks if they
    have valid owner references. Orphaned tokens (no owner) are logged
    as warnings for manual cleanup.

    Args:
        spec: Secret specification
        meta: Secret metadata
        namespace: Secret namespace
        stopped: Kopf stopped event
        **kwargs: Additional handler arguments
    """
    import asyncio

    secret_name = meta.get("name")
    if not secret_name:
        return

    # Wait before checking (give time for owner reference to be set)
    await asyncio.sleep(300)  # 5 minutes

    if stopped:
        return

    # Check for owner references
    owner_refs = meta.get("ownerReferences", [])

    if not owner_refs:
        logger.warning(
            f"⚠️  Orphaned operational token detected: {namespace}/{secret_name} "
            f"(no owner references)"
        )

        # Emit Kubernetes warning event
        v1 = client.CoreV1Api()
        from contextlib import suppress

        with suppress(ApiException):
            v1.create_namespaced_event(
                namespace=namespace,
                body={
                    "metadata": {"name": f"{secret_name}-orphaned"},
                    "type": "Warning",
                    "reason": "OrphanedToken",
                    "message": f"Operational token {secret_name} has no owner references and may need manual cleanup",
                    "involvedObject": {
                        "kind": "Secret",
                        "name": secret_name,
                        "namespace": namespace,
                    },
                    "firstTimestamp": datetime.now(UTC).isoformat(),
                    "lastTimestamp": datetime.now(UTC).isoformat(),
                },
            )

        # TODO: Implement automatic cleanup after 7 days
        # For now, just log for manual intervention
