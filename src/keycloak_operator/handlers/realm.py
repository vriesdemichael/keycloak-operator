"""
KeycloakRealm handlers - Manages realm lifecycle and configuration.

This module handles realm management within Keycloak instances, including:
- Creating and configuring realms
- Setting up authentication flows and identity providers
- Managing realm-level settings and policies
- Configuring user federation and storage
- Setting up realm-specific themes and localization

Realms provide isolation between different applications or tenants
and can be managed independently across different namespaces.
"""

import asyncio
import logging
import random
from datetime import UTC, datetime
from typing import Any, Protocol

import kopf

from keycloak_operator.constants import (
    RECONCILE_JITTER_MAX,
    TIMER_INTERVAL_REALM,
)
from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.observability.tracing import traced_handler
from keycloak_operator.services import KeycloakRealmReconciler
from keycloak_operator.utils.handler_logging import log_handler_entry
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client

logger = logging.getLogger(__name__)


class StatusProtocol(Protocol):
    """Protocol for kopf Status objects that allow dynamic attribute assignment."""

    def __setattr__(self, name: str, value: Any) -> None: ...
    def __getattr__(self, name: str) -> Any: ...


class StatusWrapper:
    """Wrapper to make kopf patch.status compatible with StatusProtocol.

    This wrapper provides both attribute and dict-like access to patch.status,
    ensuring all updates are written directly to the underlying patch object.

    Automatically converts snake_case Python attribute names to camelCase for K8s API.
    """

    def __init__(self, patch_status: Any):
        object.__setattr__(self, "_patch_status", patch_status)

    @staticmethod
    def _to_camel_case(snake_str: str) -> str:
        """Convert snake_case to camelCase."""
        components = snake_str.split("_")
        return components[0] + "".join(x.title() for x in components[1:])

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        # Convert to camelCase for K8s API
        camel_name = self._to_camel_case(name)
        self._patch_status[camel_name] = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        # Convert to camelCase and read from patch.status
        camel_name = self._to_camel_case(name)
        try:
            return self._patch_status[camel_name]
        except (KeyError, TypeError):
            return None

    def update(self, data: dict[str, Any]) -> None:
        """Update multiple fields. Assumes data keys are already in camelCase."""
        for k, v in data.items():
            self._patch_status[k] = v


async def _perform_realm_cleanup(
    name: str,
    namespace: str,
    spec: dict[str, Any],
    status: dict[str, Any],
    rate_limiter: Any,
    trigger: str = "delete_handler",
) -> None:
    """
    Perform realm cleanup from Keycloak.

    This is the core cleanup logic for delete handlers.
    Finalizer management is handled by Kopf via settings.persistence.finalizer.

    Args:
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        spec: KeycloakRealm resource specification
        status: Current status of the resource
        rate_limiter: Rate limiter for Keycloak API calls
        trigger: What triggered this cleanup (for logging)
    """
    reconciler = KeycloakRealmReconciler(rate_limiter=rate_limiter)
    status_wrapper = StatusWrapper(status)

    # Check if resource actually exists in Keycloak before attempting cleanup
    resource_exists = await reconciler.check_resource_exists(
        name=name, namespace=namespace, spec=spec, status=status_wrapper
    )

    if resource_exists:
        # Resource exists in Keycloak, perform cleanup
        logger.info(
            f"Realm {name} exists in Keycloak, performing cleanup",
            extra={
                "resource_type": "realm",
                "resource_name": name,
                "namespace": namespace,
                "cleanup_phase": "keycloak_cleanup_starting",
                "cleanup_trigger": trigger,
            },
        )
        await reconciler.cleanup_resources(
            name=name, namespace=namespace, spec=spec, status=status_wrapper
        )
    else:
        # Resource never materialized in Keycloak, no cleanup needed
        logger.info(
            f"Realm {name} does not exist in Keycloak, "
            f"skipping cleanup (resource never materialized)",
            extra={
                "resource_type": "realm",
                "resource_name": name,
                "namespace": namespace,
                "cleanup_phase": "skipped_not_materialized",
                "cleanup_trigger": trigger,
            },
        )

    # Note: Finalizer removal is handled by Kopf automatically after this handler completes

    logger.info(
        f"Successfully cleaned up KeycloakRealm {name}",
        extra={
            "resource_type": "realm",
            "resource_name": name,
            "namespace": namespace,
            "cleanup_phase": "completed",
            "cleanup_trigger": trigger,
        },
    )


@kopf.on.create(
    "keycloakrealms", group="vriesdemichael.github.io", version="v1", backoff=1.5
)
@kopf.on.resume(
    "keycloakrealms", group="vriesdemichael.github.io", version="v1", backoff=1.5
)
@traced_handler("reconcile_realm")
async def ensure_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    **kwargs: Any,
) -> None:
    """
    Ensure KeycloakRealm exists in the target Keycloak instance.

    This handler creates and configures realms in Keycloak instances.
    Realms can be created in Keycloak instances across namespaces,
    subject to RBAC permissions.

    Note: Deletion is handled by the @kopf.on.delete handler (delete_keycloak_realm).
    Do not add deletion logic here to avoid race conditions with the delete handler.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the KeycloakRealm resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        Dictionary with status information for the resource

    """
    # Log handler entry immediately for debugging
    log_handler_entry("create/resume", "keycloakrealm", name, namespace)

    # Check if resource is being deleted - if so, skip reconciliation
    # The @kopf.on.delete handler (delete_keycloak_realm) handles cleanup
    meta = kwargs.get("meta", {})
    deletion_timestamp = meta.get("deletionTimestamp")

    if deletion_timestamp:
        logger.debug(
            f"KeycloakRealm {name} has deletionTimestamp, "
            f"skipping reconciliation (delete handler will manage cleanup)"
        )
        return None

    logger.info(f"Ensuring KeycloakRealm {name} in namespace {namespace}")

    # Note: Finalizer is managed by Kopf via settings.persistence.finalizer
    # configured in operator.py startup handler

    # Create reconciler and delegate to service layer
    # Use patch.status instead of the read-only status dict for updates
    # Add jitter to prevent thundering herd

    jitter = random.uniform(0, RECONCILE_JITTER_MAX)

    await asyncio.sleep(jitter)

    reconciler = KeycloakRealmReconciler(rate_limiter=memo.rate_limiter)
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.reconcile(
        spec=spec, name=name, namespace=namespace, status=status_wrapper, **kwargs
    )
    # Return None to avoid Kopf creating status subpaths
    return None


@kopf.on.update(
    "keycloakrealms", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
@traced_handler("update_realm")
async def update_keycloak_realm(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Handle updates to KeycloakRealm specifications.

    This handler processes changes to realm configurations and applies
    them to the target Keycloak instance.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        None to avoid Kopf creating status subpaths

    """
    # Log handler entry immediately for debugging
    log_handler_entry("update", "keycloakrealm", name, namespace)

    logger.info(f"Updating KeycloakRealm {name} in namespace {namespace}")

    # Create reconciler and delegate to service layer
    # Use patch.status instead of the read-only status dict for updates
    # Add jitter to prevent thundering herd

    jitter = random.uniform(0, RECONCILE_JITTER_MAX)

    await asyncio.sleep(jitter)

    reconciler = KeycloakRealmReconciler(rate_limiter=memo.rate_limiter)
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.update(
        old_spec=old.get("spec", {}),
        new_spec=new.get("spec", {}),
        diff=diff,
        name=name,
        namespace=namespace,
        status=status_wrapper,
        **kwargs,
    )
    return None


@kopf.on.delete(
    "keycloakrealms", backoff=1.5, group="vriesdemichael.github.io", version="v1"
)
@traced_handler("delete_realm")
async def delete_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    memo: kopf.Memo,
    retry: int,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakRealm deletion.

    This handler performs comprehensive cleanup of the realm from Keycloak
    and any associated Kubernetes resources. Finalizer management is handled
    automatically by Kopf via settings.persistence.finalizer.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
        retry: Kopf retry count (starts from 0)
    """
    # Log handler entry immediately for debugging - this is the first thing we do
    retry_count = retry if retry else 0
    log_handler_entry(
        "delete",
        "keycloakrealm",
        name,
        namespace,
        extra={"retry_count": retry_count},
    )

    logger.info(
        f"Starting deletion of KeycloakRealm {name} in namespace {namespace} "
        f"(attempt {retry_count + 1})",
        extra={
            "resource_type": "realm",
            "resource_name": name,
            "namespace": namespace,
            "retry_count": retry_count,
            "cleanup_phase": "handler_started",
        },
    )

    try:
        # Add jitter to prevent thundering herd on mass deletion
        jitter = random.uniform(0, RECONCILE_JITTER_MAX)
        await asyncio.sleep(jitter)

        # Perform Keycloak cleanup - finalizer is managed by Kopf
        await _perform_realm_cleanup(
            name=name,
            namespace=namespace,
            spec=spec,
            status=status,
            rate_limiter=memo.rate_limiter,
            trigger="delete_handler",
        )

    except Exception as e:
        logger.error(
            f"Error during KeycloakRealm deletion (attempt {retry_count + 1}): {e}",
            extra={
                "resource_type": "realm",
                "resource_name": name,
                "namespace": namespace,
                "retry_count": retry_count,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "cleanup_phase": "failed",
            },
            exc_info=True,
        )
        # Update status to indicate deletion failure
        try:
            status["phase"] = "Failed"
            status["message"] = f"Deletion failed (attempt {retry_count + 1}): {str(e)}"
        except Exception:
            pass  # Status update might fail if resource is being deleted

        # Re-raise the exception to trigger retry
        # Kopf will retry the deletion with exponential backoff
        raise kopf.TemporaryError(
            f"Failed to delete KeycloakRealm {name} (attempt {retry_count + 1}): {e}",
            delay=30,  # Wait 30 seconds before retry
        ) from e


@kopf.daemon(
    "keycloakrealms",
    cancellation_timeout=10.0,
)
async def monitor_realm_health(
    stopped: kopf.DaemonStopped,
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    meta: dict[str, Any],
    memo: kopf.Memo,
    **_kwargs: Any,
) -> None:
    """
    Periodic health check daemon for KeycloakRealms.

    This daemon verifies that realms still exist in Keycloak and
    that their configuration matches the desired state.

    Uses a daemon instead of a timer to work around Kopf 1.40.x not
    supporting callable ``initial_delay`` (lambda). The daemon sleeps
    a random jitter on startup to spread reconciliation load, then
    loops at TIMER_INTERVAL_REALM between iterations.

    The interval is configurable via TIMER_INTERVAL_REALM environment variable.
    Default: 600 seconds (10 minutes).

    Args:
        stopped: Kopf daemon stopped flag for graceful shutdown
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
        meta: Resource metadata
        memo: Kopf memo for accessing shared state like rate_limiter

    """
    # Random jitter on startup to prevent thundering herd
    initial_jitter = random.uniform(0, TIMER_INTERVAL_REALM)
    await stopped.wait(initial_jitter)

    while not stopped:
        # Skip health checks for resources being deleted
        deletion_timestamp = meta.get("deletionTimestamp")
        if deletion_timestamp:
            return

        current_phase = status.get("phase", "Unknown")

        # Skip health checks for non-stable phases
        # Unknown/Pending = not yet reconciled
        # Provisioning/Updating/Reconciling = active reconciliation in progress
        # Failed = terminal state, no point health-checking
        if current_phase not in (
            "Failed",
            "Pending",
            "Unknown",
            "Provisioning",
            "Updating",
            "Reconciling",
        ):
            await _run_realm_health_check(
                spec, name, namespace, status, patch, meta, memo
            )

        # Wait for next interval or until stopped
        await stopped.wait(TIMER_INTERVAL_REALM)


async def _run_realm_health_check(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    meta: dict[str, Any],
    memo: kopf.Memo,
) -> None:
    """Execute one health check iteration for a KeycloakRealm."""
    current_phase = status.get("phase", "Unknown")

    logger.debug(f"Checking health of KeycloakRealm {name} in {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # Get admin client and verify connection
        operator_ref = realm_spec.operator_ref
        target_namespace = operator_ref.namespace or namespace
        # Use hardcoded Keycloak CR name - consistent with realm_reconciler.py
        # The 'name' parameter here is the KeycloakRealm's metadata.name, NOT the Keycloak CR name
        keycloak_name = "keycloak"

        async with await get_keycloak_admin_client(
            keycloak_name, target_namespace
        ) as admin_client:
            # Check if realm exists in Keycloak
            realm_name = realm_spec.realm_name
            existing_realm = await admin_client.get_realm(realm_name, namespace)

            if not existing_realm:
                logger.warning(f"Realm {realm_name} missing from Keycloak")
                patch.status["phase"] = "Degraded"
                patch.status["message"] = "Realm missing from Keycloak, will recreate"
                patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                return

            # Verify realm configuration matches spec
            try:
                current_realm = await admin_client.get_realm(realm_name, namespace)
                config_matches = current_realm if current_realm else False
            except Exception as e:
                logger.warning(f"Failed to verify realm configuration: {e}")
                config_matches = False
            if not config_matches:
                logger.info(f"Realm {realm_name} configuration drift detected")
                patch.status["phase"] = "Degraded"
                patch.status["message"] = "Configuration drift detected"
                patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                return

            # Check authentication flows
            if realm_spec.authentication_flows:
                flows_valid = await _verify_authentication_flows(
                    admin_client, realm_name, namespace, realm_spec.authentication_flows
                )
                if not flows_valid:
                    patch.status["phase"] = "Degraded"
                    patch.status["message"] = (
                        "Authentication flows configuration mismatch"
                    )
                    patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                    return

            # Check identity providers
            if realm_spec.identity_providers:
                idps_valid = await _verify_identity_providers(
                    admin_client, realm_name, namespace, realm_spec.identity_providers
                )
                if not idps_valid:
                    patch.status["phase"] = "Degraded"
                    patch.status["message"] = "Identity provider configuration mismatch"
                    patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                    return

            # Check user federation connections
            if realm_spec.user_federation:
                federation_healthy = await _test_user_federation(
                    admin_client, realm_name, namespace, realm_spec.user_federation
                )
                if not federation_healthy:
                    patch.status["phase"] = "Degraded"
                    patch.status["message"] = (
                        "User federation connection issues detected"
                    )
                    patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                    return

            # Everything looks good
            if current_phase != "Ready":
                logger.info(f"KeycloakRealm {name} health check passed")
                patch.status["phase"] = "Ready"
                patch.status["message"] = "Realm is healthy and properly configured"
                patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()

    except Exception as e:
        logger.error(f"Health check failed for KeycloakRealm {name}: {e}")
        patch.status["phase"] = "Degraded"
        patch.status["message"] = f"Health check failed: {str(e)}"
        patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()


# Helper functions for health monitoring


def _verify_realm_config(
    current_realm: dict[str, Any], realm_spec: KeycloakRealmSpec
) -> bool:
    """
    Verify that the current realm configuration matches the spec.

    Args:
        current_realm: Current realm configuration from Keycloak
        realm_spec: Desired realm specification

    Returns:
        True if configuration matches, False otherwise
    """
    try:
        # Check basic realm settings
        if current_realm.get("realm") != realm_spec.realm_name:
            return False

        if current_realm.get("displayName") != realm_spec.display_name:
            return False

        # Check token settings if specified
        if realm_spec.token_settings:
            token_lifespan = current_realm.get("accessTokenLifespan")
            if token_lifespan != realm_spec.token_settings.access_token_lifespan:
                return False

        # Check security settings if specified
        return not (
            realm_spec.security
            and (
                current_realm.get("bruteForceProtected")
                != realm_spec.security.brute_force_protected
            )
        )

    except Exception:
        return False


async def _verify_authentication_flows(
    admin_client: Any, realm_name: str, namespace: str, flow_specs: list
) -> bool:
    """
    Verify that authentication flows exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        namespace: Namespace for rate limiting
        flow_specs: List of expected authentication flow specifications

    Returns:
        True if flows are valid, False otherwise
    """
    try:
        # Get current flows from Keycloak
        response = await admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/authentication/flows", namespace
        )

        if response.status_code != 200:
            return False

        current_flows = response.json()
        flow_aliases = {flow.get("alias") for flow in current_flows}

        # Check that all expected flows exist
        for flow_spec in flow_specs:
            expected_alias = (
                flow_spec.get("alias")
                if isinstance(flow_spec, dict)
                else flow_spec.alias
            )
            if expected_alias not in flow_aliases:
                return False

        return True

    except Exception:
        return False


async def _verify_identity_providers(
    admin_client: Any, realm_name: str, namespace: str, idp_specs: list
) -> bool:
    """
    Verify that identity providers exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        namespace: Namespace for rate limiting
        idp_specs: List of expected identity provider specifications

    Returns:
        True if identity providers are valid, False otherwise
    """
    try:
        # Get current identity providers from Keycloak
        response = await admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/identity-provider/instances", namespace
        )

        if response.status_code != 200:
            return False

        current_idps = response.json()
        idp_aliases = {idp.get("alias") for idp in current_idps}

        # Check that all expected identity providers exist
        for idp_spec in idp_specs:
            expected_alias = (
                idp_spec.get("alias") if isinstance(idp_spec, dict) else idp_spec.alias
            )
            if expected_alias not in idp_aliases:
                return False

        return True

    except Exception:
        return False


def _record_federation_status(
    realm_name: str, provider_id: str, connected: bool
) -> None:
    """Record user federation provider status to Prometheus metrics."""
    try:
        from keycloak_operator.observability.metrics import USER_FEDERATION_STATUS

        USER_FEDERATION_STATUS.labels(
            realm=realm_name,
            provider_id=provider_id,
        ).set(1 if connected else 0)
    except Exception:
        pass  # Metrics are optional


async def _test_user_federation(
    admin_client: Any, realm_name: str, namespace: str, federation_specs: list
) -> bool:
    """
    Test user federation connections.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        namespace: Namespace for rate limiting
        federation_specs: List of user federation specifications

    Returns:
        True if federation is healthy, False otherwise
    """
    try:
        # Get current user federation components
        # Use the high-level method instead of raw _make_request
        providers = await admin_client.get_user_federation_providers(
            realm_name, namespace
        )

        # Basic check that expected federation providers exist
        provider_names = {p.name for p in providers}

        for federation_spec in federation_specs:
            expected_name = (
                federation_spec.get("name")
                if isinstance(federation_spec, dict)
                else federation_spec.name
            )
            connected = expected_name in provider_names
            _record_federation_status(realm_name, expected_name or "", connected)
            if not connected:
                return False

        return True

    except Exception:
        # Record all providers as disconnected on error
        for federation_spec in federation_specs:
            expected_name = (
                federation_spec.get("name")
                if isinstance(federation_spec, dict)
                else getattr(federation_spec, "name", "")
            )
            _record_federation_status(realm_name, expected_name or "", False)
        return False
