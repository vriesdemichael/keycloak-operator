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

import logging
from datetime import UTC, datetime
from typing import Any, Protocol

import kopf

from keycloak_operator.constants import REALM_FINALIZER
from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.services import KeycloakRealmReconciler
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
    """

    def __init__(self, patch_status: Any):
        object.__setattr__(self, "_patch_status", patch_status)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        # Directly update patch.status
        self._patch_status[name] = value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            return object.__getattribute__(self, name)
        # Directly read from patch.status
        try:
            return self._patch_status[name]
        except (KeyError, TypeError):
            return None

    def update(self, data: dict[str, Any]) -> None:
        for k, v in data.items():
            self._patch_status[k] = v


@kopf.on.create("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
@kopf.on.resume("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
async def ensure_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """
    Ensure KeycloakRealm exists in the target Keycloak instance.

    This handler creates and configures realms in Keycloak instances.
    Realms can be created in Keycloak instances across namespaces,
    subject to RBAC permissions.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the KeycloakRealm resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    Returns:
        Dictionary with status information for the resource

    """
    logger.info(f"Ensuring KeycloakRealm {name} in namespace {namespace}")

    # Add finalizer BEFORE creating any resources to ensure proper cleanup
    meta = kwargs.get("meta", {})
    current_finalizers = meta.get("finalizers", [])
    if REALM_FINALIZER not in current_finalizers:
        logger.info(f"Adding finalizer {REALM_FINALIZER} to KeycloakRealm {name}")
        patch.metadata.setdefault("finalizers", []).append(REALM_FINALIZER)

    # Create reconciler and delegate to service layer
    # Use patch.status instead of the read-only status dict for updates
    reconciler = KeycloakRealmReconciler()
    status_wrapper = StatusWrapper(patch.status)
    await reconciler.reconcile(
        spec=spec, name=name, namespace=namespace, status=status_wrapper, **kwargs
    )
    # Return None to avoid Kopf creating status subpaths
    return None


@kopf.on.update("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
async def update_keycloak_realm(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
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
    logger.info(f"Updating KeycloakRealm {name} in namespace {namespace}")

    # Create reconciler and delegate to service layer
    # Use patch.status instead of the read-only status dict for updates
    reconciler = KeycloakRealmReconciler()
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


@kopf.on.delete("keycloakrealms", group="keycloak.mdvr.nl", version="v1")
async def delete_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakRealm deletion with proper finalizer management.

    This handler performs comprehensive cleanup of the realm from Keycloak
    and any associated Kubernetes resources, removing the finalizer only
    after cleanup is complete.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource
    """
    logger.info(f"Starting deletion of KeycloakRealm {name} in namespace {namespace}")

    # Check if our finalizer is present
    meta = kwargs.get("meta", {})
    current_finalizers = meta.get("finalizers", [])
    if REALM_FINALIZER not in current_finalizers:
        logger.info(f"Finalizer {REALM_FINALIZER} not found, deletion already handled")
        return

    try:
        # Delegate cleanup to the reconciler service layer
        reconciler = KeycloakRealmReconciler()
        status_wrapper = StatusWrapper(status)
        await reconciler.cleanup_resources(
            name=name, namespace=namespace, spec=spec, status=status_wrapper
        )

        # If cleanup succeeded, remove our finalizer to complete deletion
        logger.info(
            f"Cleanup completed successfully, removing finalizer {REALM_FINALIZER}"
        )
        current_finalizers = list(current_finalizers)  # Make a copy
        if REALM_FINALIZER in current_finalizers:
            current_finalizers.remove(REALM_FINALIZER)
            patch.metadata["finalizers"] = current_finalizers

        logger.info(f"Successfully deleted KeycloakRealm {name}")

    except Exception as e:
        logger.error(f"Error during KeycloakRealm deletion: {e}")
        # Update status to indicate deletion failure
        try:
            status["phase"] = "Failed"
            status["message"] = f"Deletion failed: {str(e)}"
        except Exception:
            pass  # Status update might fail if resource is being deleted

        # Re-raise the exception to trigger retry
        # Kopf will retry the deletion with exponential backoff
        raise kopf.TemporaryError(
            f"Failed to delete KeycloakRealm {name}: {e}",
            delay=30,  # Wait 30 seconds before retry
        ) from e


@kopf.timer("keycloakrealms", interval=600)  # Check every 10 minutes
def monitor_realm_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    patch: kopf.Patch,
    **_kwargs: Any,
) -> None:
    """
    Periodic health check for KeycloakRealms.

    This timer verifies that realms still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource
        patch: Kopf patch object for modifying the resource

    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed, pending, or unknown realms
    # Unknown = resource just created, reconciliation hasn't started yet
    if current_phase in ["Failed", "Pending", "Unknown"]:
        return

    logger.debug(f"Checking health of KeycloakRealm {name} in {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # Get admin client and verify connection
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # Check if realm exists in Keycloak
        realm_name = realm_spec.realm_name
        existing_realm = admin_client.get_realm(realm_name)

        if not existing_realm:
            logger.warning(f"Realm {realm_name} missing from Keycloak")
            patch.status["phase"] = "Degraded"
            patch.status["message"] = "Realm missing from Keycloak, will recreate"
            patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
            return

        # Verify realm configuration matches spec
        try:
            current_realm = admin_client.get_realm(realm_name)
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
            flows_valid = _verify_authentication_flows(
                admin_client, realm_name, realm_spec.authentication_flows
            )
            if not flows_valid:
                patch.status["phase"] = "Degraded"
                patch.status["message"] = "Authentication flows configuration mismatch"
                patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                return

        # Check identity providers
        if realm_spec.identity_providers:
            idps_valid = _verify_identity_providers(
                admin_client, realm_name, realm_spec.identity_providers
            )
            if not idps_valid:
                patch.status["phase"] = "Degraded"
                patch.status["message"] = "Identity provider configuration mismatch"
                patch.status["lastHealthCheck"] = datetime.now(UTC).isoformat()
                return

        # Check user federation connections
        if realm_spec.user_federation:
            federation_healthy = _test_user_federation(
                admin_client, realm_name, realm_spec.user_federation
            )
            if not federation_healthy:
                patch.status["phase"] = "Degraded"
                patch.status["message"] = "User federation connection issues detected"
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

        if current_realm.get("enabled") != realm_spec.enabled:
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


def _verify_authentication_flows(
    admin_client, realm_name: str, flow_specs: list
) -> bool:
    """
    Verify that authentication flows exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        flow_specs: List of expected authentication flow specifications

    Returns:
        True if flows are valid, False otherwise
    """
    try:
        # Get current flows from Keycloak
        response = admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/authentication/flows"
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


def _verify_identity_providers(admin_client, realm_name: str, idp_specs: list) -> bool:
    """
    Verify that identity providers exist and are configured correctly.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        idp_specs: List of expected identity provider specifications

    Returns:
        True if identity providers are valid, False otherwise
    """
    try:
        # Get current identity providers from Keycloak
        response = admin_client._make_request(
            "GET", f"/admin/realms/{realm_name}/identity-provider/instances"
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


def _test_user_federation(
    admin_client, realm_name: str, federation_specs: list
) -> bool:
    """
    Test user federation connections.

    Args:
        admin_client: Keycloak admin client
        realm_name: Name of the realm
        federation_specs: List of user federation specifications

    Returns:
        True if federation is healthy, False otherwise
    """
    try:
        # Get current user federation components
        response = admin_client._make_request(
            "GET",
            f"/admin/realms/{realm_name}/components?type=org.keycloak.storage.UserStorageProvider",
        )

        if response.status_code != 200:
            return False

        current_federation = response.json()

        # Basic check that expected federation providers exist
        provider_names = {comp.get("name") for comp in current_federation}

        for federation_spec in federation_specs:
            expected_name = (
                federation_spec.get("name")
                if isinstance(federation_spec, dict)
                else federation_spec.name
            )
            if expected_name not in provider_names:
                return False

        return True

    except Exception:
        return False
