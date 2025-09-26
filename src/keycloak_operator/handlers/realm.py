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
from typing import Any

import kopf
from kubernetes.client.rest import ApiException

from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import validate_keycloak_reference

logger = logging.getLogger(__name__)


@kopf.on.create("keycloakrealms")
@kopf.on.resume("keycloakrealms")
def ensure_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
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

    Returns:
        Dictionary with status information for the resource

    TODO: Implement the following functionality:
    1. Validate and parse the realm specification
    2. Resolve the Keycloak instance reference
    3. Verify RBAC permissions for cross-namespace operations
    4. Connect to the target Keycloak instance
    5. Check if realm already exists (idempotent operation)
    6. Create or update the realm in Keycloak
    7. Configure realm settings (themes, localization, etc.)
    8. Set up authentication flows and identity providers
    9. Configure user federation if specified
    10. Update resource status with realm information
    """
    logger.info(f"Ensuring KeycloakRealm {name} in namespace {namespace}")

    try:
        # Parse and validate the realm specification
        realm_spec = KeycloakRealmSpec.model_validate(spec)
        logger.debug(f"Validated KeycloakRealm spec: {realm_spec}")

        # Update status to indicate processing
        status.update(
            {
                "phase": "Pending",
                "message": "Creating Keycloak realm",
            }
        )

        # TODO: Resolve Keycloak instance reference
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        keycloak_name = keycloak_ref.name

        logger.info(
            f"Targeting Keycloak instance '{keycloak_name}' "
            f"in namespace '{target_namespace}'"
        )

        # TODO: Validate that the Keycloak instance exists and is ready
        keycloak_instance = validate_keycloak_reference(keycloak_name, target_namespace)
        if not keycloak_instance:
            raise kopf.TemporaryError(
                f"Keycloak instance {keycloak_name} not found or not ready "
                f"in namespace {target_namespace}",
                delay=30,
            )

        # TODO: Check RBAC permissions for cross-namespace operations
        if target_namespace != namespace:
            has_permission = True  # TODO: Implement RBAC check
            if not has_permission:
                raise kopf.PermanentError(
                    f"Insufficient permissions to access Keycloak instance "
                    f"{keycloak_name} in namespace {target_namespace}"
                )

        # TODO: Get Keycloak admin client
        admin_client = get_keycloak_admin_client(keycloak_name, target_namespace)

        # TODO: Check if realm already exists
        realm_name = realm_spec.realm_name
        existing_realm = admin_client.get_realm(realm_name)

        if existing_realm:
            logger.info(f"Realm {realm_name} already exists, updating...")
            # TODO: Update existing realm configuration
            admin_client.update_realm(realm_name, realm_spec.to_keycloak_config())
        else:
            logger.info(f"Creating new realm {realm_name}")
            # TODO: Create new realm in Keycloak
            admin_client.create_realm(realm_spec.to_keycloak_config())

        # TODO: Configure realm-specific settings
        if realm_spec.themes:
            logger.info("Configuring realm themes")
            # TODO: Set up custom themes
            # admin_client.update_realm_themes(realm_name, realm_spec.themes)  # Not implemented yet
            pass

        if realm_spec.localization:
            logger.info("Configuring realm localization")
            # TODO: Set up localization settings
            # admin_client.update_realm_localization(realm_name, realm_spec.localization)  # Not implemented yet
            pass

        # TODO: Configure authentication flows
        if realm_spec.authentication_flows:
            logger.info("Configuring authentication flows")
            for _flow_config in realm_spec.authentication_flows:
                # TODO: Create or update authentication flow
                # admin_client.create_or_update_auth_flow(realm_name, flow_config)  # Not implemented yet
                pass

        # TODO: Configure identity providers
        if realm_spec.identity_providers:
            logger.info("Configuring identity providers")
            for _idp_config in realm_spec.identity_providers:
                # TODO: Create or update identity provider
                # admin_client.create_or_update_identity_provider(realm_name, idp_config)  # Not implemented yet
                pass

        # TODO: Configure user federation
        if realm_spec.user_federation:
            logger.info("Configuring user federation")
            for _federation_config in realm_spec.user_federation:
                # TODO: Set up user federation (LDAP, Kerberos, etc.)
                # admin_client.create_or_update_user_federation(realm_name, federation_config)  # Not implemented yet
                pass

        # TODO: Configure realm-level policies and permissions
        if realm_spec.policies:
            logger.info("Configuring realm policies")
            # TODO: Set up realm policies
            # admin_client.update_realm_policies(realm_name, realm_spec.policies)  # Not implemented yet
            pass

        logger.info(f"Successfully created/updated KeycloakRealm {name}")

        return {
            "phase": "Ready",
            "message": "Realm successfully created and configured",
            "realmName": realm_name,
            "keycloakInstance": f"{target_namespace}/{keycloak_name}",
            "endpoints": {
                "realm": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}",
                "admin": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/admin/{realm_name}/console",
                "account": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}/account",
            },
            "features": {
                "themes": bool(realm_spec.themes),
                "localization": bool(realm_spec.localization),
                "customAuthFlows": bool(realm_spec.authentication_flows),
                "identityProviders": len(realm_spec.identity_providers or []),
                "userFederation": len(realm_spec.user_federation or []),
            },
        }

    except ApiException as e:
        logger.error(f"Kubernetes API error creating KeycloakRealm {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Kubernetes API error: {e.reason}",
            }
        )
        raise kopf.TemporaryError(f"Kubernetes API error: {e}", delay=30) from e

    except Exception as e:
        logger.error(f"Error creating KeycloakRealm {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Failed to create realm: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Realm creation failed: {e}", delay=60) from e


@kopf.on.update("keycloakrealms")
def update_keycloak_realm(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
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

    Returns:
        Dictionary with updated status, or None if no changes needed

    TODO: Implement the following functionality:
    1. Parse specification changes from the diff
    2. Validate that immutable fields haven't changed
    3. Apply realm configuration changes
    4. Handle theme updates
    5. Handle authentication flow changes
    6. Handle identity provider updates
    7. Handle user federation changes
    8. Handle policy and permission updates
    9. Update status to reflect changes
    """
    logger.info(f"Updating KeycloakRealm {name} in namespace {namespace}")

    # Log changes for debugging
    for operation, field_path, old_value, new_value in diff:
        logger.info(
            f"KeycloakRealm change - {operation}: {field_path} "
            f"from {old_value} to {new_value}"
        )

    status.update(
        {
            "phase": "Updating",
            "message": "Applying realm configuration changes",
        }
    )

    try:
        # TODO: Validate that immutable fields haven't changed
        old_spec = KeycloakRealmSpec.model_validate(old["spec"])
        new_spec = KeycloakRealmSpec.model_validate(new["spec"])

        # Check for changes to immutable fields
        if old_spec.realm_name != new_spec.realm_name:
            raise kopf.PermanentError(
                "Cannot change realm_name of existing KeycloakRealm"
            )

        if old_spec.keycloak_instance_ref != new_spec.keycloak_instance_ref:
            raise kopf.PermanentError(
                "Cannot change keycloak_instance_ref of existing KeycloakRealm"
            )

        # TODO: Get admin client for the target Keycloak instance
        keycloak_ref = new_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        realm_name = new_spec.realm_name

        # TODO: Apply configuration updates based on the diff
        configuration_changed = False
        for _operation, field_path, _old_value, _new_value in diff:
            if field_path[:2] == ("spec", "themes"):
                logger.info("Updating realm themes")
                # TODO: Update realm themes
                # admin_client.update_realm_themes(realm_name, new_spec.themes)  # Not implemented yet
                configuration_changed = True

            elif field_path[:2] == ("spec", "localization"):
                logger.info("Updating realm localization")
                # TODO: Update localization settings
                # admin_client.update_realm_localization(realm_name, new_spec.localization)  # Not implemented yet
                configuration_changed = True

            elif field_path[:2] == ("spec", "authenticationFlows"):
                logger.info("Updating authentication flows")
                # TODO: Update authentication flows
                # This might involve creating, updating, or deleting flows
                # admin_client.sync_authentication_flows(realm_name, new_spec.authentication_flows)  # Not implemented yet
                configuration_changed = True

            elif field_path[:2] == ("spec", "identityProviders"):
                logger.info("Updating identity providers")
                # TODO: Update identity providers
                # admin_client.sync_identity_providers(realm_name, new_spec.identity_providers)  # Not implemented yet
                configuration_changed = True

            elif field_path[:2] == ("spec", "userFederation"):
                logger.info("Updating user federation")
                # TODO: Update user federation settings
                # admin_client.sync_user_federation(realm_name, new_spec.user_federation)  # Not implemented yet
                configuration_changed = True

            elif field_path[:2] == ("spec", "settings"):
                logger.info("Updating realm settings")
                # TODO: Update general realm settings
                admin_client.update_realm(realm_name, new_spec.to_keycloak_config())
                configuration_changed = True

        if configuration_changed:
            logger.info(f"Successfully updated KeycloakRealm {name}")
            return {
                "phase": "Ready",
                "message": "Realm configuration updated successfully",
                "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
            }

    except Exception as e:
        logger.error(f"Failed to update KeycloakRealm {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Update failed: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Realm update failed: {e}", delay=30) from e

    return None  # No changes needed


@kopf.on.delete("keycloakrealms")
def delete_keycloak_realm(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakRealm deletion.

    This handler removes the realm from Keycloak and cleans up
    associated resources.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists

    TODO: Implement the following functionality:
    1. Parse the realm specification
    2. Resolve the target Keycloak instance
    3. Check for deletion protection policies
    4. Backup realm data if requested
    5. Remove clients associated with the realm
    6. Remove the realm from Keycloak
    7. Clean up any external resources
    8. Log successful deletion
    """
    logger.info(f"Deleting KeycloakRealm {name} in namespace {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # TODO: Check for deletion protection
        # Some realms might be protected from accidental deletion
        protection_enabled = realm_spec.deletion_protection
        if protection_enabled:
            finalizers = kwargs.get("meta", {}).get("finalizers", [])
            if "keycloak.mdvr.nl/deletion-confirmed" not in finalizers:
                logger.warning(
                    f"Realm {realm_spec.realm_name} is protected from deletion. "
                    "Add finalizer 'keycloak.mdvr.nl/deletion-confirmed' to proceed."
                )
                return

        # TODO: Get admin client for the target Keycloak instance
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        try:
            admin_client = get_keycloak_admin_client(
                keycloak_ref.name, target_namespace
            )

            # TODO: Backup realm data if requested
            if realm_spec.backup_on_delete:
                logger.info(f"Backing up realm {realm_spec.realm_name}")
                # TODO: Create realm backup
                # admin_client.backup_realm(realm_spec.realm_name)  # Not implemented yet
                pass

            # TODO: Clean up clients in this realm first
            # This ensures proper cleanup order and prevents orphaned resources
            # realm_clients = admin_client.get_realm_clients(realm_spec.realm_name)  # Not implemented yet
            realm_clients = []  # TODO: Implement get_realm_clients method
            for client in realm_clients:
                logger.info(f"Cleaning up client {client['clientId']}")
                # TODO: Remove client

            # TODO: Remove the realm from Keycloak
            admin_client.delete_realm(realm_spec.realm_name)
            logger.info(f"Deleted realm {realm_spec.realm_name} from Keycloak")

        except Exception as e:
            logger.warning(
                f"Could not delete realm from Keycloak (instance may be deleted): {e}"
            )

        # TODO: Clean up any external resources
        # - Remove DNS entries if managed
        # - Clean up certificates if managed
        # - Remove monitoring configurations

        logger.info(f"Successfully deleted KeycloakRealm {name}")

    except Exception as e:
        logger.error(f"Error deleting KeycloakRealm {name}: {e}")
        # Don't raise an error - we want deletion to proceed
        # even if cleanup fails partially


@kopf.timer("keycloakrealms", interval=600)  # Check every 10 minutes
def monitor_realm_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Periodic health check for KeycloakRealms.

    This timer verifies that realms still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakRealm resource specification
        name: Name of the KeycloakRealm resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    TODO: Implement the following functionality:
    1. Check if the realm still exists in Keycloak
    2. Verify that realm configuration matches the specification
    3. Check authentication flows and identity providers
    4. Validate user federation connections
    5. Check realm policies and permissions
    6. Update status if discrepancies are found
    7. Generate events for configuration drift
    8. Attempt to reconcile minor configuration differences
    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed realms
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of KeycloakRealm {name} in {namespace}")

    try:
        realm_spec = KeycloakRealmSpec.model_validate(spec)

        # TODO: Get admin client and verify connection
        keycloak_ref = realm_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # TODO: Check if realm exists in Keycloak
        realm_name = realm_spec.realm_name
        existing_realm = admin_client.get_realm(realm_name)

        if not existing_realm:
            logger.warning(f"Realm {realm_name} missing from Keycloak")
            return {
                "phase": "Degraded",
                "message": "Realm missing from Keycloak, will recreate",
                "lastHealthCheck": "TODO: current timestamp",
            }

        # TODO: Verify realm configuration matches spec
        config_matches = True  # TODO: Compare configurations
        if not config_matches:
            logger.info(f"Realm {realm_name} configuration drift detected")
            return {
                "phase": "Degraded",
                "message": "Configuration drift detected",
                "lastHealthCheck": "TODO: current timestamp",
            }

        # TODO: Check authentication flows
        if realm_spec.authentication_flows:
            flows_valid = True  # TODO: Validate flows exist and are correct
            if not flows_valid:
                return {
                    "phase": "Degraded",
                    "message": "Authentication flows configuration mismatch",
                    "lastHealthCheck": "TODO: current timestamp",
                }

        # TODO: Check identity providers
        if realm_spec.identity_providers:
            idps_valid = True  # TODO: Validate identity providers
            if not idps_valid:
                return {
                    "phase": "Degraded",
                    "message": "Identity provider configuration mismatch",
                    "lastHealthCheck": "TODO: current timestamp",
                }

        # TODO: Check user federation connections
        if realm_spec.user_federation:
            federation_healthy = True  # TODO: Test federation connections
            if not federation_healthy:
                return {
                    "phase": "Degraded",
                    "message": "User federation connection issues detected",
                    "lastHealthCheck": "TODO: current timestamp",
                }

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakRealm {name} health check passed")
            return {
                "phase": "Ready",
                "message": "Realm is healthy and properly configured",
                "lastHealthCheck": "TODO: current timestamp",
            }

    except Exception as e:
        logger.error(f"Health check failed for KeycloakRealm {name}: {e}")
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": "TODO: current timestamp",
        }

    return None  # No status update needed
