"""
KeycloakClient handlers - Manages dynamic client provisioning across namespaces.

This module implements the core feature of dynamic client provisioning that
enables GitOps-compatible client management. Key features:

- Cross-namespace client creation: Clients can reference Keycloak instances
  in different namespaces (subject to RBAC permissions)
- RBAC-based authorization: Uses Kubernetes RBAC instead of Keycloak's
  built-in security mechanisms
- Secure secret management: Client credentials stored in Kubernetes secrets
  with proper access controls
- GitOps compatibility: All client configuration is declarative

The handlers support various client types including:
- Public clients (SPAs, mobile apps)
- Confidential clients (backend services)
- Service accounts for machine-to-machine communication
"""

import logging
from typing import Any

import kopf
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.kubernetes import (
    create_client_secret,
    get_kubernetes_client,
    validate_keycloak_reference,
)

logger = logging.getLogger(__name__)


@kopf.on.create("keycloakclients")
@kopf.on.resume("keycloakclients")
def ensure_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Ensure KeycloakClient exists in the target Keycloak instance.

    This handler implements dynamic client provisioning across namespaces.
    It can create clients in Keycloak instances located in any namespace,
    subject to RBAC permissions.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the KeycloakClient resource exists
        status: Current status of the resource

    Returns:
        Dictionary with status information for the resource

    TODO: Implement the following functionality:
    1. Validate and parse the client specification
    2. Resolve the Keycloak instance reference (possibly cross-namespace)
    3. Verify RBAC permissions for cross-namespace operations
    4. Connect to the target Keycloak instance using admin credentials
    5. Check if client already exists (idempotent operation)
    6. Create or update the client in Keycloak
    7. Generate and store client credentials securely
    8. Create Kubernetes secret with client credentials
    9. Set up proper secret access controls
    10. Update resource status with client information
    """
    logger.info(f"Ensuring KeycloakClient {name} in namespace {namespace}")

    try:
        # Parse and validate the client specification
        client_spec = KeycloakClientSpec.model_validate(spec)
        logger.debug(f"Validated KeycloakClient spec: {client_spec}")

        # Update status to indicate processing
        status.update(
            {
                "phase": "Pending",
                "message": "Creating Keycloak client",
            }
        )

        # TODO: Resolve Keycloak instance reference
        # This supports cross-namespace references like:
        # keycloakInstanceRef:
        #   name: main-keycloak
        #   namespace: keycloak-system  # Optional, defaults to current namespace
        keycloak_ref = client_spec.keycloak_instance_ref
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
        # If client is in different namespace than Keycloak, verify permissions
        if target_namespace != namespace:
            # Verify that the service account has permission to access
            # the Keycloak instance in the target namespace
            has_permission = True  # TODO: Implement RBAC check
            if not has_permission:
                raise kopf.PermanentError(
                    f"Insufficient permissions to access Keycloak instance "
                    f"{keycloak_name} in namespace {target_namespace}"
                )

        # TODO: Get Keycloak admin client
        admin_client = get_keycloak_admin_client(keycloak_name, target_namespace)

        # TODO: Check if client already exists in the specified realm
        realm_name = client_spec.realm or "master"
        existing_client = admin_client.get_client_by_name(
            client_spec.client_id, realm_name
        )

        if existing_client:
            logger.info(f"Client {client_spec.client_id} already exists, updating...")
            # TODO: Update existing client configuration
            admin_client.update_client(
                existing_client["id"], client_spec.to_keycloak_config(), realm_name
            )
        else:
            logger.info(f"Creating new client {client_spec.client_id}")
            # TODO: Create new client in Keycloak
            admin_client.create_client(client_spec.to_keycloak_config(), realm_name)

        # TODO: Generate and retrieve client credentials for confidential clients
        client_secret = None
        if not client_spec.public_client:
            # TODO: Get or regenerate client secret
            client_secret = admin_client.get_client_secret(
                client_spec.client_id, realm_name
            )
            logger.info("Retrieved client secret for confidential client")

        # TODO: Create Kubernetes secret with client credentials
        # Store in the same namespace as the KeycloakClient resource
        secret_name = f"{name}-credentials"
        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id=client_spec.client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_instance["status"]["endpoints"]["public"],
            realm=realm_name,
        )

        # TODO: Set up RBAC for secret access
        # Ensure only authorized services can access the client credentials

        # TODO: Configure client-specific settings
        # This might include:
        # - Setting up protocol mappers
        # - Configuring client scopes
        # - Setting up authentication flows
        # - Configuring client policies

        logger.info(f"Successfully created KeycloakClient {name}")

        return {
            "phase": "Ready",
            "message": "Client successfully created and configured",
            "clientId": client_spec.client_id,
            "realm": realm_name,
            "keycloakInstance": f"{target_namespace}/{keycloak_name}",
            "credentialsSecret": secret_name,
            "publicClient": client_spec.public_client,
            "endpoints": {
                "auth": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}",
                "token": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}/protocol/openid-connect/token",
                "userinfo": f"{keycloak_instance['status']['endpoints']['public']}"
                f"/realms/{realm_name}/protocol/openid-connect/userinfo",
            },
        }

    except ApiException as e:
        logger.error(f"Kubernetes API error creating KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Kubernetes API error: {e.reason}",
            }
        )
        raise kopf.TemporaryError(f"Kubernetes API error: {e}", delay=30) from e

    except Exception as e:
        logger.error(f"Error creating KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Failed to create client: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Client creation failed: {e}", delay=60) from e


@kopf.on.update("keycloakclients")
def update_keycloak_client(
    old: dict[str, Any],
    new: dict[str, Any],
    diff: kopf.Diff,
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Handle updates to KeycloakClient specifications.

    This handler processes changes to client configurations and applies
    them to the target Keycloak instance.

    Args:
        old: Previous specification
        new: New specification
        diff: List of changes
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    TODO: Implement the following functionality:
    1. Parse specification changes from the diff
    2. Validate that critical fields (client_id, keycloak reference) haven't changed
    3. Apply configuration changes to the Keycloak client
    4. Handle redirect URI updates
    5. Handle scope changes
    6. Handle authentication flow changes
    7. Regenerate client secret if requested
    8. Update Kubernetes secret with new credentials
    9. Update status to reflect changes
    """
    logger.info(f"Updating KeycloakClient {name} in namespace {namespace}")

    # Log changes for debugging
    for operation, field_path, old_value, new_value in diff:
        logger.info(
            f"KeycloakClient change - {operation}: {field_path} "
            f"from {old_value} to {new_value}"
        )

    status.update(
        {
            "phase": "Updating",
            "message": "Applying client configuration changes",
        }
    )

    try:
        # TODO: Validate that immutable fields haven't changed
        old_spec = KeycloakClientSpec.model_validate(old["spec"])
        new_spec = KeycloakClientSpec.model_validate(new["spec"])

        # Check for changes to immutable fields
        if old_spec.client_id != new_spec.client_id:
            raise kopf.PermanentError(
                "Cannot change client_id of existing KeycloakClient"
            )

        if old_spec.keycloak_instance_ref != new_spec.keycloak_instance_ref:
            raise kopf.PermanentError(
                "Cannot change keycloak_instance_ref of existing KeycloakClient"
            )

        # TODO: Get admin client for the target Keycloak instance
        keycloak_ref = new_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        realm_name = new_spec.realm or "master"

        # TODO: Apply configuration updates based on the diff
        configuration_changed = False
        for _operation, field_path, _old_value, _new_value in diff:
            if field_path[:2] == ("spec", "redirectUris"):
                logger.info("Updating client redirect URIs")
                # TODO: Update redirect URIs in Keycloak
                configuration_changed = True

            elif field_path[:2] == ("spec", "scopes"):
                logger.info("Updating client scopes")
                # TODO: Update client scopes
                configuration_changed = True

            elif field_path[:2] == ("spec", "settings"):
                logger.info("Updating client settings")
                # TODO: Update client configuration
                configuration_changed = True

        if configuration_changed:
            # TODO: Apply all changes to Keycloak
            admin_client.update_client(
                new_spec.client_id, new_spec.to_keycloak_config(), realm_name
            )

        # TODO: Handle client secret regeneration
        regenerate_secret = new_spec.regenerate_secret
        if regenerate_secret and not new_spec.public_client:
            logger.info("Regenerating client secret")
            # TODO: Generate new secret in Keycloak
            new_secret = admin_client.regenerate_client_secret(
                new_spec.client_id, realm_name
            )

            # TODO: Update Kubernetes secret
            secret_name = f"{name}-credentials"
            create_client_secret(
                secret_name=secret_name,
                namespace=namespace,
                client_id=new_spec.client_id,
                client_secret=new_secret,
                keycloak_url="TODO: get from keycloak instance",
                realm=realm_name,
                update_existing=True,
            )

        logger.info(f"Successfully updated KeycloakClient {name}")

        return {
            "phase": "Ready",
            "message": "Client configuration updated successfully",
            "lastUpdated": kwargs.get("meta", {}).get("generation", 0),
        }

    except Exception as e:
        logger.error(f"Failed to update KeycloakClient {name}: {e}")
        status.update(
            {
                "phase": "Failed",
                "message": f"Update failed: {str(e)}",
            }
        )
        raise kopf.TemporaryError(f"Client update failed: {e}", delay=30) from e


@kopf.on.delete("keycloakclients")
def delete_keycloak_client(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    **kwargs: Any,
) -> None:
    """
    Handle KeycloakClient deletion.

    This handler cleans up the client from Keycloak and removes
    associated Kubernetes resources.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists

    TODO: Implement the following functionality:
    1. Parse the client specification
    2. Resolve the target Keycloak instance
    3. Remove the client from Keycloak
    4. Delete the credentials secret from Kubernetes
    5. Clean up any associated RBAC resources
    6. Log successful deletion
    """
    logger.info(f"Deleting KeycloakClient {name} in namespace {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # TODO: Get admin client for the target Keycloak instance
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace

        # Check if Keycloak instance still exists
        # If it's being deleted too, we might not be able to clean up
        try:
            admin_client = get_keycloak_admin_client(
                keycloak_ref.name, target_namespace
            )

            # TODO: Remove client from Keycloak
            realm_name = client_spec.realm or "master"
            admin_client.delete_client(client_spec.client_id, realm_name)
            logger.info(f"Deleted client {client_spec.client_id} from Keycloak")

        except Exception as e:
            logger.warning(
                f"Could not delete client from Keycloak (instance may be deleted): {e}"
            )

        # TODO: Delete the credentials secret
        try:
            core_api = client.CoreV1Api(get_kubernetes_client())
            secret_name = f"{name}-credentials"
            core_api.delete_namespaced_secret(name=secret_name, namespace=namespace)
            logger.info(f"Deleted credentials secret {secret_name}")
        except ApiException as e:
            if e.status != 404:  # Ignore "not found" errors
                logger.warning(f"Failed to delete credentials secret: {e}")

        # TODO: Clean up any additional resources
        # - Remove RBAC bindings if created
        # - Remove any custom annotations or labels

        logger.info(f"Successfully deleted KeycloakClient {name}")

    except Exception as e:
        logger.error(f"Error deleting KeycloakClient {name}: {e}")
        # Don't raise an error - we want deletion to proceed
        # even if cleanup fails partially


@kopf.timer("keycloakclients", interval=300)  # Check every 5 minutes
def monitor_client_health(
    spec: dict[str, Any],
    name: str,
    namespace: str,
    status: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Periodic health check for KeycloakClients.

    This timer verifies that clients still exist in Keycloak and
    that their configuration matches the desired state.

    Args:
        spec: KeycloakClient resource specification
        name: Name of the KeycloakClient resource
        namespace: Namespace where the resource exists
        status: Current status of the resource

    Returns:
        Dictionary with updated status, or None if no changes needed

    TODO: Implement the following functionality:
    1. Check if the client still exists in Keycloak
    2. Verify that client configuration matches the specification
    3. Check that credentials secret still exists and is valid
    4. Validate client permissions and scopes
    5. Update status if discrepancies are found
    6. Generate events for configuration drift
    7. Attempt to reconcile minor configuration differences
    """
    current_phase = status.get("phase", "Unknown")

    # Skip health checks for failed clients
    if current_phase in ["Failed", "Pending"]:
        return None

    logger.debug(f"Checking health of KeycloakClient {name} in {namespace}")

    try:
        client_spec = KeycloakClientSpec.model_validate(spec)

        # TODO: Get admin client and verify connection
        keycloak_ref = client_spec.keycloak_instance_ref
        target_namespace = keycloak_ref.namespace or namespace
        admin_client = get_keycloak_admin_client(keycloak_ref.name, target_namespace)

        # TODO: Check if client exists in Keycloak
        realm_name = client_spec.realm or "master"
        existing_client = admin_client.get_client_by_name(
            client_spec.client_id, realm_name
        )

        if not existing_client:
            logger.warning(f"Client {client_spec.client_id} missing from Keycloak")
            return {
                "phase": "Degraded",
                "message": "Client missing from Keycloak, will recreate",
                "lastHealthCheck": "TODO: current timestamp",
            }

        # TODO: Verify client configuration matches spec
        config_matches = True  # TODO: Compare configurations
        if not config_matches:
            logger.info(f"Client {client_spec.client_id} configuration drift detected")
            return {
                "phase": "Degraded",
                "message": "Configuration drift detected",
                "lastHealthCheck": "TODO: current timestamp",
            }

        # TODO: Check credentials secret exists and is valid
        if not client_spec.public_client:
            secret_exists = True  # TODO: Check secret exists
            if not secret_exists:
                return {
                    "phase": "Degraded",
                    "message": "Client credentials secret missing",
                    "lastHealthCheck": "TODO: current timestamp",
                }

        # Everything looks good
        if current_phase != "Ready":
            logger.info(f"KeycloakClient {name} health check passed")
            return {
                "phase": "Ready",
                "message": "Client is healthy and properly configured",
                "lastHealthCheck": "TODO: current timestamp",
            }

    except Exception as e:
        logger.error(f"Health check failed for KeycloakClient {name}: {e}")
        return {
            "phase": "Degraded",
            "message": f"Health check failed: {str(e)}",
            "lastHealthCheck": "TODO: current timestamp",
        }

    return None  # No status update needed
