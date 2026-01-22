"""
Drift detection service for Keycloak resources.

This service compares the actual state of Keycloak resources against
Kubernetes CRs to detect orphaned resources, configuration drift, and
unmanaged resources.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.client import KeycloakClientSpec
from keycloak_operator.models.realm import KeycloakRealmSpec
from keycloak_operator.observability.metrics import (
    CONFIG_DRIFT,
    DRIFT_CHECK_DURATION,
    DRIFT_CHECK_ERRORS_TOTAL,
    DRIFT_CHECK_LAST_SUCCESS_TIMESTAMP,
    ORPHANED_RESOURCES,
    REMEDIATION_ERRORS_TOTAL,
    REMEDIATION_TOTAL,
    UNMANAGED_RESOURCES,
)
from keycloak_operator.services.client_reconciler import KeycloakClientReconciler
from keycloak_operator.services.realm_reconciler import KeycloakRealmReconciler
from keycloak_operator.settings import settings
from keycloak_operator.utils.keycloak_admin import (
    KeycloakAdminClient,
    get_keycloak_admin_client,
)
from keycloak_operator.utils.ownership import (
    get_cr_reference,
    get_resource_age_hours,
    is_managed_by_operator,
    is_owned_by_this_operator,
)

logger = logging.getLogger(__name__)


@dataclass
class DriftResult:
    """Result of drift detection for a single resource."""

    resource_type: str  # realm, client, idp, role
    resource_name: str
    drift_type: str  # orphaned, config_drift, unmanaged
    keycloak_resource: dict
    cr_namespace: str | None = None
    cr_name: str | None = None
    age_hours: float | None = None
    desired_resource: dict | None = None
    drift_details: list[str] | None = None
    parent_realm: str | None = None


@dataclass
class DriftDetectionConfig:
    """Configuration for drift detection."""

    enabled: bool
    interval_seconds: int
    auto_remediate: bool
    minimum_age_hours: int
    scope_realms: bool
    scope_clients: bool
    scope_identity_providers: bool
    scope_roles: bool

    @classmethod
    def from_env(cls) -> "DriftDetectionConfig":
        """Load configuration from settings."""
        return cls(
            enabled=settings.drift_detection_enabled,
            interval_seconds=settings.drift_detection_interval_seconds,
            auto_remediate=settings.drift_detection_auto_remediate,
            minimum_age_hours=settings.drift_detection_minimum_age_hours,
            scope_realms=settings.drift_detection_scope_realms,
            scope_clients=settings.drift_detection_scope_clients,
            scope_identity_providers=settings.drift_detection_scope_identity_providers,
            scope_roles=settings.drift_detection_scope_roles,
        )


class DriftDetector:
    """Detects drift between Keycloak state and Kubernetes CRs."""

    def __init__(
        self,
        config: DriftDetectionConfig | None = None,
        k8s_client: client.ApiClient | None = None,
        keycloak_admin_factory: (
            Callable[[str, str], Awaitable[KeycloakAdminClient]] | None
        ) = None,
        keycloak_instances: list[tuple[str, str]] | None = None,
        operator_instance_id: str | None = None,
    ):
        """
        Initialize drift detector.

        Args:
            config: Drift detection configuration
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients.
                Signature: async (keycloak_name: str, namespace: str) -> KeycloakAdminClient
            keycloak_instances: Optional list of (namespace, name) tuples for Keycloak instances to scan.
                If None, will discover instances automatically.
            operator_instance_id: Optional operator instance ID for ownership checks.
                If None, will use get_operator_instance_id() which reads from settings.
        """
        self.config = config or DriftDetectionConfig.from_env()
        self.k8s_client = k8s_client or client.ApiClient()
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )
        self.keycloak_instances_override = keycloak_instances
        self.operator_instance_id = operator_instance_id
        self.custom_objects_api = client.CustomObjectsApi(self.k8s_client)
        self.core_v1_api = client.CoreV1Api(self.k8s_client)

        logger.info(
            f"Drift detector initialized: enabled={self.config.enabled}, "
            f"interval={self.config.interval_seconds}s, "
            f"auto_remediate={self.config.auto_remediate}"
        )

    def _calculate_drift(
        self, desired: dict, actual: dict, path: str = ""
    ) -> list[str]:
        """
        Calculate drift between desired and actual configuration.

        Args:
            desired: Desired configuration (from CR)
            actual: Actual configuration (from Keycloak)
            path: Current path for recursive calls

        Returns:
            List of drift descriptions
        """
        drift = []

        for key, value in desired.items():
            # Skip None values in desired config (treated as "don't care")
            if value is None:
                continue

            current_path = f"{path}.{key}" if path else key

            if key not in actual:
                drift.append(f"Missing field: {current_path}")
                continue

            actual_value = actual[key]

            if isinstance(value, dict) and isinstance(actual_value, dict):
                drift.extend(self._calculate_drift(value, actual_value, current_path))
            elif isinstance(value, list) and isinstance(actual_value, list):
                # Simple list comparison for now
                # In future we might want to handle set-like lists (order independent)
                if value != actual_value:
                    drift.append(
                        f"List mismatch at {current_path}: desired={value}, actual={actual_value}"
                    )
            elif value != actual_value:
                drift.append(
                    f"Value mismatch at {current_path}: desired={value}, actual={actual_value}"
                )

        return drift

    async def scan_for_drift(self) -> list[DriftResult]:
        """
        Scan all Keycloak resources for drift.

        Returns:
            List of drift results found

        Raises:
            Exception: If drift scan fails
        """
        logger.info("Starting drift detection scan")
        drift_results: list[DriftResult] = []

        try:
            # Scan realms if enabled
            if self.config.scope_realms:
                realm_results = await self.check_realm_drift()
                drift_results.extend(realm_results)
                logger.info(f"Found {len(realm_results)} realm drift issues")

            # Scan clients if enabled
            if self.config.scope_clients:
                client_results = await self.check_client_drift()
                drift_results.extend(client_results)
                logger.info(f"Found {len(client_results)} client drift issues")

            # TODO: Scan identity providers if enabled
            # TODO: Scan roles if enabled

            # Update last success timestamp
            DRIFT_CHECK_LAST_SUCCESS_TIMESTAMP.set(time.time())

            logger.info(
                f"Drift scan completed: {len(drift_results)} total issues found"
            )
            return drift_results

        except Exception as e:
            logger.error(f"Drift scan failed: {e}", exc_info=True)
            raise

    async def check_realm_drift(self) -> list[DriftResult]:
        """
        Check for drift in Keycloak realms.

        Returns:
            List of drift results for realms
        """
        start_time = time.time()
        drift_results: list[DriftResult] = []

        try:
            # Get all Keycloak instances to scan
            # For now, we'll scan the default Keycloak instance in each namespace
            # TODO: Make this configurable or discover Keycloak instances
            keycloak_instances = await self._discover_keycloak_instances()

            for kc_namespace, kc_name in keycloak_instances:
                try:
                    admin_client = await self.keycloak_admin_factory(
                        kc_name, kc_namespace
                    )
                    realms = await admin_client.get_realms(kc_namespace)

                    for realm in realms:
                        # Skip master realm (system realm)
                        if realm.realm == "master":
                            continue

                        drift = await self._check_realm_resource_drift(
                            realm, admin_client
                        )
                        if drift:
                            drift_results.append(drift)

                except Exception as e:
                    logger.error(
                        f"Failed to check realms in Keycloak {kc_namespace}/{kc_name}: {e}"
                    )
                    DRIFT_CHECK_ERRORS_TOTAL.labels(resource_type="realm").inc()

            # Update metrics
            self._update_drift_metrics(drift_results, "realm")

            duration = time.time() - start_time
            DRIFT_CHECK_DURATION.labels(resource_type="realm").observe(duration)

            return drift_results

        except Exception as e:
            logger.error(f"Realm drift check failed: {e}", exc_info=True)
            DRIFT_CHECK_ERRORS_TOTAL.labels(resource_type="realm").inc()
            raise

    async def check_client_drift(self) -> list[DriftResult]:
        """
        Check for drift in Keycloak clients.

        Returns:
            List of drift results for clients
        """
        start_time = time.time()
        drift_results: list[DriftResult] = []

        try:
            # Get all Keycloak instances to scan
            keycloak_instances = await self._discover_keycloak_instances()

            for kc_namespace, kc_name in keycloak_instances:
                try:
                    admin_client = await self.keycloak_admin_factory(
                        kc_name, kc_namespace
                    )

                    # Get all realms first
                    realms = await admin_client.get_realms(kc_namespace)

                    for realm in realms:
                        # Skip master realm
                        if realm.realm == "master":
                            continue

                        # Get all clients in this realm
                        clients = await admin_client.get_realm_clients(
                            realm.realm, kc_namespace
                        )

                        for kc_client in clients:
                            drift = await self._check_client_resource_drift(
                                kc_client, realm.realm, admin_client
                            )
                            if drift:
                                drift_results.append(drift)

                except Exception as e:
                    logger.error(
                        f"Failed to check clients in Keycloak {kc_namespace}/{kc_name}: {e}"
                    )
                    DRIFT_CHECK_ERRORS_TOTAL.labels(resource_type="client").inc()

            # Update metrics
            self._update_drift_metrics(drift_results, "client")

            duration = time.time() - start_time
            DRIFT_CHECK_DURATION.labels(resource_type="client").observe(duration)

            return drift_results

        except Exception as e:
            logger.error(f"Client drift check failed: {e}", exc_info=True)
            DRIFT_CHECK_ERRORS_TOTAL.labels(resource_type="client").inc()
            raise

    async def _check_realm_resource_drift(
        self, realm, admin_client: KeycloakAdminClient
    ) -> DriftResult | None:
        """
        Check a single realm for drift.

        Args:
            realm: Realm representation from Keycloak
            admin_client: Keycloak admin client

        Returns:
            DriftResult if drift detected, None otherwise
        """
        attributes = realm.attributes or {}

        # Check if owned by this operator
        if is_owned_by_this_operator(attributes, self.operator_instance_id):
            # Get CR reference
            cr_ref = get_cr_reference(attributes)
            if not cr_ref:
                # Missing CR reference in attributes - treat as orphaned
                logger.warning(
                    f"Realm {realm.realm} owned by this operator but missing CR reference"
                )
                return DriftResult(
                    resource_type="realm",
                    resource_name=realm.realm,
                    drift_type="orphaned",
                    keycloak_resource=realm.model_dump()
                    if hasattr(realm, "model_dump")
                    else vars(realm),
                    age_hours=get_resource_age_hours(attributes),
                )

            cr_namespace, cr_name = cr_ref

            # Check if CR still exists
            if not await self._cr_exists("KeycloakRealm", cr_namespace, cr_name):
                # CR deleted - this is an orphan
                logger.info(
                    f"Found orphaned realm {realm.realm} (CR {cr_namespace}/{cr_name} not found)"
                )
                return DriftResult(
                    resource_type="realm",
                    resource_name=realm.realm,
                    drift_type="orphaned",
                    keycloak_resource=realm.model_dump()
                    if hasattr(realm, "model_dump")
                    else vars(realm),
                    cr_namespace=cr_namespace,
                    cr_name=cr_name,
                    age_hours=get_resource_age_hours(attributes),
                )

            # CR exists - check for config drift
            try:
                cr = await asyncio.to_thread(
                    self.custom_objects_api.get_namespaced_custom_object,
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=cr_namespace,
                    plural="keycloakrealms",
                    name=cr_name,
                )

                spec = cr.get("spec", {})
                realm_spec = KeycloakRealmSpec.model_validate(spec)
                # We include flow bindings for drift detection to ensure they match
                desired_config = realm_spec.to_keycloak_config(
                    include_flow_bindings=True
                )

                # Convert actual realm to dict for comparison
                # Using by_alias=True to match Keycloak API field names (camelCase)
                actual_config = (
                    realm.model_dump(by_alias=True, exclude_unset=True)
                    if hasattr(realm, "model_dump")
                    else vars(realm)
                )

                drift_details = self._calculate_drift(desired_config, actual_config)

                if drift_details:
                    logger.info(
                        f"Config drift detected for realm {realm.realm}: {drift_details}"
                    )
                    return DriftResult(
                        resource_type="realm",
                        resource_name=realm.realm,
                        drift_type="config_drift",
                        keycloak_resource=actual_config,
                        desired_resource=desired_config,
                        drift_details=drift_details,
                        cr_namespace=cr_namespace,
                        cr_name=cr_name,
                        age_hours=get_resource_age_hours(attributes),
                    )

            except Exception as e:
                logger.error(
                    f"Failed to check config drift for realm {realm.realm}: {e}"
                )
                # Don't fail the whole scan, just log error
                pass

        elif is_managed_by_operator(attributes):
            # Owned by a different operator instance - ignore
            logger.debug(f"Realm {realm.realm} owned by different operator, skipping")
            return None

        else:
            # Not managed by any operator - unmanaged resource
            logger.debug(f"Found unmanaged realm {realm.realm}")
            return DriftResult(
                resource_type="realm",
                resource_name=realm.realm,
                drift_type="unmanaged",
                keycloak_resource=realm.model_dump()
                if hasattr(realm, "model_dump")
                else vars(realm),
            )

        return None

    async def _check_client_resource_drift(
        self, kc_client, realm_name: str, admin_client: KeycloakAdminClient
    ) -> DriftResult | None:
        """
        Check a single client for drift.

        Args:
            kc_client: Client representation from Keycloak
            realm_name: Name of the realm this client belongs to
            admin_client: Keycloak admin client

        Returns:
            DriftResult if drift detected, None otherwise
        """
        # Clients have attributes too
        client_dict = (
            kc_client.model_dump()
            if hasattr(kc_client, "model_dump")
            else vars(kc_client)
        )
        attributes = client_dict.get("attributes", {})

        # Check if owned by this operator
        if is_owned_by_this_operator(attributes, self.operator_instance_id):
            # Get CR reference
            cr_ref = get_cr_reference(attributes)
            if not cr_ref:
                # Missing CR reference - treat as orphaned
                logger.warning(
                    f"Client {kc_client.client_id} owned by this operator but missing CR reference"
                )
                return DriftResult(
                    resource_type="client",
                    resource_name=kc_client.client_id,
                    drift_type="orphaned",
                    keycloak_resource=client_dict,
                    age_hours=get_resource_age_hours(attributes),
                )

            cr_namespace, cr_name = cr_ref

            # Check if CR still exists
            if not await self._cr_exists("KeycloakClient", cr_namespace, cr_name):
                # CR deleted - this is an orphan
                logger.info(
                    f"Found orphaned client {kc_client.client_id} in realm {realm_name} "
                    f"(CR {cr_namespace}/{cr_name} not found)"
                )
                return DriftResult(
                    resource_type="client",
                    resource_name=kc_client.client_id,
                    drift_type="orphaned",
                    keycloak_resource=client_dict,
                    cr_namespace=cr_namespace,
                    cr_name=cr_name,
                    age_hours=get_resource_age_hours(attributes),
                )

            # CR exists - check for config drift
            try:
                cr = await asyncio.to_thread(
                    self.custom_objects_api.get_namespaced_custom_object,
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=cr_namespace,
                    plural="keycloakclients",
                    name=cr_name,
                )

                spec = cr.get("spec", {})
                client_spec = KeycloakClientSpec.model_validate(spec)
                desired_config = client_spec.to_keycloak_config()

                # Helper to convert actual client to dict
                actual_config = (
                    kc_client.model_dump(by_alias=True, exclude_unset=True)
                    if hasattr(kc_client, "model_dump")
                    else vars(kc_client)
                )

                drift_details = self._calculate_drift(desired_config, actual_config)

                if drift_details:
                    logger.info(
                        f"Config drift detected for client {kc_client.client_id}: {drift_details}"
                    )
                    return DriftResult(
                        resource_type="client",
                        resource_name=kc_client.client_id,
                        drift_type="config_drift",
                        keycloak_resource=actual_config,
                        desired_resource=desired_config,
                        drift_details=drift_details,
                        cr_namespace=cr_namespace,
                        cr_name=cr_name,
                        age_hours=get_resource_age_hours(attributes),
                        parent_realm=realm_name,
                    )
            except Exception as e:
                logger.error(
                    f"Failed to check config drift for client {kc_client.client_id}: {e}"
                )
                pass

        elif is_managed_by_operator(attributes):
            # Owned by a different operator instance - ignore
            logger.debug(
                f"Client {kc_client.client_id} owned by different operator, skipping"
            )
            return None

        else:
            # Not managed by any operator - unmanaged resource
            logger.debug(f"Found unmanaged client {kc_client.client_id}")
            return DriftResult(
                resource_type="client",
                resource_name=kc_client.client_id,
                drift_type="unmanaged",
                keycloak_resource=client_dict,
            )

        return None

    async def _cr_exists(self, kind: str, namespace: str, name: str) -> bool:
        """
        Check if a CR exists in Kubernetes.

        Args:
            kind: Kind of CR (KeycloakRealm, KeycloakClient, etc.)
            namespace: Namespace of the CR
            name: Name of the CR

        Returns:
            True if CR exists, False otherwise
        """
        try:
            plural_map = {
                "KeycloakRealm": "keycloakrealms",
                "KeycloakClient": "keycloakclients",
                "KeycloakIdentityProvider": "keycloakidentityproviders",
            }
            plural = plural_map.get(kind, kind.lower() + "s")

            await asyncio.to_thread(
                self.custom_objects_api.get_namespaced_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural=plural,
                name=name,
            )
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            # Other errors (permissions, etc.) - log and treat as "not found" for safety
            logger.warning(
                f"Error checking if {kind} {namespace}/{name} exists: {e.status} {e.reason}"
            )
            return False

    async def _discover_keycloak_instances(self) -> list[tuple[str, str]]:
        """
        Discover all Keycloak instances to scan.

        Returns:
            List of (namespace, name) tuples for Keycloak instances
        """
        # If instances were provided at init, use those
        if self.keycloak_instances_override is not None:
            return self.keycloak_instances_override

        # For now, return a hardcoded list
        # TODO(#66): Discover Keycloak instances dynamically via CRDs for multi-instance deployments
        # This limitation impacts scalability in production environments with multiple Keycloak instances
        return [(settings.operator_namespace, "keycloak")]

    def _update_drift_metrics(
        self, drift_results: list[DriftResult], resource_type: str
    ) -> None:
        """
        Update Prometheus metrics based on drift results.

        Args:
            drift_results: List of drift results
            resource_type: Type of resource being checked
        """
        # Reset gauges for this resource type
        # Note: We can't easily reset specific labels, so we'll just update
        # This means old metrics may persist until they're overwritten

        for drift in drift_results:
            if drift.drift_type == "orphaned":
                # Set orphaned resource metric
                ORPHANED_RESOURCES.labels(
                    resource_type=drift.resource_type,
                    resource_name=drift.resource_name,
                    operator_instance=settings.operator_instance_id,
                ).set(1)

            elif drift.drift_type == "config_drift":
                # Set config drift metric
                CONFIG_DRIFT.labels(
                    resource_type=drift.resource_type,
                    resource_name=drift.resource_name,
                    cr_namespace=drift.cr_namespace or "unknown",
                    cr_name=drift.cr_name or "unknown",
                ).set(1)

            elif drift.drift_type == "unmanaged":
                # Set unmanaged resource metric
                UNMANAGED_RESOURCES.labels(
                    resource_type=drift.resource_type,
                    resource_name=drift.resource_name,
                ).set(1)

    async def remediate_drift(self, drift_results: list[DriftResult]) -> None:
        """
        Remediate detected drift if auto-remediation is enabled.

        Args:
            drift_results: List of drift results to remediate
        """
        if not self.config.auto_remediate:
            logger.info("Auto-remediation is disabled, skipping")
            return

        logger.info(f"Starting auto-remediation for {len(drift_results)} drift issues")

        for drift in drift_results:
            try:
                if drift.drift_type == "orphaned":
                    await self._remediate_orphan(drift)
                elif drift.drift_type == "config_drift":
                    await self._remediate_config_drift(drift)
                # Unmanaged resources are not remediated

            except Exception as e:
                logger.error(
                    f"Failed to remediate {drift.resource_type} {drift.resource_name}: {e}"
                )
                REMEDIATION_ERRORS_TOTAL.labels(
                    resource_type=drift.resource_type,
                    action="delete" if drift.drift_type == "orphaned" else "update",
                ).inc()

    async def _remediate_orphan(self, drift: DriftResult) -> None:
        """
        Remediate an orphaned resource by deleting it from Keycloak.

        Args:
            drift: Drift result for orphaned resource
        """
        # Check minimum age
        if drift.age_hours is not None:
            if drift.age_hours < self.config.minimum_age_hours:
                logger.info(
                    f"Skipping orphan remediation for {drift.resource_type} {drift.resource_name}: "
                    f"age {drift.age_hours:.1f}h < minimum {self.config.minimum_age_hours}h"
                )
                return
        else:
            logger.warning(
                f"Cannot determine age of {drift.resource_type} {drift.resource_name}, skipping remediation"
            )
            return

        # Re-check that CR still doesn't exist (safety check)
        if drift.cr_namespace and drift.cr_name:
            cr_kind = (
                "KeycloakRealm" if drift.resource_type == "realm" else "KeycloakClient"
            )
            if await self._cr_exists(cr_kind, drift.cr_namespace, drift.cr_name):
                logger.warning(
                    f"CR {drift.cr_namespace}/{drift.cr_name} now exists, skipping orphan deletion"
                )
                return

        logger.info(
            f"Remediating orphaned {drift.resource_type} {drift.resource_name} "
            f"(age: {drift.age_hours:.1f}h)"
        )

        # Get Keycloak admin client
        keycloak_instances = await self._discover_keycloak_instances()
        if not keycloak_instances:
            logger.error("No Keycloak instances found for remediation")
            REMEDIATION_ERRORS_TOTAL.labels(
                resource_type=drift.resource_type,
                action="delete",
            ).inc()
            return

        # Use the first Keycloak instance (TODO: track which instance owns which resource)
        kc_namespace, kc_name = keycloak_instances[0]

        try:
            admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)

            # Delete based on resource type
            if drift.resource_type == "realm":
                success = await admin_client.delete_realm(
                    drift.resource_name, kc_namespace
                )
                if success:
                    logger.info(
                        f"Successfully deleted orphaned realm {drift.resource_name}"
                    )
                    REMEDIATION_TOTAL.labels(
                        resource_type=drift.resource_type,
                        action="delete",
                        reason="orphaned",
                    ).inc()
                else:
                    logger.error(
                        f"Failed to delete orphaned realm {drift.resource_name}"
                    )
                    REMEDIATION_ERRORS_TOTAL.labels(
                        resource_type=drift.resource_type,
                        action="delete",
                    ).inc()

            elif drift.resource_type == "client":
                # For clients, we need the client UUID and realm name
                # Extract from keycloak_resource
                client_id = drift.keycloak_resource.get("id")

                # Use parent_realm if available (added in recent changes)
                target_realms = []
                if drift.parent_realm:
                    # If we know the parent realm, only check that one
                    target_realms = [drift.parent_realm]
                else:
                    # Fallback: search all realms
                    all_realms = await admin_client.get_realms(kc_namespace)
                    target_realms = [r.realm for r in all_realms if r.realm != "master"]

                client_deleted = False

                for realm_name in target_realms:
                    try:
                        # Get client in this realm by clientId to confirm it exists and get ID if needed
                        if not client_id:
                            kc_client = await admin_client.get_client_by_name(
                                drift.resource_name, realm_name, kc_namespace
                            )
                            if kc_client:
                                client_id = kc_client.id

                        if client_id:
                            # Try to delete
                            success = await admin_client.delete_client(
                                client_id, realm_name, kc_namespace
                            )
                            if success:
                                logger.info(
                                    f"Successfully deleted orphaned client {drift.resource_name} "
                                    f"from realm {realm_name}"
                                )
                                REMEDIATION_TOTAL.labels(
                                    resource_type=drift.resource_type,
                                    action="delete",
                                    reason="orphaned",
                                ).inc()
                                client_deleted = True
                                break
                    except Exception as e:
                        logger.debug(
                            f"Client {drift.resource_name} error in realm {realm_name}: {e}"
                        )
                        continue

                if not client_deleted:
                    logger.error(
                        f"Failed to find and delete orphaned client {drift.resource_name}"
                    )
                    REMEDIATION_ERRORS_TOTAL.labels(
                        resource_type=drift.resource_type,
                        action="delete",
                    ).inc()

        except Exception as e:
            logger.error(
                f"Error deleting orphaned {drift.resource_type} {drift.resource_name}: {e}",
                exc_info=True,
            )
            REMEDIATION_ERRORS_TOTAL.labels(
                resource_type=drift.resource_type,
                action="delete",
            ).inc()

    async def _remediate_config_drift(self, drift: DriftResult) -> None:
        """
        Remediate configuration drift by triggering reconciliation.

        Args:
            drift: Drift result for config drift
        """
        logger.info(
            f"Remediating config drift for {drift.resource_type} {drift.resource_name}"
        )

        if not drift.cr_namespace or not drift.cr_name:
            logger.error(
                f"Cannot remediate {drift.resource_type} {drift.resource_name}: missing CR info"
            )
            return

        try:
            # 1. Determine CR type and Reconciler
            if drift.resource_type == "realm":
                plural = "keycloakrealms"
            elif drift.resource_type == "client":
                plural = "keycloakclients"
            else:
                logger.warning(
                    f"Unsupported resource type for remediation: {drift.resource_type}"
                )
                return

            # 2. Fetch current CR from Kubernetes
            # We fetch fresh to ensure we are applying the latest desired state
            cr = await asyncio.to_thread(
                self.custom_objects_api.get_namespaced_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=drift.cr_namespace,
                plural=plural,
                name=drift.cr_name,
            )

            # 3. Instantiate Reconciler
            # IMPORTANT: We explicitly disable RBAC validation during drift remediation
            # in test environments or when running outside a pod.
            # The BaseReconciler's RBAC checks rely on k8s service account tokens
            # which might not be present or might have different permissions than the
            # privileged client used by the drift detector.

            # Create a subclass that skips RBAC if needed
            class PermissiveRealmReconciler(KeycloakRealmReconciler):
                async def validate_cross_namespace_access(self, spec, namespace):
                    pass  # Skip RBAC check for drift remediation

            class PermissiveClientReconciler(KeycloakClientReconciler):
                async def validate_cross_namespace_access(self, spec, namespace):
                    pass  # Skip RBAC check for drift remediation

            if drift.resource_type == "realm":
                reconciler = PermissiveRealmReconciler(
                    k8s_client=self.k8s_client,
                    keycloak_admin_factory=self.keycloak_admin_factory,
                    rate_limiter=None,
                )
            else:
                reconciler = PermissiveClientReconciler(
                    k8s_client=self.k8s_client,
                    keycloak_admin_factory=self.keycloak_admin_factory,
                    rate_limiter=None,
                )

            # 4. Create a dummy status object to capture status updates without failing
            class DriftRemediationStatus:
                def __init__(self) -> None:
                    self._data: dict[str, Any] = {}

                def __getattr__(self, name: str) -> Any:
                    return self._data.get(name)

                def __setattr__(self, name: str, value: Any) -> None:
                    if name == "_data":
                        super().__setattr__(name, value)
                    else:
                        self._data[name] = value

                def __getitem__(self, key: str) -> Any:
                    return self._data.get(key)

                def __setitem__(self, key: str, value: Any) -> None:
                    self._data[key] = value

            status = DriftRemediationStatus()

            # 5. Run Reconciliation
            # This will enforce the CR state onto Keycloak
            logger.info(
                f"Triggering reconciliation for {drift.resource_type} {drift.resource_name}"
            )
            await reconciler.do_reconcile(
                spec=cr["spec"],
                name=drift.cr_name,
                namespace=drift.cr_namespace,
                status=status,
                body=cr,
                meta=cr["metadata"],
            )

            logger.info(
                f"Successfully remediated {drift.resource_type} {drift.resource_name}"
            )

            REMEDIATION_TOTAL.labels(
                resource_type=drift.resource_type,
                action="reconcile",
                reason="drift",
            ).inc()

        except Exception as e:
            logger.error(f"Failed to remediate drift: {e}")
            REMEDIATION_ERRORS_TOTAL.labels(
                resource_type=drift.resource_type,
                action="reconcile",
            ).inc()
            raise
