"""
Drift detection service for Keycloak resources.

This service compares the actual state of Keycloak resources against
Kubernetes CRs to detect orphaned resources, configuration drift, and
unmanaged resources.
"""

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from kubernetes import client
from kubernetes.client.rest import ApiException

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
        """Load configuration from environment variables."""
        return cls(
            enabled=os.getenv("DRIFT_DETECTION_ENABLED", "true").lower() == "true",
            interval_seconds=int(os.getenv("DRIFT_DETECTION_INTERVAL_SECONDS", "300")),
            auto_remediate=os.getenv("DRIFT_DETECTION_AUTO_REMEDIATE", "false").lower()
            == "true",
            minimum_age_hours=int(os.getenv("DRIFT_DETECTION_MINIMUM_AGE_HOURS", "24")),
            scope_realms=os.getenv("DRIFT_DETECTION_SCOPE_REALMS", "true").lower()
            == "true",
            scope_clients=os.getenv("DRIFT_DETECTION_SCOPE_CLIENTS", "true").lower()
            == "true",
            scope_identity_providers=os.getenv(
                "DRIFT_DETECTION_SCOPE_IDENTITY_PROVIDERS", "true"
            ).lower()
            == "true",
            scope_roles=os.getenv("DRIFT_DETECTION_SCOPE_ROLES", "true").lower()
            == "true",
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
    ):
        """
        Initialize drift detector.

        Args:
            config: Drift detection configuration
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients.
                Signature: async (keycloak_name: str, namespace: str) -> KeycloakAdminClient
        """
        self.config = config or DriftDetectionConfig.from_env()
        self.k8s_client = k8s_client or client.ApiClient()
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )
        self.custom_objects_api = client.CustomObjectsApi(self.k8s_client)
        self.core_v1_api = client.CoreV1Api(self.k8s_client)

        logger.info(
            f"Drift detector initialized: enabled={self.config.enabled}, "
            f"interval={self.config.interval_seconds}s, "
            f"auto_remediate={self.config.auto_remediate}"
        )

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
        if is_owned_by_this_operator(attributes):
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
            # TODO: Implement config drift detection
            # For now, we just detect orphans

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
        if is_owned_by_this_operator(attributes):
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
            # TODO: Implement config drift detection

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
                group="keycloak.mdvr.nl",
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
        # For now, return a hardcoded list
        # TODO(#66): Discover Keycloak instances dynamically via CRDs for multi-instance deployments
        # This limitation impacts scalability in production environments with multiple Keycloak instances
        operator_namespace = os.getenv("OPERATOR_NAMESPACE", "keycloak-system")
        return [(operator_namespace, "keycloak")]

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
                    operator_instance=os.getenv("OPERATOR_INSTANCE_ID", "unknown"),
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
                # Find which realm this client belongs to
                # We stored the client data, so we can try to extract realm from attributes
                # or search through all realms
                realms = await admin_client.get_realms(kc_namespace)
                client_deleted = False

                for realm in realms:
                    if realm.realm == "master":
                        continue

                    try:
                        # Get client in this realm by clientId
                        kc_client = await admin_client.get_client_by_name(
                            drift.resource_name, realm.realm, kc_namespace
                        )
                        if kc_client and kc_client.id == client_id:
                            # Found it! Delete it
                            success = await admin_client.delete_client(
                                kc_client.id, realm.realm, kc_namespace
                            )
                            if success:
                                logger.info(
                                    f"Successfully deleted orphaned client {drift.resource_name} "
                                    f"from realm {realm.realm}"
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
                            f"Client {drift.resource_name} not in realm {realm.realm}: {e}"
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
        Remediate configuration drift by updating Keycloak resource.

        Args:
            drift: Drift result for config drift
        """
        logger.info(
            f"Remediating config drift for {drift.resource_type} {drift.resource_name}"
        )

        # TODO: Implement actual config update via Keycloak Admin API

        REMEDIATION_TOTAL.labels(
            resource_type=drift.resource_type,
            action="updated",
            reason="drift",
        ).inc()
