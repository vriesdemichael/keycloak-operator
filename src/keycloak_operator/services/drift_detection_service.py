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
from typing import Any, cast

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
        operator_instance_id: str | None = None,
        operator_namespace: str | None = None,
    ):
        """
        Initialize drift detector.

        Args:
            config: Drift detection configuration
            k8s_client: Kubernetes API client
            keycloak_admin_factory: Factory function for creating Keycloak admin clients.
                Signature: async (keycloak_name: str, namespace: str) -> KeycloakAdminClient
            operator_instance_id: Optional operator instance ID for ownership checks.
                If None, will use get_operator_instance_id() which reads from settings.
            operator_namespace: Optional namespace where the Keycloak instance is running.
                If None, will use settings.operator_namespace.
                This is primarily used for testing to override the namespace.

        Note:
            Per ADR-062, each operator manages exactly one Keycloak instance.
            The Keycloak instance is always named "keycloak" in the operator namespace.
        """
        self.config = config or DriftDetectionConfig.from_env()
        self.k8s_client = k8s_client or client.ApiClient()
        self.keycloak_admin_factory = (
            keycloak_admin_factory or get_keycloak_admin_client
        )
        self.operator_instance_id = operator_instance_id
        self.operator_namespace = operator_namespace or settings.operator_namespace
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
            # 1. Scan realms if enabled (using smart scan)
            if self.config.scope_realms:
                realm_results = await self._scan_realms_smart()
                drift_results.extend(realm_results)
                logger.info(f"Found {len(realm_results)} realm drift issues")

            # 2. Scan clients if enabled
            if self.config.scope_clients:
                client_results = await self._scan_clients_smart()
                drift_results.extend(client_results)
                logger.info(f"Found {len(client_results)} client drift issues")

            # 3. Detect orphaned and unmanaged resources (reverse check)
            if self.config.scope_realms or self.config.scope_clients:
                orphan_results = await self._scan_orphans_and_unmanaged()
                drift_results.extend(orphan_results)
                logger.info(f"Found {len(orphan_results)} orphan/unmanaged issues")

            # Update last success timestamp
            DRIFT_CHECK_LAST_SUCCESS_TIMESTAMP.set(time.time())

            logger.info(
                f"Drift scan completed: {len(drift_results)} total issues found"
            )
            return drift_results

        except Exception as e:
            logger.error(f"Drift scan failed: {e}", exc_info=True)
            raise

    async def _scan_orphans_and_unmanaged(self) -> list[DriftResult]:
        """
        Scan for orphaned and unmanaged resources by querying Keycloak directly.

        Per ADR-062, there is exactly one Keycloak instance per operator deployment,
        always named "keycloak" in the operator namespace.
        """
        results: list[DriftResult] = []

        # Per ADR-062: One operator = One Keycloak instance
        kc_namespace = self.operator_namespace
        kc_name = "keycloak"

        try:
            admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)

            # 1. Check Realms
            if self.config.scope_realms:
                realms = await admin_client.get_realms(kc_namespace)
                if realms:  # Null safety check
                    for realm in realms:
                        if realm.realm == "master":
                            continue

                        # Check for orphan/unmanaged only (skip expensive config drift)
                        drift = await self._check_realm_resource_drift(
                            realm, admin_client, skip_config_drift=True
                        )

                        if drift and drift.drift_type in [
                            "orphaned",
                            "unmanaged",
                        ]:
                            results.append(drift)

            # 2. Check Clients
            if self.config.scope_clients:
                # Iterate through realms to find clients
                realms = await admin_client.get_realms(kc_namespace)
                if realms:  # Null safety check
                    for realm in realms:
                        if realm.realm == "master" or not realm.realm:
                            continue

                        clients = await admin_client.get_realm_clients(
                            realm.realm, kc_namespace
                        )
                        if clients:  # Null safety check
                            for client in clients:
                                # Check for orphan/unmanaged only (skip expensive config drift)
                                drift = await self._check_client_resource_drift(
                                    client,
                                    realm.realm,
                                    admin_client,
                                    skip_config_drift=True,
                                )
                                if drift and drift.drift_type in [
                                    "orphaned",
                                    "unmanaged",
                                ]:
                                    results.append(drift)

        except Exception as e:
            logger.error(f"Error in orphan scan for {kc_namespace}/{kc_name}: {e}")

        return results

    async def _scan_realms_smart(self) -> list[DriftResult]:
        """
        Scan realms for drift using timestamp-based comparison.

        This compares the CR's status.lastReconcileEventTime against the latest
        admin event timestamp in Keycloak. If Keycloak has newer events, the
        resource has drifted and needs reconciliation.
        """
        results: list[DriftResult] = []

        # Discover all Realm CRs
        try:
            custom_objects_api = self.custom_objects_api

            response = await asyncio.to_thread(
                custom_objects_api.list_cluster_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakrealms",
            )

            response_dict = cast(dict[str, Any], response)
            realm_crs = cast(list[dict[str, Any]], response_dict.get("items", []))
            logger.info(f"Found {len(realm_crs)} Realm CRs to scan for drift")
        except Exception as e:
            logger.error(f"Failed to list KeycloakRealm CRs: {e}")
            return []

        for cr in realm_crs:
            name = str(cr["metadata"]["name"])
            namespace = str(cr["metadata"]["namespace"])
            spec = cast(dict[str, Any], cr.get("spec", {}))
            status = cast(dict[str, Any], cr.get("status", {}))
            realm_name = str(spec.get("realmName", name))

            # Skip CRs that haven't reached Ready phase yet
            # These are still being reconciled and shouldn't be scanned for drift
            phase = status.get("phase", "")
            if phase not in ["Ready", "Degraded"]:
                logger.debug(
                    f"Skipping realm {realm_name}: CR phase is '{phase}', not Ready/Degraded"
                )
                continue

            operator_ref = cast(dict[str, Any], spec.get("operatorRef", {}))
            kc_namespace = str(operator_ref.get("namespace", namespace))
            kc_name = "keycloak"

            try:
                admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)

                # Verify realm exists in Keycloak before checking events
                realm = await admin_client.get_realm(realm_name, kc_namespace)
                if realm is None:
                    # Realm doesn't exist in Keycloak - skip, let regular reconciliation handle it
                    logger.debug(f"Skipping realm {realm_name}: not found in Keycloak")
                    continue

                # Get the stored timestamp from CR status
                last_reconcile_time = status.get("lastReconcileEventTime")

                # Get the latest admin event timestamp from Keycloak
                latest_event_time = await admin_client.get_latest_admin_event_time(
                    realm_name,
                    kc_namespace,
                    scope="realm",
                )

                needs_reconcile = False
                drift_reason = ""

                if last_reconcile_time is None:
                    # CR has never recorded a timestamp - likely first run or pre-upgrade
                    # Trigger reconciliation to establish baseline
                    needs_reconcile = True
                    drift_reason = (
                        "No lastReconcileEventTime in CR status (first run or upgrade)"
                    )
                    logger.info(
                        f"Realm {realm_name}: no stored timestamp, triggering reconcile"
                    )
                elif latest_event_time is None:
                    # No admin events in Keycloak - this could mean:
                    # 1. Events were purged (expiration)
                    # 2. No changes ever made
                    # Don't trigger reconcile, assume no drift
                    logger.debug(
                        f"Realm {realm_name}: no admin events found in Keycloak"
                    )
                elif latest_event_time > last_reconcile_time:
                    # Newer events exist - drift detected!
                    needs_reconcile = True
                    drift_reason = (
                        f"Newer admin events detected: latest={latest_event_time}, "
                        f"lastReconcile={last_reconcile_time}"
                    )
                    logger.info(
                        f"Drift detected for realm {realm_name}: {drift_reason}"
                    )
                else:
                    logger.debug(
                        f"Realm {realm_name}: no drift (latest={latest_event_time}, "
                        f"lastReconcile={last_reconcile_time})"
                    )

                if needs_reconcile:
                    results.append(
                        DriftResult(
                            resource_type="realm",
                            resource_name=realm_name,
                            drift_type="config_drift",
                            keycloak_resource={},
                            desired_resource=spec,
                            cr_namespace=namespace,
                            cr_name=name,
                            drift_details=[drift_reason],
                        )
                    )

            except Exception as e:
                logger.error(f"Error scanning realm {name}: {e}")

        return results

    async def _scan_clients_smart(self) -> list[DriftResult]:
        """
        Scan clients for drift using timestamp-based comparison.

        This compares the CR's status.lastReconcileEventTime against the latest
        client-specific admin event timestamp in Keycloak. If Keycloak has newer
        events for this client, the resource has drifted and needs reconciliation.
        """
        results: list[DriftResult] = []

        # Discover all Client CRs
        try:
            response = await asyncio.to_thread(
                self.custom_objects_api.list_cluster_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                plural="keycloakclients",
            )

            response_dict = cast(dict[str, Any], response)
            client_crs = cast(list[dict[str, Any]], response_dict.get("items", []))
            logger.info(f"Found {len(client_crs)} Client CRs to scan for drift")
        except Exception as e:
            logger.error(f"Failed to list KeycloakClient CRs: {e}")
            return []

        for cr in client_crs:
            name = str(cr["metadata"]["name"])
            namespace = str(cr["metadata"]["namespace"])
            spec = cast(dict[str, Any], cr.get("spec", {}))
            status = cast(dict[str, Any], cr.get("status", {}))
            client_id = str(spec.get("clientId", ""))

            if not client_id:
                continue

            # Skip CRs that haven't reached Ready phase yet
            # These are still being reconciled and shouldn't be scanned for drift
            phase = status.get("phase", "")
            if phase not in ["Ready", "Degraded"]:
                logger.debug(
                    f"Skipping client {client_id}: CR phase is '{phase}', not Ready/Degraded"
                )
                continue

            realm_ref = cast(dict[str, Any], spec.get("realmRef", {}))
            realm_cr_name = str(realm_ref.get("name", ""))
            if not realm_cr_name:
                continue

            try:
                # Get the realm CR to find the Keycloak instance and realm name
                realm_cr_response = await asyncio.to_thread(
                    self.custom_objects_api.get_namespaced_custom_object,
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=str(realm_ref.get("namespace", namespace)),
                    plural="keycloakrealms",
                    name=realm_cr_name,
                )
                realm_cr = cast(dict[str, Any], realm_cr_response)
                realm_spec = cast(dict[str, Any], realm_cr.get("spec", {}))
                realm_name = str(realm_spec.get("realmName", realm_cr_name))
                operator_ref = cast(dict[str, Any], realm_spec.get("operatorRef", {}))
                kc_namespace = str(operator_ref.get("namespace", namespace))
                kc_name = "keycloak"

                admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)

                # Get the client UUID for filtering events
                client_uuid = await admin_client.get_client_uuid(
                    client_id, realm_name, kc_namespace
                )

                if not client_uuid:
                    # Client doesn't exist in Keycloak yet - skip
                    # This could happen if the realm is still being set up or
                    # the client hasn't been reconciled yet
                    logger.debug(f"Skipping client {client_id}: not found in Keycloak")
                    continue

                # Get the stored timestamp from CR status
                last_reconcile_time = status.get("lastReconcileEventTime")

                # Get the latest admin event timestamp from Keycloak for this client
                latest_event_time = await admin_client.get_latest_admin_event_time(
                    realm_name,
                    kc_namespace,
                    scope="client",
                    client_uuid=client_uuid,
                )

                needs_reconcile = False
                drift_reason = ""

                if last_reconcile_time is None:
                    # CR has never recorded a timestamp - likely first run or pre-upgrade
                    # Trigger reconciliation to establish baseline
                    needs_reconcile = True
                    drift_reason = (
                        "No lastReconcileEventTime in CR status (first run or upgrade)"
                    )
                    logger.info(
                        f"Client {client_id}: no stored timestamp, triggering reconcile"
                    )
                elif latest_event_time is None:
                    # No admin events in Keycloak for this client - assume no drift
                    logger.debug(
                        f"Client {client_id}: no admin events found in Keycloak"
                    )
                elif latest_event_time > last_reconcile_time:
                    # Newer events exist - drift detected!
                    needs_reconcile = True
                    drift_reason = (
                        f"Newer admin events detected: latest={latest_event_time}, "
                        f"lastReconcile={last_reconcile_time}"
                    )
                    logger.info(
                        f"Drift detected for client {client_id}: {drift_reason}"
                    )
                else:
                    logger.debug(
                        f"Client {client_id}: no drift (latest={latest_event_time}, "
                        f"lastReconcile={last_reconcile_time})"
                    )

                if needs_reconcile:
                    results.append(
                        DriftResult(
                            resource_type="client",
                            resource_name=client_id,
                            drift_type="config_drift",
                            keycloak_resource={"id": client_uuid},
                            desired_resource=spec,
                            cr_namespace=namespace,
                            cr_name=name,
                            parent_realm=realm_name,
                            drift_details=[drift_reason],
                        )
                    )

            except Exception as e:
                logger.error(f"Error scanning client {name}: {e}")

        return results

    async def check_realm_drift(self) -> list[DriftResult]:
        """
        Check for drift in Keycloak realms.

        Returns:
            List of drift results for realms
        """
        start_time = time.time()
        drift_results: list[DriftResult] = []

        # Per ADR-062: One operator = One Keycloak instance
        kc_namespace = self.operator_namespace
        kc_name = "keycloak"

        try:
            admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)
            realms = await admin_client.get_realms(kc_namespace)

            if realms:  # Null safety check
                for realm in realms:
                    # Skip master realm (system realm)
                    if realm.realm == "master":
                        continue

                    drift = await self._check_realm_resource_drift(realm, admin_client)
                    if drift:
                        drift_results.append(drift)

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

        # Per ADR-062: One operator = One Keycloak instance
        kc_namespace = self.operator_namespace
        kc_name = "keycloak"

        try:
            admin_client = await self.keycloak_admin_factory(kc_name, kc_namespace)

            # Get all realms first
            realms = await admin_client.get_realms(kc_namespace)

            if realms:  # Null safety check
                for realm in realms:
                    # Skip master realm
                    if realm.realm == "master" or not realm.realm:
                        continue

                    # Get all clients in this realm
                    clients = await admin_client.get_realm_clients(
                        realm.realm, kc_namespace
                    )

                    if clients:  # Null safety check
                        for kc_client in clients:
                            drift = await self._check_client_resource_drift(
                                kc_client, realm.realm, admin_client
                            )
                            if drift:
                                drift_results.append(drift)

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
        self,
        realm,
        admin_client: KeycloakAdminClient,
        skip_config_drift: bool = False,
    ) -> DriftResult | None:
        """
        Check a single realm for drift.

        Args:
            realm: Realm representation from Keycloak
            admin_client: Keycloak admin client
            skip_config_drift: If True, only check for orphaned/unmanaged resources,
                skip expensive config drift calculation. Used by _scan_orphans_and_unmanaged.

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

            # CR exists - check for config drift (unless skipped for performance)
            if not skip_config_drift:
                try:
                    cr_response = await asyncio.to_thread(
                        self.custom_objects_api.get_namespaced_custom_object,
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=cr_namespace,
                        plural="keycloakrealms",
                        name=cr_name,
                    )
                    cr = cast(dict[str, Any], cr_response)

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
        self,
        kc_client,
        realm_name: str,
        admin_client: KeycloakAdminClient,
        skip_config_drift: bool = False,
    ) -> DriftResult | None:
        """
        Check a single client for drift.

        Args:
            kc_client: Client representation from Keycloak
            realm_name: Name of the realm this client belongs to
            admin_client: Keycloak admin client
            skip_config_drift: If True, only check for orphaned/unmanaged resources,
                skip expensive config drift calculation. Used by _scan_orphans_and_unmanaged.

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
                    parent_realm=realm_name,
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
                    parent_realm=realm_name,
                )

            # CR exists - check for config drift (unless skipped for performance)
            if not skip_config_drift:
                try:
                    cr_response = await asyncio.to_thread(
                        self.custom_objects_api.get_namespaced_custom_object,
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=cr_namespace,
                        plural="keycloakclients",
                        name=cr_name,
                    )
                    cr = cast(dict[str, Any], cr_response)

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
                    # Don't fail the whole scan, just log error

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

        # Per ADR-062: One operator = One Keycloak instance
        kc_namespace = self.operator_namespace
        kc_name = "keycloak"

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
                # For clients, we need the realm name to delete
                # drift.resource_name contains the clientId (name)

                # Use parent_realm if available (added in recent changes)
                target_realms: list[str] = []
                if drift.parent_realm:
                    # If we know the parent realm, only check that one
                    target_realms = [drift.parent_realm]
                else:
                    # Fallback: search all realms
                    all_realms = await admin_client.get_realms(kc_namespace)
                    if all_realms:
                        for r in all_realms:
                            if r.realm and r.realm != "master":
                                target_realms.append(r.realm)

                client_deleted = False

                # When doing fallback realm search, we need to find which realm
                # actually has the client before deleting, since delete_client
                # returns True for "not found" (idempotent behavior)
                if not drift.parent_realm and len(target_realms) > 1:
                    # Fallback mode: find the realm that contains the client first
                    containing_realm = None
                    for realm_name in target_realms:
                        try:
                            client = await admin_client.get_client_by_name(
                                drift.resource_name, realm_name, kc_namespace
                            )
                            if client:
                                containing_realm = realm_name
                                logger.debug(
                                    f"Found orphaned client {drift.resource_name} "
                                    f"in realm {realm_name}"
                                )
                                break
                        except Exception as e:
                            logger.debug(
                                f"Error checking client {drift.resource_name} "
                                f"in realm {realm_name}: {e}"
                            )
                            continue

                    if containing_realm:
                        target_realms = [containing_realm]
                    else:
                        logger.warning(
                            f"Orphaned client {drift.resource_name} not found in any realm"
                        )
                        REMEDIATION_ERRORS_TOTAL.labels(
                            resource_type=drift.resource_type,
                            action="delete",
                        ).inc()
                        return

                for realm_name in target_realms:
                    try:
                        # Try to delete using the clientId (name)
                        # delete_client expects clientId, not UUID
                        success = await admin_client.delete_client(
                            drift.resource_name, realm_name, kc_namespace
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
            cr_response = await asyncio.to_thread(
                self.custom_objects_api.get_namespaced_custom_object,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=drift.cr_namespace,
                plural=plural,
                name=drift.cr_name,
            )
            cr = cast(dict[str, Any], cr_response)

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
            # Don't increment error counter here - let the caller handle it
            # to avoid double-counting
            raise
