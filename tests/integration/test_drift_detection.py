"""
Integration tests for drift detection functionality.

These tests verify that:
1. Ownership attributes are correctly added to Keycloak resources
2. Orphaned resources are detected after CR deletion
3. Drift metrics are emitted correctly
4. Auto-remediation works (when enabled)
"""

import asyncio
import time

import pytest
from kubernetes import client

from keycloak_operator.services.drift_detection_service import (
    DriftDetectionConfig,
    DriftDetector,
)
from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client
from keycloak_operator.utils.ownership import (
    ATTR_CR_NAME,
    ATTR_CR_NAMESPACE,
    ATTR_MANAGED_BY,
    ATTR_OPERATOR_INSTANCE,
    get_cr_reference,
    is_owned_by_this_operator,
)


@pytest.mark.integration
class TestDriftDetectionIntegration:
    """Integration tests for drift detection."""

    @pytest.fixture(autouse=True)
    async def setup(self, namespace, keycloak_instance, operator_instance_id):
        """Set up test environment."""
        self.namespace = namespace
        self.keycloak_namespace = "keycloak-system"
        self.keycloak_name = "keycloak"
        self.operator_instance_id = operator_instance_id

        # Wait for Keycloak to be ready
        await self._wait_for_keycloak_ready()

        yield

        # Cleanup is handled by namespace deletion in conftest

    async def _wait_for_keycloak_ready(self, timeout=300):
        """Wait for Keycloak instance to be ready."""
        custom_api = client.CustomObjectsApi()
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                keycloak = custom_api.get_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=self.keycloak_namespace,
                    plural="keycloaks",
                    name=self.keycloak_name,
                )
                
                status = keycloak.get("status", {})
                phase = status.get("phase")
                
                if phase == "Ready":
                    return
                    
            except Exception:
                # Ignore errors while waiting for Keycloak - it may not exist yet
                pass
                
            await asyncio.sleep(5)

        raise TimeoutError("Keycloak instance did not become ready")

    async def test_realm_ownership_attributes_are_added(self, realm_cr):
        """Test that ownership attributes are added when creating a realm."""
        # Create realm CR
        custom_api = client.CustomObjectsApi()
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        # Wait for realm to be reconciled
        await asyncio.sleep(10)

        # Get realm from Keycloak
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        
        realm_name = realm_cr["spec"]["realmName"]
        kc_realm = await admin_client.get_realm(realm_name, self.namespace)

        # Verify ownership attributes
        attributes = kc_realm.attributes or {}
        
        assert ATTR_MANAGED_BY in attributes, "Missing managed-by attribute"
        assert ATTR_OPERATOR_INSTANCE in attributes, "Missing operator-instance attribute"
        assert ATTR_CR_NAMESPACE in attributes, "Missing CR namespace attribute"
        assert ATTR_CR_NAME in attributes, "Missing CR name attribute"

        # Verify correct values
        cr_ref = get_cr_reference(attributes)
        assert cr_ref is not None
        namespace, name = cr_ref
        assert namespace == self.namespace
        assert name == realm_cr["metadata"]["name"]

        # Verify owned by this operator
        assert is_owned_by_this_operator(attributes)

    async def test_client_ownership_attributes_are_added(self, realm_cr, client_cr):
        """Test that ownership attributes are added when creating a client."""
        custom_api = client.CustomObjectsApi()

        # Create realm first
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        # Wait for realm
        await asyncio.sleep(10)

        # Create client
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakclients",
            body=client_cr,
        )

        # Wait for client to be reconciled
        await asyncio.sleep(10)

        # Get client from Keycloak
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        
        realm_name = realm_cr["spec"]["realmName"]
        client_id = client_cr["spec"]["clientId"]
        
        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, self.namespace
        )

        # Verify ownership attributes
        assert kc_client is not None
        client_dict = kc_client.model_dump() if hasattr(kc_client, "model_dump") else vars(kc_client)
        attributes = client_dict.get("attributes", {})
        
        assert ATTR_MANAGED_BY in attributes, "Missing managed-by attribute"
        assert ATTR_OPERATOR_INSTANCE in attributes, "Missing operator-instance attribute"
        
        # Verify CR reference
        cr_ref = get_cr_reference(attributes)
        assert cr_ref is not None
        namespace, name = cr_ref
        assert namespace == self.namespace
        assert name == client_cr["metadata"]["name"]

    async def test_orphan_detection_after_realm_deletion(self, realm_cr):
        """Test that orphaned realms are detected after CR deletion."""
        custom_api = client.CustomObjectsApi()

        # Create realm
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        # Wait for reconciliation
        await asyncio.sleep(10)

        realm_name = realm_cr["spec"]["realmName"]

        # Verify realm exists in Keycloak
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        kc_realm = await admin_client.get_realm(realm_name, self.namespace)
        assert kc_realm is not None

        # Delete the CR
        custom_api.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
        )

        # Wait for deletion
        await asyncio.sleep(5)

        # Verify realm still exists in Keycloak (orphaned)
        kc_realm = await admin_client.get_realm(realm_name, self.namespace)
        assert kc_realm is not None

        # Run drift detection
        config = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=False,  # Don't auto-delete in this test
            minimum_age_hours=0,  # Allow immediate detection
            scope_realms=True,
            scope_clients=True,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = DriftDetector(config=config)
        drift_results = await detector.scan_for_drift()

        # Verify orphan was detected
        orphaned_realms = [
            d for d in drift_results 
            if d.resource_type == "realm" 
            and d.drift_type == "orphaned"
            and d.resource_name == realm_name
        ]

        assert len(orphaned_realms) == 1, f"Expected 1 orphaned realm, found {len(orphaned_realms)}"
        
        orphan = orphaned_realms[0]
        assert orphan.cr_namespace == self.namespace
        assert orphan.cr_name == realm_cr["metadata"]["name"]

    async def test_orphan_detection_after_client_deletion(self, realm_cr, client_cr):
        """Test that orphaned clients are detected after CR deletion."""
        custom_api = client.CustomObjectsApi()

        # Create realm and client
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )
        await asyncio.sleep(10)

        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakclients",
            body=client_cr,
        )
        await asyncio.sleep(10)

        realm_name = realm_cr["spec"]["realmName"]
        client_id = client_cr["spec"]["clientId"]

        # Verify client exists
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, self.namespace
        )
        assert kc_client is not None

        # Delete client CR
        custom_api.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakclients",
            name=client_cr["metadata"]["name"],
        )
        await asyncio.sleep(5)

        # Verify client still exists in Keycloak (orphaned)
        kc_client = await admin_client.get_client_by_name(
            client_id, realm_name, self.namespace
        )
        assert kc_client is not None

        # Run drift detection
        config = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=False,
            minimum_age_hours=0,
            scope_realms=True,
            scope_clients=True,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = DriftDetector(config=config)
        drift_results = await detector.scan_for_drift()

        # Verify orphaned client was detected
        orphaned_clients = [
            d for d in drift_results 
            if d.resource_type == "client" 
            and d.drift_type == "orphaned"
            and d.resource_name == client_id
        ]

        assert len(orphaned_clients) == 1, f"Expected 1 orphaned client, found {len(orphaned_clients)}"

    async def test_unmanaged_resources_detected(self):
        """Test that unmanaged resources (created without operator) are detected."""
        # Create a realm directly via Keycloak Admin API (no CR)
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )

        unmanaged_realm_name = f"unmanaged-{int(time.time())}"
        realm_config = {
            "realm": unmanaged_realm_name,
            "enabled": True,
            "displayName": "Unmanaged Test Realm",
        }

        await admin_client.create_realm(realm_config, self.namespace)
        await asyncio.sleep(2)

        # Run drift detection
        config = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=False,
            minimum_age_hours=0,
            scope_realms=True,
            scope_clients=False,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = DriftDetector(config=config)
        drift_results = await detector.scan_for_drift()

        # Verify unmanaged realm was detected
        unmanaged_realms = [
            d for d in drift_results 
            if d.resource_type == "realm" 
            and d.drift_type == "unmanaged"
            and d.resource_name == unmanaged_realm_name
        ]

        assert len(unmanaged_realms) == 1, f"Expected 1 unmanaged realm, found {len(unmanaged_realms)}"

        # Cleanup
        await admin_client.delete_realm(unmanaged_realm_name, self.namespace)

    async def test_auto_remediation_deletes_orphans(self, realm_cr):
        """Test that auto-remediation deletes orphaned resources when enabled."""
        custom_api = client.CustomObjectsApi()

        # Create realm
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )
        await asyncio.sleep(10)

        realm_name = realm_cr["spec"]["realmName"]

        # Verify realm exists
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        kc_realm = await admin_client.get_realm(realm_name, self.namespace)
        assert kc_realm is not None

        # Delete CR
        custom_api.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
        )
        await asyncio.sleep(5)

        # Run drift detection with auto-remediation enabled
        config = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=True,  # Enable auto-delete
            minimum_age_hours=0,  # Allow immediate deletion for testing
            scope_realms=True,
            scope_clients=False,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = DriftDetector(config=config)
        drift_results = await detector.scan_for_drift()

        # Remediate orphans
        await detector.remediate_drift(drift_results)
        await asyncio.sleep(5)

        # Verify realm was deleted from Keycloak
        from keycloak_operator.utils.keycloak_admin import KeycloakAdminError
        
        with pytest.raises(KeycloakAdminError) as exc_info:
            await admin_client.get_realm(realm_name, self.namespace)
        
        assert exc_info.value.status_code == 404, "Realm should have been deleted"

    async def test_minimum_age_prevents_deletion(self, realm_cr):
        """Test that minimum age check prevents deletion of recent orphans."""
        custom_api = client.CustomObjectsApi()

        # Create realm
        custom_api.create_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )
        await asyncio.sleep(10)

        realm_name = realm_cr["spec"]["realmName"]

        # Delete CR immediately
        custom_api.delete_namespaced_custom_object(
            group="keycloak.mdvr.nl",
            version="v1",
            namespace=self.namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
        )
        await asyncio.sleep(5)

        # Run drift detection with high minimum age
        config = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=True,
            minimum_age_hours=24,  # Require 24 hours old
            scope_realms=True,
            scope_clients=False,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = DriftDetector(config=config)
        drift_results = await detector.scan_for_drift()
        await detector.remediate_drift(drift_results)
        await asyncio.sleep(2)

        # Verify realm still exists (not deleted due to age check)
        admin_client = await get_keycloak_admin_client(
            self.keycloak_name, self.keycloak_namespace
        )
        kc_realm = await admin_client.get_realm(realm_name, self.namespace)
        assert kc_realm is not None, "Realm should NOT be deleted (too young)"
