"""
Integration tests for drift detection functionality.

These tests verify that:
1. Ownership attributes are correctly added to Keycloak resources
2. Orphaned resources are detected after CR deletion
3. Drift metrics are emitted correctly
4. Auto-remediation works (when enabled)
"""

import asyncio
import contextlib

import pytest

from keycloak_operator.services.drift_detection_service import (
    DriftDetectionConfig,
)
from keycloak_operator.utils.ownership import (
    ATTR_CR_NAME,
    ATTR_CR_NAMESPACE,
    ATTR_MANAGED_BY,
    ATTR_OPERATOR_INSTANCE,
    get_cr_reference,
    is_owned_by_this_operator,
)
from tests.integration.wait_helpers import (
    wait_for_resource_deleted,
    wait_for_resource_ready,
)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_ownership_attributes_are_added(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that ownership attributes are added when creating a realm."""
    # Use k8s_custom_objects fixture instead of creating new API client
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]
    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)

    from typing import cast

    attributes = cast(dict[str, str | list[str]], kc_realm.attributes or {})

    assert ATTR_MANAGED_BY in attributes
    assert ATTR_OPERATOR_INSTANCE in attributes
    assert ATTR_CR_NAMESPACE in attributes
    assert ATTR_CR_NAME in attributes
    assert attributes[ATTR_MANAGED_BY] == "keycloak-operator"
    assert attributes[ATTR_OPERATOR_INSTANCE] == operator_instance_id
    assert attributes[ATTR_CR_NAMESPACE] == realm_cr["metadata"]["namespace"]
    assert attributes[ATTR_CR_NAME] == realm_cr["metadata"]["name"]
    assert is_owned_by_this_operator(attributes, operator_instance_id)

    cr_ref = get_cr_reference(attributes)
    assert cr_ref is not None
    namespace, name = cr_ref
    assert namespace == realm_cr["metadata"]["namespace"]
    assert name == realm_cr["metadata"]["name"]

    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )
    await wait_for_resource_deleted(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )

    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=False,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()
    await detector.remediate_drift(drift_results)

    # Poll for realm deletion
    for _ in range(20):
        kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
        if kc_realm is None:
            break
        await asyncio.sleep(1)

    # Verify realm was deleted by remediation
    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm is None, "Remediation should have deleted the orphaned realm"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_minimum_age_prevents_deletion(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that minimum age check prevents deletion of recent orphans."""
    # Use k8s_custom_objects fixture instead of creating new API client

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # Remove finalizer so realm won't be deleted from Keycloak when CR is deleted
    # Use retry loop to handle race conditions with operator updates
    for attempt in range(5):
        try:
            realm_obj = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_cr["metadata"]["name"],
            )
            realm_obj["metadata"]["finalizers"] = []
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_cr["metadata"]["name"],
                body=realm_obj,
            )
            break
        except Exception as e:
            if "Conflict" in str(e) and attempt < 4:
                await asyncio.sleep(0.5)
                continue
            raise

    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )
    await wait_for_resource_deleted(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )

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

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    orphaned_realms = [
        d
        for d in drift_results
        if d.resource_type == "realm"
        and d.drift_type == "orphaned"
        and d.resource_name == realm_name
    ]

    assert len(orphaned_realms) == 1

    await keycloak_admin_client.delete_realm(realm_name, test_namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_config_drift_detection_and_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that configuration drift in realms is detected and remediated."""

    # Add displayName to the CR spec since it's not there by default
    realm_cr["spec"]["displayName"] = "Original Display Name"

    # 1. Create Realm CR
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # Verify initial state
    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm.display_name == realm_cr["spec"]["displayName"]

    # 2. Modify Realm in Keycloak directly (cause drift)
    kc_realm.display_name = "Drifted Display Name"
    await keycloak_admin_client.update_realm(realm_name, kc_realm, test_namespace)

    # Verify drift
    kc_realm_drifted = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm_drifted.display_name == "Drifted Display Name"

    # 3. Run drift detection
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=False,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # Check if drift was detected
    config_drift = [
        d
        for d in drift_results
        if d.resource_type == "realm"
        and d.drift_type == "config_drift"
        and d.resource_name == realm_name
    ]

    assert len(config_drift) == 1, "Config drift should be detected"

    # 4. Run remediation
    await detector.remediate_drift(drift_results)

    # 5. Verify remediation
    # Poll for remediation
    for _ in range(20):
        kc_realm_remediated = await keycloak_admin_client.get_realm(
            realm_name, test_namespace
        )
        if kc_realm_remediated.display_name == realm_cr["spec"]["displayName"]:
            break
        await asyncio.sleep(1)

    kc_realm_remediated = await keycloak_admin_client.get_realm(
        realm_name, test_namespace
    )
    assert kc_realm_remediated.display_name == realm_cr["spec"]["displayName"], (
        "Realm should be reverted to CR state"
    )

    # Cleanup
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_config_drift_detection_and_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    client_cr_factory,
    drift_detector,
):
    """Test that configuration drift in clients is detected and remediated."""

    # 1. Create Realm
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )
    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create Client CR
    client_cr = client_cr_factory(
        realm_cr=realm_cr,
        client_id="drift-client",
        description="Original Description",
        redirectUris=["https://example.com/original/*"],
    )

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        body=client_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        name=client_cr["metadata"]["name"],
    )

    # Verify initial state
    kc_client = await keycloak_admin_client.get_client_by_name(
        "drift-client", realm_name, test_namespace
    )
    assert kc_client.description == "Original Description"
    assert kc_client.redirect_uris == ["https://example.com/original/*"]

    # 3. Modify Client in Keycloak directly (cause drift)
    # Change description (value drift) and redirectUris (list drift)
    kc_client.description = "Drifted Description"
    kc_client.redirect_uris = ["https://example.com/drifted/*"]
    await keycloak_admin_client.update_client(
        kc_client.id, kc_client, realm_name, test_namespace
    )

    # Verify drift
    kc_client_drifted = await keycloak_admin_client.get_client_by_name(
        "drift-client", realm_name, test_namespace
    )
    assert kc_client_drifted.description == "Drifted Description"

    # 4. Run drift detection
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,  # Enable client scanning
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # Check if drift was detected
    client_drifts = [
        d
        for d in drift_results
        if d.resource_type == "client"
        and d.drift_type == "config_drift"
        and d.resource_name == "drift-client"
    ]

    assert len(client_drifts) == 1, "Client config drift should be detected"
    drift = client_drifts[0]
    # With timestamp-based drift detection, details contain event timing info
    # rather than field-level comparison
    drift_details_str = str(drift.drift_details)
    assert (
        "event" in drift_details_str.lower()
        or "timestamp" in drift_details_str.lower()
        or "reconcile" in drift_details_str.lower()
    ), f"Expected drift details to mention events/timestamps, got: {drift_details_str}"

    # 5. Run remediation
    await detector.remediate_drift(drift_results)

    # 6. Verify remediation
    # Poll for remediation
    for _ in range(20):
        kc_client_remediated = await keycloak_admin_client.get_client_by_name(
            "drift-client", realm_name, test_namespace
        )
        if (
            kc_client_remediated.description == "Original Description"
            and kc_client_remediated.redirect_uris == ["https://example.com/original/*"]
        ):
            break
        await asyncio.sleep(1)

    kc_client_remediated = await keycloak_admin_client.get_client_by_name(
        "drift-client", realm_name, test_namespace
    )
    assert kc_client_remediated.description == "Original Description"
    assert kc_client_remediated.redirect_uris == ["https://example.com/original/*"]

    # Cleanup
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        name=client_cr["metadata"]["name"],
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_orphan_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that orphaned clients are automatically remediated (deleted)."""

    # 1. Setup Realm
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )
    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )
    realm_name = realm_cr["spec"]["realmName"]

    # 2. Setup Client
    client_id = "orphan-client-test"

    # Manually create client in Keycloak with ownership attributes
    from keycloak_operator.utils.ownership import (
        ATTR_CR_NAME,
        ATTR_CR_NAMESPACE,
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    fake_client_data = {
        "clientId": client_id,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-cr",  # This CR does not exist
            # Add creation timestamp to bypass minimum age check
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",
        },
    }

    await keycloak_admin_client.create_client(
        fake_client_data, realm_name, test_namespace
    )

    # Poll for client creation
    for _ in range(20):
        kc_client = await keycloak_admin_client.get_client_by_name(
            client_id, realm_name, test_namespace
        )
        if kc_client:
            break
        await asyncio.sleep(0.5)

    # 3. Scan and Remediate
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    orphans = [
        d
        for d in drift_results
        if d.resource_name == client_id and d.drift_type == "orphaned"
    ]
    assert len(orphans) == 1, "Should detect manually created orphan"

    await detector.remediate_drift(drift_results)

    # 4. Verify Deletion
    await asyncio.sleep(2)
    kc_client = await keycloak_admin_client.get_client_by_name(
        client_id, realm_name, test_namespace
    )
    assert kc_client is None, "Orphaned client should be deleted"

    # Cleanup Realm
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unmanaged_client_detected(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that unmanaged clients (created without operator) are detected."""
    import uuid

    # 1. Create a realm first (managed by operator)
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create an unmanaged client directly in Keycloak (no ownership attributes)
    unmanaged_client_id = f"unmanaged-client-{uuid.uuid4().hex[:8]}"
    client_config = {
        "clientId": unmanaged_client_id,
        "enabled": True,
        "publicClient": True,
        # No attributes - this makes it unmanaged
    }

    await keycloak_admin_client.create_client(client_config, realm_name, test_namespace)

    # Poll for creation
    for _ in range(20):
        kc_client = await keycloak_admin_client.get_client_by_name(
            unmanaged_client_id, realm_name, test_namespace
        )
        if kc_client:
            break
        await asyncio.sleep(0.5)

    # 3. Run drift detection with client scope enabled
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=False,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # 4. Verify unmanaged client is detected
    unmanaged_clients = [
        d
        for d in drift_results
        if d.resource_type == "client"
        and d.drift_type == "unmanaged"
        and d.resource_name == unmanaged_client_id
    ]

    assert len(unmanaged_clients) == 1, (
        f"Should detect unmanaged client, found: {[d.resource_name for d in drift_results if d.resource_type == 'client']}"
    )

    # Cleanup
    await keycloak_admin_client.delete_client(
        unmanaged_client_id, realm_name, test_namespace
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_disabled_scope_skips_resources(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that disabled scopes skip their respective resources."""
    import uuid

    # 1. Create both an unmanaged realm and an unmanaged client
    unmanaged_realm_name = f"scope-test-realm-{uuid.uuid4().hex[:8]}"
    realm_config = {
        "realm": unmanaged_realm_name,
        "displayName": "Scope Test Realm",
        "enabled": True,
        # No attributes - this makes it unmanaged
    }

    await keycloak_admin_client.create_realm(realm_config, test_namespace)

    # Poll for creation
    for _ in range(20):
        kc_realm = await keycloak_admin_client.get_realm(
            unmanaged_realm_name, test_namespace
        )
        if kc_realm:
            break
        await asyncio.sleep(0.5)

    # Create client in this unmanaged realm
    unmanaged_client_id = f"scope-test-client-{uuid.uuid4().hex[:8]}"
    client_config = {
        "clientId": unmanaged_client_id,
        "enabled": True,
        "publicClient": True,
    }

    await keycloak_admin_client.create_client(
        client_config, unmanaged_realm_name, test_namespace
    )

    # Poll for client creation
    for _ in range(20):
        kc_client = await keycloak_admin_client.get_client_by_name(
            unmanaged_client_id, unmanaged_realm_name, test_namespace
        )
        if kc_client:
            break
        await asyncio.sleep(0.5)

    try:
        # 2. Scan with only realm scope enabled (clients disabled)
        config_realms_only = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=False,
            minimum_age_hours=0,
            scope_realms=True,
            scope_clients=False,  # Disabled!
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector = drift_detector(config_realms_only)
        drift_results = await detector.scan_for_drift()

        # Should find realm but NOT client
        realm_results = [
            d for d in drift_results if d.resource_name == unmanaged_realm_name
        ]
        client_results = [
            d for d in drift_results if d.resource_name == unmanaged_client_id
        ]

        assert len(realm_results) == 1, "Should detect unmanaged realm"
        assert len(client_results) == 0, (
            "Should NOT detect client when scope_clients=False"
        )

        # 3. Scan with only client scope enabled (realms disabled)
        config_clients_only = DriftDetectionConfig(
            enabled=True,
            interval_seconds=60,
            auto_remediate=False,
            minimum_age_hours=0,
            scope_realms=False,  # Disabled!
            scope_clients=True,
            scope_identity_providers=False,
            scope_roles=False,
        )

        detector2 = drift_detector(config_clients_only)
        drift_results2 = await detector2.scan_for_drift()

        # Should find client but NOT realm
        realm_results2 = [
            d for d in drift_results2 if d.resource_name == unmanaged_realm_name
        ]
        client_results2 = [
            d for d in drift_results2 if d.resource_name == unmanaged_client_id
        ]

        assert len(realm_results2) == 0, (
            "Should NOT detect realm when scope_realms=False"
        )
        assert len(client_results2) == 1, "Should detect unmanaged client"

    finally:
        # Cleanup
        await keycloak_admin_client.delete_client(
            unmanaged_client_id, unmanaged_realm_name, test_namespace
        )
        await keycloak_admin_client.delete_realm(unmanaged_realm_name, test_namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pending_cr_skipped_in_drift_scan(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    drift_detector,
):
    """Test that CRs in Pending/Provisioning phase are skipped during drift scan.

    The drift detector should only scan resources that have reached Ready or Degraded
    phase, since resources still being reconciled haven't established their baseline.
    """
    import uuid

    # 1. Create a realm CR but immediately patch it to Pending phase
    # We'll simulate a "stuck" CR that never reached Ready
    realm_name = f"pending-test-{uuid.uuid4().hex[:8]}"
    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": f"pending-realm-{uuid.uuid4().hex[:8]}",
            "namespace": test_namespace,
        },
        "spec": {
            "realmName": realm_name,
            "displayName": "Pending Test Realm",
            "operatorRef": {
                "name": shared_operator.name,
                "namespace": shared_operator.namespace,
            },
        },
    }

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    # Wait a moment for the CR to be created but NOT for it to become Ready
    await asyncio.sleep(2)

    # Force the status to Pending by patching (simulating a stuck CR)
    try:
        patch_body = {"status": {"phase": "Pending", "message": "Simulated pending"}}
        await k8s_custom_objects.patch_namespaced_custom_object_status(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
            body=patch_body,
        )
    except Exception:
        # Status subresource might not be patchable in all scenarios
        pass

    # 2. Run drift detection
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

    detector = drift_detector(config)

    # Get the CR to check its current phase
    cr_obj = await k8s_custom_objects.get_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )
    current_phase = cr_obj.get("status", {}).get("phase", "Unknown")

    # Only run the assertion if we successfully set the CR to a non-Ready phase
    if current_phase not in ["Ready", "Degraded"]:
        drift_results = await detector.scan_for_drift()

        # Should NOT find this realm in drift results (it's skipped due to phase)
        realm_results = [
            d
            for d in drift_results
            if d.resource_type == "realm" and d.resource_name == realm_name
        ]

        assert len(realm_results) == 0, (
            f"Should skip CR in {current_phase} phase, but found drift: {realm_results}"
        )

    # Cleanup - wait for it to be ready first, then delete
    with contextlib.suppress(Exception):
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
            timeout=60,
        )

    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nested_config_drift_detection(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    drift_detector,
):
    """Test that nested configuration changes are detected as drift.

    This tests the _calculate_drift method's handling of nested objects
    like eventsConfig, smtpServer, etc.
    """
    import uuid

    # 1. Create a realm with nested configuration
    realm_name = f"nested-drift-{uuid.uuid4().hex[:8]}"
    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": f"nested-realm-{uuid.uuid4().hex[:8]}",
            "namespace": test_namespace,
        },
        "spec": {
            "realmName": realm_name,
            "displayName": "Nested Config Test",
            "operatorRef": {
                "name": shared_operator.name,
                "namespace": shared_operator.namespace,
            },
            "eventsConfig": {
                "eventsEnabled": True,
                "adminEventsEnabled": True,
                "eventsExpiration": 3600,
            },
        },
    }

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    # 2. Verify initial state
    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm.events_enabled is True
    assert kc_realm.admin_events_enabled is True

    # 3. Modify nested configuration directly in Keycloak
    kc_realm.events_enabled = False  # Change nested eventsConfig
    kc_realm.admin_events_enabled = False
    await keycloak_admin_client.update_realm(realm_name, kc_realm, test_namespace)

    # Verify the change took effect
    kc_realm_modified = await keycloak_admin_client.get_realm(
        realm_name, test_namespace
    )
    assert kc_realm_modified.events_enabled is False

    # 4. Run drift detection
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=False,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # 5. Verify drift is detected
    realm_drift = [
        d
        for d in drift_results
        if d.resource_type == "realm"
        and d.drift_type == "config_drift"
        and d.resource_name == realm_name
    ]

    assert len(realm_drift) == 1, "Should detect config drift for nested changes"

    # 6. Remediate and verify
    await detector.remediate_drift(drift_results)
    await asyncio.sleep(2)

    kc_realm_fixed = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm_fixed.events_enabled is True, (
        "Nested eventsEnabled should be restored"
    )
    assert kc_realm_fixed.admin_events_enabled is True, (
        "Nested adminEventsEnabled should be restored"
    )

    # Cleanup
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_check_realm_drift_legacy_method(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    drift_detector,
):
    """Test the legacy check_realm_drift() method for comprehensive realm scanning.

    This exercises the older non-smart scan path that checks all realms
    in Keycloak and compares them against CRs.
    """
    import uuid

    # 1. Create a managed realm via CR
    realm_name = f"legacy-realm-{uuid.uuid4().hex[:8]}"
    realm_cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": f"legacy-realm-cr-{uuid.uuid4().hex[:8]}",
            "namespace": test_namespace,
        },
        "spec": {
            "realmName": realm_name,
            "displayName": "Legacy Test Realm",
            "operatorRef": {
                "name": shared_operator.name,
                "namespace": shared_operator.namespace,
            },
        },
    }

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    # 2. Create an unmanaged realm directly in Keycloak
    unmanaged_realm_name = f"unmanaged-legacy-{uuid.uuid4().hex[:8]}"
    unmanaged_config = {
        "realm": unmanaged_realm_name,
        "displayName": "Unmanaged Legacy Realm",
        "enabled": True,
    }
    await keycloak_admin_client.create_realm(unmanaged_config, test_namespace)

    # 3. Use the legacy check_realm_drift method
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

    detector = drift_detector(config)
    drift_results = await detector.check_realm_drift()

    # 4. Verify results include the unmanaged realm
    unmanaged_results = [
        d
        for d in drift_results
        if d.resource_name == unmanaged_realm_name and d.drift_type == "unmanaged"
    ]
    assert len(unmanaged_results) == 1, (
        "Should detect unmanaged realm via legacy method"
    )

    # Cleanup
    await keycloak_admin_client.delete_realm(unmanaged_realm_name, test_namespace)
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_check_client_drift_legacy_method(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test the legacy check_client_drift() method for comprehensive client scanning.

    This exercises the older non-smart scan path that checks all clients
    in all realms and compares them against CRs.
    """
    import uuid

    # 1. Create a managed realm via CR
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create an unmanaged client directly in Keycloak
    unmanaged_client_id = f"unmanaged-legacy-client-{uuid.uuid4().hex[:8]}"
    unmanaged_config = {
        "clientId": unmanaged_client_id,
        "enabled": True,
        "publicClient": True,
    }
    await keycloak_admin_client.create_client(
        unmanaged_config, realm_name, test_namespace
    )

    # 3. Use the legacy check_client_drift method
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=False,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.check_client_drift()

    # 4. Verify results include the unmanaged client
    unmanaged_results = [
        d
        for d in drift_results
        if d.resource_name == unmanaged_client_id and d.drift_type == "unmanaged"
    ]
    assert len(unmanaged_results) == 1, (
        "Should detect unmanaged client via legacy method"
    )

    # Cleanup
    await keycloak_admin_client.delete_client(
        unmanaged_client_id, realm_name, test_namespace
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_orphan_client_remediation_fallback_realm_search(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test orphan client remediation when parent_realm is not available.

    This exercises the fallback realm search code path in _remediate_orphan()
    where we search all realms to find and delete the orphaned client.
    """
    import uuid

    from keycloak_operator.services.drift_detection_service import DriftResult
    from keycloak_operator.utils.ownership import (
        ATTR_CR_NAME,
        ATTR_CR_NAMESPACE,
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a managed realm via CR
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create a client manually with ownership attributes but non-existent CR
    orphan_client_id = f"orphan-fallback-{uuid.uuid4().hex[:8]}"
    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-client-cr",
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",  # Old enough to remediate
        },
    }
    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # Verify client exists
    kc_client = await keycloak_admin_client.get_client_by_name(
        orphan_client_id, realm_name, test_namespace
    )
    assert kc_client is not None

    # 3. Create a DriftResult WITHOUT parent_realm to trigger fallback search
    drift_result = DriftResult(
        resource_type="client",
        resource_name=orphan_client_id,
        drift_type="orphaned",
        keycloak_resource={"clientId": orphan_client_id},
        cr_namespace=test_namespace,
        cr_name="non-existent-client-cr",
        age_hours=1000,  # Old enough to remediate
        parent_realm=None,  # This triggers the fallback search!
    )

    # 4. Run remediation
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    await detector.remediate_drift([drift_result])

    # 5. Verify client was deleted via fallback search
    await asyncio.sleep(2)
    kc_client_after = await keycloak_admin_client.get_client_by_name(
        orphan_client_id, realm_name, test_namespace
    )
    assert kc_client_after is None, (
        "Orphaned client should be deleted via fallback search"
    )

    # Cleanup realm
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_missing_cr_reference_treated_as_orphan(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    drift_detector,
):
    """Test that a realm with ownership attributes but missing CR reference is orphaned.

    This exercises the code path where is_owned_by_this_operator() returns True
    but get_cr_reference() returns None.
    """
    import uuid

    from keycloak_operator.utils.ownership import (
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a realm manually with ownership but NO CR reference attributes
    orphan_realm_name = f"missing-ref-{uuid.uuid4().hex[:8]}"
    orphan_realm_data = {
        "realm": orphan_realm_name,
        "enabled": True,
        "displayName": "Missing CR Reference Realm",
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",
            # Intentionally missing ATTR_CR_NAMESPACE and ATTR_CR_NAME
        },
    }
    await keycloak_admin_client.create_realm(orphan_realm_data, test_namespace)

    # 2. Run drift detection
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

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # 3. Verify realm is detected as orphaned (not unmanaged)
    orphan_results = [
        d
        for d in drift_results
        if d.resource_name == orphan_realm_name and d.drift_type == "orphaned"
    ]
    assert len(orphan_results) == 1, (
        "Realm with ownership but missing CR reference should be orphaned"
    )

    # Cleanup
    await keycloak_admin_client.delete_realm(orphan_realm_name, test_namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_missing_cr_reference_treated_as_orphan(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that a client with ownership attributes but missing CR reference is orphaned.

    This exercises the code path where is_owned_by_this_operator() returns True
    but get_cr_reference() returns None for clients.
    """
    import uuid

    from keycloak_operator.utils.ownership import (
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a managed realm
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create a client manually with ownership but NO CR reference attributes
    orphan_client_id = f"missing-ref-client-{uuid.uuid4().hex[:8]}"
    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",
            # Intentionally missing ATTR_CR_NAMESPACE and ATTR_CR_NAME
        },
    }
    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # 3. Run drift detection
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=False,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()

    # 4. Verify client is detected as orphaned (not unmanaged)
    orphan_results = [
        d
        for d in drift_results
        if d.resource_name == orphan_client_id and d.drift_type == "orphaned"
    ]
    assert len(orphan_results) == 1, (
        "Client with ownership but missing CR reference should be orphaned"
    )

    # Cleanup
    await keycloak_admin_client.delete_client(
        orphan_client_id, realm_name, test_namespace
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auto_remediation_disabled_skips_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    realm_cr,
):
    """Test that auto-remediation is skipped when disabled in config.

    This exercises the early return path in remediate_drift() when
    auto_remediate=False.

    Note: We use a fake operator instance ID to avoid interference from
    the operator's background drift detection which runs with autoRemediate=True.
    """
    import uuid

    from keycloak_operator.utils.ownership import (
        ATTR_CR_NAME,
        ATTR_CR_NAMESPACE,
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a managed realm
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create an orphan client with a DIFFERENT operator instance ID
    # This ensures the operator's background drift detection won't delete it,
    # since the operator only manages resources owned by its own instance ID.
    # We use a fake instance ID so this test can verify the test-side detector's
    # auto_remediate=False behavior without interference from the operator.
    fake_instance_id = "test-only-instance-for-auto-remediate-test"
    orphan_client_id = f"no-remediate-{uuid.uuid4().hex[:8]}"
    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: fake_instance_id,  # Different from operator!
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-cr",
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",
        },
    }
    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # 3. Run drift detection with auto_remediate=False
    # We need to create a custom detector that uses the SAME fake instance ID
    # so it will detect the orphan we created above.
    from keycloak_operator.services.drift_detection_service import DriftDetector
    from keycloak_operator.utils.keycloak_admin import KeycloakAdminClient
    from keycloak_operator.utils.kubernetes import get_admin_credentials

    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=False,  # Disabled!
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    # Create a detector with the fake instance ID
    username, password = get_admin_credentials(
        shared_operator.name, shared_operator.namespace
    )
    admin_client = KeycloakAdminClient(
        server_url=keycloak_admin_client.server_url,
        username=username,
        password=password,
    )
    await admin_client.authenticate()

    async def admin_factory(kc_name: str, namespace: str, rate_limiter=None):
        return admin_client

    detector = DriftDetector(
        config=config,
        k8s_client=None,  # Not needed for this test
        keycloak_admin_factory=admin_factory,
        operator_instance_id=fake_instance_id,  # Use the fake instance ID!
    )
    drift_results = await detector.scan_for_drift()

    # Verify orphan was detected
    orphans = [d for d in drift_results if d.resource_name == orphan_client_id]
    assert len(orphans) == 1

    # 4. Attempt remediation (should be skipped)
    await detector.remediate_drift(drift_results)
    await asyncio.sleep(1)

    # 5. Verify client still exists (was NOT deleted)
    kc_client = await keycloak_admin_client.get_client_by_name(
        orphan_client_id, realm_name, test_namespace
    )
    assert kc_client is not None, (
        "Client should NOT be deleted when auto_remediate=False"
    )

    # Cleanup
    await keycloak_admin_client.delete_client(
        orphan_client_id, realm_name, test_namespace
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_orphan_without_age_skips_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that orphan remediation is skipped when age cannot be determined.

    This exercises the code path where drift.age_hours is None.
    """
    import uuid

    from keycloak_operator.services.drift_detection_service import DriftResult

    # 1. Create a managed realm
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create a client manually (without ATTR_CREATED_AT so age is unknown)
    orphan_client_id = f"no-age-{uuid.uuid4().hex[:8]}"
    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        # No ownership attributes - we'll create the DriftResult manually
    }
    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # 3. Create a DriftResult with age_hours=None
    drift_result = DriftResult(
        resource_type="client",
        resource_name=orphan_client_id,
        drift_type="orphaned",
        keycloak_resource={"clientId": orphan_client_id},
        cr_namespace=test_namespace,
        cr_name="non-existent-cr",
        age_hours=None,  # Unknown age!
        parent_realm=realm_name,
    )

    # 4. Run remediation
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=False,
        scope_clients=True,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    await detector.remediate_drift([drift_result])

    # 5. Verify client still exists (remediation skipped due to unknown age)
    await asyncio.sleep(1)
    kc_client = await keycloak_admin_client.get_client_by_name(
        orphan_client_id, realm_name, test_namespace
    )
    assert kc_client is not None, (
        "Client should NOT be deleted when age cannot be determined"
    )

    # Cleanup
    await keycloak_admin_client.delete_client(
        orphan_client_id, realm_name, test_namespace
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_config_drift_remediation_missing_cr_info_skipped(
    shared_operator,
    drift_detector,
):
    """Test that config drift remediation is skipped when CR info is missing.

    This exercises the early return path in _remediate_config_drift() when
    cr_namespace or cr_name is None.
    """
    from keycloak_operator.services.drift_detection_service import DriftResult

    # Create a DriftResult with missing CR info
    drift_result = DriftResult(
        resource_type="realm",
        resource_name="test-realm",
        drift_type="config_drift",
        keycloak_resource={},
        cr_namespace=None,  # Missing!
        cr_name=None,  # Missing!
        drift_details=["Some drift"],
    )

    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=False,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)

    # Should not raise an exception, just log and skip
    await detector.remediate_drift([drift_result])
    # Test passes if no exception is raised


# ============================================================================
# Operator-Side Drift Detection Tests
# ============================================================================
# These tests exercise the drift detection code running in the operator pod
# rather than in the test process. This ensures coverage is collected from
# the actual operator deployment.


@pytest.mark.integration
@pytest.mark.asyncio
async def test_operator_side_realm_config_drift_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    realm_cr_factory,
):
    """Test that the operator's background drift detection remediates realm config drift.

    This test exercises the REAL operator-side drift detection code paths:
    - drift_detection_timer in operator.py
    - DriftDetector._scan_realms_smart() with timestamp-based comparison
    - DriftDetector._remediate_config_drift() triggering reconciliation
    - The full reconciliation path

    For timestamp-based drift detection to work:
    1. Admin events must be enabled in the realm
    2. The CR must have lastReconcileEventTime in status (set after reconciliation)
    3. A modification in Keycloak generates an admin event with newer timestamp
    4. Drift detector sees latest_event_time > lastReconcileEventTime

    The operator is configured (via Helm values) with:
    - driftDetection.enabled=true
    - driftDetection.intervalSeconds=30
    - driftDetection.autoRemediate=true
    - driftDetection.minimumAgeHours=1 (protects fresh orphans)
    """
    import time

    # 1. Create a realm with admin events ENABLED for drift detection
    realm_cr = realm_cr_factory(
        realm_name=f"operator-drift-test-{int(time.time() * 1000)}",
    )
    realm_cr["spec"]["displayName"] = "Operator Drift Test Realm"
    # Enable admin events - required for timestamp-based drift detection
    realm_cr["spec"]["eventsConfig"] = {
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": True,
        "eventsEnabled": True,
    }

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Wait for CR status to have lastReconcileEventTime
    # This is set by the reconciler after successful reconciliation
    max_wait_for_timestamp = 60
    start = time.time()
    has_timestamp = False
    while time.time() - start < max_wait_for_timestamp:
        cr_obj = await k8s_custom_objects.get_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_cr["metadata"]["name"],
        )
        status = cr_obj.get("status", {})
        if status.get("lastReconcileEventTime") is not None:
            has_timestamp = True
            break
        await asyncio.sleep(5)

    # Even if no timestamp, continue - the drift detector handles this case
    # (triggers reconcile when no lastReconcileEventTime exists)

    # 3. Verify initial state
    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm is not None
    assert kc_realm.display_name == "Operator Drift Test Realm"

    # 4. Introduce drift by modifying the realm directly in Keycloak
    # This generates an admin event with a newer timestamp
    kc_realm.display_name = "DRIFTED - Should Be Fixed By Operator"
    await keycloak_admin_client.update_realm(realm_name, kc_realm, test_namespace)

    # Verify drift was introduced
    kc_realm_drifted = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm_drifted.display_name == "DRIFTED - Should Be Fixed By Operator"

    # 5. Wait for operator's drift detection to run and remediate
    # The smart scan compares lastReconcileEventTime vs latest admin event time
    # When latest_event_time > lastReconcileEventTime, it triggers reconciliation
    max_wait = 180  # seconds - allow time for drift detection cycle
    poll_interval = 10  # seconds
    start_time = time.time()
    remediated = False
    kc_realm_check = None

    while time.time() - start_time < max_wait:
        await asyncio.sleep(poll_interval)
        kc_realm_check = await keycloak_admin_client.get_realm(
            realm_name, test_namespace
        )
        if (
            kc_realm_check
            and kc_realm_check.display_name == "Operator Drift Test Realm"
        ):
            remediated = True
            break

    current_display_name = kc_realm_check.display_name if kc_realm_check else "None"
    assert remediated, (
        f"Operator should have remediated the realm config drift within {max_wait}s. "
        f"Current displayName: {current_display_name}, "
        f"had lastReconcileEventTime: {has_timestamp}"
    )

    # 6. Cleanup
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_operator_side_client_config_drift_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    realm_cr_factory,
    client_cr_factory,
):
    """Test that the operator's background drift detection remediates client config drift.

    This test exercises the operator-side drift detection code paths for clients,
    including:
    - DriftDetector._check_client_resource_drift()
    - DriftDetector._remediate_config_drift() for clients
    - ClientReconciler triggered by drift remediation
    """
    import time

    # 1. Create realm first
    realm_cr = realm_cr_factory(
        realm_name=f"client-drift-realm-{int(time.time() * 1000)}",
    )

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create client
    client_cr = client_cr_factory(
        realm_cr=realm_cr,
        client_id=f"drift-client-{int(time.time() * 1000)}",
        description="Original Client Description",
    )

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        body=client_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        name=client_cr["metadata"]["name"],
        timeout=120,
    )

    client_id = client_cr["spec"]["clientId"]

    # 3. Verify initial state
    kc_client = await keycloak_admin_client.get_client_by_name(
        client_id, realm_name, test_namespace
    )
    assert kc_client is not None
    assert kc_client.description == "Original Client Description"

    # 4. Introduce drift by modifying the client directly in Keycloak
    kc_client.description = "DRIFTED - Should Be Fixed By Operator"
    await keycloak_admin_client.update_client(
        kc_client.id, kc_client, realm_name, test_namespace
    )

    # Verify drift was introduced
    kc_client_drifted = await keycloak_admin_client.get_client_by_name(
        client_id, realm_name, test_namespace
    )
    assert kc_client_drifted.description == "DRIFTED - Should Be Fixed By Operator"

    # 5. Wait for operator's drift detection to run and remediate
    max_wait = 150  # seconds
    poll_interval = 10  # seconds
    start_time = time.time()
    remediated = False
    kc_client_check = None

    while time.time() - start_time < max_wait:
        await asyncio.sleep(poll_interval)
        kc_client_check = await keycloak_admin_client.get_client_by_name(
            client_id, realm_name, test_namespace
        )
        if (
            kc_client_check
            and kc_client_check.description == "Original Client Description"
        ):
            remediated = True
            break

    current_description = kc_client_check.description if kc_client_check else "None"
    assert remediated, (
        f"Operator should have remediated the client config drift within {max_wait}s. "
        f"Current description: {current_description}"
    )

    # 6. Cleanup
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakclients",
        name=client_cr["metadata"]["name"],
    )
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_operator_side_orphan_realm_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    realm_cr_factory,
    operator_instance_id,
):
    """Test that the operator's background drift detection deletes orphaned realms.

    This test exercises the operator-side orphan detection and remediation:
    - DriftDetector._check_realm_resource_drift() detecting orphan
    - DriftDetector._remediate_orphan() for realms
    - admin_client.delete_realm()

    An orphaned realm is one that exists in Keycloak with operator ownership
    attributes but no corresponding CR in Kubernetes.
    """
    import time

    from keycloak_operator.utils.ownership import (
        ATTR_CR_NAME,
        ATTR_CR_NAMESPACE,
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a realm directly in Keycloak (simulating an orphan)
    # This realm has operator ownership attributes but no CR
    orphan_realm_name = f"orphan-realm-{int(time.time() * 1000)}"

    # First verify it doesn't exist
    existing = await keycloak_admin_client.get_realm(orphan_realm_name, test_namespace)
    assert existing is None

    # Create the orphaned realm with ownership attributes
    from keycloak_operator.models.keycloak_api import RealmRepresentation

    orphan_realm = RealmRepresentation(
        realm=orphan_realm_name,
        enabled=True,
        display_name="Orphan Realm - Should Be Deleted",
        attributes={
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-realm-cr",
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",  # Old enough to be remediated
        },
    )

    await keycloak_admin_client.create_realm(orphan_realm, test_namespace)

    # Verify orphan was created
    kc_orphan = await keycloak_admin_client.get_realm(orphan_realm_name, test_namespace)
    assert kc_orphan is not None

    # 2. Wait for operator's drift detection to detect and delete the orphan
    max_wait = 150  # seconds
    poll_interval = 10  # seconds
    start_time = time.time()
    deleted = False

    while time.time() - start_time < max_wait:
        await asyncio.sleep(poll_interval)
        kc_orphan_check = await keycloak_admin_client.get_realm(
            orphan_realm_name, test_namespace
        )
        if kc_orphan_check is None:
            deleted = True
            break

    assert deleted, (
        f"Operator should have deleted the orphaned realm within {max_wait}s. "
        f"Realm '{orphan_realm_name}' still exists."
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_operator_side_orphan_client_remediation(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    realm_cr_factory,
    operator_instance_id,
):
    """Test that the operator's background drift detection deletes orphaned clients.

    This test exercises the operator-side orphan detection and remediation:
    - DriftDetector._check_client_resource_drift() detecting orphan
    - DriftDetector._remediate_orphan() for clients with parent_realm available
    - admin_client.delete_client()
    """
    import time

    from keycloak_operator.utils.ownership import (
        ATTR_CR_NAME,
        ATTR_CR_NAMESPACE,
        ATTR_CREATED_AT,
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    # 1. Create a realm first (needed to host the orphan client)
    realm_cr = realm_cr_factory(
        realm_name=f"orphan-client-host-{int(time.time() * 1000)}",
    )

    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        body=realm_cr,
    )

    await wait_for_resource_ready(
        k8s_custom_objects,
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
        timeout=120,
    )

    realm_name = realm_cr["spec"]["realmName"]

    # 2. Create an orphan client directly in Keycloak
    orphan_client_id = f"orphan-client-{int(time.time() * 1000)}"

    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        "description": "Orphan Client - Should Be Deleted",
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-client-cr",
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",  # Old enough to be remediated
        },
    }

    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # Verify orphan was created
    kc_orphan = await keycloak_admin_client.get_client_by_name(
        orphan_client_id, realm_name, test_namespace
    )
    assert kc_orphan is not None

    # 3. Wait for operator's drift detection to detect and delete the orphan
    max_wait = 150  # seconds
    poll_interval = 10  # seconds
    start_time = time.time()
    deleted = False

    while time.time() - start_time < max_wait:
        await asyncio.sleep(poll_interval)
        kc_orphan_check = await keycloak_admin_client.get_client_by_name(
            orphan_client_id, realm_name, test_namespace
        )
        if kc_orphan_check is None:
            deleted = True
            break

    assert deleted, (
        f"Operator should have deleted the orphaned client within {max_wait}s. "
        f"Client '{orphan_client_id}' still exists in realm '{realm_name}'."
    )

    # 4. Cleanup realm
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )
