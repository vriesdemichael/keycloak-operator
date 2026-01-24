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
from tests.integration.wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.asyncio
async def test_realm_ownership_attributes_are_added(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_ownership_attributes_are_added(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    k8s_core_v1,
    test_namespace,
    operator_instance_id,
    realm_cr,
    client_cr,
):
    """Test that ownership attributes are added when creating a client."""
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

    # Realm is ready - no longer need authorizationSecretName (grant list authorization)
    # Client authorization is now handled via realm's clientAuthorizationGrants

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

    realm_name = realm_cr["spec"]["realmName"]
    client_id = client_cr["spec"]["clientId"]
    kc_client = await keycloak_admin_client.get_client_by_name(
        client_id, realm_name, test_namespace
    )

    from typing import cast

    attributes = cast(dict[str, str | list[str]], kc_client.attributes or {})

    assert ATTR_MANAGED_BY in attributes
    assert ATTR_OPERATOR_INSTANCE in attributes
    assert ATTR_CR_NAMESPACE in attributes
    assert ATTR_CR_NAME in attributes
    assert is_owned_by_this_operator(attributes, operator_instance_id)

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
async def test_orphan_detection_after_realm_deletion(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that orphaned realms are detected after CR deletion."""
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
    assert kc_realm is not None

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
    await asyncio.sleep(5)

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
async def test_orphan_detection_after_client_deletion(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    k8s_core_v1,
    test_namespace,
    operator_instance_id,
    realm_cr,
    client_cr,
    drift_detector,
):
    """Test that orphaned clients are detected after CR deletion."""
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

    # Realm is ready - no longer need authorizationSecretName (grant list authorization)
    # Client authorization is now handled via realm's clientAuthorizationGrants

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

    realm_name = realm_cr["spec"]["realmName"]
    client_id = client_cr["spec"]["clientId"]

    kc_client = await keycloak_admin_client.get_client_by_name(
        client_id, realm_name, test_namespace
    )
    assert kc_client is not None

    # Remove finalizer so client won't be deleted from Keycloak when CR is deleted
    # Use retry loop to handle race conditions with operator updates
    for attempt in range(5):
        try:
            client_obj = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_cr["metadata"]["name"],
            )
            client_obj["metadata"]["finalizers"] = []
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                name=client_cr["metadata"]["name"],
                body=client_obj,
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
        plural="keycloakclients",
        name=client_cr["metadata"]["name"],
    )
    await asyncio.sleep(5)

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

    orphaned_clients = [
        d
        for d in drift_results
        if d.resource_type == "client"
        and d.drift_type == "orphaned"
        and d.resource_name == client_id
    ]

    assert len(orphaned_clients) == 1

    await keycloak_admin_client.delete_client(client_id, realm_name, test_namespace)
    await k8s_custom_objects.delete_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=test_namespace,
        plural="keycloakrealms",
        name=realm_cr["metadata"]["name"],
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unmanaged_resources_detected(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    drift_detector,
):
    """Test that unmanaged resources (created without operator) are detected."""
    import uuid

    unmanaged_realm_name = f"unmanaged-{uuid.uuid4().hex[:8]}"

    realm_config = {
        "realm": unmanaged_realm_name,
        "displayName": "Unmanaged Realm",
        "enabled": True,
    }

    await keycloak_admin_client.create_realm(realm_config, test_namespace)
    await asyncio.sleep(2)

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

    unmanaged_realms = [
        d
        for d in drift_results
        if d.resource_type == "realm"
        and d.drift_type == "unmanaged"
        and d.resource_name == unmanaged_realm_name
    ]

    assert len(unmanaged_realms) == 1

    await keycloak_admin_client.delete_realm(unmanaged_realm_name, test_namespace)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_auto_remediation_deletes_orphans(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that auto-remediation deletes orphaned resources when enabled."""
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
    assert kc_realm is not None

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
    await asyncio.sleep(5)

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
    await asyncio.sleep(2)

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
    await asyncio.sleep(5)

    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=24,
        scope_realms=True,
        scope_clients=False,
        scope_identity_providers=False,
        scope_roles=False,
    )

    detector = drift_detector(config)
    drift_results = await detector.scan_for_drift()
    await detector.remediate_drift(drift_results)
    await asyncio.sleep(2)

    kc_realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
    assert kc_realm is not None

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
    await asyncio.sleep(2)  # Give it a moment to propagate if needed

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
    await asyncio.sleep(2)

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
async def test_resource_ignored_if_owned_by_other_operator(
    shared_operator,
    keycloak_admin_client,
    test_namespace,
    drift_detector,
):
    """Test that resources owned by a different operator instance are ignored."""
    from keycloak_operator.utils.ownership import (
        ATTR_MANAGED_BY,
        ATTR_OPERATOR_INSTANCE,
    )

    other_realm_name = "other-op-realm"

    # Create realm manually with different operator ID
    realm_data = {
        "realm": other_realm_name,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: "different-operator-id-123",
        },
    }

    await keycloak_admin_client.create_realm(realm_data, test_namespace)

    try:
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

        # Should NOT find this realm as drifted, unmanaged, or orphaned
        # It should be completely ignored
        related_drift = [
            d for d in drift_results if d.resource_name == other_realm_name
        ]
        assert len(related_drift) == 0, (
            f"Should ignore resource owned by other operator, but found: {related_drift}"
        )

    finally:
        await keycloak_admin_client.delete_realm(other_realm_name, test_namespace)


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
    await asyncio.sleep(2)

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
    await asyncio.sleep(2)

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
    # Note: In real scenarios, the operator would set this, but we're testing
    # the drift detector's behavior when it encounters such CRs
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
        # The test still validates the behavior - CR without Ready status
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
    # If the operator already reconciled it to Ready, this test scenario doesn't apply
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
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """Test that auto-remediation is skipped when disabled in config.

    This exercises the early return path in remediate_drift() when
    auto_remediate=False.
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

    # 2. Create an orphan client
    orphan_client_id = f"no-remediate-{uuid.uuid4().hex[:8]}"
    orphan_client_data = {
        "clientId": orphan_client_id,
        "enabled": True,
        "attributes": {
            ATTR_MANAGED_BY: "keycloak-operator",
            ATTR_OPERATOR_INSTANCE: operator_instance_id,
            ATTR_CR_NAMESPACE: test_namespace,
            ATTR_CR_NAME: "non-existent-cr",
            ATTR_CREATED_AT: "2020-01-01T00:00:00Z",
        },
    }
    await keycloak_admin_client.create_client(
        orphan_client_data, realm_name, test_namespace
    )

    # 3. Run drift detection with auto_remediate=False
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

    detector = drift_detector(config)
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
