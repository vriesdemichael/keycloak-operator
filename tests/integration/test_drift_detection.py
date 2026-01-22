"""
Integration tests for drift detection functionality.

These tests verify that:
1. Ownership attributes are correctly added to Keycloak resources
2. Orphaned resources are detected after CR deletion
3. Drift metrics are emitted correctly
4. Auto-remediation works (when enabled)
"""

import asyncio

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
    # Check that details contain expected mismatches
    drift_details_str = str(drift.drift_details)
    assert "description" in drift_details_str
    assert "redirectUris" in drift_details_str

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

    # 3. Create Orphan Condition (remove finalizer & delete CR)
    # Remove finalizer to simulate orphan (normally operator removes it on delete)
    # We want to delete CR but keep Keycloak resource to test drift detection

    # Actually, we can just delete the CR. Since the operator is running, it might
    # process the deletion and remove the client. To test orphan detection,
    # we need a situation where the CR is gone but the resource remains.
    # The best way is to manually remove the finalizer via API patch,
    # then delete the CR. The operator might still catch the delete event though.
    #
    # Safer way: Disable the operator temporarily? No, shared operator.
    #
    # Alternative: Create the resource in Keycloak MANUALLY, but with
    # operator ownership attributes pointing to a non-existent CR.

    # Let's try the manual creation approach which is more stable
    # Delete the proper CR first to clear state
    # await k8s_custom_objects.delete_namespaced_custom_object(
    #     group="vriesdemichael.github.io",
    #     version="v1",
    #     namespace=test_namespace,
    #     plural="keycloakclients",
    #     name=client_cr["metadata"]["name"],
    # )

    # Wait for deletion
    await asyncio.sleep(2)

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

    # 4. Scan and Remediate
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

    # 5. Verify Deletion
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
