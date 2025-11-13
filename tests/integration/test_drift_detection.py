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
