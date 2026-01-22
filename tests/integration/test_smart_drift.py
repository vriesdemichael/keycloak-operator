import asyncio

import pytest

from keycloak_operator.services.drift_detection_service import DriftDetectionConfig
from tests.integration.wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.asyncio
async def test_smart_drift_detection_remediates_tampered_idp(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    drift_detector,
):
    """
    Test that smart drift detection (using admin events) detects and remediates
    a manually added Identity Provider (child resource tampering).
    """

    # 1. Create Realm with adminEventsEnabled
    # This is crucial for smart detection
    realm_cr["spec"]["eventsConfig"] = {"adminEventsEnabled": True}

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

    # Ensure realm is ready and initial scan would set the baseline timestamp
    # We run a scan once to "initialize" the state
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=True,
        scope_identity_providers=True,
        scope_roles=True,
    )
    detector = drift_detector(config)
    await detector.scan_for_drift()  # This sets _last_scan_times

    # 2. Tamper: Create an unmanaged IDP manually
    # This generates a CREATE event
    idp_alias = "tampered-idp"
    idp_data = {
        "alias": idp_alias,
        "providerId": "keycloak-oidc",
        "enabled": True,
        "config": {
            "clientId": "tampered",
            "clientSecret": "secret",
            "authorizationUrl": "https://example.com/auth",
            "tokenUrl": "https://example.com/token",
        },
    }

    # We must ensure there's a slight delay so the event time > last scan time
    # Keycloak events are in millis, but our scan time is float seconds.
    await asyncio.sleep(1)

    await keycloak_admin_client.create_identity_provider(
        realm_name, idp_data, test_namespace
    )

    # Verify IDP exists
    idps = await keycloak_admin_client.get_identity_providers(
        realm_name, test_namespace
    )
    assert any(i.alias == idp_alias for i in idps), (
        "Tampered IDP should exist before remediation"
    )

    # 3. Run Smart Scan & Remediation
    # The detector should see the event and trigger realm reconciliation
    results = await detector.scan_for_drift()

    # Verify drift was detected
    # Note: With smart scan, we report "Realm Drift", not specific resource drift
    assert len(results) > 0, "Should detect drift via events"
    assert results[0].resource_type == "realm", "Should report realm drift"

    # Run remediation
    await detector.remediate_drift(results)

    # 4. Verify Remediation (IDP should be gone)
    await asyncio.sleep(2)  # Give it a moment to propagate

    idps_after = await keycloak_admin_client.get_identity_providers(
        realm_name, test_namespace
    )
    assert not any(i.alias == idp_alias for i in idps_after), (
        "Tampered IDP should be deleted by remediation"
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
async def test_smart_drift_detection_client_update(
    shared_operator,
    keycloak_admin_client,
    k8s_custom_objects,
    test_namespace,
    operator_instance_id,
    realm_cr,
    client_cr_factory,
    drift_detector,
):
    """
    Test that smart drift detection detects client tampering via events.
    """
    # 1. Setup Realm & Client
    realm_cr["spec"]["eventsConfig"] = {"adminEventsEnabled": True}

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

    client_cr = client_cr_factory(realm_cr=realm_cr, client_id="smart-client-test")
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

    # Initialize baseline
    config = DriftDetectionConfig(
        enabled=True,
        interval_seconds=60,
        auto_remediate=True,
        minimum_age_hours=0,
        scope_realms=True,
        scope_clients=True,
        scope_identity_providers=True,
        scope_roles=True,
    )
    detector = drift_detector(config)
    await detector.scan_for_drift()

    # 2. Tamper: Modify Client
    await asyncio.sleep(1)

    kc_client = await keycloak_admin_client.get_client_by_name(
        "smart-client-test", realm_name, test_namespace
    )
    kc_client.description = "Tampered Description"
    await keycloak_admin_client.update_client(
        kc_client.id, kc_client, realm_name, test_namespace
    )

    # 3. Scan
    results = await detector.scan_for_drift()

    assert len(results) > 0, "Should detect client drift via events"
    assert results[0].resource_type == "client", "Should report client drift"

    # 4. Remediate
    await detector.remediate_drift(results)

    await asyncio.sleep(2)

    # Verify
    kc_client_fixed = await keycloak_admin_client.get_client_by_name(
        "smart-client-test", realm_name, test_namespace
    )
    assert kc_client_fixed.description == "Managed by Keycloak Operator", (
        "Client should be reverted"
    )

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
