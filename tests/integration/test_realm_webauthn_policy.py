import asyncio
import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.models.realm import (
    KeycloakRealmSpec,
    KeycloakWebAuthnPasswordlessPolicy,
    KeycloakWebAuthnPolicy,
    OperatorRef,
)

from .wait_helpers import (
    wait_for_reconciliation_complete,
    wait_for_resource_deleted,
    wait_for_resource_ready,
)


@pytest.mark.integration
async def test_realm_webauthn_policy_reconciliation(
    k8s_custom_objects,
    test_namespace,
    operator_namespace,
    keycloak_admin_client,
):
    """
    Test that WebAuthn policy is correctly applied to a Keycloak realm via CRD.
    """
    suffix = uuid.uuid4().hex[:8]
    realm_name = f"webauthn-test-{suffix}"

    # Create a realm spec with WebAuthn policies
    webauthn_policy = KeycloakWebAuthnPolicy(
        rpEntityName="test-rp",
        signatureAlgorithms=["ES256"],
        rpId="example.com",
        attestationConveyancePreference="none",
        authenticatorAttachment="platform",
        requireResidentKey="Yes",
        userVerificationRequirement="preferred",
        createTimeout=30,
        avoidSameAuthenticatorRegister=True,
        acceptableAaguids=["123"],
        extraOrigins=["https://example.com"],
    )

    passwordless_policy = KeycloakWebAuthnPasswordlessPolicy(
        rpEntityName="test-passwordless-rp",
        signatureAlgorithms=["RS256"],
        rpId="passwordless.example.com",
        passkeysEnabled=True,
    )

    realm_spec = KeycloakRealmSpec(
        realmName=realm_name,
        operatorRef=OperatorRef(namespace=operator_namespace),
        webAuthnPolicy=webauthn_policy,
        webAuthnPasswordlessPolicy=passwordless_policy,
        clientAuthorizationGrants=[test_namespace],
    )

    realm_manifest = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "KeycloakRealm",
        "metadata": {"name": realm_name, "namespace": test_namespace},
        "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
    }

    try:
        # CREATE: Deploy realm
        await k8s_custom_objects.create_namespaced_custom_object(
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_manifest,
        )

        # READY: Wait for realm to become ready
        await wait_for_resource_ready(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=150,
            operator_namespace=operator_namespace,
        )

        # VERIFY: Check realm configuration in Keycloak
        realm = await keycloak_admin_client.get_realm(realm_name, test_namespace)
        assert realm is not None

        # Verify WebAuthn policy settings
        assert realm.web_authn_policy_rp_entity_name == "test-rp"
        assert realm.web_authn_policy_signature_algorithms == ["ES256"]
        assert realm.web_authn_policy_rp_id == "example.com"
        assert realm.web_authn_policy_attestation_conveyance_preference == "none"
        assert realm.web_authn_policy_authenticator_attachment == "platform"
        assert realm.web_authn_policy_require_resident_key == "Yes"
        assert realm.web_authn_policy_user_verification_requirement == "preferred"
        assert realm.web_authn_policy_create_timeout == 30
        assert realm.web_authn_policy_avoid_same_authenticator_register is True
        assert realm.web_authn_policy_acceptable_aaguids == ["123"]
        assert realm.web_authn_policy_extra_origins == ["https://example.com"]

        # Verify Passwordless policy settings
        assert (
            realm.web_authn_policy_passwordless_rp_entity_name == "test-passwordless-rp"
        )
        assert realm.web_authn_policy_passwordless_signature_algorithms == ["RS256"]
        assert realm.web_authn_policy_passwordless_rp_id == "passwordless.example.com"
        assert realm.web_authn_policy_passwordless_passkeys_enabled is True

        # UPDATE: Change policy settings
        # Retry loop for conflict handling
        new_generation = 0
        for attempt in range(5):
            try:
                realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

                # Load spec, modify, dump back
                current_spec = KeycloakRealmSpec.model_validate(realm_cr["spec"])
                # Initialize policies if they somehow became None (shouldn't happen but safe)
                if not current_spec.web_authn_policy:
                    current_spec.web_authn_policy = KeycloakWebAuthnPolicy()
                assert current_spec.web_authn_policy
                if not current_spec.web_authn_passwordless_policy:
                    current_spec.web_authn_passwordless_policy = (
                        KeycloakWebAuthnPasswordlessPolicy()
                    )
                assert current_spec.web_authn_passwordless_policy

                current_spec.web_authn_policy.rp_entity_name = "updated-rp"
                current_spec.web_authn_passwordless_policy.create_timeout = 60

                realm_cr["spec"] = current_spec.model_dump(
                    by_alias=True, exclude_unset=True
                )

                response = await k8s_custom_objects.patch_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                    body=realm_cr,
                )
                new_generation = response["metadata"]["generation"]
                break
            except ApiException as e:
                if e.status == 409 and attempt < 4:
                    await asyncio.sleep(0.5)
                    continue
                raise

        # Wait for reconciliation after update
        await wait_for_reconciliation_complete(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            min_generation=new_generation,
            timeout=60,
            operator_namespace=operator_namespace,
        )

        # Verify update in Keycloak (poll for a few seconds)
        for _ in range(20):
            updated_realm = await keycloak_admin_client.get_realm(
                realm_name, test_namespace
            )
            if updated_realm.web_authn_policy_rp_entity_name == "updated-rp":
                break
            await asyncio.sleep(1)

        assert updated_realm.web_authn_policy_rp_entity_name == "updated-rp"
        assert updated_realm.web_authn_policy_passwordless_create_timeout == 60

    finally:
        # Cleanup
        with contextlib.suppress(ApiException):
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

        # Wait for deletion
        await wait_for_resource_deleted(
            k8s_custom_objects=k8s_custom_objects,
            group="vriesdemichael.github.io",
            version="v1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=realm_name,
            timeout=120,
        )
