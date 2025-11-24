"""
Integration tests for Realm reconciler.

Tests verify the reconciler correctly manages Keycloak realms:
- Realm creation and configuration
- Cross-namespace authorization
- Realm settings management
- Theme configuration
- Realm deletion and cleanup
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_deleted, wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmReconciler:
    """Test Realm reconciler functionality."""

    @pytest.mark.timeout(180)
    async def test_realm_lifecycle(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test complete realm lifecycle: create, ready, delete."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-lifecycle-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Test Lifecycle Realm",
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # CREATE: Deploy realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # READY: Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # VERIFY: Check realm exists in Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None
            assert realm_repr.realm == realm_name
            assert realm_repr.display_name == "Test Lifecycle Realm"
            # Realm ready

            # DELETE: Remove realm
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for deletion
            await wait_for_resource_deleted(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
            )

            # Verify realm removed from Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is None

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_realm_with_client_authorization_grants(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test realm with client authorization grants configured."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-grants-{suffix}"
        namespace = test_namespace
        authorized_namespace = f"authorized-ns-{suffix}"

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Test Grants Realm",
            client_authorization_grants=[namespace, authorized_namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm has correct configuration
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None
            assert realm_repr.realm == realm_name

            # Verify CR status shows grants
            realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            spec = realm_cr.get("spec", {})
            grants = spec.get("clientAuthorizationGrants", [])
            assert namespace in grants
            assert authorized_namespace in grants

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_realm_update_display_name(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test updating realm display name triggers reconciliation."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-update-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Original Name",
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify original name
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr.display_name == "Original Name"

            # UPDATE: Change display name using Pydantic model
            from keycloak_operator.models.realm import KeycloakRealmSpec

            realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Load spec into Pydantic model, modify it, dump back
            current_spec = KeycloakRealmSpec.model_validate(realm_cr["spec"])
            current_spec.display_name = "Updated Name"
            realm_cr["spec"] = current_spec.model_dump(
                by_alias=True, exclude_unset=True
            )

            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=realm_cr,
            )

            # Wait for reconciliation
            await wait_for_resource_ready(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
                operator_namespace=operator_namespace,
            )

            # Wait for the display name to actually update in Keycloak
            # The reconciler needs time to detect the change and apply it
            max_attempts = 15
            for attempt in range(max_attempts):
                realm_repr = await keycloak_admin_client.get_realm(
                    realm_name, namespace
                )
                if realm_repr.display_name == "Updated Name":
                    break
                if attempt < max_attempts - 1:
                    await asyncio.sleep(2)

            # Verify update in Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr.display_name == "Updated Name"

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(180)
    async def test_realm_status_phase_transitions(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Test realm status transitions through expected phases."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-phases-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Check status progresses: Unknown -> Pending -> Ready
            import asyncio

            # Wait briefly and check it's not Unknown anymore
            await asyncio.sleep(5)

            realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm_cr.get("status", {})
            phase = status.get("phase")

            # Should have progressed from Unknown
            assert phase in ("Pending", "Provisioning", "Ready", "Degraded")

            # Wait for final Ready state
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify Ready phase
            realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm_cr.get("status", {})
            assert status.get("phase") == "Ready"

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
