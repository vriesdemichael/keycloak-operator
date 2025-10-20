"""Integration tests for authorization token delegation architecture.

This module tests the end-to-end authorization flow:
1. Operator generates token at startup
2. Realms validate operator token and generate their own token
3. Clients validate realm token before operations
4. Cross-namespace authorization works correctly
5. Invalid tokens are properly rejected
"""

from __future__ import annotations

import base64
import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
from keycloak_operator.models.common import AuthorizationSecretRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestAuthorizationDelegation:
    """Test authorization token delegation flow."""

    @pytest.mark.timeout(600)  # Uses shared Keycloak (10 minutes)
    async def test_realm_validates_operator_token(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
        admission_token_setup,
    ) -> None:
        """Verify that realms validate the operator token before reconciliation.

        Test flow:
        1. Use shared Keycloak instance
        2. Create realm with admission token reference
        3. Verify realm reaches Ready state and bootstraps operational token
        4. Verify operational token secret is created
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"auth-realm-{suffix}"
        
        # Get admission token from fixture
        admission_secret_name, _admission_token = admission_token_setup

        # Create realm with admission token reference
        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_ready(plural: str, name: str) -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                # Accept Ready or Degraded (both mean resource is operational)
                return phase in ("Ready", "Degraded")

            return await wait_for_condition(_condition, timeout=90, interval=3)

        try:
            # Create realm with operator token reference (shared Keycloak already ready)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to become ready (validates operator token internally)
            ready = await _wait_resource_ready("keycloakrealms", realm_name)
            assert ready, f"Realm {realm_name} did not become Ready"

            # Get realm status
            realm = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Verify realm bootstrapped operational token
            operational_secret_name = f"{namespace}-operator-token"
            operational_secret = k8s_core_v1.read_namespaced_secret(
                name=operational_secret_name, namespace=namespace
            )
            assert operational_secret.data, "Operational token secret should have data"
            assert "token" in operational_secret.data, (
                "Operational token secret should have 'token' key"
            )

            # Verify operational token has proper labels
            assert operational_secret.metadata.labels, "Secret should have labels"
            assert (
                operational_secret.metadata.labels.get("keycloak.mdvr.nl/managed-by")
                == "keycloak-operator"
            )
            assert (
                operational_secret.metadata.labels.get("keycloak.mdvr.nl/token-type")
                == "operational"
            )

            # Verify realm status includes authorizationStatus for operational token
            status = realm.get("status", {}) or {}
            auth_status = status.get("authorizationStatus")
            if auth_status:
                # Verify status points to operational token
                secret_ref = auth_status.get("secretRef", {})
                assert secret_ref.get("name") == operational_secret_name
                assert auth_status.get("tokenType") == "operational"
                assert "tokenVersion" in auth_status
                assert "validUntil" in auth_status

        finally:
            # Cleanup realm only (admission token cleaned by fixture)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(600)
    async def test_client_validates_realm_token(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
        admission_token_setup,
    ) -> None:
        """Verify that clients validate realm token before reconciliation.

        Test flow:
        1. Use shared Keycloak instance
        2. Create realm with admission token (bootstraps operational token)
        3. Create client with realmRef pointing to realm's token
        4. Verify client reaches Ready state
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"client-realm-{suffix}"
        client_name = f"client-{suffix}"
        
        # Get admission token from fixture
        admission_secret_name, _admission_token = admission_token_setup

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_ready(plural: str, name: str) -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase in ("Ready", "Degraded")

            return await wait_for_condition(_condition, timeout=90, interval=3)

        try:
            # Create realm (shared Keycloak already ready)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            ready = await _wait_resource_ready("keycloakrealms", realm_name)
            assert ready, f"Realm {realm_name} did not become Ready"

            # Get realm's authorization secret name from status (camelCase in CRD)
            realm = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm.get("status", {}) or {}
            # CRDs use camelCase, so read as camelCase from status dict
            realm_auth_secret_name = status.get("authorizationSecretName")
            assert realm_auth_secret_name, (
                f"Realm should have authorizationSecretName in status. "
                f"Status keys: {list(status.keys())}"
            )

            # Wait for the authorization secret to actually exist before using it
            from kubernetes import client as k8s_client

            k8s_core = k8s_client.CoreV1Api()

            async def check_secret_exists():
                try:
                    k8s_core.read_namespaced_secret(realm_auth_secret_name, namespace)
                    return True
                except ApiException as e:
                    if e.status == 404:
                        return False
                    raise

            assert await wait_for_condition(
                check_secret_exists, timeout=30, interval=2
            ), f"Authorization secret {realm_auth_secret_name} was not created"

            # Create client with realmRef pointing to realm's token
            client_spec = KeycloakClientSpec(
                client_id=client_name,
                public_client=False,
                realm_ref=RealmRef(
                    name=realm_name,
                    namespace=namespace,
                    authorization_secret_ref=AuthorizationSecretRef(
                        name=realm_auth_secret_name,
                        key="token",
                    ),
                ),
            )

            client_manifest = {
                "apiVersion": "keycloak.mdvr.nl/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to become ready (validates realm token internally)
            ready = await _wait_resource_ready("keycloakclients", client_name)
            assert ready, f"Client {client_name} did not become Ready"

        finally:
            # Cleanup test resources only (shared Keycloak persists)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )

            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(600)
    async def test_invalid_operator_token_rejects_realm(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        wait_for_condition,
    ) -> None:
        """Verify that realms with invalid operator token are rejected.

        Test flow:
        1. Use shared operator instance
        2. Create fake secret with wrong token in test namespace
        3. Create realm pointing to fake secret (invalid token)
        4. Verify realm enters Degraded/Failed state (not Ready)

        Note: We use the shared operator but create a realm with an invalid token
        reference, which the operator will reject during authorization validation.
        """

        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"invalid-realm-{suffix}"
        fake_secret_name = f"fake-operator-token-{suffix}"

        # Create fake secret with invalid token (with required RBAC label)
        fake_token = b"invalid-fake-token-not-matching-operator"
        fake_secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": fake_secret_name,
                "namespace": namespace,
                "labels": {"keycloak.mdvr.nl/allow-operator-read": "true"},
            },
            "type": "Opaque",
            "data": {"token": base64.b64encode(fake_token).decode("utf-8")},
        }

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=test_namespace,  # Secret is in test namespace  
                authorization_secret_ref=AuthorizationSecretRef(
                    name=fake_secret_name,
                    key="token",
                ),
            ),
            # But Keycloak is in operator namespace  
            keycloak_name="keycloak",
            keycloak_namespace=operator_namespace,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_failed(plural: str, name: str) -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                message = status.get("message", "")

                # Should be in Failed or Degraded state with authorization error message
                return (
                    phase in ("Failed", "Degraded")
                    and "Authorization failed" in message
                )

            return await wait_for_condition(_condition, timeout=120, interval=3)

        try:
            # Create fake secret
            k8s_core_v1.create_namespaced_secret(namespace=namespace, body=fake_secret)

            # Create realm with invalid token reference
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to fail due to authorization
            failed = await _wait_resource_failed("keycloakrealms", realm_name)
            assert failed, f"Realm {realm_name} should have failed authorization check"

            # Verify the error message contains authorization failure
            realm = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm.get("status", {}) or {}
            message = status.get("message", "")

            assert "Authorization failed" in message, (
                f"Realm should report authorization failure, got: {message}"
            )

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

            with contextlib.suppress(ApiException):
                k8s_core_v1.delete_namespaced_secret(
                    name=fake_secret_name, namespace=namespace
                )

    @pytest.mark.timeout(600)
    async def test_invalid_realm_token_rejects_client(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
        admission_token_setup,
    ) -> None:
        """Verify that clients with invalid realm token are rejected.

        Test flow:
        1. Use shared Keycloak and create realm with admission token
        2. Create fake secret with wrong token
        3. Create client pointing to fake secret (not realm's token)
        4. Verify client enters Failed state
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"valid-realm-{suffix}"
        client_name = f"bad-client-{suffix}"
        fake_secret_name = f"fake-realm-token-{suffix}"

        # Get admission token from fixture
        admission_secret_name, _admission_token = admission_token_setup

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_ready(plural: str, name: str) -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase in ("Ready", "Degraded")

            return await wait_for_condition(_condition, timeout=90, interval=3)

        async def _wait_client_failed() -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                message = status.get("message", "")

                # Should fail with authorization error
                return phase == "Failed" and "Authorization failed" in message

            return await wait_for_condition(_condition, timeout=120, interval=3)

        try:
            # Create realm (shared Keycloak already ready, will generate valid token)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            ready = await _wait_resource_ready("keycloakrealms", realm_name)
            assert ready, f"Realm {realm_name} did not become Ready"

            # Create fake secret with invalid token (with required RBAC label)
            fake_token = b"invalid-fake-realm-token"
            fake_secret = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": fake_secret_name,
                    "namespace": namespace,
                    "labels": {"keycloak.mdvr.nl/allow-operator-read": "true"},
                },
                "type": "Opaque",
                "data": {"token": base64.b64encode(fake_token).decode("utf-8")},
            }
            k8s_core_v1.create_namespaced_secret(namespace=namespace, body=fake_secret)

            # Create client with fake token (not realm's token)
            client_spec = KeycloakClientSpec(
                client_id=client_name,
                public_client=False,
                realm_ref=RealmRef(
                    name=realm_name,
                    namespace=namespace,
                    authorization_secret_ref=AuthorizationSecretRef(
                        name=fake_secret_name,  # Wrong token!
                        key="token",
                    ),
                ),
            )

            client_manifest = {
                "apiVersion": "keycloak.mdvr.nl/v1",
                "kind": "KeycloakClient",
                "metadata": {"name": client_name, "namespace": namespace},
                "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to fail authorization
            failed = await _wait_client_failed()
            assert failed, (
                f"Client {client_name} should have failed authorization check"
            )

            # Verify error message
            client = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
            )
            status = client.get("status", {}) or {}
            message = status.get("message", "")
            assert "Authorization failed" in message

        finally:
            # Cleanup test resources only (shared Keycloak persists)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakclients",
                    name=client_name,
                )

            with contextlib.suppress(ApiException):
                k8s_core_v1.delete_namespaced_secret(
                    name=fake_secret_name, namespace=namespace
                )

            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.timeout(600)
    async def test_realm_secret_cleanup_on_deletion(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
        admission_token_setup,
    ) -> None:
        """Verify that operational token secrets are cleaned up with realm deletion.

        Test flow:
        1. Use shared Keycloak and create realm with admission token
        2. Verify operational token secret exists (bootstrapped)
        3. Delete realm
        4. Verify operational token secret persists (shared across realms)
        
        Note: Operational tokens are per-namespace, not per-realm, so they
        persist even after realm deletion (cleaned up when all realms gone).
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"cleanup-realm-{suffix}"
        
        # Get admission token from fixture
        admission_secret_name, _admission_token = admission_token_setup

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=admission_secret_name,
                    key="token",
                ),
            ),
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        async def _wait_resource_ready(plural: str, name: str) -> bool:
            async def _condition() -> bool:
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural=plural,
                        name=name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase in ("Ready", "Degraded")

            return await wait_for_condition(_condition, timeout=90, interval=3)

        async def _wait_secret_deleted(secret_name: str) -> bool:
            async def _condition() -> bool:
                try:
                    k8s_core_v1.read_namespaced_secret(
                        name=secret_name, namespace=namespace
                    )
                    return False  # Secret still exists
                except ApiException as exc:
                    if exc.status == 404:
                        return True  # Secret deleted
                    raise

            return await wait_for_condition(_condition, timeout=90, interval=2)

        try:
            # Create realm (shared Keycloak already ready)
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            ready = await _wait_resource_ready("keycloakrealms", realm_name)
            assert ready, f"Realm {realm_name} did not become Ready"

            # Verify operational token secret was bootstrapped
            operational_secret_name = f"{namespace}-operator-token"
            operational_secret = k8s_core_v1.read_namespaced_secret(
                name=operational_secret_name, namespace=namespace
            )
            assert operational_secret, "Operational token secret should exist"

            # Delete realm
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Verify operational token persists (shared across all realms in namespace)
            # It should NOT be deleted with a single realm
            try:
                secret_after_delete = k8s_core_v1.read_namespaced_secret(
                    name=operational_secret_name, namespace=namespace
                )
                assert secret_after_delete, (
                    "Operational token should persist after realm deletion "
                    "(shared across all realms in namespace)"
                )
            except ApiException as e:
                if e.status == 404:
                    pytest.fail(
                        f"Operational token {operational_secret_name} was deleted "
                        "but should persist (shared resource)"
                    )
                raise

        finally:
            # Cleanup is automatic via owner references (shared Keycloak persists)
            pass
