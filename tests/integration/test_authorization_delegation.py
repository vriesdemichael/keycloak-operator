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
    ) -> None:
        """Verify that realms validate the operator token before reconciliation.

        Test flow:
        1. Use shared Keycloak instance
        2. Create realm with valid operator token reference
        3. Verify realm reaches Ready state
        4. Verify realm authorization secret is created
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"auth-realm-{suffix}"
        
        # Create admission token in test namespace for bootstrap
        # (New auth system requires token in same namespace as realm)
        admission_secret_name = f"admission-token-{suffix}"
        admission_token = f"test-admission-token-{suffix}"
        
        # Create admission token secret
        from datetime import UTC, datetime, timedelta
        import hashlib
        import json
        
        secret_body = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": admission_secret_name,
                "namespace": namespace,
                "labels": {
                    "keycloak.mdvr.nl/allow-operator-read": "true",
                    "keycloak.mdvr.nl/token-type": "admission",
                },
            },
            "type": "Opaque",
            "data": {
                "token": base64.b64encode(admission_token.encode()).decode(),
            },
        }
        
        k8s_core_v1.create_namespaced_secret(namespace, secret_body)
        
        # Store admission token metadata in operator namespace ConfigMap
        token_hash = hashlib.sha256(admission_token.encode()).hexdigest()
        valid_until = datetime.now(UTC) + timedelta(days=365)
        
        token_metadata = {
            "namespace": namespace,
            "token_type": "admission",
            "issued_at": datetime.now(UTC).isoformat(),
            "valid_until": valid_until.isoformat(),
            "version": 1,
            "created_by_realm": None,
            "revoked": False,
            "revoked_at": None,
        }
        
        # Update or create metadata ConfigMap
        configmap_name = "keycloak-operator-token-metadata"
        try:
            cm = k8s_core_v1.read_namespaced_config_map(
                name=configmap_name, namespace=operator_namespace
            )
            if not cm.data:
                cm.data = {}
            cm.data[token_hash] = json.dumps(token_metadata)
            k8s_core_v1.patch_namespaced_config_map(
                name=configmap_name, namespace=operator_namespace, body=cm
            )
        except ApiException as e:
            if e.status == 404:
                # ConfigMap doesn't exist, create it
                cm_body = {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": configmap_name,
                        "namespace": operator_namespace,
                    },
                    "data": {token_hash: json.dumps(token_metadata)},
                }
                k8s_core_v1.create_namespaced_config_map(
                    namespace=operator_namespace, body=cm_body
                )
            else:
                raise

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
            # Cleanup realm only (shared Keycloak persists)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
            
            # Cleanup admission secret
            with contextlib.suppress(ApiException):
                k8s_core_v1.delete_namespaced_secret(
                    name=admission_secret_name, namespace=namespace
                )
            
            # Cleanup token metadata from ConfigMap
            try:
                cm = k8s_core_v1.read_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace
                )
                if cm.data and token_hash in cm.data:
                    del cm.data[token_hash]
                    k8s_core_v1.patch_namespaced_config_map(
                        name=configmap_name, namespace=operator_namespace, body=cm
                    )
            except ApiException:
                pass  # ConfigMap might not exist or already cleaned up

    @pytest.mark.timeout(600)
    async def test_client_validates_realm_token(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
        wait_for_condition,
    ) -> None:
        """Verify that clients validate realm token before reconciliation.

        Test flow:
        1. Use shared Keycloak instance
        2. Create realm (generates realm token)
        3. Create client with realmRef pointing to realm's token
        4. Verify client reaches Ready state
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"client-realm-{suffix}"
        client_name = f"client-{suffix}"

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
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
                namespace=namespace,  # Point to our fake secret in test namespace
                authorization_secret_ref=AuthorizationSecretRef(
                    name=fake_secret_name,
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
    ) -> None:
        """Verify that clients with invalid realm token are rejected.

        Test flow:
        1. Use shared Keycloak and create realm
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

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
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
    ) -> None:
        """Verify that realm authorization secrets are deleted with the realm.

        Test flow:
        1. Use shared Keycloak and create realm
        2. Verify realm authorization secret exists
        3. Delete realm
        4. Verify authorization secret is automatically deleted (owner reference)
        """

        # Use shared Keycloak instance (already ready)
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"cleanup-realm-{suffix}"

        realm_spec = KeycloakRealmSpec(
            realm_name=realm_name,
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
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

            # Get authorization secret name
            realm = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            status = realm.get("status", {}) or {}
            auth_secret_name = status.get("authorizationSecretName")
            assert auth_secret_name, "Realm should have authorizationSecretName"

            # Verify secret exists
            secret = k8s_core_v1.read_namespaced_secret(
                name=auth_secret_name, namespace=namespace
            )
            assert secret, "Authorization secret should exist"

            # Delete realm
            k8s_custom_objects.delete_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for secret to be deleted (via owner reference)
            deleted = await _wait_secret_deleted(auth_secret_name)
            assert deleted, (
                f"Authorization secret {auth_secret_name} should be "
                "automatically deleted with realm"
            )

        finally:
            # Cleanup is automatic via owner references (shared Keycloak persists)
            pass
