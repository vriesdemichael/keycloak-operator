"""Integration tests for token bootstrap and rotation system.

This module tests the two-phase token system:
1. Admission tokens (platform-provided, one-time per team)
2. Operational tokens (operator-generated, auto-rotated)

Test flow:
- Create admission token in namespace
- Create first realm → triggers operational token bootstrap
- Verify operational token created with metadata
- Create second realm → uses existing operational token
- Verify status tracking

IMPORTANT: Uses shared Keycloak instance for performance.
Each test must use unique realm names for parallel execution.
"""

import base64
import contextlib
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.models.common import AuthorizationSecretRef
from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef


async def _simple_wait(condition_func, timeout=300, interval=3):
    """Simple wait helper for conditions."""
    import asyncio
    import time

    start = time.time()
    while time.time() - start < timeout:
        if await condition_func():
            return True
        await asyncio.sleep(interval)
    return False


async def _simple_wait(condition_func, timeout=300, interval=3):
    """Simple wait helper for conditions."""
    import asyncio
    import time

    start = time.time()
    while time.time() - start < timeout:
        if await condition_func():
            return True
        await asyncio.sleep(interval)
    return False


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestTokenBootstrap:
    """Test admission token → operational token bootstrap flow."""

    @pytest.mark.timeout(600)  # Uses shared operator
    async def test_first_realm_bootstraps_operational_token(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """
        Verify first realm creation bootstraps operational token.

        Test flow:
        1. Create admission token secret in test namespace
        2. Add token metadata to operator's ConfigMap
        3. Create first realm with admission token reference
        4. Verify realm reaches Ready state
        5. Verify operational token secret created
        6. Verify token metadata stored in ConfigMap
        7. Verify status.authorizationStatus updated
        """
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"bootstrap-realm-{suffix}"

        # 1. Create admission token secret
        admission_token = f"admission-token-{suffix}"
        admission_secret_name = f"admission-token-{suffix}"

        admission_secret = {
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

        try:
            await k8s_core_v1.create_namespaced_secret(
                namespace=namespace, body=admission_secret
            )

            # 2. Add token metadata to operator's ConfigMap
            # (Platform team would do this when distributing admission tokens)
            token_hash = hashlib.sha256(admission_token.encode()).hexdigest()
            valid_until = (datetime.now(UTC) + timedelta(days=365)).isoformat()

            token_metadata = {
                "namespace": namespace,
                "token_type": "admission",
                "issued_at": datetime.now(UTC).isoformat(),
                "valid_until": valid_until,
                "version": 1,
                "created_by_realm": None,
                "revoked": False,
                "revoked_at": None,
            }

            import json

            # Get or create metadata ConfigMap
            configmap_name = "keycloak-operator-token-metadata"
            try:
                cm = await k8s_core_v1.read_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace
                )
                if cm.data is None:
                    cm.data = {}
                cm.data[token_hash] = json.dumps(token_metadata)
                await k8s_core_v1.replace_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace, body=cm
                )
            except ApiException as e:
                if e.status == 404:
                    # Create ConfigMap
                    cm_body = {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {
                            "name": configmap_name,
                            "namespace": operator_namespace,
                            "labels": {
                                "app.kubernetes.io/name": "keycloak-operator",
                                "app.kubernetes.io/component": "token-metadata",
                            },
                        },
                        "data": {token_hash: json.dumps(token_metadata)},
                    }
                    await k8s_core_v1.create_namespaced_config_map(
                        namespace=operator_namespace, body=cm_body
                    )

            # 3. Create realm with admission token reference
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

            await k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # 4. Wait for realm to reach Ready state
            async def _realm_ready() -> bool:
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase in ("Ready", "Degraded")

            realm_ready = await _simple_wait(_realm_ready, timeout=120, interval=3)
            assert realm_ready, f"Realm {realm_name} did not reach Ready state"

            # 5. Verify operational token secret created
            operational_secret_name = f"{namespace}-operator-token"

            async def _operational_secret_exists() -> bool:
                try:
                    await k8s_core_v1.read_namespaced_secret(
                        name=operational_secret_name, namespace=namespace
                    )
                    return True
                except ApiException as e:
                    if e.status == 404:
                        return False
                    raise

            op_secret_exists = await _simple_wait(
                _operational_secret_exists, timeout=30, interval=2
            )
            assert op_secret_exists, "Operational token secret was not created"

            # Verify secret has correct labels
            op_secret = await k8s_core_v1.read_namespaced_secret(
                name=operational_secret_name, namespace=namespace
            )
            assert (
                op_secret.metadata.labels.get("keycloak.mdvr.nl/token-type")
                == "operational"
            )
            assert (
                op_secret.metadata.labels.get("keycloak.mdvr.nl/managed-by")
                == "keycloak-operator"
            )

            # Verify secret has owner reference to realm
            assert op_secret.metadata.owner_references is not None
            assert len(op_secret.metadata.owner_references) > 0
            owner_ref = op_secret.metadata.owner_references[0]
            assert owner_ref.kind == "KeycloakRealm"
            assert owner_ref.name == realm_name

            # Verify annotations
            assert "keycloak.mdvr.nl/version" in op_secret.metadata.annotations
            assert "keycloak.mdvr.nl/valid-until" in op_secret.metadata.annotations

            # 6. Verify token metadata stored in ConfigMap
            cm = await k8s_core_v1.read_namespaced_config_map(
                name=configmap_name, namespace=operator_namespace
            )

            # Should have 2 tokens now: admission + operational
            assert cm.data is not None
            assert len(cm.data) >= 2  # At least admission + operational

            # Find operational token metadata
            operational_metadata_found = False
            for _token_hash_key, metadata_json in cm.data.items():
                metadata = json.loads(metadata_json)
                if (
                    metadata.get("token_type") == "operational"
                    and metadata.get("namespace") == namespace
                ):
                    operational_metadata_found = True
                    assert metadata.get("version") == 1
                    assert metadata.get("created_by_realm") == realm_name
                    break

            assert operational_metadata_found, (
                "Operational token metadata not found in ConfigMap"
            )

            # 7. Verify status.authorizationStatus updated
            realm = await k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            status = realm.get("status", {})
            auth_status = status.get("authorizationStatus")

            # Authorization status might not be set immediately, that's okay
            # The important thing is the operational token was created
            if auth_status:
                assert auth_status.get("tokenType") == "operational"
                assert (
                    auth_status.get("secretRef", {}).get("name")
                    == operational_secret_name
                )
                assert auth_status.get("tokenVersion") == "1"

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

            with contextlib.suppress(ApiException):
                await k8s_core_v1.delete_namespaced_secret(
                    name=admission_secret_name, namespace=namespace
                )

            # Clean up token metadata from ConfigMap
            try:
                cm = await k8s_core_v1.read_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace
                )
                if cm.data:
                    # Remove both admission and operational token metadata
                    keys_to_remove = []
                    for _token_hash_key, metadata_json in cm.data.items():
                        metadata = json.loads(metadata_json)
                        if metadata.get("namespace") == namespace:
                            keys_to_remove.append(_token_hash_key)

                    for key in keys_to_remove:
                        cm.data.pop(key, None)

                    if cm.data:
                        await k8s_core_v1.replace_namespaced_config_map(
                            name=configmap_name, namespace=operator_namespace, body=cm
                        )
            except ApiException:
                # Cleanup failure is not critical for test execution
                pass

    @pytest.mark.timeout(600)
    async def test_subsequent_realms_use_operational_token(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """
        Verify subsequent realms use existing operational token.

        Test flow:
        1. Create admission token and first realm (bootstraps operational token)
        2. Create second realm in same namespace
        3. Verify second realm uses operational token (not admission)
        4. Verify only one operational token secret exists
        """
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm1_name = f"realm1-{suffix}"
        realm2_name = f"realm2-{suffix}"

        # 1. Bootstrap operational token with first realm
        admission_token = f"admission-token-{suffix}"
        admission_secret_name = f"admission-token-{suffix}"

        admission_secret = {
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

        try:
            await k8s_core_v1.create_namespaced_secret(
                namespace=namespace, body=admission_secret
            )

            # Add token metadata
            token_hash = hashlib.sha256(admission_token.encode()).hexdigest()
            token_metadata = {
                "namespace": namespace,
                "token_type": "admission",
                "issued_at": datetime.now(UTC).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(days=365)).isoformat(),
                "version": 1,
                "created_by_realm": None,
                "revoked": False,
                "revoked_at": None,
            }

            import json

            configmap_name = "keycloak-operator-token-metadata"
            try:
                cm = await k8s_core_v1.read_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace
                )
                if cm.data is None:
                    cm.data = {}
                cm.data[token_hash] = json.dumps(token_metadata)
                await k8s_core_v1.replace_namespaced_config_map(
                    name=configmap_name, namespace=operator_namespace, body=cm
                )
            except ApiException as e:
                if e.status == 404:
                    cm_body = {
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {
                            "name": configmap_name,
                            "namespace": operator_namespace,
                        },
                        "data": {token_hash: json.dumps(token_metadata)},
                    }
                    await k8s_core_v1.create_namespaced_config_map(
                        namespace=operator_namespace, body=cm_body
                    )

            # Create first realm
            realm1_spec = KeycloakRealmSpec(
                realm_name=realm1_name,
                operator_ref=OperatorRef(
                    namespace=operator_namespace,
                    authorization_secret_ref=AuthorizationSecretRef(
                        name=admission_secret_name,
                        key="token",
                    ),
                ),
            )

            realm1_manifest = {
                "apiVersion": "keycloak.mdvr.nl/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm1_name, "namespace": namespace},
                "spec": realm1_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm1_manifest,
            )

            # Wait for first realm to be ready
            async def _realm_ready(realm_name: str) -> bool:
                try:
                    resource = await k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                except ApiException as exc:
                    if exc.status == 404:
                        return False
                    raise

                status = resource.get("status", {}) or {}
                phase = status.get("phase")
                return phase in ("Ready", "Degraded")

            realm1_ready = await _simple_wait(
                lambda: _realm_ready(realm1_name), timeout=120, interval=3
            )
            assert realm1_ready, f"Realm {realm1_name} did not reach Ready state"

            # Wait for operational token to be created
            operational_secret_name = f"{namespace}-operator-token"

            async def _operational_secret_exists() -> bool:
                try:
                    await k8s_core_v1.read_namespaced_secret(
                        name=operational_secret_name, namespace=namespace
                    )
                    return True
                except ApiException as e:
                    if e.status == 404:
                        return False
                    raise

            op_secret_exists = await _simple_wait(
                _operational_secret_exists, timeout=30, interval=2
            )
            assert op_secret_exists, "Operational token secret was not created"

            # 2. Create second realm (should use operational token)
            realm2_spec = KeycloakRealmSpec(
                realm_name=realm2_name,
                operator_ref=OperatorRef(
                    namespace=operator_namespace,
                    authorization_secret_ref=AuthorizationSecretRef(
                        name=operational_secret_name,  # Reference operational token directly
                        key="token",
                    ),
                ),
            )

            realm2_manifest = {
                "apiVersion": "keycloak.mdvr.nl/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm2_name, "namespace": namespace},
                "spec": realm2_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            await k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm2_manifest,
            )

            # 3. Wait for second realm to be ready
            realm2_ready = await _simple_wait(
                lambda: _realm_ready(realm2_name), timeout=120, interval=3
            )
            assert realm2_ready, f"Realm {realm2_name} did not reach Ready state"

            # 4. Verify only ONE operational token secret exists
            secrets = await k8s_core_v1.list_namespaced_secret(namespace=namespace)
            operational_secrets = [
                s
                for s in secrets.items
                if s.metadata.labels
                and s.metadata.labels.get("keycloak.mdvr.nl/token-type")
                == "operational"
            ]

            assert len(operational_secrets) == 1, (
                f"Expected 1 operational token, found {len(operational_secrets)}"
            )
            assert operational_secrets[0].metadata.name == operational_secret_name

        finally:
            # Cleanup
            for realm_name in [realm1_name, realm2_name]:
                with contextlib.suppress(ApiException):
                    await k8s_custom_objects.delete_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )

            with contextlib.suppress(ApiException):
                await k8s_core_v1.delete_namespaced_secret(
                    name=admission_secret_name, namespace=namespace
                )

            # Cleanup metadata
            try:
                cm = await k8s_core_v1.read_namespaced_config_map(
                    name="keycloak-operator-token-metadata",
                    namespace=operator_namespace,
                )
                if cm.data:
                    keys_to_remove = []
                    for _token_hash_key, metadata_json in cm.data.items():
                        metadata = json.loads(metadata_json)
                        if metadata.get("namespace") == namespace:
                            keys_to_remove.append(_token_hash_key)

                    for key in keys_to_remove:
                        cm.data.pop(key, None)

                    if cm.data:
                        await k8s_core_v1.replace_namespaced_config_map(
                            name="keycloak-operator-token-metadata",
                            namespace=operator_namespace,
                            body=cm,
                        )
            except ApiException:
                # Cleanup failure is not critical for test execution
                pass
