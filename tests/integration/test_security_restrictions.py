"""Integration tests for security restrictions on client service account roles and script mappers."""

from __future__ import annotations

import uuid

import pytest

from .cleanup_utils import delete_custom_resource_with_retry
from .wait_helpers import wait_for_resource_failed, wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestSecurityRestrictions:
    """Test security restrictions for clients."""

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_service_account_admin_role_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that assigning 'admin' realm role to service account is blocked."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-{suffix}"
        client_name = f"sec-client-admin-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ServiceAccountRoles,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Create realm
        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with 'admin' realm role
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=["admin"], client_roles={}
            ),
            settings=KeycloakClientSettings(service_accounts_enabled=True),
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )

            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Expect Failed state due to ValidationError
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )

        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_service_account_realm_admin_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that assigning 'realm-admin' client role from 'realm-management' is blocked."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-ra-{suffix}"
        client_name = f"sec-client-ra-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ServiceAccountRoles,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with 'realm-admin' role from 'realm-management'
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=[], client_roles={"realm-management": ["realm-admin"]}
            ),
            settings=KeycloakClientSettings(service_accounts_enabled=True),
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )
        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_service_account_manage_realm_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that assigning 'manage-realm' client role from 'realm-management' is blocked."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-mr-{suffix}"
        client_name = f"sec-client-mr-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ServiceAccountRoles,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with 'manage-realm' role from 'realm-management'
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=[], client_roles={"realm-management": ["manage-realm"]}
            ),
            settings=KeycloakClientSettings(service_accounts_enabled=True),
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )
        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_service_account_impersonation_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that assigning 'impersonation' client role from 'realm-management' is blocked by default."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-imp-{suffix}"
        client_name = f"sec-client-imp-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientSettings,
            KeycloakClientSpec,
            RealmRef,
            ServiceAccountRoles,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with 'impersonation' role from 'realm-management'
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            public_client=False,
            service_account_roles=ServiceAccountRoles(
                realm_roles=[], client_roles={"realm-management": ["impersonation"]}
            ),
            settings=KeycloakClientSettings(service_accounts_enabled=True),
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )
        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_saml_script_mapper_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that SAML script mappers are blocked."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-saml-{suffix}"
        client_name = f"sec-client-saml-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientProtocolMapper,
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with SAML script mapper
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            protocol="saml",
            protocol_mappers=[
                KeycloakClientProtocolMapper(
                    name="saml-script-mapper",
                    protocol="saml",
                    protocolMapper="saml-javascript-mapper",
                    config={"script": "test"},
                )
            ],
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )
        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )

    @pytest.mark.timeout(240)  # 90s realm + 90s client + 60s margin for cleanup
    async def test_script_mapper_blocked(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
    ) -> None:
        """Verify that script mappers are blocked by default."""
        namespace = test_namespace
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"sec-realm-sm-{suffix}"
        client_name = f"sec-client-sm-{suffix}"

        from keycloak_operator.models.client import (
            KeycloakClientProtocolMapper,
            KeycloakClientSpec,
            RealmRef,
        )
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            client_authorization_grants=[namespace],
        )
        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        # Client with script mapper
        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(name=realm_name, namespace=namespace),
            client_id=client_name,
            protocol_mappers=[
                KeycloakClientProtocolMapper(
                    name="script-mapper",
                    protocol="openid-connect",
                    protocolMapper="oidc-script-based-protocol-mapper",
                    config={"script": "test"},
                )
            ],
        )
        client_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
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
                timeout=90,
                operator_namespace=operator_namespace,
            )
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )
            await wait_for_resource_failed(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=90,
                operator_namespace=operator_namespace,
            )
        finally:
            # Clean up client first (depends on realm)
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                name=client_name,
                timeout=60,
            )
            # Then clean up realm
            await delete_custom_resource_with_retry(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=60,
            )
