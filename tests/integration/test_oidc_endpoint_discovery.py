"""Integration tests for OIDC endpoint discovery in realm status."""

from __future__ import annotations

import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestOIDCEndpointDiscovery:
    """Test OIDC endpoint discovery and population in realm status."""

    @pytest.mark.timeout(
        180
    )  # 3 minutes: realm creation (60s) + verification (30s) + cleanup (90s)
    async def test_realm_status_contains_oidc_endpoints(
        self, k8s_custom_objects, test_namespace, operator_namespace, shared_operator
    ) -> None:
        """Verify that realm status contains all OIDC discovery endpoints.

        This integration test verifies that when a realm is created,
        its status is populated with all standard OIDC endpoints including:
        - issuer
        - auth
        - token
        - userinfo
        - jwks
        - endSession
        - registration
        """

        # Use shared Keycloak instance in operator namespace
        namespace = test_namespace

        suffix = uuid.uuid4().hex[:8]
        realm_name = f"oidc-endpoints-realm-{suffix}"

        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        # Create a realm with OIDC endpoints
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
            # Create realm and wait until Ready
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
                allow_degraded=False,
            )

            # Fetch the realm resource to check status
            realm = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Verify status exists
            assert "status" in realm, "Realm status should exist"
            status = realm["status"]

            # Verify endpoints exist in status
            assert "endpoints" in status, "Realm status should contain endpoints"
            endpoints = status["endpoints"]

            # Verify all required OIDC endpoints are present
            required_endpoints = [
                "issuer",
                "auth",
                "token",
                "userinfo",
                "jwks",
                "endSession",
                "registration",
            ]

            for endpoint_name in required_endpoints:
                assert (
                    endpoint_name in endpoints
                ), f"Endpoint '{endpoint_name}' should be present in status.endpoints"
                assert endpoints[
                    endpoint_name
                ], f"Endpoint '{endpoint_name}' should not be empty"

            # Verify endpoint URLs follow expected patterns
            issuer = endpoints["issuer"]
            assert realm_name in issuer, f"Issuer should contain realm name: {issuer}"
            assert (
                "/realms/" in issuer
            ), f"Issuer should contain '/realms/' path: {issuer}"

            # Verify other endpoints are based on issuer
            assert endpoints["auth"].startswith(
                issuer
            ), "Auth endpoint should start with issuer URL"
            assert endpoints["token"].startswith(
                issuer
            ), "Token endpoint should start with issuer URL"
            assert endpoints["userinfo"].startswith(
                issuer
            ), "UserInfo endpoint should start with issuer URL"
            assert endpoints["jwks"].startswith(
                issuer
            ), "JWKS endpoint should start with issuer URL"
            assert endpoints["endSession"].startswith(
                issuer
            ), "EndSession endpoint should start with issuer URL"
            assert endpoints["registration"].startswith(
                issuer
            ), "Registration endpoint should start with issuer URL"

            # Verify OIDC protocol paths
            assert (
                "/protocol/openid-connect/auth" in endpoints["auth"]
            ), "Auth endpoint should contain OIDC protocol path"
            assert (
                "/protocol/openid-connect/token" in endpoints["token"]
            ), "Token endpoint should contain OIDC protocol path"
            assert (
                "/protocol/openid-connect/userinfo" in endpoints["userinfo"]
            ), "UserInfo endpoint should contain OIDC protocol path"
            assert (
                "/protocol/openid-connect/certs" in endpoints["jwks"]
            ), "JWKS endpoint should contain OIDC protocol path"
            assert (
                "/protocol/openid-connect/logout" in endpoints["endSession"]
            ), "EndSession endpoint should contain OIDC protocol path"
            assert (
                "/protocol/openid-connect/registrations" in endpoints["registration"]
            ), "Registration endpoint should contain OIDC protocol path"

        finally:
            # Cleanup realm (explicit cleanup prevents test fixture timeout)
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
