"""
Integration tests for Realm security headers.

Tests verify that browser security headers are correctly configured in Keycloak.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import wait_for_resource_ready


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmSecurityHeaders:
    """Test Realm security headers functionality."""

    @pytest.mark.timeout(300)
    async def test_realm_security_headers(
        self,
        k8s_custom_objects,
        test_namespace,
        operator_namespace,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test configuring browser security headers."""
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-headers-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakBrowserSecurityHeaders,
            KeycloakRealmSpec,
            OperatorRef,
        )

        headers = KeycloakBrowserSecurityHeaders(
            contentSecurityPolicy="frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            xFrameOptions="SAMEORIGIN",
            xContentTypeOptions="nosniff",
            xRobotsTag="none",
            xXSSProtection="1; mode=block",
            strictTransportSecurity="max-age=31536000; includeSubDomains",
            referrerPolicy="no-referrer",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Test Security Headers Realm",
            client_authorization_grants=[namespace],
            browserSecurityHeaders=headers,
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
                timeout=150,
                operator_namespace=operator_namespace,
            )

            # VERIFY: Check headers in Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None

            # The Keycloak API returns browserSecurityHeaders as a dict
            security_headers = realm_repr.browser_security_headers
            assert security_headers is not None
            assert (
                security_headers["contentSecurityPolicy"]
                == "frame-src 'self'; frame-ancestors 'self'; object-src 'none';"
            )
            assert security_headers["xFrameOptions"] == "SAMEORIGIN"
            assert security_headers["xContentTypeOptions"] == "nosniff"
            assert security_headers["xRobotsTag"] == "none"
            assert security_headers["xXSSProtection"] == "1; mode=block"
            assert (
                security_headers["strictTransportSecurity"]
                == "max-age=31536000; includeSubDomains"
            )
            assert security_headers["referrerPolicy"] == "no-referrer"

            # UPDATE: Change headers
            for attempt in range(5):
                try:
                    realm_cr = await k8s_custom_objects.get_namespaced_custom_object(
                        group="vriesdemichael.github.io",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )

                    current_spec = KeycloakRealmSpec.model_validate(realm_cr["spec"])
                    # Update X-Frame-Options to DENY
                    if current_spec.browser_security_headers:
                        current_spec.browser_security_headers.x_frame_options = "DENY"
                        # Add Report Only CSP
                        current_spec.browser_security_headers.content_security_policy_report_only = "default-src 'none';"
                    else:
                        # Should not happen given setup, but for type safety
                        current_spec.browser_security_headers = (
                            KeycloakBrowserSecurityHeaders(
                                xFrameOptions="DENY",
                                contentSecurityPolicyReportOnly="default-src 'none';",
                            )
                        )

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
                    break
                except ApiException as e:
                    if e.status == 409 and attempt < 4:
                        await asyncio.sleep(0.5)
                        continue
                    raise

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

            # Wait for update in Keycloak
            max_attempts = 10
            for attempt in range(max_attempts):
                realm_repr = await keycloak_admin_client.get_realm(
                    realm_name, namespace
                )
                headers = realm_repr.browser_security_headers
                if headers and headers.get("xFrameOptions") == "DENY":
                    break
                if attempt < max_attempts - 1:
                    await asyncio.sleep(1)

            # VERIFY updates
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            security_headers = realm_repr.browser_security_headers
            assert security_headers["xFrameOptions"] == "DENY"
            assert (
                security_headers["contentSecurityPolicyReportOnly"]
                == "default-src 'none';"
            )

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
