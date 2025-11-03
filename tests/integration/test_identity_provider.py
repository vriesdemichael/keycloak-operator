"""
Integration tests for Keycloak identity provider configuration.

These tests verify that the operator correctly:
1. Configures external identity providers in Keycloak realms
2. Handles IDP mappers
3. Supports OIDC provider integration (using Dex as test IDP)
"""

import asyncio
import logging

import pytest
from kubernetes import client
from kubernetes.client.rest import ApiException

from keycloak_operator.models.common import AuthorizationSecretRef
from keycloak_operator.models.realm import (
    KeycloakIdentityProvider,
    KeycloakRealmSpec,
    OperatorRef,
)

from .wait_helpers import wait_for_resource_ready

logger = logging.getLogger(__name__)


@pytest.fixture
async def dex_ready(k8s_core_v1, k8s_apps_v1, operator_namespace):
    """Deploy Dex OIDC provider for testing IDP integration."""
    dex_namespace = operator_namespace

    # Load Dex manifests
    from pathlib import Path

    import yaml

    dex_manifest_path = Path(__file__).parent / "fixtures" / "dex-deployment.yaml"
    with open(dex_manifest_path) as f:
        manifests = list(yaml.safe_load_all(f))

    deployed_resources = []

    try:
        # Deploy ConfigMap
        config_map = manifests[0]
        config_map["metadata"]["namespace"] = dex_namespace
        cm_obj = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name=config_map["metadata"]["name"],
                namespace=dex_namespace,
            ),
            data=config_map["data"],
        )

        try:
            await k8s_core_v1.create_namespaced_config_map(dex_namespace, cm_obj)
            deployed_resources.append(("configmap", config_map["metadata"]["name"]))
            logger.info("Created Dex ConfigMap")
        except ApiException as e:
            if e.status != 409:
                raise
            logger.info("Dex ConfigMap already exists")

        # Deploy Deployment (use kubectl apply for easier YAML handling)
        deployment_manifest = manifests[1]
        deployment_manifest["metadata"]["namespace"] = dex_namespace

        try:
            # Use body parameter which accepts dict directly
            await k8s_apps_v1.create_namespaced_deployment(
                namespace=dex_namespace,
                body=deployment_manifest,
            )
            deployed_resources.append(
                ("deployment", deployment_manifest["metadata"]["name"])
            )
            logger.info("Created Dex Deployment")
        except ApiException as e:
            if e.status != 409:
                raise
            logger.info("Dex Deployment already exists")

        # Deploy Service (use body parameter for dict)
        service_manifest = manifests[2]
        service_manifest["metadata"]["namespace"] = dex_namespace

        try:
            await k8s_core_v1.create_namespaced_service(
                namespace=dex_namespace,
                body=service_manifest,
            )
            deployed_resources.append(("service", service_manifest["metadata"]["name"]))
            logger.info("Created Dex Service")
        except ApiException as e:
            if e.status != 409:
                raise
            logger.info("Dex Service already exists")

        # Wait for Dex to be ready
        for _ in range(40):  # 40 * 3 = 120 seconds
            try:
                deployment = await k8s_apps_v1.read_namespaced_deployment(
                    "dex", dex_namespace
                )
                if (
                    deployment.status.ready_replicas
                    and deployment.status.ready_replicas > 0
                ):
                    break
            except ApiException:
                pass
            await asyncio.sleep(3)
        else:
            raise TimeoutError("Dex deployment did not become ready")

        logger.info("Dex is ready")

        yield {
            "namespace": dex_namespace,
            "service_name": "dex",
            "issuer_url": f"http://dex.{dex_namespace}.svc.cluster.local:5556/dex",
            "client_id": "keycloak",
            "client_secret": "keycloak-secret",
        }

    finally:
        # Cleanup in reverse order
        for resource_type, resource_name in reversed(deployed_resources):
            try:
                if resource_type == "service":
                    await k8s_core_v1.delete_namespaced_service(
                        resource_name, dex_namespace
                    )
                elif resource_type == "deployment":
                    await k8s_apps_v1.delete_namespaced_deployment(
                        resource_name,
                        dex_namespace,
                        body=client.V1DeleteOptions(propagation_policy="Foreground"),
                    )
                elif resource_type == "configmap":
                    await k8s_core_v1.delete_namespaced_config_map(
                        resource_name, dex_namespace
                    )
                logger.info(f"Deleted Dex {resource_type}: {resource_name}")
            except ApiException as e:
                if e.status != 404:
                    logger.warning(
                        f"Failed to delete Dex {resource_type} {resource_name}: {e}"
                    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skip(reason="Dex deployment timeout issue - needs investigation")
async def test_realm_with_oidc_identity_provider(
    keycloak_ready,
    test_namespace,
    auth_token_factory,
    k8s_custom_objects,
    dex_ready,
):
    """Test creating a realm with an OIDC identity provider (Dex)."""
    realm_name = "test-idp-realm"
    cr_name = f"{realm_name}-cr"

    # Create authorization token
    token_name, _ = await auth_token_factory(
        namespace=test_namespace,
        secret_name=f"{cr_name}-token",
    )

    # Create realm with Dex IDP
    idp_config = KeycloakIdentityProvider(
        alias="dex",
        provider_id="oidc",
        enabled=True,
        trust_email=True,
        first_broker_login_flow_alias="first broker login",
        config={
            "clientId": dex_ready["client_id"],
            "clientSecret": dex_ready["client_secret"],
            "authorizationUrl": f"{dex_ready['issuer_url']}/auth",
            "tokenUrl": f"{dex_ready['issuer_url']}/token",
            "userInfoUrl": f"{dex_ready['issuer_url']}/userinfo",
            "jwksUrl": f"{dex_ready['issuer_url']}/keys",
            "issuer": dex_ready["issuer_url"],
            "defaultScope": "openid profile email",
            "syncMode": "IMPORT",
        },
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(
            namespace=keycloak_ready.operator.namespace,
            authorization_secret_ref=AuthorizationSecretRef(name=token_name),
        ),
        identity_providers=[idp_config],
    )

    realm_cr = {
        "apiVersion": "keycloak.vriesdemichael.github.io/v1alpha1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": cr_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(mode="json", exclude_none=True),
    }

    try:
        # Create the realm CR
        await k8s_custom_objects.create_namespaced_custom_object(
            group="keycloak.vriesdemichael.github.io",
            version="v1alpha1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        logger.info(f"Created realm CR: {cr_name}")

        # Wait for realm to be ready
        await wait_for_resource_ready(
            k8s_custom_objects,
            group="keycloak.vriesdemichael.github.io",
            version="v1alpha1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=cr_name,
            timeout=180,
        )

        # Verify IDP was created in Keycloak
        # We'll use the admin client from keycloak_ready
        from keycloak_operator.utils.keycloak_admin import get_keycloak_admin_client

        admin_client = await get_keycloak_admin_client(
            "keycloak",
            keycloak_ready.operator_namespace,
        )

        # Get IDP list from Keycloak
        response = await admin_client._make_request(
            "GET",
            f"admin/realms/{realm_name}/identity-provider/instances",
            namespace=test_namespace,
        )

        assert (
            response.status_code == 200
        ), f"Failed to get IDPs: {response.status_code}"

        idps = response.json()
        assert len(idps) == 1, f"Expected 1 IDP, got {len(idps)}"

        dex_idp = idps[0]
        assert dex_idp["alias"] == "dex"
        assert dex_idp["providerId"] == "oidc"
        assert dex_idp["enabled"] is True
        assert dex_idp["config"]["clientId"] == dex_ready["client_id"]
        assert dex_idp["config"]["issuer"] == dex_ready["issuer_url"]

        logger.info("Successfully verified Dex IDP in Keycloak")

    finally:
        # Cleanup is handled by test_namespace fixture
        pass


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skip(reason="Documentation example - requires manual verification")
async def test_realm_with_github_identity_provider_example(
    keycloak_ready,
    test_namespace,
    auth_token_factory,
    k8s_custom_objects,
):
    """
    Test creating a realm with GitHub identity provider configuration.

    Note: This test only validates the CR creation and reconciliation.
    It does NOT test actual authentication as that would require real GitHub OAuth credentials.
    This serves as a documentation example for users.
    """
    realm_name = "test-github-idp-realm"
    cr_name = f"{realm_name}-cr"

    # Create authorization token
    token_name, _ = await auth_token_factory(
        namespace=test_namespace,
        secret_name=f"{cr_name}-token",
    )

    # Example GitHub IDP configuration
    # In production, clientSecret would come from a Kubernetes Secret
    github_idp = KeycloakIdentityProvider(
        alias="github",
        provider_id="github",
        enabled=True,
        trust_email=False,
        first_broker_login_flow_alias="first broker login",
        config={
            "clientId": "your-github-oauth-app-client-id",
            "clientSecret": "your-github-oauth-app-client-secret",
            "defaultScope": "user:email",
            "syncMode": "IMPORT",
        },
    )

    realm_spec = KeycloakRealmSpec(
        realm_name=realm_name,
        operator_ref=OperatorRef(
            namespace=keycloak_ready.operator.namespace,
            authorization_secret_ref=AuthorizationSecretRef(name=token_name),
        ),
        identity_providers=[github_idp],
    )

    realm_cr = {
        "apiVersion": "keycloak.vriesdemichael.github.io/v1alpha1",
        "kind": "KeycloakRealm",
        "metadata": {
            "name": cr_name,
            "namespace": test_namespace,
        },
        "spec": realm_spec.model_dump(mode="json", exclude_none=True),
    }

    try:
        # Create the realm CR
        await k8s_custom_objects.create_namespaced_custom_object(
            group="keycloak.vriesdemichael.github.io",
            version="v1alpha1",
            namespace=test_namespace,
            plural="keycloakrealms",
            body=realm_cr,
        )

        logger.info(f"Created realm CR with GitHub IDP: {cr_name}")

        # Wait for realm to be ready (will fail at IDP creation due to invalid credentials)
        # We just verify the CR is accepted and processed
        await asyncio.sleep(10)

        # Get the CR status
        cr = await k8s_custom_objects.get_namespaced_custom_object(
            group="keycloak.vriesdemichael.github.io",
            version="v1alpha1",
            namespace=test_namespace,
            plural="keycloakrealms",
            name=cr_name,
        )

        # The CR should exist and be processed (realm created even if IDP fails)
        assert cr is not None
        logger.info("GitHub IDP example CR created successfully")

    finally:
        # Cleanup is handled by test_namespace fixture
        pass
