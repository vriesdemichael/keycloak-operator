"""
Integration tests for operator lifecycle and basic functionality.

These tests validate that the operator can be deployed, becomes healthy,
and can manage Keycloak resources in a real Kubernetes environment.
"""

import contextlib

import pytest
from kubernetes.client.rest import ApiException


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestOperatorLifecycle:
    """Test operator deployment and basic lifecycle."""

    async def test_operator_deployment_exists(self, k8s_apps_v1, operator_namespace):
        """Test that the operator deployment exists and is ready."""
        try:
            deployment = k8s_apps_v1.read_namespaced_deployment(
                name="keycloak-operator", namespace=operator_namespace
            )

            assert deployment.status.ready_replicas > 0, (
                "Operator has no ready replicas"
            )
            assert deployment.status.replicas == deployment.status.ready_replicas, (
                "Not all operator replicas are ready"
            )

        except ApiException as e:
            pytest.fail(f"Failed to read operator deployment: {e}")

    async def test_operator_pods_healthy(self, k8s_core_v1, operator_namespace):
        """Test that operator pods are running and healthy."""
        try:
            pods = k8s_core_v1.list_namespaced_pod(
                namespace=operator_namespace,
                label_selector="app.kubernetes.io/name=keycloak-operator",
            )

            assert len(pods.items) > 0, "No operator pods found"

            for pod in pods.items:
                assert pod.status.phase == "Running", (
                    f"Pod {pod.metadata.name} is not running"
                )

                # Check container readiness
                if pod.status.container_statuses:
                    for container in pod.status.container_statuses:
                        assert container.ready, (
                            f"Container {container.name} is not ready"
                        )

        except ApiException as e:
            pytest.fail(f"Failed to list operator pods: {e}")

    async def test_operator_crds_installed(self, k8s_client):
        """Test that required CRDs are installed and available."""
        from kubernetes import client

        api = client.ApiextensionsV1Api(k8s_client)

        required_crds = [
            "keycloaks.keycloak.mdvr.nl",
            "keycloakrealms.keycloak.mdvr.nl",
            "keycloakclients.keycloak.mdvr.nl",
        ]

        for crd_name in required_crds:
            try:
                crd = api.read_custom_resource_definition(name=crd_name)
                assert crd.status.conditions, f"CRD {crd_name} has no status conditions"

                # Check if CRD is established
                established = False
                for condition in crd.status.conditions:
                    if condition.type == "Established" and condition.status == "True":
                        established = True
                        break

                assert established, f"CRD {crd_name} is not established"

            except ApiException as e:
                pytest.fail(f"Failed to read CRD {crd_name}: {e}")

    async def test_operator_rbac_permissions(self, k8s_client, operator_namespace):
        """Test that operator has required RBAC permissions."""
        from kubernetes import client

        rbac_api = client.RbacAuthorizationV1Api(k8s_client)

        try:
            # Check ClusterRole exists
            cluster_role = rbac_api.read_cluster_role(name="keycloak-operator")
            assert cluster_role.rules, "ClusterRole has no rules"

            # Check if essential permissions are present
            required_permissions = [
                (
                    "keycloak.mdvr.nl",
                    ["keycloaks", "keycloakrealms", "keycloakclients"],
                ),
                ("apps", ["deployments"]),
                ("", ["services", "secrets"]),
                ("coordination.k8s.io", ["leases"]),  # For leader election
            ]

            for api_group, resources in required_permissions:
                found = False
                for rule in cluster_role.rules:
                    if api_group in (rule.api_groups or []) and any(
                        resource in (rule.resources or []) for resource in resources
                    ):
                        found = True
                        break
                assert found, (
                    f"Missing permissions for {api_group} resources: {resources}"
                )

        except ApiException as e:
            pytest.fail(f"Failed to check RBAC permissions: {e}")


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestBasicKeycloakDeployment:
    """Test basic Keycloak resource deployment."""

    async def test_create_keycloak_resource(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test creating a basic Keycloak resource."""
        keycloak_name = "test-keycloak"

        # Create Keycloak resource
        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        try:
            # Create the resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for resource to be processed
            async def check_resource_created():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloaks",
                        name=keycloak_name,
                    )
                    return resource is not None
                except ApiException:
                    return False

            assert await wait_for_condition(check_resource_created, timeout=180), (
                "Keycloak resource was not created successfully"
            )

        except ApiException as e:
            pytest.fail(f"Failed to create Keycloak resource: {e}")

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    async def test_keycloak_finalizer_added(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test that finalizers are properly added to Keycloak resources."""
        keycloak_name = "test-keycloak-finalizer"

        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        try:
            # Create the resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for finalizer to be added
            async def check_finalizer_added():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
                        plural="keycloaks",
                        name=keycloak_name,
                    )
                    finalizers = resource.get("metadata", {}).get("finalizers", [])
                    return "keycloak.mdvr.nl/cleanup" in finalizers
                except ApiException:
                    return False

            assert await wait_for_condition(check_finalizer_added, timeout=300), (
                "Finalizer was not added to Keycloak resource"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test finalizer behavior: {e}")

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )

    async def test_keycloak_deployment_created(
        self,
        k8s_custom_objects,
        k8s_apps_v1,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test that Keycloak deployment is created for Keycloak resource."""
        keycloak_name = "test-keycloak-deployment"

        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        try:
            # Create the resource
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for deployment to be created
            async def check_deployment_created():
                try:
                    deployment = k8s_apps_v1.read_namespaced_deployment(
                        name=f"{keycloak_name}-keycloak", namespace=test_namespace
                    )
                    return deployment is not None
                except ApiException:
                    return False

            assert await wait_for_condition(check_deployment_created, timeout=480), (
                "Keycloak deployment was not created"
            )

            # Verify deployment has correct configuration
            deployment = k8s_apps_v1.read_namespaced_deployment(
                name=f"{keycloak_name}-keycloak", namespace=test_namespace
            )

            assert deployment.spec.replicas == 1, (
                "Deployment has incorrect replica count"
            )
            assert len(deployment.spec.template.spec.containers) > 0, (
                "Deployment has no containers"
            )

            container = deployment.spec.template.spec.containers[0]
            assert "keycloak" in container.image.lower(), (
                "Container is not using Keycloak image"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test deployment creation: {e}")

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
