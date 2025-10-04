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
    """Test basic Keycloak resource deployment using a shared instance."""

    async def test_create_keycloak_resource(
        self,
        k8s_custom_objects,
        shared_keycloak_instance,
    ):
        """Test that the shared Keycloak resource was created successfully."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify the shared resource exists
            resource = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
            )
            assert resource is not None, "Keycloak resource was not created"

        except ApiException as e:
            pytest.fail(f"Failed to verify Keycloak resource: {e}")

    async def test_keycloak_finalizer_added(
        self,
        k8s_custom_objects,
        shared_keycloak_instance,
    ):
        """Test that finalizers are properly added to the shared Keycloak resource."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify finalizer exists on shared resource
            resource = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
            )
            finalizers = resource.get("metadata", {}).get("finalizers", [])
            assert "keycloak.mdvr.nl/cleanup" in finalizers, (
                "Finalizer was not added to Keycloak resource"
            )

        except ApiException as e:
            pytest.fail(f"Failed to verify finalizer: {e}")

    async def test_keycloak_deployment_created(
        self,
        k8s_apps_v1,
        shared_keycloak_instance,
    ):
        """Test that Keycloak deployment is created for the shared resource."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify deployment exists
            deployment = k8s_apps_v1.read_namespaced_deployment(
                name=f"{keycloak_name}-keycloak", namespace=namespace
            )

            # Verify deployment has correct configuration
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
            pytest.fail(f"Failed to verify deployment: {e}")

    async def test_keycloak_service_created(
        self,
        k8s_core_v1,
        shared_keycloak_instance,
    ):
        """Test that Keycloak service is created for the shared resource."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify service exists
            service = k8s_core_v1.read_namespaced_service(
                name=f"{keycloak_name}-keycloak", namespace=namespace
            )

            # Verify service configuration
            assert service.spec.type == "ClusterIP", "Service has incorrect type"
            assert len(service.spec.ports) > 0, "Service has no ports"
            assert service.spec.ports[0].port == 8080, "Service has incorrect port"

        except ApiException as e:
            pytest.fail(f"Failed to verify service: {e}")

    async def test_keycloak_becomes_ready(
        self,
        k8s_custom_objects,
        shared_keycloak_instance,
    ):
        """Test that the shared Keycloak instance is ready and operational."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify status is set correctly (instance is already ready from fixture)
            resource = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            status = resource.get("status", {})
            assert status, "Keycloak resource has no status"

        except ApiException as e:
            pytest.fail(f"Failed to verify Keycloak readiness: {e}")

    async def test_keycloak_pods_running(
        self,
        k8s_core_v1,
        shared_keycloak_instance,
    ):
        """Test that Keycloak pods are running and healthy for the shared instance."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]

        try:
            # Verify pods are running (instance is already ready from fixture)
            pods = k8s_core_v1.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"keycloak.mdvr.nl/instance={keycloak_name}",
            )

            assert pods.items, "No Keycloak pods found"

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
            pytest.fail(f"Failed to verify Keycloak pods: {e}")


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestKeycloakAdminAPI:
    """Test Keycloak admin API accessibility and basic operations."""

    async def test_keycloak_admin_api_accessible(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        sample_keycloak_spec,
        wait_for_keycloak_ready,
        wait_for_condition,
    ):
        """Test that Keycloak instance is ready to take admin API requests."""
        keycloak_name = "test-keycloak-api"

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

            # Wait for Keycloak to become ready
            assert await wait_for_keycloak_ready(
                keycloak_name, test_namespace, timeout=420
            ), "Keycloak instance did not become ready for API testing"

            # Verify admin credentials are accessible
            async def check_admin_secret():
                try:
                    secret_name = sample_keycloak_spec["spec"]["admin_access"][
                        "password_secret"
                    ]["name"]
                    secret = k8s_core_v1.read_namespaced_secret(
                        name=secret_name, namespace=test_namespace
                    )
                    return secret is not None and "password" in (secret.data or {})
                except ApiException:
                    return False

            assert await wait_for_condition(check_admin_secret, timeout=60), (
                "Admin credentials not available"
            )

            # Verify service endpoint is available
            service = k8s_core_v1.read_namespaced_service(
                name=f"{keycloak_name}-keycloak", namespace=test_namespace
            )
            assert service.spec.cluster_ip, "Service has no cluster IP"

        except ApiException as e:
            pytest.fail(f"Failed to test admin API accessibility: {e}")

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


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmBasicOperations:
    """Test basic realm operations using a shared Keycloak instance."""

    async def test_create_realm_resource(
        self,
        k8s_custom_objects,
        shared_keycloak_instance,
        sample_realm_spec,
        wait_for_condition,
    ):
        """Test creating a basic realm resource on the shared Keycloak instance."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]
        realm_name = "test-realm-basic"

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = namespace
        realm_manifest["spec"]["keycloak_instance_ref"]["name"] = keycloak_name

        try:
            # Create realm on the shared Keycloak instance
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be created
            async def check_realm_created():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakrealms",
                        name=realm_name,
                    )
                    return resource is not None
                except ApiException:
                    return False

            assert await wait_for_condition(check_realm_created, timeout=180), (
                "Realm resource was not created successfully"
            )

        except ApiException as e:
            pytest.fail(f"Failed to create realm resource: {e}")

        finally:
            # Cleanup realm only (shared Keycloak is managed by fixture)
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestClientBasicOperations:
    """Test basic client operations using a shared Keycloak instance."""

    async def test_create_client_resource(
        self,
        k8s_custom_objects,
        shared_keycloak_instance,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
    ):
        """Test creating a basic client resource on the shared Keycloak instance."""
        keycloak_name = shared_keycloak_instance["name"]
        namespace = shared_keycloak_instance["namespace"]
        realm_name = "test-client-realm"
        client_name = "test-client-basic"

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = namespace
        realm_manifest["spec"]["keycloak_instance_ref"]["name"] = keycloak_name

        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": namespace},
        }
        client_manifest["spec"]["keycloak_instance_ref"]["namespace"] = namespace
        client_manifest["spec"]["keycloak_instance_ref"]["name"] = keycloak_name

        try:
            # Create realm on shared Keycloak instance
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Create client
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to be created
            async def check_client_created():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=namespace,
                        plural="keycloakclients",
                        name=client_name,
                    )
                    return resource is not None
                except ApiException:
                    return False

            assert await wait_for_condition(check_client_created, timeout=180), (
                "Client resource was not created successfully"
            )

        except ApiException as e:
            pytest.fail(f"Failed to create client resource: {e}")

        finally:
            # Cleanup client and realm (shared Keycloak is managed by fixture)
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
