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

            assert await wait_for_condition(check_deployment_created, timeout=180), (
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

    async def test_keycloak_service_created(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test that Keycloak service is created."""
        keycloak_name = "test-keycloak-service"

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

            # Wait for service to be created
            async def check_service_created():
                try:
                    service = k8s_core_v1.read_namespaced_service(
                        name=f"{keycloak_name}-keycloak", namespace=test_namespace
                    )
                    return service is not None
                except ApiException:
                    return False

            assert await wait_for_condition(check_service_created, timeout=180), (
                "Keycloak service was not created"
            )

            # Verify service configuration
            service = k8s_core_v1.read_namespaced_service(
                name=f"{keycloak_name}-keycloak", namespace=test_namespace
            )

            assert service.spec.type == "ClusterIP", "Service has incorrect type"
            assert len(service.spec.ports) > 0, "Service has no ports"
            assert service.spec.ports[0].port == 8080, "Service has incorrect port"

        except ApiException as e:
            pytest.fail(f"Failed to test service creation: {e}")

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

    async def test_keycloak_becomes_ready(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        wait_for_keycloak_ready,
    ):
        """Test that Keycloak instance becomes fully ready and operational."""
        keycloak_name = "test-keycloak-ready"

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
            ), "Keycloak instance did not become ready in time"

            # Verify status is set correctly
            resource = k8s_custom_objects.get_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                name=keycloak_name,
            )

            status = resource.get("status", {})
            assert status, "Keycloak resource has no status"

        except ApiException as e:
            pytest.fail(f"Failed to test Keycloak readiness: {e}")

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

    async def test_keycloak_pods_running(
        self,
        k8s_custom_objects,
        k8s_core_v1,
        test_namespace,
        sample_keycloak_spec,
        wait_for_condition,
    ):
        """Test that Keycloak pods are running and healthy."""
        keycloak_name = "test-keycloak-pods"

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

            # Wait for pods to be running
            async def check_pods_running():
                try:
                    pods = k8s_core_v1.list_namespaced_pod(
                        namespace=test_namespace,
                        label_selector=f"app.kubernetes.io/instance={keycloak_name}",
                    )

                    if not pods.items:
                        return False

                    for pod in pods.items:
                        if pod.status.phase != "Running":
                            return False

                        # Check container readiness
                        if pod.status.container_statuses:
                            for container in pod.status.container_statuses:
                                if not container.ready:
                                    return False

                    return True

                except ApiException:
                    return False

            assert await wait_for_condition(check_pods_running, timeout=420), (
                "Keycloak pods did not become running in time"
            )

        except ApiException as e:
            pytest.fail(f"Failed to test Keycloak pods: {e}")

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
    """Test basic realm operations."""

    async def test_create_realm_resource(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        sample_realm_spec,
        wait_for_keycloak_ready,
        wait_for_condition,
    ):
        """Test creating a basic realm resource."""
        keycloak_name = "test-realm-kc"
        realm_name = "test-realm-basic"

        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": test_namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        try:
            # Create Keycloak instance first
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for Keycloak to be ready
            assert await wait_for_keycloak_ready(keycloak_name, test_namespace), (
                "Keycloak instance not ready for realm creation"
            )

            # Create realm
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to be created
            async def check_realm_created():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
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
            # Cleanup in reverse order
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

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
class TestClientBasicOperations:
    """Test basic client operations."""

    async def test_create_client_resource(
        self,
        k8s_custom_objects,
        test_namespace,
        sample_keycloak_spec,
        sample_realm_spec,
        sample_client_spec,
        wait_for_keycloak_ready,
        wait_for_condition,
    ):
        """Test creating a basic client resource."""
        keycloak_name = "test-client-kc"
        realm_name = "test-client-realm"
        client_name = "test-client-basic"

        keycloak_manifest = {
            **sample_keycloak_spec,
            "metadata": {"name": keycloak_name, "namespace": test_namespace},
        }

        realm_manifest = {
            **sample_realm_spec,
            "metadata": {"name": realm_name, "namespace": test_namespace},
        }
        realm_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        client_manifest = {
            **sample_client_spec,
            "metadata": {"name": client_name, "namespace": test_namespace},
        }
        client_manifest["spec"]["keycloak_instance_ref"]["namespace"] = test_namespace

        try:
            # Create Keycloak instance
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloaks",
                body=keycloak_manifest,
            )

            # Wait for Keycloak to be ready
            assert await wait_for_keycloak_ready(keycloak_name, test_namespace), (
                "Keycloak instance not ready for client creation"
            )

            # Create realm
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Create client
            k8s_custom_objects.create_namespaced_custom_object(
                group="keycloak.mdvr.nl",
                version="v1",
                namespace=test_namespace,
                plural="keycloakclients",
                body=client_manifest,
            )

            # Wait for client to be created
            async def check_client_created():
                try:
                    resource = k8s_custom_objects.get_namespaced_custom_object(
                        group="keycloak.mdvr.nl",
                        version="v1",
                        namespace=test_namespace,
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
            # Cleanup in reverse order
            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakclients",
                    name=client_name,
                )

            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

            with contextlib.suppress(ApiException):
                k8s_custom_objects.delete_namespaced_custom_object(
                    group="keycloak.mdvr.nl",
                    version="v1",
                    namespace=test_namespace,
                    plural="keycloaks",
                    name=keycloak_name,
                )
