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
        """Test that operator has required RBAC permissions with new namespaced model."""
        from kubernetes import client

        rbac_api = client.RbacAuthorizationV1Api(k8s_client)

        try:
            # Check core ClusterRole exists (minimal cluster-wide permissions)
            cluster_role_name = f"keycloak-operator-{operator_namespace}-core"
            cluster_role = rbac_api.read_cluster_role(name=cluster_role_name)
            assert cluster_role.rules, "ClusterRole has no rules"

            # Check if essential cluster-wide permissions are present (read-only CRDs)
            required_permissions = [
                (
                    "keycloak.mdvr.nl",
                    ["keycloaks", "keycloakrealms", "keycloakclients"],
                    ["list", "watch"],  # Only list/watch at cluster level
                ),
                ("", ["namespaces"], ["get", "list", "watch"]),
                ("authorization.k8s.io", ["subjectaccessreviews"], ["create"]),
                ("coordination.k8s.io", ["leases"], ["get", "list", "watch"]),
            ]

            for api_group, resources, expected_verbs in required_permissions:
                found = False
                for rule in cluster_role.rules:
                    if (
                        api_group in (rule.api_groups or [])
                        and any(
                            resource in (rule.resources or []) for resource in resources
                        )
                        and any(verb in (rule.verbs or []) for verb in expected_verbs)
                    ):
                        found = True
                        break
                assert found, (
                    f"Missing permissions for {api_group} resources: {resources} "
                    f"with verbs: {expected_verbs}"
                )

            # Check namespace-access ClusterRole template exists
            namespace_access_role_name = (
                f"keycloak-operator-{operator_namespace}-namespace-access"
            )
            namespace_access_role = rbac_api.read_cluster_role(
                name=namespace_access_role_name
            )
            assert namespace_access_role.rules, (
                "Namespace access ClusterRole has no rules"
            )

            # Check namespace Role exists (full management in operator namespace)
            manager_role_name = f"keycloak-operator-{operator_namespace}-manager"
            manager_role = rbac_api.read_namespaced_role(
                name=manager_role_name, namespace=operator_namespace
            )
            assert manager_role.rules, "Manager Role has no rules"

            # Verify manager role has full CRUD on deployments, services, secrets
            full_crud_resources = [
                ("apps", ["deployments"]),
                ("", ["services", "secrets"]),
            ]

            for api_group, resources in full_crud_resources:
                found = False
                for rule in manager_role.rules:
                    if (
                        api_group in (rule.api_groups or [])
                        and any(
                            resource in (rule.resources or []) for resource in resources
                        )
                        and all(
                            verb in (rule.verbs or [])
                            for verb in ["create", "update", "delete"]
                        )
                    ):
                        found = True
                        break
                assert found, (
                    f"Missing full CRUD permissions for {api_group} resources: {resources}"
                )

        except ApiException as e:
            if e.status == 404:
                pytest.fail(
                    f"RBAC resources not found. The new namespaced RBAC model may not be deployed correctly: {e}"
                )
            pytest.fail(f"Failed to check RBAC permissions: {e}")


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestBasicKeycloakDeployment:
    """Test basic Keycloak resource deployment using a shared instance."""

    async def test_create_keycloak_resource(
        self,
        k8s_custom_objects,
        shared_operator,
    ):
        """Test that the shared Keycloak resource was created successfully."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
        shared_operator,
    ):
        """Test that finalizers are properly added to the shared Keycloak resource."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
        shared_operator,
    ):
        """Test that Keycloak deployment is created for the shared resource."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
        shared_operator,
    ):
        """Test that Keycloak service is created for the shared resource."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
        shared_operator,
    ):
        """Test that the shared Keycloak instance is ready and operational."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
        shared_operator,
    ):
        """Test that Keycloak pods are running and healthy for the shared instance."""
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

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
    """Test Keycloak admin API accessibility using shared instance (1-1 coupling)."""

    async def test_keycloak_admin_api_accessible(
        self,
        k8s_core_v1,
        k8s_apps_v1,
        shared_operator,
    ):
        """Test that shared Keycloak instance is ready and admin API is accessible.

        Uses the pre-installed shared Keycloak instance (1-1 operator-Keycloak coupling).
        Verifies deployment, service, and admin credentials are properly configured.
        """
        keycloak_name = shared_operator["name"]
        namespace = shared_operator["namespace"]

        try:
            # Verify deployment exists and is ready
            deployment = k8s_apps_v1.read_namespaced_deployment(
                name=f"{keycloak_name}-keycloak", namespace=namespace
            )

            assert deployment.status.ready_replicas, (
                "Keycloak deployment has no ready replicas"
            )
            assert deployment.status.ready_replicas >= deployment.spec.replicas, (
                f"Keycloak deployment not fully ready: "
                f"{deployment.status.ready_replicas}/{deployment.spec.replicas}"
            )

            # Verify admin credentials secret exists
            admin_secret_name = f"{keycloak_name}-admin-credentials"
            secret = k8s_core_v1.read_namespaced_secret(
                name=admin_secret_name, namespace=namespace
            )
            assert secret.data, "Admin credentials secret has no data"
            assert "password" in secret.data, (
                "Admin credentials secret missing 'password' key"
            )
            assert "username" in secret.data, (
                "Admin credentials secret missing 'username' key"
            )

            # Verify service endpoint is available
            service = k8s_core_v1.read_namespaced_service(
                name=f"{keycloak_name}-keycloak", namespace=namespace
            )
            assert service.spec.cluster_ip, "Service has no cluster IP"

            # Verify service has correct ports
            ports = {port.name: port.port for port in service.spec.ports}
            assert "http" in ports, "Service missing 'http' port"
            assert "management" in ports, "Service missing 'management' port"

        except ApiException as e:
            pytest.fail(
                f"Failed to verify shared Keycloak admin API accessibility: {e}"
            )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestRealmBasicOperations:
    """Test basic realm operations using a shared Keycloak instance."""

    async def test_create_realm_resource(
        self,
        k8s_custom_objects,
        shared_operator,
        operator_namespace,
        sample_realm_spec,
        wait_for_condition,
    ):
        """Test creating a basic realm resource on the shared Keycloak instance."""
        import uuid

        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        namespace = shared_operator["namespace"]
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-realm-basic-{suffix}"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
                    key="token",
                ),
            ),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

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
        shared_operator,
        operator_namespace,
        sample_realm_spec,
        sample_client_spec,
        wait_for_condition,
    ):
        """Test creating a basic client resource on the shared Keycloak instance."""
        import uuid

        from keycloak_operator.models.client import KeycloakClientSpec, RealmRef
        from keycloak_operator.models.common import AuthorizationSecretRef
        from keycloak_operator.models.realm import KeycloakRealmSpec, OperatorRef

        namespace = shared_operator["namespace"]
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"test-client-realm-{suffix}"
        client_name = f"test-client-basic-{suffix}"

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(
                namespace=operator_namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name="keycloak-operator-auth-token",
                    key="token",
                ),
            ),
            realm_name=realm_name,
        )

        realm_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        client_spec = KeycloakClientSpec(
            realm_ref=RealmRef(
                name=realm_name,
                namespace=namespace,
                authorization_secret_ref=AuthorizationSecretRef(
                    name=f"{realm_name}-auth-token",
                    key="token",
                ),
            ),
            client_id=client_name,
        )

        client_manifest = {
            "apiVersion": "keycloak.mdvr.nl/v1",
            "kind": "KeycloakClient",
            "metadata": {"name": client_name, "namespace": namespace},
            "spec": client_spec.model_dump(by_alias=True, exclude_unset=True),
        }

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
