"""Unit tests for Kubernetes utility functions."""

from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.rest import ApiException

from keycloak_operator.utils.kubernetes import (
    create_client_secret,
    create_keycloak_deployment,
    create_keycloak_discovery_service,
    get_deployment_pods,
    get_pod_logs,
)


@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
def test_create_client_secret_with_metadata(mock_get_k8s_client):
    """Test creating a client secret with custom labels and annotations."""
    # Mock K8s client and API
    mock_api = MagicMock()
    mock_get_k8s_client.return_value = MagicMock()

    # We need to mock client.CoreV1Api(k8s) to return our mock_api
    with patch("kubernetes.client.CoreV1Api", return_value=mock_api):
        # inputs
        secret_name = "test-secret"
        namespace = "test-ns"
        client_id = "test-client"
        client_secret = "super-secret"
        keycloak_url = "https://keycloak.example.com"
        realm = "test-realm"

        custom_labels = {"foo": "bar", "managed-by": "me"}
        custom_annotations = {"note": "test note"}

        # Execute
        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id=client_id,
            client_secret=client_secret,
            keycloak_url=keycloak_url,
            realm=realm,
            update_existing=False,
            labels=custom_labels,
            annotations=custom_annotations,
        )

        # Verify
        mock_api.create_namespaced_secret.assert_called_once()
        call_args = mock_api.create_namespaced_secret.call_args
        created_secret = call_args[1]["body"]

        # Check basic fields
        assert created_secret.metadata.name == secret_name
        assert created_secret.metadata.namespace == namespace

        # Check merged labels
        expected_labels = {
            "vriesdemichael.github.io/keycloak-client": client_id,
            "vriesdemichael.github.io/keycloak-realm": realm,
            "vriesdemichael.github.io/keycloak-component": "client-credentials",
            "foo": "bar",
            "managed-by": "me",
        }
        assert created_secret.metadata.labels == expected_labels

        # Check merged annotations
        expected_annotations = {
            "vriesdemichael.github.io/keycloak-client-type": "confidential",
            "note": "test note",
        }
        assert created_secret.metadata.annotations == expected_annotations


@patch("keycloak_operator.utils.kubernetes.get_kubernetes_client")
def test_create_client_secret_update_with_metadata(mock_get_k8s_client):
    """Test updating a client secret with metadata."""
    # Mock K8s client and API
    mock_api = MagicMock()
    mock_get_k8s_client.return_value = MagicMock()

    with patch("kubernetes.client.CoreV1Api", return_value=mock_api):
        # inputs
        secret_name = "test-secret"
        namespace = "test-ns"

        custom_labels = {"new": "label"}
        custom_annotations = {"new": "annotation"}

        # Execute with update_existing=True
        create_client_secret(
            secret_name=secret_name,
            namespace=namespace,
            client_id="test-client",
            client_secret="secret",
            keycloak_url="http://url",
            realm="realm",
            update_existing=True,
            labels=custom_labels,
            annotations=custom_annotations,
        )

        # Verify patch was called
        mock_api.patch_namespaced_secret.assert_called_once()
        created_secret = mock_api.patch_namespaced_secret.call_args[1]["body"]

        # Verify metadata in the patch body
        assert created_secret.metadata.labels["new"] == "label"
        assert created_secret.metadata.annotations["new"] == "annotation"


class TestKeycloakDiscoveryService:
    """Tests for the headless discovery service used for JGroups clustering."""

    def test_create_keycloak_discovery_service_creates_headless_service(self):
        """Test that discovery service is created as a headless service."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            create_keycloak_discovery_service(
                name="my-keycloak",
                namespace="test-ns",
                k8s_client=mock_k8s_client,
            )

            # Verify service was created
            mock_core_api.create_namespaced_service.assert_called_once()
            call_args = mock_core_api.create_namespaced_service.call_args

            # Check namespace
            assert call_args[1]["namespace"] == "test-ns"

            # Check service body
            created_service = call_args[1]["body"]

            # Verify it's a headless service
            assert created_service.spec.cluster_ip == "None"

            # Verify publish_not_ready_addresses is True for peer discovery during startup
            assert created_service.spec.publish_not_ready_addresses is True

            # Verify service name follows convention
            assert created_service.metadata.name == "my-keycloak-discovery"

            # Verify labels
            assert created_service.metadata.labels["app"] == "keycloak"
            assert (
                created_service.metadata.labels[
                    "vriesdemichael.github.io/keycloak-instance"
                ]
                == "my-keycloak"
            )
            assert (
                created_service.metadata.labels[
                    "vriesdemichael.github.io/keycloak-component"
                ]
                == "discovery"
            )

            # Verify selector
            assert created_service.spec.selector["app"] == "keycloak"
            assert (
                created_service.spec.selector[
                    "vriesdemichael.github.io/keycloak-instance"
                ]
                == "my-keycloak"
            )

    def test_create_keycloak_discovery_service_exposes_jgroups_port(self):
        """Test that discovery service exposes JGroups port 7800."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            create_keycloak_discovery_service(
                name="my-keycloak",
                namespace="test-ns",
                k8s_client=mock_k8s_client,
            )

            call_args = mock_core_api.create_namespaced_service.call_args
            created_service = call_args[1]["body"]

            # Verify JGroups port
            assert len(created_service.spec.ports) == 1
            jgroups_port = created_service.spec.ports[0]
            assert jgroups_port.name == "jgroups"
            assert jgroups_port.port == 7800
            assert jgroups_port.target_port == 7800
            assert jgroups_port.protocol == "TCP"


class TestKeycloakDeploymentJGroups:
    """Tests for JGroups clustering configuration in Keycloak deployment."""

    def test_deployment_includes_jgroups_env_vars(self):
        """Test that deployment includes JGroups environment variables."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            optimized=True,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            # Get environment variables
            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify KC_CACHE_STACK is set to kubernetes
            assert "KC_CACHE_STACK" in env_var_dict
            assert env_var_dict["KC_CACHE_STACK"].value == "kubernetes"

            # Verify JAVA_OPTS_APPEND contains JGroups DNS query
            assert "JAVA_OPTS_APPEND" in env_var_dict
            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            assert "-Djgroups.dns.query=" in java_opts
            assert "my-keycloak-discovery.test-ns.svc.cluster.local" in java_opts

    def test_deployment_includes_jgroups_port(self):
        """Test that deployment exposes JGroups port 7800."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            # Get container ports
            container = deployment.spec.template.spec.containers[0]
            port_names = {p.name: p.container_port for p in container.ports}

            # Verify JGroups port is included
            assert "jgroups" in port_names
            assert port_names["jgroups"] == 7800

            # Verify other ports are still there
            assert "http" in port_names
            assert port_names["http"] == 8080
            assert "management" in port_names
            assert port_names["management"] == 9000

    def test_deployment_jgroups_dns_query_uses_correct_namespace(self):
        """Test that JGroups DNS query uses the deployment's namespace."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            optimized=True,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="prod-keycloak",
                namespace="production",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            # Should use the correct namespace
            assert "prod-keycloak-discovery.production.svc.cluster.local" in java_opts


class TestKeycloakDeploymentTracing:
    """Tests for OpenTelemetry tracing configuration in Keycloak deployment."""

    def test_deployment_includes_tracing_env_vars_when_enabled(self):
        """Test that tracing env vars are added when tracing is enabled."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            image="quay.io/keycloak/keycloak:26.4.0",  # Supports tracing
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            tracing={
                "enabled": True,
                "endpoint": "http://otel-collector:4317",
                "service_name": "my-keycloak",
                "sample_rate": 0.5,
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            # Get environment variables
            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify tracing env vars are present
            assert "KC_TRACING_ENABLED" in env_var_dict
            assert env_var_dict["KC_TRACING_ENABLED"].value == "true"

            assert "KC_TRACING_ENDPOINT" in env_var_dict
            assert (
                env_var_dict["KC_TRACING_ENDPOINT"].value
                == "http://otel-collector:4317"
            )

            assert "KC_TRACING_SERVICE_NAME" in env_var_dict
            assert env_var_dict["KC_TRACING_SERVICE_NAME"].value == "my-keycloak"

            assert "KC_TRACING_SAMPLER_RATIO" in env_var_dict
            assert env_var_dict["KC_TRACING_SAMPLER_RATIO"].value == "0.5"

    def test_deployment_no_tracing_when_disabled(self):
        """Test that no tracing env vars are added when tracing is disabled."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            image="quay.io/keycloak/keycloak:26.4.0",
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            tracing={
                "enabled": False,
                "endpoint": "http://otel-collector:4317",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify tracing env vars are NOT present
            assert "KC_TRACING_ENABLED" not in env_var_dict
            assert "KC_TRACING_ENDPOINT" not in env_var_dict
            assert "KC_TRACING_SERVICE_NAME" not in env_var_dict
            assert "KC_TRACING_SAMPLER_RATIO" not in env_var_dict

    def test_deployment_no_tracing_when_not_configured(self):
        """Test that no tracing env vars are added when tracing is not configured."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            image="quay.io/keycloak/keycloak:26.4.0",
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            # No tracing configuration
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify tracing env vars are NOT present
            assert "KC_TRACING_ENABLED" not in env_var_dict
            assert "KC_TRACING_ENDPOINT" not in env_var_dict

    def test_deployment_no_tracing_for_unsupported_version(self, caplog):
        """Test that tracing is skipped for Keycloak versions < 26.0.0."""
        import logging

        from keycloak_operator.models.keycloak import KeycloakSpec

        caplog.set_level(logging.WARNING)
        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            image="quay.io/keycloak/keycloak:25.0.6",  # Does NOT support tracing
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            tracing={
                "enabled": True,
                "endpoint": "http://otel-collector:4317",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify tracing env vars are NOT present (unsupported version)
            assert "KC_TRACING_ENABLED" not in env_var_dict
            assert "KC_TRACING_ENDPOINT" not in env_var_dict

            # Verify warning was logged
            assert (
                "does not support" in caplog.text
                or "Tracing will be skipped" in caplog.text
            )

    def test_deployment_tracing_with_version_override(self):
        """Test that version_override is used for tracing version check."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        # Image tag says 26.x but version_override says 25.x
        spec = KeycloakSpec(
            replicas=1,
            image="quay.io/keycloak/keycloak:26.4.0",
            keycloak_version="25.0.0",  # Override says 25.x - no tracing support
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            tracing={
                "enabled": True,
                "endpoint": "http://otel-collector:4317",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Verify tracing env vars are NOT present (version override says 25.x)
            assert "KC_TRACING_ENABLED" not in env_var_dict

    def test_deployment_tracing_uses_default_image_when_none(self):
        """Test that default image is used for version detection when image is None."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            # image is None - should use DEFAULT_KEYCLOAK_IMAGE
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
            tracing={
                "enabled": True,
                "endpoint": "http://otel-collector:4317",
                "service_name": "default-keycloak",
                "sample_rate": 1.0,
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # The default image is 26.x, so tracing should be enabled
            assert "KC_TRACING_ENABLED" in env_var_dict
            assert env_var_dict["KC_TRACING_ENABLED"].value == "true"


class TestKeycloakDeploymentOptimized:
    """Tests for the --optimized startup flag in Keycloak deployment."""

    def test_deployment_args_include_optimized_flag(self):
        """Test that container args include --optimized to skip build-time discovery."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            optimized=True,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]

            # Verify command is kc.sh
            assert container.command == ["/opt/keycloak/bin/kc.sh"]

            # Verify args include start and --optimized
            assert "start" in container.args
            assert "--optimized" in container.args
            assert "--http-enabled=true" in container.args
            assert "--proxy-headers=xforwarded" in container.args

    def test_deployment_args_exclude_optimized_flag_when_disabled(self):
        """Test that --optimized is NOT in args when spec.optimized is False."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            optimized=False,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]

            # Verify args include start but NOT --optimized
            assert "start" in container.args
            assert "--optimized" not in container.args
            # Other flags should still be present
            assert "--http-enabled=true" in container.args
            assert "--proxy-headers=xforwarded" in container.args


class TestKeycloakDeploymentJvmOptions:
    """Tests for JVM options passthrough in Keycloak deployment."""

    def test_deployment_jvm_options_in_java_opts_append(self):
        """Test that spec.jvm_options are appended to JAVA_OPTS_APPEND."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            jvm_options=["-Xms512m", "-Xmx2048m", "-XX:+UseG1GC"],
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            # JGroups DNS query should still be present
            assert "-Djgroups.dns.query=" in java_opts
            # Custom JVM options should be appended
            assert "-Xms512m" in java_opts
            assert "-Xmx2048m" in java_opts
            assert "-XX:+UseG1GC" in java_opts

    def test_deployment_no_jvm_options_only_jgroups(self):
        """Test that JAVA_OPTS_APPEND contains only JGroups when no jvm_options."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            # Should only contain JGroups DNS query
            assert java_opts == (
                "-Djgroups.dns.query=my-keycloak-discovery.test-ns.svc.cluster.local"
            )

    def test_deployment_jit_tuning_option(self):
        """Test CompileThresholdScaling JVM option flows through correctly."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            jvm_options=["-XX:CompileThresholdScaling=0.3"],
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            java_opts = env_var_dict["JAVA_OPTS_APPEND"].value
            assert "-XX:CompileThresholdScaling=0.3" in java_opts


class TestKeycloakDeploymentConnectionPool:
    """Tests for database connection pool configuration in Keycloak deployment."""

    def test_deployment_includes_db_pool_env_vars(self):
        """Test that DB pool sizing env vars are set from spec defaults."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            # Default pool config: min_connections=5, max_connections=20
            assert "KC_DB_POOL_INITIAL_SIZE" in env_var_dict
            assert env_var_dict["KC_DB_POOL_INITIAL_SIZE"].value == "5"

            assert "KC_DB_POOL_MIN_SIZE" in env_var_dict
            assert env_var_dict["KC_DB_POOL_MIN_SIZE"].value == "5"

            assert "KC_DB_POOL_MAX_SIZE" in env_var_dict
            assert env_var_dict["KC_DB_POOL_MAX_SIZE"].value == "20"

    def test_deployment_custom_pool_sizes(self):
        """Test that custom connection pool sizes are propagated."""
        from keycloak_operator.models.keycloak import KeycloakSpec

        mock_k8s_client = MagicMock()
        mock_apps_api = MagicMock()

        spec = KeycloakSpec(
            replicas=1,
            database={
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentials_secret": "db-credentials",
                "connection_pool": {
                    "min_connections": 10,
                    "max_connections": 50,
                },
            },
        )

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            create_keycloak_deployment(
                name="my-keycloak",
                namespace="test-ns",
                spec=spec,
                k8s_client=mock_k8s_client,
            )

            call_args = mock_apps_api.create_namespaced_deployment.call_args
            deployment = call_args[1]["body"]

            container = deployment.spec.template.spec.containers[0]
            env_var_dict = {env.name: env for env in container.env}

            assert env_var_dict["KC_DB_POOL_INITIAL_SIZE"].value == "10"
            assert env_var_dict["KC_DB_POOL_MIN_SIZE"].value == "10"
            assert env_var_dict["KC_DB_POOL_MAX_SIZE"].value == "50"


class TestGetDeploymentPods:
    """Tests for get_deployment_pods helper function."""

    def test_get_deployment_pods_success(self):
        """Test successful pod listing for a deployment."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_pod = MagicMock()
        mock_pod.metadata.name = "my-keycloak-keycloak-abc123"
        mock_core_api.list_namespaced_pod.return_value = MagicMock(items=[mock_pod])

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            pods = get_deployment_pods(
                "my-keycloak-keycloak", "test-ns", mock_k8s_client
            )

        assert len(pods) == 1
        assert pods[0].metadata.name == "my-keycloak-keycloak-abc123"
        mock_core_api.list_namespaced_pod.assert_called_once_with(
            namespace="test-ns",
            label_selector="vriesdemichael.github.io/keycloak-instance=my-keycloak",
        )

    def test_get_deployment_pods_invalid_name_pattern(self):
        """Test that invalid deployment name returns empty list."""
        mock_k8s_client = MagicMock()

        pods = get_deployment_pods("bad-name", "test-ns", mock_k8s_client)

        assert pods == []

    def test_get_deployment_pods_api_error(self):
        """Test that API errors return empty list."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.list_namespaced_pod.side_effect = ApiException(status=500)

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            pods = get_deployment_pods(
                "my-keycloak-keycloak", "test-ns", mock_k8s_client
            )

        assert pods == []

    def test_get_deployment_pods_no_pods(self):
        """Test empty pod list returned when no pods match."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.list_namespaced_pod.return_value = MagicMock(items=[])

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            pods = get_deployment_pods(
                "my-keycloak-keycloak", "test-ns", mock_k8s_client
            )

        assert pods == []


class TestGetPodLogs:
    """Tests for get_pod_logs helper function."""

    def test_get_pod_logs_success(self):
        """Test successful log retrieval."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_pod_log.return_value = (
            "2025-01-01 Starting Keycloak\n2025-01-01 Ready"
        )

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            logs = get_pod_logs("my-pod", "test-ns", mock_k8s_client)

        assert "Starting Keycloak" in logs
        mock_core_api.read_namespaced_pod_log.assert_called_once_with(
            name="my-pod", namespace="test-ns", tail_lines=50
        )

    def test_get_pod_logs_custom_tail_lines(self):
        """Test log retrieval with custom tail_lines parameter."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_pod_log.return_value = "log line"

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            get_pod_logs("my-pod", "test-ns", mock_k8s_client, tail_lines=100)

        mock_core_api.read_namespaced_pod_log.assert_called_once_with(
            name="my-pod", namespace="test-ns", tail_lines=100
        )

    def test_get_pod_logs_api_error_non_400(self):
        """Test that non-400 API errors return empty string and log warning."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_pod_log.side_effect = ApiException(status=500)

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            logs = get_pod_logs("my-pod", "test-ns", mock_k8s_client)

        assert logs == ""

    def test_get_pod_logs_api_error_400_silent(self):
        """Test that 400 errors (container creating) are silent."""
        mock_k8s_client = MagicMock()
        mock_core_api = MagicMock()
        mock_core_api.read_namespaced_pod_log.side_effect = ApiException(status=400)

        with patch("kubernetes.client.CoreV1Api", return_value=mock_core_api):
            logs = get_pod_logs("my-pod", "test-ns", mock_k8s_client)

        assert logs == ""


class TestCheckPodLogsForBuildErrors:
    """Tests for _check_pod_logs_for_build_errors in KeycloakInstanceReconciler."""

    @pytest.fixture
    def reconciler(self):
        """Create a minimal KeycloakInstanceReconciler for testing."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            reconciler = KeycloakInstanceReconciler()
        return reconciler

    def _make_pod(
        self,
        name="test-pod",
        phase="Running",
        waiting_reason=None,
        terminated_exit_code=None,
    ):
        """Helper to create a mock pod with specific status."""
        pod = MagicMock()
        pod.metadata.name = name
        pod.status.phase = phase

        if waiting_reason or terminated_exit_code is not None:
            container_status = MagicMock()
            if waiting_reason:
                container_status.state.waiting.reason = waiting_reason
                container_status.state.terminated = None
            elif terminated_exit_code is not None:
                container_status.state.waiting = None
                container_status.state.terminated.exit_code = terminated_exit_code
            else:
                container_status.state.waiting = None
                container_status.state.terminated = None
            pod.status.container_statuses = [container_status]
        else:
            pod.status.container_statuses = None

        return pod

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_no_pods_returns_none(self, mock_logs, mock_pods, reconciler):
        """Test returns None when no pods exist."""
        mock_pods.return_value = []

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is None

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_healthy_pod_not_checked(self, mock_logs, mock_pods, reconciler):
        """Test that healthy running pods are not checked."""
        pod = self._make_pod(phase="Running")
        # No container_statuses means no waiting/terminated state to check
        pod.status.container_statuses = None
        mock_pods.return_value = [pod]

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is None
        mock_logs.assert_not_called()

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_failed_pod_checked(self, mock_logs, mock_pods, reconciler):
        """Test that Failed pods have their logs checked."""
        pod = self._make_pod(phase="Failed")
        mock_pods.return_value = [pod]
        mock_logs.return_value = "Normal startup log without errors"

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is None
        mock_logs.assert_called_once()

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_crashloopbackoff_detected_optimized_mismatch(
        self, mock_logs, mock_pods, reconciler
    ):
        """Test detecting optimized flag mismatch in CrashLoopBackOff pod."""
        pod = self._make_pod(phase="Running", waiting_reason="CrashLoopBackOff")
        mock_pods.return_value = [pod]
        mock_logs.return_value = (
            "ERROR: The '--optimized' flag was used for first ever server start. "
            "Please run the 'build' command first."
        )

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is not None
        assert "optimized" in result.lower()
        assert "not built with 'kc.sh build'" in result

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_crashloopbackoff_detected_build_option_mismatch(
        self, mock_logs, mock_pods, reconciler
    ):
        """Test detecting build option mismatch in CrashLoopBackOff pod."""
        pod = self._make_pod(phase="Running", waiting_reason="CrashLoopBackOff")
        mock_pods.return_value = [pod]
        mock_logs.return_value = (
            "ERROR: The following build time options have values that differ from what is persisted: "
            "kc.spi-connections-jpa-default-migration-strategy"
        )

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is not None
        assert "Requested features" in result
        assert "differ" in result

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_terminated_nonzero_exit_code(self, mock_logs, mock_pods, reconciler):
        """Test that pods with terminated containers (non-zero exit) are checked."""
        pod = self._make_pod(phase="Running", terminated_exit_code=1)
        mock_pods.return_value = [pod]
        mock_logs.return_value = (
            "The '--optimized' flag was used for first ever server start"
        )

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is not None
        assert "optimized" in result.lower()

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_error_waiting_reason(self, mock_logs, mock_pods, reconciler):
        """Test that pods with Error waiting reason are checked."""
        pod = self._make_pod(phase="Running", waiting_reason="Error")
        mock_pods.return_value = [pod]
        mock_logs.return_value = "Some unrelated error message"

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        # Error is checked but log doesn't match known patterns
        assert result is None
        mock_logs.assert_called_once()

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_create_container_config_error(self, mock_logs, mock_pods, reconciler):
        """Test that CreateContainerConfigError waiting reason triggers check."""
        pod = self._make_pod(
            phase="Pending", waiting_reason="CreateContainerConfigError"
        )
        mock_pods.return_value = [pod]
        mock_logs.return_value = "Some container config problem"

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is None
        mock_logs.assert_called_once()

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_multiple_pods_first_match_wins(self, mock_logs, mock_pods, reconciler):
        """Test that when multiple pods have issues, first match is returned."""
        pod1 = self._make_pod(
            name="pod-1", phase="Running", waiting_reason="CrashLoopBackOff"
        )
        pod2 = self._make_pod(
            name="pod-2", phase="Running", waiting_reason="CrashLoopBackOff"
        )
        mock_pods.return_value = [pod1, pod2]
        mock_logs.side_effect = [
            "The '--optimized' flag was used for first ever server start",
            "The following build time options have values that differ from what is persisted",
        ]

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        # First pod matches optimized flag error
        assert "optimized" in result.lower()
        # Only first pod's logs were needed
        assert mock_logs.call_count == 1

    @patch("keycloak_operator.utils.kubernetes.get_deployment_pods")
    @patch("keycloak_operator.utils.kubernetes.get_pod_logs")
    def test_terminated_zero_exit_code_not_checked(
        self, mock_logs, mock_pods, reconciler
    ):
        """Test that pods with zero exit code terminated containers are NOT checked."""
        pod = MagicMock()
        pod.metadata.name = "test-pod"
        pod.status.phase = "Running"
        container_status = MagicMock()
        container_status.state.waiting = None
        container_status.state.terminated.exit_code = 0
        pod.status.container_statuses = [container_status]
        mock_pods.return_value = [pod]

        result = reconciler._check_pod_logs_for_build_errors("test-keycloak", "test-ns")

        assert result is None
        mock_logs.assert_not_called()


class TestWaitForDeploymentReady:
    """Tests for wait_for_deployment_ready in KeycloakInstanceReconciler."""

    @pytest.fixture
    def reconciler(self):
        """Create a minimal KeycloakInstanceReconciler for testing."""
        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            reconciler = KeycloakInstanceReconciler()
        return reconciler

    @pytest.mark.asyncio
    async def test_deployment_ready_immediately(self, reconciler):
        """Test when deployment is already ready."""
        mock_apps_api = MagicMock()
        mock_deployment = MagicMock()
        mock_deployment.status.ready_replicas = 1
        mock_deployment.spec.replicas = 1
        mock_apps_api.read_namespaced_deployment_status.return_value = mock_deployment

        with patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api):
            ready, error = await reconciler.wait_for_deployment_ready(
                "test", "test-ns", max_wait_time=10
            )

        assert ready is True
        assert error is None

    @pytest.mark.asyncio
    async def test_deployment_timeout(self, reconciler):
        """Test when deployment never becomes ready (timeout)."""
        mock_apps_api = MagicMock()
        mock_deployment = MagicMock()
        mock_deployment.status.ready_replicas = 0
        mock_deployment.spec.replicas = 1
        mock_apps_api.read_namespaced_deployment_status.return_value = mock_deployment

        with (
            patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api),
            patch.object(
                reconciler,
                "_check_pod_logs_for_build_errors",
                return_value=None,
            ),
            patch("asyncio.sleep", return_value=None),
        ):
            ready, error = await reconciler.wait_for_deployment_ready(
                "test", "test-ns", max_wait_time=5
            )

        assert ready is False
        assert error is None

    @pytest.mark.asyncio
    async def test_deployment_build_error_detected(self, reconciler):
        """Test when build error is detected in pod logs."""
        mock_apps_api = MagicMock()
        mock_deployment = MagicMock()
        mock_deployment.status.ready_replicas = 0
        mock_deployment.spec.replicas = 1
        mock_apps_api.read_namespaced_deployment_status.return_value = mock_deployment

        build_error_msg = "Configuration Error: The 'optimized' flag is enabled"

        with (
            patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api),
            patch.object(
                reconciler,
                "_check_pod_logs_for_build_errors",
                return_value=build_error_msg,
            ),
        ):
            ready, error = await reconciler.wait_for_deployment_ready(
                "test", "test-ns", max_wait_time=300
            )

        assert ready is False
        assert error == build_error_msg

    @pytest.mark.asyncio
    async def test_deployment_api_exception_continues(self, reconciler):
        """Test that API exceptions don't crash the wait loop."""
        mock_apps_api = MagicMock()
        # First call raises, second call returns ready
        mock_deployment_ready = MagicMock()
        mock_deployment_ready.status.ready_replicas = 1
        mock_deployment_ready.spec.replicas = 1

        mock_apps_api.read_namespaced_deployment_status.side_effect = [
            ApiException(status=503),
            mock_deployment_ready,
        ]

        with (
            patch("kubernetes.client.AppsV1Api", return_value=mock_apps_api),
            patch("asyncio.sleep", return_value=None),
        ):
            ready, error = await reconciler.wait_for_deployment_ready(
                "test", "test-ns", max_wait_time=300
            )

        assert ready is True
        assert error is None


class TestDoReconcileBuildMismatchFlow:
    """Tests for do_reconcile error handling with build mismatch detection."""

    @pytest.fixture
    def reconciler(self):
        """Create a KeycloakInstanceReconciler with all pre-wait methods mocked."""
        from unittest.mock import AsyncMock

        from keycloak_operator.services.keycloak_reconciler import (
            KeycloakInstanceReconciler,
        )

        with patch("keycloak_operator.services.keycloak_reconciler.client.ApiClient"):
            reconciler = KeycloakInstanceReconciler()

        # Mock all methods called before wait_for_deployment_ready in do_reconcile
        reconciler.validate_production_settings = AsyncMock(  # type: ignore[method-assign]
            return_value={"host": "db", "port": 5432}
        )
        reconciler.ensure_admin_access = AsyncMock()  # type: ignore[method-assign]
        reconciler.ensure_deployment = AsyncMock()  # type: ignore[method-assign]
        reconciler.ensure_service = AsyncMock()  # type: ignore[method-assign]
        reconciler.ensure_discovery_service = AsyncMock()  # type: ignore[method-assign]

        return reconciler

    @pytest.mark.asyncio
    async def test_raises_configuration_error_on_build_mismatch(self, reconciler):
        """Test that ConfigurationError is raised when build error is detected."""
        from unittest.mock import AsyncMock

        from keycloak_operator.errors.operator_errors import ConfigurationError

        reconciler.wait_for_deployment_ready = AsyncMock(
            return_value=(False, "Configuration Error: optimized flag mismatch")
        )

        status = MagicMock()
        spec = {
            "image": "quay.io/keycloak/keycloak:26.4.0",
            "replicas": 1,
            "optimized": True,
            "ingress": {"enabled": False},
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentialsSecret": "db-creds",
            },
        }

        with pytest.raises(ConfigurationError):
            await reconciler.do_reconcile(
                spec=spec,
                name="test",
                namespace="test-ns",
                status=status,
                meta={"generation": 1},
            )

    @pytest.mark.asyncio
    async def test_raises_temporary_error_on_timeout(self, reconciler):
        """Test that TemporaryError is raised when deployment times out."""
        from unittest.mock import AsyncMock

        from keycloak_operator.errors.operator_errors import TemporaryError

        reconciler.wait_for_deployment_ready = AsyncMock(return_value=(False, None))

        status = MagicMock()
        spec = {
            "image": "quay.io/keycloak/keycloak:26.4.0",
            "replicas": 1,
            "optimized": False,
            "ingress": {"enabled": False},
            "database": {
                "type": "postgresql",
                "host": "db",
                "database": "keycloak",
                "credentialsSecret": "db-creds",
            },
        }

        with pytest.raises(TemporaryError, match="not ready"):
            await reconciler.do_reconcile(
                spec=spec,
                name="test",
                namespace="test-ns",
                status=status,
                meta={"generation": 1},
            )
