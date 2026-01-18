"""Unit tests for Kubernetes utility functions."""

from unittest.mock import MagicMock, patch

from keycloak_operator.utils.kubernetes import create_client_secret


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
