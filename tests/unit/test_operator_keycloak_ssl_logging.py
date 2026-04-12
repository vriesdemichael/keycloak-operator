from unittest.mock import patch

from keycloak_operator.operator import log_keycloak_connection_security_configuration


@patch("keycloak_operator.operator.logging.warning")
@patch("keycloak_operator.operator.operator_settings")
def test_logs_warning_for_insecure_https_keycloak_connection(
    mock_settings, mock_warning
):
    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.resolved_keycloak_verify_ssl = False

    log_keycloak_connection_security_configuration()

    mock_warning.assert_called_once()


@patch("keycloak_operator.operator.logging.warning")
@patch("keycloak_operator.operator.operator_settings")
def test_does_not_log_warning_for_internal_http_keycloak_connection(
    mock_settings, mock_warning
):
    mock_settings.keycloak_url = "http://keycloak.operator-ns.svc.cluster.local:8080"
    mock_settings.resolved_keycloak_verify_ssl = False

    log_keycloak_connection_security_configuration()

    mock_warning.assert_not_called()


@patch("keycloak_operator.operator.logging.warning")
@patch("keycloak_operator.operator.operator_settings")
def test_does_not_log_warning_for_verified_https_keycloak_connection(
    mock_settings, mock_warning
):
    mock_settings.keycloak_url = "https://external.keycloak"
    mock_settings.resolved_keycloak_verify_ssl = True

    log_keycloak_connection_security_configuration()

    mock_warning.assert_not_called()
