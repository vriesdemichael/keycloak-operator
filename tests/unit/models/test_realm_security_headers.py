from keycloak_operator.models.realm import (
    KeycloakBrowserSecurityHeaders,
    KeycloakRealmSpec,
)


def test_browser_security_headers_defaults_are_none():
    """Test that default values for browser security headers are None (use Keycloak defaults)."""
    headers = KeycloakBrowserSecurityHeaders()
    assert headers.content_security_policy is None
    assert headers.x_content_type_options is None
    assert headers.x_frame_options is None
    assert headers.x_robots_tag is None
    assert headers.x_xss_protection is None
    assert headers.strict_transport_security is None
    assert headers.referrer_policy is None
    assert headers.content_security_policy_report_only is None


def test_realm_spec_with_security_headers():
    """Test realm spec serialization with security headers."""
    headers = KeycloakBrowserSecurityHeaders(
        contentSecurityPolicy="default-src 'self';", xFrameOptions="DENY"
    )
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "test-ns"},
        browserSecurityHeaders=headers,
    )

    config = spec.to_keycloak_config(include_flow_bindings=False)
    assert "browserSecurityHeaders" in config
    assert (
        config["browserSecurityHeaders"]["contentSecurityPolicy"]
        == "default-src 'self';"
    )
    assert config["browserSecurityHeaders"]["xFrameOptions"] == "DENY"
    # Unset fields should NOT be in config
    assert "xContentTypeOptions" not in config["browserSecurityHeaders"]


def test_realm_spec_without_security_headers():
    """Test realm spec serialization without security headers."""
    spec = KeycloakRealmSpec(
        realmName="test-realm", operatorRef={"namespace": "test-ns"}
    )

    config = spec.to_keycloak_config(include_flow_bindings=False)
    assert "browserSecurityHeaders" not in config


def test_realm_spec_with_empty_security_headers_object():
    """Test realm spec with empty security headers object."""
    headers = KeycloakBrowserSecurityHeaders()
    spec = KeycloakRealmSpec(
        realmName="test-realm",
        operatorRef={"namespace": "test-ns"},
        browserSecurityHeaders=headers,
    )

    config = spec.to_keycloak_config(include_flow_bindings=False)
    # Should not include empty browserSecurityHeaders dict
    assert "browserSecurityHeaders" not in config
