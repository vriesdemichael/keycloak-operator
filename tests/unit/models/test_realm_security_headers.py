from keycloak_operator.models.realm import (
    KeycloakBrowserSecurityHeaders,
    KeycloakRealmSpec,
)


def test_browser_security_headers_defaults():
    """Test default values for browser security headers."""
    headers = KeycloakBrowserSecurityHeaders()
    assert (
        headers.content_security_policy
        == "frame-src 'self'; frame-ancestors 'self'; object-src 'none';"
    )
    assert headers.x_content_type_options == "nosniff"
    assert headers.x_frame_options == "SAMEORIGIN"
    assert headers.x_robots_tag == "none"
    assert headers.x_xss_protection == "1; mode=block"
    assert headers.strict_transport_security == "max-age=31536000; includeSubDomains"
    assert headers.referrer_policy == "no-referrer"
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
    # Defaults should be preserved if not overridden
    assert config["browserSecurityHeaders"]["xContentTypeOptions"] == "nosniff"


def test_realm_spec_without_security_headers():
    """Test realm spec serialization without security headers."""
    spec = KeycloakRealmSpec(
        realmName="test-realm", operatorRef={"namespace": "test-ns"}
    )

    config = spec.to_keycloak_config(include_flow_bindings=False)
    assert "browserSecurityHeaders" not in config
