"""
Test fixtures for Keycloak resources.

This module provides sample Keycloak custom resources for testing
purposes, including valid and invalid configurations.
"""

from typing import Any

# Basic Keycloak instance
MINIMAL_KEYCLOAK = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "Keycloak",
    "metadata": {"name": "test-keycloak", "namespace": "default"},
    "spec": {},
}

# Complete Keycloak instance with all options
COMPLETE_KEYCLOAK = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "Keycloak",
    "metadata": {
        "name": "production-keycloak",
        "namespace": "keycloak-system",
        "labels": {"app": "keycloak", "environment": "production"},
    },
    "spec": {
        "image": "quay.io/keycloak/keycloak:22.0.0",
        "replicas": 3,
        "resources": {
            "requests": {"cpu": "1000m", "memory": "1Gi"},
            "limits": {"cpu": "2000m", "memory": "2Gi"},
        },
        "service": {
            "type": "LoadBalancer",
            "httpPort": 8080,
            "httpsPort": 8443,
            "annotations": {"service.beta.kubernetes.io/aws-load-balancer-type": "nlb"},
        },
        "ingress": {
            "enabled": True,
            "className": "nginx",
            "host": "keycloak.example.com",
            "tlsEnabled": True,
            "tlsSecretName": "keycloak-tls",
        },
        "persistence": {"enabled": True, "storageClass": "fast-ssd", "size": "20Gi"},
        "database": {
            "type": "postgresql",
            "host": "postgres.database.svc.cluster.local",
            "port": 5432,
            "database": "keycloak",
            "username": "keycloak",
            "passwordSecret": "keycloak-db-credentials",
        },
        "admin": {"username": "admin", "createSecret": True},
        "tls": {"enabled": True, "secretName": "keycloak-server-tls"},
        "monitoringEnabled": True,
        "backupEnabled": True,
        "backupSchedule": "0 2 * * *",
    },
}

# Basic KeycloakClient
MINIMAL_KEYCLOAK_CLIENT = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {"name": "test-client", "namespace": "default"},
    "spec": {
        "clientId": "test-webapp",
        "keycloakInstanceRef": {"name": "test-keycloak"},
    },
}

# Complete KeycloakClient with all options
COMPLETE_KEYCLOAK_CLIENT = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {
        "name": "webapp-client",
        "namespace": "webapp",
        "labels": {"app": "webapp", "client-type": "web"},
    },
    "spec": {
        "clientId": "webapp",
        "clientName": "Web Application",
        "description": "Main web application client",
        "keycloakInstanceRef": {"name": "keycloak", "namespace": "keycloak-system"},
        "realm": "production",
        "publicClient": False,
        "protocol": "openid-connect",
        "redirectUris": [
            "https://webapp.example.com/auth/callback",
            "https://webapp.example.com/silent-callback",
        ],
        "webOrigins": ["https://webapp.example.com"],
        "postLogoutRedirectUris": ["https://webapp.example.com/logout"],
        "settings": {
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "consentRequired": False,
            "accessTokenLifespan": 300,
            "refreshTokenLifespan": 1800,
        },
        "defaultClientScopes": ["openid", "profile", "email"],
        "optionalClientScopes": ["address", "phone"],
        "clientRoles": ["user", "admin"],
        "attributes": {"pkce.code.challenge.method": "S256"},
        "manageSecret": True,
    },
}

# Public client for mobile/SPA
PUBLIC_CLIENT = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {"name": "mobile-app", "namespace": "mobile"},
    "spec": {
        "clientId": "mobile-app",
        "clientName": "Mobile Application",
        "keycloakInstanceRef": {"name": "keycloak", "namespace": "keycloak-system"},
        "realm": "mobile",
        "publicClient": True,
        "redirectUris": ["myapp://auth/callback"],
        "settings": {
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": False,
        },
        "attributes": {"pkce.code.challenge.method": "S256"},
    },
}

# Service account client
SERVICE_ACCOUNT_CLIENT = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {"name": "api-service", "namespace": "api"},
    "spec": {
        "clientId": "api-service",
        "clientName": "API Service Account",
        "keycloakInstanceRef": {"name": "keycloak", "namespace": "keycloak-system"},
        "realm": "services",
        "publicClient": False,
        "bearerOnly": True,
        "settings": {
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True,
        },
        "clientRoles": ["service-user"],
    },
}

# Basic KeycloakRealm
MINIMAL_KEYCLOAK_REALM = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakRealm",
    "metadata": {"name": "test-realm", "namespace": "default"},
    "spec": {"realmName": "test", "keycloakInstanceRef": {"name": "test-keycloak"}},
}

# Complete KeycloakRealm with all options
COMPLETE_KEYCLOAK_REALM = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakRealm",
    "metadata": {
        "name": "production-realm",
        "namespace": "production",
        "labels": {"environment": "production", "realm-type": "application"},
    },
    "spec": {
        "realmName": "production",
        "displayName": "Production Environment",
        "displayNameHtml": "<b>Production</b> Environment",
        "keycloakInstanceRef": {"name": "keycloak", "namespace": "keycloak-system"},
        "enabled": True,
        "themes": {
            "login": "custom-login",
            "admin": "custom-admin",
            "account": "custom-account",
            "email": "custom-email",
        },
        "localization": {
            "defaultLocale": "en",
            "supportedLocales": ["en", "de", "fr", "es"],
            "internationalizationEnabled": True,
        },
        "tokenSettings": {
            "accessTokenLifespan": 300,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
            "offlineSessionIdleTimeout": 2592000,
        },
        "security": {
            "passwordPolicy": "length(8) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)",
            "bruteForceProtected": True,
            "registrationAllowed": False,
            "resetPasswordAllowed": True,
            "rememberMe": True,
            "verifyEmail": True,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
        },
        "identityProviders": [
            {
                "alias": "google",
                "providerId": "google",
                "displayName": "Google",
                "enabled": True,
                "config": {
                    "clientId": "google-client-id",
                    "clientSecret": "google-client-secret",
                    "defaultScope": "openid profile email",
                },
                "trustEmail": True,
            },
            {
                "alias": "github",
                "providerId": "github",
                "displayName": "GitHub",
                "enabled": True,
                "config": {
                    "clientId": "github-client-id",
                    "clientSecret": "github-client-secret",
                },
            },
        ],
        "userFederation": [
            {
                "name": "company-ldap",
                "providerId": "ldap",
                "priority": 0,
                "enabled": True,
                "config": {
                    "connectionUrl": "ldaps://ldap.company.com:636",
                    "usersDn": "ou=users,dc=company,dc=com",
                    "bindDn": "cn=service,dc=company,dc=com",
                    "bindCredential": "service-password",
                },
            }
        ],
        "smtpServer": {
            "host": "smtp.company.com",
            "port": "587",
            "auth": "true",
            "starttls": "true",
            "user": "keycloak@company.com",
            "password": "smtp-password",
        },
        "eventsEnabled": True,
        "eventsListeners": ["jboss-logging", "email"],
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": True,
        "deletionProtection": True,
        "backupOnDelete": True,
    },
}

# Invalid resources for testing validation
INVALID_KEYCLOAK_MISSING_METADATA = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "Keycloak",
    "spec": {},
}

INVALID_KEYCLOAK_CLIENT_NO_CLIENT_ID = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {"name": "invalid-client", "namespace": "default"},
    "spec": {"keycloakInstanceRef": {"name": "keycloak"}},
}

INVALID_KEYCLOAK_CLIENT_WILDCARD_REDIRECT = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakClient",
    "metadata": {"name": "invalid-client", "namespace": "default"},
    "spec": {
        "clientId": "invalid-client",
        "keycloakInstanceRef": {"name": "keycloak"},
        "redirectUris": ["https://*.example.com/callback"],
    },
}

INVALID_KEYCLOAK_REALM_BAD_NAME = {
    "apiVersion": "keycloak.mdvr.nl/v1",
    "kind": "KeycloakRealm",
    "metadata": {"name": "invalid-realm", "namespace": "default"},
    "spec": {
        "realmName": "realm with spaces",
        "keycloakInstanceRef": {"name": "keycloak"},
    },
}


def get_test_resource(resource_name: str) -> dict[str, Any]:
    """
    Get a test resource by name.

    Args:
        resource_name: Name of the resource to retrieve

    Returns:
        Dictionary containing the resource definition

    Raises:
        KeyError: If resource name is not found
    """
    resources = {
        "minimal_keycloak": MINIMAL_KEYCLOAK,
        "complete_keycloak": COMPLETE_KEYCLOAK,
        "minimal_client": MINIMAL_KEYCLOAK_CLIENT,
        "complete_client": COMPLETE_KEYCLOAK_CLIENT,
        "public_client": PUBLIC_CLIENT,
        "service_account_client": SERVICE_ACCOUNT_CLIENT,
        "minimal_realm": MINIMAL_KEYCLOAK_REALM,
        "complete_realm": COMPLETE_KEYCLOAK_REALM,
        "invalid_keycloak_missing_metadata": INVALID_KEYCLOAK_MISSING_METADATA,
        "invalid_client_no_client_id": INVALID_KEYCLOAK_CLIENT_NO_CLIENT_ID,
        "invalid_client_wildcard_redirect": INVALID_KEYCLOAK_CLIENT_WILDCARD_REDIRECT,
        "invalid_realm_bad_name": INVALID_KEYCLOAK_REALM_BAD_NAME,
    }

    if resource_name not in resources:
        raise KeyError(f"Test resource '{resource_name}' not found")

    # Return a copy to avoid modifying the original
    import copy

    return copy.deepcopy(resources[resource_name])
