"""
Admission webhooks for Keycloak operator.

This module provides validating admission webhooks for KeycloakRealm,
KeycloakClient, and Keycloak custom resources. Webhooks validate resources
before they are accepted by Kubernetes, providing immediate feedback and
preventing invalid configurations from being stored.

Webhooks are served by Kopf's built-in HTTPS server with automatic
self-signed certificate generation and rotation.
"""
