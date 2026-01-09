"""
Pytest fixtures for user federation integration testing.

This module provides fixtures for:
- OpenLDAP server (standard LDAP testing)
- OpenLDAP with AD schema (Active Directory simulation)
- MIT Kerberos KDC (Kerberos authentication testing)

These fixtures deploy the test infrastructure into the Kind cluster
and provide connection information for tests.
"""

import asyncio
import base64
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from kubernetes import client
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# Paths to deployment manifests
FIXTURES_DIR = Path(__file__).parent / "fixtures"
OPENLDAP_MANIFEST = FIXTURES_DIR / "openldap-deployment.yaml"
OPENLDAP_AD_MANIFEST = FIXTURES_DIR / "openldap-ad-deployment.yaml"
KERBEROS_MANIFEST = FIXTURES_DIR / "kerberos-deployment.yaml"


async def _wait_for_deployment_ready(
    apps_api: client.AppsV1Api,
    name: str,
    namespace: str,
    timeout: int = 300,
) -> bool:
    """Wait for a deployment to be ready."""
    start_time = asyncio.get_event_loop().time()
    while (asyncio.get_event_loop().time() - start_time) < timeout:
        try:
            deployment = apps_api.read_namespaced_deployment(name, namespace)
            if (
                deployment.status.ready_replicas
                and deployment.status.ready_replicas >= 1
            ):
                return True
        except ApiException:
            pass
        await asyncio.sleep(5)
    return False


def _apply_manifests(manifest_path: Path, namespace: str) -> None:
    """Apply Kubernetes manifests with namespace override."""
    with open(manifest_path) as f:
        manifests = list(yaml.safe_load_all(f))

    # Update namespace in all manifests
    for manifest in manifests:
        if manifest and "metadata" in manifest:
            manifest["metadata"]["namespace"] = namespace

    # Write updated manifests to temp file and apply
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump_all(manifests, f)
        temp_manifest = f.name

    try:
        result = subprocess.run(
            ["kubectl", "apply", "-f", temp_manifest],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        logger.info(f"Applied manifests from {manifest_path.name}: {result.stdout}")
    finally:
        Path(temp_manifest).unlink(missing_ok=True)


def _delete_manifests(manifest_path: Path, namespace: str) -> None:
    """Delete Kubernetes manifests."""
    with open(manifest_path) as f:
        manifests = list(yaml.safe_load_all(f))

    # Update namespace in all manifests
    for manifest in manifests:
        if manifest and "metadata" in manifest:
            manifest["metadata"]["namespace"] = namespace

    # Write updated manifests to temp file and delete
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump_all(manifests, f)
        temp_manifest = f.name

    try:
        subprocess.run(
            ["kubectl", "delete", "-f", temp_manifest, "--ignore-not-found=true"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        logger.info(f"Deleted manifests from {manifest_path.name}")
    except Exception as e:
        logger.warning(f"Error deleting manifests: {e}")
    finally:
        Path(temp_manifest).unlink(missing_ok=True)


@pytest.fixture
async def openldap_ready(
    operator_namespace: str,
) -> dict[str, Any]:
    """Deploy OpenLDAP server for LDAP federation testing.

    Deploys a standard OpenLDAP server with test users and groups.
    The server is deployed to the operator namespace and cleaned up after tests.

    Test users (password = username):
    - alice (uid=alice, member of developers)
    - bob (uid=bob, member of developers)
    - charlie (uid=charlie, member of admins)

    Yields:
        dict with connection information:
        - connection_url: LDAP URL
        - bind_dn: Admin bind DN
        - bind_password: Admin password
        - users_dn: Base DN for users
        - groups_dn: Base DN for groups
        - readonly_bind_dn: Read-only user bind DN
        - readonly_password: Read-only user password
        - test_users: List of test user info
    """
    apps_api = client.AppsV1Api()
    namespace = operator_namespace

    logger.info(f"Deploying OpenLDAP to {namespace}...")
    _apply_manifests(OPENLDAP_MANIFEST, namespace)

    try:
        # Wait for deployment to be ready
        ready = await _wait_for_deployment_ready(
            apps_api, "openldap", namespace, timeout=300
        )
        if not ready:
            # Get pod logs for debugging
            try:
                result = subprocess.run(
                    [
                        "kubectl",
                        "logs",
                        "-n",
                        namespace,
                        "-l",
                        "app=openldap",
                        "--tail=50",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.error(f"OpenLDAP logs:\n{result.stdout}\n{result.stderr}")
            except Exception as e:
                logger.error(f"Failed to get OpenLDAP logs: {e}")
            raise TimeoutError(
                f"OpenLDAP deployment did not become ready within 300s in {namespace}"
            )

        logger.info("✓ OpenLDAP is ready")

        yield {
            "connection_url": f"ldap://openldap.{namespace}.svc.cluster.local:389",
            "bind_dn": "cn=admin,dc=example,dc=org",
            "bind_password": "admin",
            "users_dn": "ou=People,dc=example,dc=org",
            "groups_dn": "ou=Groups,dc=example,dc=org",
            "readonly_bind_dn": "cn=readonly,dc=example,dc=org",
            "readonly_password": "readonly123",
            "base_dn": "dc=example,dc=org",
            "vendor": "other",  # Standard OpenLDAP
            "username_attribute": "uid",
            "uuid_attribute": "entryUUID",
            "test_users": [
                {"uid": "alice", "password": "alice123", "email": "alice@example.org"},
                {"uid": "bob", "password": "bob123", "email": "bob@example.org"},
                {
                    "uid": "charlie",
                    "password": "charlie123",
                    "email": "charlie@example.org",
                },
            ],
            "test_groups": [
                {"cn": "developers", "members": ["alice", "bob"]},
                {"cn": "admins", "members": ["charlie"]},
            ],
        }

    finally:
        logger.info("Cleaning up OpenLDAP...")
        _delete_manifests(OPENLDAP_MANIFEST, namespace)


@pytest.fixture
async def openldap_ad_ready(
    operator_namespace: str,
) -> dict[str, Any]:
    """Deploy OpenLDAP with Active Directory schema simulation.

    Deploys OpenLDAP with custom AD-compatible schema attributes:
    - sAMAccountName (login name)
    - userPrincipalName (user@domain format)

    This simulates an Active Directory environment for testing AD-specific
    federation configurations.

    Test users (password = username):
    - alice (sAMAccountName=alice, userPrincipalName=alice@corp.example.com)
    - bob (sAMAccountName=bob, userPrincipalName=bob@corp.example.com)
    - charlie (sAMAccountName=charlie, userPrincipalName=charlie@corp.example.com)

    Yields:
        dict with AD-style connection information
    """
    apps_api = client.AppsV1Api()
    namespace = operator_namespace

    logger.info(f"Deploying OpenLDAP with AD schema to {namespace}...")
    _apply_manifests(OPENLDAP_AD_MANIFEST, namespace)

    try:
        # Wait for deployment to be ready
        ready = await _wait_for_deployment_ready(
            apps_api, "openldap-ad", namespace, timeout=300
        )
        if not ready:
            # Get pod logs for debugging
            try:
                result = subprocess.run(
                    [
                        "kubectl",
                        "logs",
                        "-n",
                        namespace,
                        "-l",
                        "app=openldap-ad",
                        "--tail=50",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.error(f"OpenLDAP-AD logs:\n{result.stdout}\n{result.stderr}")
            except Exception as e:
                logger.error(f"Failed to get OpenLDAP-AD logs: {e}")
            raise TimeoutError(
                f"OpenLDAP-AD deployment did not become ready within 300s in {namespace}"
            )

        logger.info("✓ OpenLDAP with AD schema is ready")

        yield {
            "connection_url": f"ldap://openldap-ad.{namespace}.svc.cluster.local:389",
            "bind_dn": "cn=admin,dc=corp,dc=example,dc=com",
            "bind_password": "admin",
            "users_dn": "ou=Users,dc=corp,dc=example,dc=com",
            "groups_dn": "ou=Groups,dc=corp,dc=example,dc=com",
            "readonly_bind_dn": "cn=readonly,dc=corp,dc=example,dc=com",
            "readonly_password": "readonly123",
            "base_dn": "dc=corp,dc=example,dc=com",
            "vendor": "ad",  # Active Directory
            "username_attribute": "sAMAccountName",
            "upn_attribute": "userPrincipalName",
            "uuid_attribute": "objectGUID",  # AD uses objectGUID
            "rdn_attribute": "cn",  # AD uses cn as RDN
            "test_users": [
                {
                    "sAMAccountName": "alice",
                    "userPrincipalName": "alice@corp.example.com",
                    "password": "alice123",
                    "email": "alice@corp.example.com",
                },
                {
                    "sAMAccountName": "bob",
                    "userPrincipalName": "bob@corp.example.com",
                    "password": "bob123",
                    "email": "bob@corp.example.com",
                },
                {
                    "sAMAccountName": "charlie",
                    "userPrincipalName": "charlie@corp.example.com",
                    "password": "charlie123",
                    "email": "charlie@corp.example.com",
                },
            ],
            "test_groups": [
                {"cn": "Domain Users", "members": ["alice", "bob", "charlie"]},
                {"cn": "Domain Admins", "members": ["charlie"]},
                {"cn": "Developers", "members": ["alice", "bob"]},
            ],
        }

    finally:
        logger.info("Cleaning up OpenLDAP-AD...")
        _delete_manifests(OPENLDAP_AD_MANIFEST, namespace)


@pytest.fixture
async def kerberos_ready(
    operator_namespace: str,
) -> dict[str, Any]:
    """Deploy MIT Kerberos KDC for Kerberos federation testing.

    Deploys a MIT Kerberos KDC with:
    - Kerberos realm: EXAMPLE.ORG
    - HTTP service principal for Keycloak
    - Test user principals

    The keytab for the HTTP service is generated and can be retrieved
    from the pod.

    Test principals (password = username):
    - alice@EXAMPLE.ORG
    - bob@EXAMPLE.ORG
    - charlie@EXAMPLE.ORG

    Yields:
        dict with Kerberos configuration:
        - realm: Kerberos realm name
        - kdc_server: KDC hostname
        - admin_server: Admin server hostname
        - service_principal: HTTP service principal for Keycloak
        - keytab_path: Path to keytab in pod
        - test_principals: List of test principals
    """
    apps_api = client.AppsV1Api()
    namespace = operator_namespace

    logger.info(f"Deploying MIT Kerberos KDC to {namespace}...")
    _apply_manifests(KERBEROS_MANIFEST, namespace)

    try:
        # Wait for deployment to be ready
        ready = await _wait_for_deployment_ready(
            apps_api,
            "kerberos",
            namespace,
            timeout=360,  # KDC takes longer to init
        )
        if not ready:
            # Get pod logs for debugging
            try:
                result = subprocess.run(
                    [
                        "kubectl",
                        "logs",
                        "-n",
                        namespace,
                        "-l",
                        "app=kerberos",
                        "-c",
                        "kdc",
                        "--tail=50",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                logger.error(f"Kerberos KDC logs:\n{result.stdout}\n{result.stderr}")
            except Exception as e:
                logger.error(f"Failed to get Kerberos logs: {e}")
            raise TimeoutError(
                f"Kerberos KDC deployment did not become ready within 360s in {namespace}"
            )

        # Wait for keytab to be ready (check for .ready marker)
        keytab_ready = False
        for _ in range(60):  # 60 * 5 = 300 seconds
            try:
                # Check if the keytab exporter has created the ready marker
                result = subprocess.run(
                    [
                        "kubectl",
                        "exec",
                        "-n",
                        namespace,
                        "-l",
                        "app=kerberos",
                        "-c",
                        "keytab-exporter",
                        "--",
                        "test",
                        "-f",
                        "/keytab-out/.ready",
                    ],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    keytab_ready = True
                    break
            except Exception:
                pass
            await asyncio.sleep(5)

        if not keytab_ready:
            logger.warning("Keytab ready marker not found, but KDC is running")

        logger.info("✓ MIT Kerberos KDC is ready")

        keycloak_host = f"keycloak.{namespace}.svc.cluster.local"
        yield {
            "realm": "EXAMPLE.ORG",
            "kdc_server": f"kerberos.{namespace}.svc.cluster.local",
            "admin_server": f"kerberos.{namespace}.svc.cluster.local",
            "service_principal": f"HTTP/{keycloak_host}@EXAMPLE.ORG",
            "keytab_pod_path": "/keytab-out/keycloak.keytab",
            "admin_principal": "admin@EXAMPLE.ORG",
            "admin_password": "admin",
            "namespace": namespace,
            "test_principals": [
                {"principal": "alice@EXAMPLE.ORG", "password": "alice"},
                {"principal": "bob@EXAMPLE.ORG", "password": "bob"},
                {"principal": "charlie@EXAMPLE.ORG", "password": "charlie"},
            ],
        }

    finally:
        logger.info("Cleaning up Kerberos KDC...")
        _delete_manifests(KERBEROS_MANIFEST, namespace)


async def retrieve_kerberos_keytab(
    kerberos_info: dict[str, Any],
) -> bytes:
    """Retrieve the keytab from the Kerberos KDC pod.

    Args:
        kerberos_info: The dict returned by kerberos_ready fixture

    Returns:
        bytes: The keytab file content
    """
    namespace = kerberos_info["namespace"]
    keytab_path = kerberos_info["keytab_pod_path"]

    # Get pod name
    result = subprocess.run(
        [
            "kubectl",
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            "app=kerberos",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    pod_name = result.stdout.strip()

    # Copy keytab to local temp file
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_path = f.name

    try:
        subprocess.run(
            [
                "kubectl",
                "cp",
                f"{namespace}/{pod_name}:{keytab_path}",
                temp_path,
                "-c",
                "keytab-exporter",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )

        with open(temp_path, "rb") as f:
            return f.read()
    finally:
        Path(temp_path).unlink(missing_ok=True)


async def create_keytab_secret(
    core_api: client.CoreV1Api,
    kerberos_info: dict[str, Any],
    secret_name: str,
    target_namespace: str,
) -> None:
    """Create a Kubernetes secret containing the Kerberos keytab.

    This creates a secret that can be referenced by the user federation
    configuration for Kerberos authentication.

    Args:
        core_api: Kubernetes Core V1 API client
        kerberos_info: The dict returned by kerberos_ready fixture
        secret_name: Name for the secret
        target_namespace: Namespace to create the secret in
    """
    keytab_data = await retrieve_kerberos_keytab(kerberos_info)

    secret = client.V1Secret(
        metadata=client.V1ObjectMeta(
            name=secret_name,
            namespace=target_namespace,
            labels={
                "vriesdemichael.github.io/keycloak-allow-operator-read": "true",
            },
        ),
        data={
            "keytab": base64.b64encode(keytab_data).decode("utf-8"),
        },
    )

    try:
        core_api.create_namespaced_secret(namespace=target_namespace, body=secret)
        logger.info(f"Created keytab secret {secret_name} in {target_namespace}")
    except ApiException as e:
        if e.status == 409:
            # Secret already exists, update it
            core_api.replace_namespaced_secret(
                name=secret_name, namespace=target_namespace, body=secret
            )
            logger.info(f"Updated keytab secret {secret_name} in {target_namespace}")
        else:
            raise
