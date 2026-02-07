import asyncio
import logging

import pytest
from kubernetes import client

logger = logging.getLogger(__name__)

# Constants from Kind cluster state
STOCK_IMAGE = "quay.io/keycloak/keycloak:26.0.0"
# Use full names as reported by crictl to ensure Kind finds them locally
OPTIMIZED_NO_TRACING = "docker.io/library/keycloak-optimized:26.5.2"
OPTIMIZED_WITH_TRACING = "docker.io/library/keycloak-optimized-tracing:26.5.2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        {
            "name": "optimized_flag_mismatch",
            "image": STOCK_IMAGE,
            "optimized": True,
            "tracing": False,
            "expect_error": True,
            # Stock image fails either because --optimized flag is new, OR because DB defaults (H2) mismatch requested (Postgres)
            "error_substrs": [
                "The 'optimized' flag is enabled, but the image was not built",
                "Requested features (e.g. Tracing, DB, Cache) differ",
            ],
        },
        {
            "name": "tracing_mismatch",
            "image": OPTIMIZED_NO_TRACING,
            "optimized": True,
            "tracing": True,
            "expect_error": True,
            "error_substrs": ["Requested features (e.g. Tracing, DB, Cache) differ"],
        },
        {
            "name": "tracing_success",
            "image": OPTIMIZED_WITH_TRACING,
            "optimized": True,
            "tracing": True,
            "expect_error": False,
            "error_substrs": [],
        },
    ],
)
async def test_build_mismatch(
    k8s_client,
    test_keycloak_namespace,
    shared_cnpg_info,
    k8s_core_v1,
    k8s_custom_objects,
    scenario,
):
    """Test that build mismatches are detected and reported in CR status."""
    namespace = test_keycloak_namespace

    # 1. Setup Secrets (copy from CNPG)
    # We need to manually copy because we are not using sample_keycloak_spec_factory
    # which hides this logic.
    source_secret_name = shared_cnpg_info["password_secret"]
    source_namespace = shared_cnpg_info["password_secret_namespace"]

    try:
        source_secret = await k8s_core_v1.read_namespaced_secret(
            source_secret_name, source_namespace
        )

        db_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="test-db-secret",
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            data=source_secret.data,
            type=source_secret.type,
        )
        await k8s_core_v1.create_namespaced_secret(namespace, db_secret)

        # Create dummy admin secret
        admin_secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name="test-admin-secret",
                namespace=namespace,
                labels={
                    "vriesdemichael.github.io/keycloak-allow-operator-read": "true"
                },
            ),
            string_data={"password": "admin", "username": "admin"},
        )
        await k8s_core_v1.create_namespaced_secret(namespace, admin_secret)
    except Exception as e:
        pytest.fail(f"Failed to setup secrets: {e}")

    # 2. Create CR
    name = f"test-{scenario['name']}".replace("_", "-")
    spec = {
        "image": scenario["image"],
        "replicas": 1,
        "ingress": {"enabled": False},
        "optimized": scenario["optimized"],
        "database": {
            "type": shared_cnpg_info["type"],
            "host": shared_cnpg_info["host"],
            "port": shared_cnpg_info["port"],
            "database": shared_cnpg_info["database"],
            "username": shared_cnpg_info["username"],
            "credentialsSecret": "test-db-secret",
        },
    }

    if scenario["tracing"]:
        spec["tracing"] = {
            "enabled": True,
            "endpoint": "http://localhost:4317",
            "serviceName": "keycloak",
            "sampleRate": 1.0,
        }

    cr = {
        "apiVersion": "vriesdemichael.github.io/v1",
        "kind": "Keycloak",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"test": "mismatch-detection"},
        },
        "spec": spec,
    }

    logger.info(f"Creating Keycloak {name} with image {scenario['image']}")
    await k8s_custom_objects.create_namespaced_custom_object(
        group="vriesdemichael.github.io",
        version="v1",
        namespace=namespace,
        plural="keycloaks",
        body=cr,
    )

    # 3. Wait for result
    timeout = 300  # 5 minutes
    interval = 5
    elapsed = 0

    while elapsed < timeout:
        try:
            obj = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloaks",
                name=name,
            )
            status = obj.get("status", {})
            conditions = status.get("conditions", [])

            ready_cond = next((c for c in conditions if c["type"] == "Ready"), None)

            if scenario["expect_error"]:
                if ready_cond and ready_cond["status"] == "False":
                    msg = ready_cond.get("message", "")
                    # Check if ANY of the expected substrings are present
                    if any(sub in msg for sub in scenario["error_substrs"]):
                        logger.info(f"✓ Detected expected error: {msg}")
                        return
            else:
                if ready_cond and ready_cond["status"] == "True":
                    logger.info("✓ Resource is Ready as expected")
                    return

        except Exception as e:
            logger.debug(f"Error checking status: {e}")

        await asyncio.sleep(interval)
        elapsed += interval

    pytest.fail(f"Timeout waiting for scenario {scenario['name']} result")
