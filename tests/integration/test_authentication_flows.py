"""
Integration tests for Keycloak authentication flow configuration.

These tests verify that the operator correctly:
1. Creates custom authentication flows with executions
2. Copies built-in flows and modifies them
3. Configures required actions
4. Binds flows to realm authentication types

Note: Authentication flow testing requires careful timing as flows
may take longer to fully propagate in Keycloak.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid

import pytest
from kubernetes.client.rest import ApiException

from .wait_helpers import (
    wait_for_keycloak_realm_state,
    wait_for_reconciliation_complete,
    wait_for_resource_deleted,
    wait_for_resource_ready,
)

logger = logging.getLogger(__name__)


async def _cleanup_resource(
    k8s_custom_objects,
    group: str,
    version: str,
    namespace: str,
    plural: str,
    name: str,
    timeout: int = 60,
) -> None:
    """Helper to delete a resource and wait for deletion to complete."""
    with contextlib.suppress(ApiException):
        await k8s_custom_objects.delete_namespaced_custom_object(
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
        )
    # Wait for resource to be fully deleted (ignore if already gone)
    with contextlib.suppress(Exception):
        await wait_for_resource_deleted(
            k8s_custom_objects=k8s_custom_objects,
            group=group,
            version=version,
            namespace=namespace,
            plural=plural,
            name=name,
            timeout=timeout,
        )


@pytest.mark.integration
@pytest.mark.requires_cluster
class TestAuthenticationFlows:
    """Test authentication flow configuration via the operator."""

    @pytest.mark.timeout(180)
    async def test_realm_with_custom_authentication_flow(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with a custom authentication flow.

        This test verifies that:
        - A realm can be created with an authentication flow definition
        - The flow is created in Keycloak with the correct alias
        - The flow has the expected provider ID
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"auth-flow-{suffix}"
        flow_alias = f"custom-browser-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Define a simple custom flow with cookie and identity provider redirector
        custom_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Custom browser flow for testing",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",
                    priority=10,
                ),
                AuthenticationExecutionExport(
                    authenticator="identity-provider-redirector",
                    requirement="ALTERNATIVE",
                    priority=20,
                ),
            ],
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Auth Flow Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[custom_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with authentication flow
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with flow: {flow_alias}")

            # Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm exists in Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Verify authentication flow was created
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, f"Flow {flow_alias} should exist in realm"
            assert flow.alias == flow_alias
            assert flow.provider_id == "basic-flow"
            assert flow.top_level is True
            assert flow.built_in is False

            logger.info(f"✓ Successfully verified custom flow '{flow_alias}'")

            # Verify executions exist in flow
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            # Should have at least 2 executions (auth-cookie and identity-provider-redirector)
            assert len(executions) >= 2, (
                f"Flow should have at least 2 executions, got {len(executions)}"
            )

            # Check that expected authenticators are present
            authenticator_ids = [ex.provider_id for ex in executions if ex.provider_id]
            assert "auth-cookie" in authenticator_ids, (
                "auth-cookie should be in flow executions"
            )
            assert "identity-provider-redirector" in authenticator_ids, (
                "identity-provider-redirector should be in flow executions"
            )

            logger.info(
                f"✓ Flow has {len(executions)} executions with correct authenticators"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_copied_flow(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with a flow copied from built-in browser flow.

        This test verifies that:
        - A flow can be created by copying an existing built-in flow
        - The copied flow has a different alias
        - The copied flow is not marked as built-in
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"copy-flow-{suffix}"
        new_flow_alias = f"browser-copy-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Define a flow that copies from the built-in browser flow
        copied_flow = KeycloakAuthenticationFlow(
            alias=new_flow_alias,
            description="Copied browser flow for testing",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            copy_from="browser",  # Copy from built-in browser flow
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Copy Flow Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[copied_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(
                f"Created realm CR: {realm_name} with copied flow: {new_flow_alias}"
            )

            # Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm exists
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Verify the copied flow exists and is not built-in
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, new_flow_alias, namespace
            )
            assert flow is not None, f"Copied flow {new_flow_alias} should exist"
            assert flow.alias == new_flow_alias
            assert flow.built_in is False, (
                "Copied flow should not be marked as built-in"
            )

            # Verify the copied flow has executions (inherited from browser flow)
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, new_flow_alias, namespace
            )
            assert len(executions) > 0, (
                "Copied flow should have executions from browser flow"
            )

            logger.info(
                f"✓ Successfully copied flow '{new_flow_alias}' with "
                f"{len(executions)} executions"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_flow_binding(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with a custom flow bound as browser flow.

        This test verifies that:
        - A custom flow can be created and bound to the realm
        - The browserFlow binding is correctly set in the realm
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"flow-bind-{suffix}"
        custom_flow_alias = f"custom-browser-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a flow that will be bound as browser flow
        # We copy from browser so it has valid executions
        custom_flow = KeycloakAuthenticationFlow(
            alias=custom_flow_alias,
            description="Custom browser flow to be bound",
            provider_id="basic-flow",
            top_level=True,
            copy_from="browser",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Flow Binding Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[custom_flow],
            browser_flow=custom_flow_alias,  # Bind the custom flow as browser flow
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with flow binding
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(
                f"Created realm CR: {realm_name} with browserFlow: {custom_flow_alias}"
            )

            # Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm exists and has correct browser flow binding
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Check the browserFlow is set to our custom flow
            # Note: The reconciler applies flow bindings via realm update
            assert realm_repr.browser_flow == custom_flow_alias, (
                f"browserFlow should be '{custom_flow_alias}', "
                f"got '{realm_repr.browser_flow}'"
            )

            logger.info(f"✓ Browser flow correctly bound to '{custom_flow_alias}'")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_required_actions(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with required actions configuration.

        This test verifies that:
        - Required actions can be configured via the realm spec
        - Actions can be enabled/disabled
        - Default action flag can be set
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"req-actions-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            RequiredActionProvider,
        )

        # Configure some required actions
        required_actions = [
            RequiredActionProvider(
                alias="CONFIGURE_TOTP",
                name="Configure OTP",
                enabled=True,
                default_action=False,
                priority=10,
            ),
            RequiredActionProvider(
                alias="VERIFY_EMAIL",
                name="Verify Email",
                enabled=True,
                default_action=True,  # New users must verify email
                priority=20,
            ),
            RequiredActionProvider(
                alias="UPDATE_PASSWORD",
                name="Update Password",
                enabled=True,
                default_action=False,
                priority=30,
            ),
        ]

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Required Actions Test Realm",
            client_authorization_grants=[namespace],
            required_actions=required_actions,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm with required actions
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with required actions")

            # Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm exists
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Poll for required actions to be configured
            actions = []
            for _ in range(20):
                actions = await keycloak_admin_client.get_required_actions(
                    realm_name, namespace
                )
                action_map = {action.alias: action for action in actions}
                # Check if our custom actions are present
                if (
                    action_map.get("CONFIGURE_TOTP")
                    and action_map.get("VERIFY_EMAIL")
                    and action_map.get("UPDATE_PASSWORD")
                ):
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for required actions to be configured")

            # Build a map for easier lookup
            action_map = {action.alias: action for action in actions}

            # Check CONFIGURE_TOTP
            totp_action = action_map.get("CONFIGURE_TOTP")
            assert totp_action is not None, "CONFIGURE_TOTP should exist"
            assert totp_action.enabled is True, "CONFIGURE_TOTP should be enabled"

            # Check VERIFY_EMAIL is default action
            verify_email = action_map.get("VERIFY_EMAIL")
            assert verify_email is not None, "VERIFY_EMAIL should exist"
            assert verify_email.enabled is True, "VERIFY_EMAIL should be enabled"
            assert verify_email.default_action is True, (
                "VERIFY_EMAIL should be a default action"
            )

            # Check UPDATE_PASSWORD
            update_pwd = action_map.get("UPDATE_PASSWORD")
            assert update_pwd is not None, "UPDATE_PASSWORD should exist"
            assert update_pwd.enabled is True, "UPDATE_PASSWORD should be enabled"

            logger.info("✓ Successfully verified required actions in realm")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_authentication_flow_cleanup(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that authentication flows are cleaned up when realm is deleted.

        This test verifies that:
        - Custom flows are removed when realm is deleted
        - Realm deletion succeeds with custom flows
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"flow-cleanup-{suffix}"
        flow_alias = f"cleanup-test-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        custom_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Flow for cleanup testing",
            provider_id="basic-flow",
            top_level=True,
            copy_from="browser",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Flow Cleanup Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[custom_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            # Wait for realm to become ready
            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify flow exists
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, f"Flow {flow_alias} should exist before deletion"

            logger.info(f"✓ Flow '{flow_alias}' exists, now deleting realm...")

            # Delete realm
            await k8s_custom_objects.delete_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

            # Wait for CR deletion
            await wait_for_resource_deleted(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
            )

            # Wait for realm to be removed from Keycloak (poll instead of fixed sleep)
            # The finalizer deletes the realm, but there can be a delay under load
            async def realm_deleted_from_keycloak() -> bool:
                realm_repr = await keycloak_admin_client.get_realm(
                    realm_name, namespace
                )
                return realm_repr is None

            for _ in range(30):  # 30 * 2s = 60s max
                if await realm_deleted_from_keycloak():
                    break
                await asyncio.sleep(2)
            else:
                pytest.fail(
                    f"Timed out waiting for realm {realm_name} deletion from Keycloak"
                )

            # Verify realm (and thus flows) are deleted from Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is None, (
                f"Realm {realm_name} should be deleted from Keycloak"
            )

            logger.info("✓ Realm and flows successfully cleaned up")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_multiple_flow_bindings(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a realm with multiple flow bindings.

        This test verifies that:
        - Multiple custom flows can be created
        - Multiple flow bindings can be set (browserFlow, directGrantFlow)
        - All bindings are correctly applied to the realm
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"multi-bind-{suffix}"
        browser_flow_alias = f"custom-browser-{suffix}"
        direct_grant_alias = f"custom-direct-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create two custom flows
        browser_flow = KeycloakAuthenticationFlow(
            alias=browser_flow_alias,
            description="Custom browser flow",
            provider_id="basic-flow",
            top_level=True,
            copy_from="browser",
        )

        direct_grant_flow = KeycloakAuthenticationFlow(
            alias=direct_grant_alias,
            description="Custom direct grant flow",
            provider_id="basic-flow",
            top_level=True,
            copy_from="direct grant",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Multi Binding Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[browser_flow, direct_grant_flow],
            browser_flow=browser_flow_alias,
            direct_grant_flow=direct_grant_alias,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with multiple flow bindings")

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Poll Keycloak directly for flow bindings - Ready status doesn't
            # guarantee bindings are applied due to reconciliation timing
            realm_repr = await wait_for_keycloak_realm_state(
                keycloak_admin_client,
                realm_name=realm_name,
                namespace=namespace,
                condition_func=lambda r: (
                    r.browser_flow == browser_flow_alias
                    and r.direct_grant_flow == direct_grant_alias
                ),
                condition_description=(
                    f"flow bindings applied (browserFlow={browser_flow_alias}, "
                    f"directGrantFlow={direct_grant_alias})"
                ),
                timeout=60,
            )
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            logger.info("✓ Multiple flow bindings correctly applied")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_required_action_default_action_flag(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that defaultAction flag is correctly set on required actions.

        This test specifically verifies that:
        - defaultAction=True makes an action apply to new users
        - defaultAction=False does not apply to new users
        - Multiple actions with different defaultAction settings work
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"default-action-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            RequiredActionProvider,
        )

        # CONFIGURE_TOTP as default action (new users must set up OTP)
        # VERIFY_EMAIL as non-default (users can verify later)
        required_actions = [
            RequiredActionProvider(
                alias="CONFIGURE_TOTP",
                name="Configure OTP",
                enabled=True,
                default_action=True,  # NEW users must configure
                priority=10,
            ),
            RequiredActionProvider(
                alias="VERIFY_EMAIL",
                name="Verify Email",
                enabled=True,
                default_action=False,  # NOT required for new users
                priority=20,
            ),
        ]

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Default Action Test Realm",
            client_authorization_grants=[namespace],
            required_actions=required_actions,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Allow time for required actions to be configured
            actions = []
            for _ in range(20):
                actions = await keycloak_admin_client.get_required_actions(
                    realm_name, namespace
                )
                action_map = {action.alias: action for action in actions}
                if action_map.get("CONFIGURE_TOTP") and action_map.get("VERIFY_EMAIL"):
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for required actions to be configured")
            action_map = {action.alias: action for action in actions}

            # CONFIGURE_TOTP should be a default action
            totp = action_map.get("CONFIGURE_TOTP")
            assert totp is not None, "CONFIGURE_TOTP should exist"
            assert totp.default_action is True, (
                "CONFIGURE_TOTP should be a default action"
            )

            # VERIFY_EMAIL should NOT be a default action
            verify_email = action_map.get("VERIFY_EMAIL")
            assert verify_email is not None, "VERIFY_EMAIL should exist"
            assert verify_email.default_action is False, (
                "VERIFY_EMAIL should NOT be a default action"
            )

            logger.info("✓ defaultAction flags correctly applied")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_update_adds_new_flow(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that updating a realm spec adds new authentication flows.

        This tests the re-reconciliation scenario:
        1. Create realm without authentication flows
        2. Update realm to add an authentication flow
        3. Verify the flow is created
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"update-flow-{suffix}"
        flow_alias = f"added-flow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # First create realm WITHOUT authentication flows
        realm_spec_v1 = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Update Flow Test Realm",
            client_authorization_grants=[namespace],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec_v1.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create initial realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} without flows")

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify no custom flow exists yet
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is None, f"Flow {flow_alias} should not exist yet"

            # Now update the realm to add an authentication flow
            new_flow = KeycloakAuthenticationFlow(
                alias=flow_alias,
                description="Flow added via update",
                provider_id="basic-flow",
                top_level=True,
                copy_from="browser",
            )

            realm_spec_v2 = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Update Flow Test Realm - Updated",
                client_authorization_grants=[namespace],
                authentication_flows=[new_flow],
            )

            updated_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm_name, "namespace": namespace},
                "spec": realm_spec_v2.model_dump(by_alias=True, exclude_unset=True),
            }

            # Patch the realm
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=updated_manifest,
            )

            logger.info(f"Updated realm CR: {realm_name} to add flow")

            # Wait for re-reconciliation to complete
            # The operator needs time to process the update and create the flow
            # Poll for the flow to appear (max 60s)
            flow = None
            for _ in range(20):  # 20 * 3s = 60s max
                await asyncio.sleep(3)
                flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                    realm_name, flow_alias, namespace
                )
                if flow is not None:
                    break
            else:
                pytest.fail(f"Timed out waiting for flow {flow_alias} to be created")

            assert flow is not None, f"Flow {flow_alias} should exist after update"
            assert flow.alias == flow_alias

            logger.info("✓ Flow successfully added via realm update")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_inline_flow_executions(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a flow with inline executions (not copyFrom).

        This tests the _add_flow_executions code path:
        - Create a new flow from scratch (not copying)
        - Add executions with specific requirements
        - Verify executions exist with correct settings
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"inline-exec-{suffix}"
        flow_alias = f"inline-flow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a flow from scratch with inline executions
        inline_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Flow with inline executions",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            # No copyFrom - create from scratch
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",
                    priority=10,
                ),
                AuthenticationExecutionExport(
                    authenticator="identity-provider-redirector",
                    requirement="ALTERNATIVE",
                    priority=20,
                ),
            ],
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Inline Executions Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[inline_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(
                f"Created realm CR: {realm_name} with inline flow: {flow_alias}"
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify the flow was created
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, f"Flow {flow_alias} should exist"
            assert flow.alias == flow_alias
            assert flow.built_in is False

            # Verify executions were added
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            # Should have at least 2 executions
            assert len(executions) >= 2, (
                f"Flow should have at least 2 executions, got {len(executions)}"
            )

            # Check authenticators are present
            authenticator_ids = [ex.provider_id for ex in executions if ex.provider_id]
            assert "auth-cookie" in authenticator_ids, (
                "auth-cookie should be in flow executions"
            )

            logger.info(
                f"✓ Flow {flow_alias} created with {len(executions)} inline executions"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_disabled_required_action(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that required actions can be disabled.

        This tests the enabled=False path:
        - Configure a required action with enabled=False
        - Verify it's disabled in Keycloak
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"disabled-action-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            RequiredActionProvider,
        )

        # Disable UPDATE_PASSWORD action
        required_actions = [
            RequiredActionProvider(
                alias="UPDATE_PASSWORD",
                name="Update Password",
                enabled=False,  # Explicitly disabled
                default_action=False,
                priority=10,
            ),
        ]

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Disabled Action Test Realm",
            client_authorization_grants=[namespace],
            required_actions=required_actions,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Allow time for required actions to be configured
            actions = []
            for _ in range(20):
                actions = await keycloak_admin_client.get_required_actions(
                    realm_name, namespace
                )
                action_map = {action.alias: action for action in actions}
                update_pwd = action_map.get("UPDATE_PASSWORD")
                # Wait until action exists and is disabled
                if update_pwd and update_pwd.enabled is False:
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for UPDATE_PASSWORD to be disabled")
            action_map = {action.alias: action for action in actions}

            update_pwd = action_map.get("UPDATE_PASSWORD")
            assert update_pwd is not None, "UPDATE_PASSWORD should exist"
            assert update_pwd.enabled is False, "UPDATE_PASSWORD should be disabled"

            logger.info("✓ Required action correctly disabled")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_nested_subflow(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a flow with nested sub-flows.

        This tests the add_subflow_to_flow code path:
        - Create a top-level flow
        - Add a sub-flow execution (authenticatorFlow=true with flowAlias)
        - Verify the sub-flow structure is created correctly
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"subflow-test-{suffix}"
        flow_alias = f"parent-flow-{suffix}"
        subflow_alias = f"subflow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a flow with a nested sub-flow
        parent_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Parent flow with sub-flow",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            authentication_executions=[
                # Regular authenticator
                AuthenticationExecutionExport(
                    authenticator="auth-cookie",
                    requirement="ALTERNATIVE",
                    priority=10,
                ),
                # Sub-flow reference
                AuthenticationExecutionExport(
                    flow_alias=subflow_alias,
                    authenticator_flow=True,
                    requirement="ALTERNATIVE",
                    priority=20,
                ),
            ],
        )

        # Define the sub-flow itself
        sub_flow = KeycloakAuthenticationFlow(
            alias=subflow_alias,
            description="Nested sub-flow",
            provider_id="basic-flow",
            top_level=False,  # Sub-flow, not top-level
            built_in=False,
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-username-password-form",
                    requirement="REQUIRED",
                    priority=10,
                ),
            ],
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Sub-flow Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[parent_flow, sub_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with nested sub-flow")

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify the parent flow was created
            parent = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert parent is not None, f"Parent flow {flow_alias} should exist"

            # Verify executions include the sub-flow reference
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            # Find the sub-flow execution
            subflow_exec = None
            for ex in executions:
                if ex.display_name == subflow_alias or ex.alias == subflow_alias:
                    subflow_exec = ex
                    break

            assert subflow_exec is not None, (
                f"Sub-flow {subflow_alias} should be in executions"
            )
            assert subflow_exec.authentication_flow is True, (
                "Should be marked as authentication flow"
            )

            logger.info(
                f"✓ Flow {flow_alias} created with nested sub-flow {subflow_alias}"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_authenticator_config(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a flow with authenticator configuration.

        This tests the _configure_authenticator_configs code path:
        - Create a flow with an OTP authenticator
        - Configure OTP settings via authenticatorConfig
        - Verify the config is applied in Keycloak
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"authconfig-test-{suffix}"
        flow_alias = f"otp-flow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            AuthenticatorConfigInfo,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create a flow with OTP authenticator and custom config
        otp_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Flow with OTP config",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="auth-otp-form",
                    requirement="REQUIRED",
                    priority=10,
                    authenticator_config="custom-otp-config",
                ),
            ],
            authenticator_config=[
                AuthenticatorConfigInfo(
                    alias="custom-otp-config",
                    config={
                        "otpType": "totp",
                        "otpHashAlgorithm": "HmacSHA256",
                        "otpLength": "8",
                        "lookAheadWindow": "2",
                        "otpPeriod": "60",
                    },
                ),
            ],
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Authenticator Config Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=[otp_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with authenticator config")

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Allow time for authenticator config to be applied
            # Poll until config is available
            otp_exec = None
            executions = []
            for _ in range(20):
                executions = await keycloak_admin_client.get_flow_executions(
                    realm_name, flow_alias, namespace
                )
                for ex in executions:
                    if ex.provider_id == "auth-otp-form" and ex.authentication_config:
                        otp_exec = ex
                        break
                if otp_exec:
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for authenticator config to be applied")

            assert otp_exec is not None, "OTP execution should exist"

            # Check if authenticator config was created
            if otp_exec.authentication_config:
                config = await keycloak_admin_client.get_authenticator_config(
                    realm_name, otp_exec.authentication_config, namespace
                )
                assert config is not None, "Authenticator config should exist"
                assert config.config.get("otpLength") == "8", "OTP length should be 8"
                assert config.config.get("otpPeriod") == "60", "OTP period should be 60"
                logger.info(f"✓ Authenticator config applied: {config.config}")
            else:
                logger.warning("Authenticator config ID not found on execution")

            logger.info(f"✓ Flow {flow_alias} created with authenticator config")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(240)
    async def test_realm_update_modifies_flow_executions(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test updating a realm to modify flow execution requirements.

        This tests the _sync_flow_executions update path:
        - Create a realm with a flow
        - Update the realm to change execution requirements
        - Verify the changes are applied
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"update-exec-{suffix}"
        flow_alias = f"update-flow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Initial flow config - spnego DISABLED
        initial_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            copy_from="browser",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Update Executions Test",
            client_authorization_grants=[namespace],
            authentication_flows=[initial_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            # Create initial realm
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            logger.info(f"Created initial realm: {realm_name}")

            # Get current executions to find auth-spnego
            initial_executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            spnego_exec = None
            for ex in initial_executions:
                if ex.provider_id == "auth-spnego":
                    spnego_exec = ex
                    break

            initial_requirement = spnego_exec.requirement if spnego_exec else "DISABLED"
            logger.info(f"Initial auth-spnego requirement: {initial_requirement}")

            # Update the flow to change auth-spnego to ALTERNATIVE
            updated_flow = KeycloakAuthenticationFlow(
                alias=flow_alias,
                copy_from="browser",
                authentication_executions=[
                    AuthenticationExecutionExport(
                        authenticator="auth-spnego",
                        requirement="ALTERNATIVE",  # Change from DISABLED
                    ),
                ],
            )

            updated_spec = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Update Executions Test - Updated",
                client_authorization_grants=[namespace],
                authentication_flows=[updated_flow],
            )

            updated_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm_name, "namespace": namespace},
                "spec": updated_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            # Get generation before patching
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            current_generation = resource["metadata"]["generation"]

            # Patch the realm
            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=updated_manifest,
            )

            logger.info("Patched realm with updated execution requirement")

            # Wait for reconciliation
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=current_generation + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify the execution requirement was updated
            updated_executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )

            updated_spnego = None
            for ex in updated_executions:
                if ex.provider_id == "auth-spnego":
                    updated_spnego = ex
                    break

            assert updated_spnego is not None, "auth-spnego execution should exist"
            assert updated_spnego.requirement == "ALTERNATIVE", (
                f"auth-spnego should be ALTERNATIVE, got {updated_spnego.requirement}"
            )

            logger.info(
                f"✓ Execution requirement updated from {initial_requirement} to ALTERNATIVE"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_all_flow_binding_types(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test binding all possible flow types to custom flows.

        This tests all 7 flow binding fields:
        - browserFlow
        - registrationFlow
        - directGrantFlow
        - resetCredentialsFlow
        - clientAuthenticationFlow
        - dockerAuthenticationFlow
        - firstBrokerLoginFlow
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"all-bindings-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create flows for each binding type
        flows = [
            KeycloakAuthenticationFlow(alias=f"browser-{suffix}", copy_from="browser"),
            KeycloakAuthenticationFlow(
                alias=f"registration-{suffix}", copy_from="registration"
            ),
            KeycloakAuthenticationFlow(
                alias=f"direct-grant-{suffix}", copy_from="direct grant"
            ),
            KeycloakAuthenticationFlow(
                alias=f"reset-creds-{suffix}", copy_from="reset credentials"
            ),
            KeycloakAuthenticationFlow(
                alias=f"client-auth-{suffix}", copy_from="clients"
            ),
            KeycloakAuthenticationFlow(
                alias=f"docker-{suffix}", copy_from="docker auth"
            ),
            KeycloakAuthenticationFlow(
                alias=f"first-broker-{suffix}", copy_from="first broker login"
            ),
        ]

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="All Bindings Test Realm",
            client_authorization_grants=[namespace],
            authentication_flows=flows,
            browser_flow=f"browser-{suffix}",
            registration_flow=f"registration-{suffix}",
            direct_grant_flow=f"direct-grant-{suffix}",
            reset_credentials_flow=f"reset-creds-{suffix}",
            client_authentication_flow=f"client-auth-{suffix}",
            docker_authentication_flow=f"docker-{suffix}",
            first_broker_login_flow=f"first-broker-{suffix}",
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            logger.info(f"Created realm CR: {realm_name} with all flow bindings")

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify realm configuration
            realm = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm is not None, "Realm should exist"

            # Check all flow bindings
            assert realm.browser_flow == f"browser-{suffix}", "browserFlow binding"
            assert realm.registration_flow == f"registration-{suffix}", (
                "registrationFlow binding"
            )
            assert realm.direct_grant_flow == f"direct-grant-{suffix}", (
                "directGrantFlow binding"
            )
            assert realm.reset_credentials_flow == f"reset-creds-{suffix}", (
                "resetCredentialsFlow binding"
            )
            assert realm.client_authentication_flow == f"client-auth-{suffix}", (
                "clientAuthenticationFlow binding"
            )
            assert realm.docker_authentication_flow == f"docker-{suffix}", (
                "dockerAuthenticationFlow binding"
            )
            assert realm.first_broker_login_flow == f"first-broker-{suffix}", (
                "firstBrokerLoginFlow binding"
            )

            logger.info("✓ All 7 flow bindings correctly configured")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_required_action_priority_ordering(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test that required action priorities are correctly applied.

        This tests that:
        - Multiple required actions can be configured
        - Priority ordering is respected
        - All properties (enabled, defaultAction) are set correctly
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"action-priority-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            RequiredActionProvider,
        )

        # Configure multiple required actions with specific priorities
        required_actions = [
            RequiredActionProvider(
                alias="VERIFY_EMAIL",
                name="Verify Email",
                enabled=True,
                default_action=True,
                priority=100,
            ),
            RequiredActionProvider(
                alias="UPDATE_PASSWORD",
                name="Update Password",
                enabled=True,
                default_action=False,
                priority=200,
            ),
            RequiredActionProvider(
                alias="CONFIGURE_TOTP",
                name="Configure OTP",
                enabled=True,
                default_action=True,
                priority=300,
            ),
            RequiredActionProvider(
                alias="UPDATE_PROFILE",
                name="Update Profile",
                enabled=False,  # Disabled
                default_action=False,
                priority=400,
            ),
        ]

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Required Action Priority Test",
            client_authorization_grants=[namespace],
            required_actions=required_actions,
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Allow time for required actions to be configured
            actions = []
            for _ in range(20):
                actions = await keycloak_admin_client.get_required_actions(
                    realm_name, namespace
                )
                action_map = {action.alias: action for action in actions}
                if (
                    action_map.get("VERIFY_EMAIL")
                    and action_map.get("UPDATE_PASSWORD")
                    and action_map.get("CONFIGURE_TOTP")
                    and action_map.get("UPDATE_PROFILE")
                ):
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for required actions to be configured")
            action_map = {action.alias: action for action in actions}

            # Check VERIFY_EMAIL
            verify_email = action_map.get("VERIFY_EMAIL")
            assert verify_email is not None, "VERIFY_EMAIL should exist"
            assert verify_email.enabled is True, "VERIFY_EMAIL should be enabled"
            assert verify_email.default_action is True, "VERIFY_EMAIL should be default"
            assert verify_email.priority == 100, "VERIFY_EMAIL priority should be 100"

            # Check UPDATE_PASSWORD
            update_pwd = action_map.get("UPDATE_PASSWORD")
            assert update_pwd is not None, "UPDATE_PASSWORD should exist"
            assert update_pwd.enabled is True, "UPDATE_PASSWORD should be enabled"
            assert update_pwd.default_action is False, (
                "UPDATE_PASSWORD should not be default"
            )

            # Check CONFIGURE_TOTP
            config_totp = action_map.get("CONFIGURE_TOTP")
            assert config_totp is not None, "CONFIGURE_TOTP should exist"
            assert config_totp.enabled is True, "CONFIGURE_TOTP should be enabled"
            assert config_totp.default_action is True, (
                "CONFIGURE_TOTP should be default"
            )

            # Check UPDATE_PROFILE is disabled
            update_profile = action_map.get("UPDATE_PROFILE")
            assert update_profile is not None, "UPDATE_PROFILE should exist"
            assert update_profile.enabled is False, "UPDATE_PROFILE should be disabled"

            logger.info("✓ All required actions configured with correct properties")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_flow_with_subflow_executions(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test creating a flow with sub-flow that contains its own executions.

        This tests the add_subflow_to_flow code path more thoroughly:
        - Create parent flow with sub-flow reference
        - Verify sub-flow is correctly nested
        - Verify sub-flow executions are added
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"subflow-exec-{suffix}"
        parent_alias = f"parent-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create parent flow that copies from browser (which has sub-flows)
        parent_flow = KeycloakAuthenticationFlow(
            alias=parent_alias,
            description="Parent flow with browser structure",
            provider_id="basic-flow",
            top_level=True,
            copy_from="browser",  # Browser has nested forms sub-flow
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Sub-flow Executions Test",
            client_authorization_grants=[namespace],
            authentication_flows=[parent_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Get executions and verify sub-flows exist
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, parent_alias, namespace
            )

            # Browser flow should have nested sub-flows (like "forms")
            subflow_execs = [ex for ex in executions if ex.authentication_flow is True]
            assert len(subflow_execs) >= 1, "Should have at least one sub-flow"

            # Verify we can see the structure
            for subflow in subflow_execs:
                logger.info(
                    f"Found sub-flow: {subflow.display_name or subflow.alias} "
                    f"(auth_flow={subflow.authentication_flow})"
                )

            logger.info(
                f"✓ Flow {parent_alias} has {len(subflow_execs)} nested sub-flows"
            )

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_with_update_authenticator_config(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test updating an existing authenticator config.

        This tests the update_authenticator_config code path:
        - Create realm with authenticator config
        - Update the realm to change config values
        - Verify the update is applied
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"update-config-{suffix}"
        flow_alias = f"idp-flow-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            AuthenticationExecutionExport,
            AuthenticatorConfigInfo,
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create flow with identity-provider-redirector and config
        initial_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Flow with configurable IDP redirector",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            authentication_executions=[
                AuthenticationExecutionExport(
                    authenticator="identity-provider-redirector",
                    requirement="ALTERNATIVE",
                    priority=10,
                    authenticator_config="idp-redirector-config",
                ),
            ],
            authenticator_config=[
                AuthenticatorConfigInfo(
                    alias="idp-redirector-config",
                    config={
                        "defaultProvider": "google",
                    },
                ),
            ],
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Update Config Test",
            client_authorization_grants=[namespace],
            authentication_flows=[initial_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Give time for config to be created - poll for it
            # While wait_for_resource_ready should be enough, polling ensures KC is consistent
            for _ in range(20):
                executions = await keycloak_admin_client.get_flow_executions(
                    realm_name, flow_alias, namespace
                )
                idp_exec = next(
                    (
                        ex
                        for ex in executions
                        if ex.provider_id == "identity-provider-redirector"
                    ),
                    None,
                )
                if idp_exec and idp_exec.authentication_config:
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail("Timed out waiting for identity-provider-redirector config")

            # Now update the config
            updated_flow = KeycloakAuthenticationFlow(
                alias=flow_alias,
                description="Flow with updated IDP redirector config",
                provider_id="basic-flow",
                top_level=True,
                built_in=False,
                authentication_executions=[
                    AuthenticationExecutionExport(
                        authenticator="identity-provider-redirector",
                        requirement="ALTERNATIVE",
                        priority=10,
                        authenticator_config="idp-redirector-config",
                    ),
                ],
                authenticator_config=[
                    AuthenticatorConfigInfo(
                        alias="idp-redirector-config",
                        config={
                            "defaultProvider": "github",  # Changed from google
                        },
                    ),
                ],
            )

            updated_spec = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Update Config Test - Updated",
                client_authorization_grants=[namespace],
                authentication_flows=[updated_flow],
            )

            updated_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm_name, "namespace": namespace},
                "spec": updated_spec.model_dump(by_alias=True, exclude_unset=True),
            }

            # Get generation before patching
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            current_generation = resource["metadata"]["generation"]

            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=updated_manifest,
            )

            # Wait for reconciliation
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=current_generation + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify flow exists
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, f"Flow {flow_alias} should exist"

            logger.info("✓ Authenticator config update test completed")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_direct_delete_authentication_flow(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test directly deleting an authentication flow via admin client.

        This tests the delete_authentication_flow code path directly:
        - Create a realm with a custom flow
        - Delete the flow directly via admin client
        - Verify deletion succeeded
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"delete-flow-{suffix}"
        flow_alias = f"to-delete-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        custom_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Flow to be deleted",
            provider_id="basic-flow",
            top_level=True,
            copy_from="browser",
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Delete Flow Test",
            client_authorization_grants=[namespace],
            authentication_flows=[custom_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify flow exists
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, "Flow should exist"
            assert flow.id is not None, "Flow should have an ID"

            flow_id = flow.id

            # Delete flow directly via admin client
            success = await keycloak_admin_client.delete_authentication_flow(
                realm_name, flow_id, namespace
            )
            assert success is True, "Flow deletion should succeed"

            # Verify flow no longer exists
            deleted_flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert deleted_flow is None, "Flow should be deleted"

            logger.info(f"✓ Successfully deleted flow {flow_alias} directly")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_direct_execution_operations(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test direct execution operations via admin client.

        This tests add_execution_to_flow and delete_execution paths:
        - Create realm with empty flow
        - Add execution directly
        - Delete execution directly
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"exec-ops-{suffix}"
        flow_alias = f"exec-test-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakAuthenticationFlow,
            KeycloakRealmSpec,
            OperatorRef,
        )

        # Create an empty flow (no executions)
        empty_flow = KeycloakAuthenticationFlow(
            alias=flow_alias,
            description="Empty flow for execution operations",
            provider_id="basic-flow",
            top_level=True,
            built_in=False,
            # No authentication_executions - start empty
        )

        realm_spec = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Execution Operations Test",
            client_authorization_grants=[namespace],
            authentication_flows=[empty_flow],
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify flow exists
            flow = await keycloak_admin_client.get_authentication_flow_by_alias(
                realm_name, flow_alias, namespace
            )
            assert flow is not None, "Flow should exist"

            # Add execution directly
            exec_id = await keycloak_admin_client.add_execution_to_flow(
                realm_name,
                flow_alias,
                "auth-cookie",
                namespace,
            )
            assert exec_id is not None, "Should return execution ID"
            logger.info(f"Added execution with ID: {exec_id}")

            # Verify execution exists
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )
            assert len(executions) >= 1, "Should have at least 1 execution"

            cookie_exec = None
            for ex in executions:
                if ex.provider_id == "auth-cookie":
                    cookie_exec = ex
                    break

            assert cookie_exec is not None, "auth-cookie execution should exist"
            assert cookie_exec.id is not None, "Execution should have ID"

            # Delete execution directly
            success = await keycloak_admin_client.delete_execution(
                realm_name, cookie_exec.id, namespace
            )
            assert success is True, "Execution deletion should succeed"

            # Verify execution is gone
            executions_after = await keycloak_admin_client.get_flow_executions(
                realm_name, flow_alias, namespace
            )
            cookie_after = None
            for ex in executions_after:
                if ex.provider_id == "auth-cookie":
                    cookie_after = ex
                    break

            assert cookie_after is None, "auth-cookie execution should be deleted"

            logger.info("✓ Direct execution add/delete operations successful")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )

    @pytest.mark.timeout(180)
    async def test_realm_required_action_update_from_existing(
        self,
        k8s_custom_objects,
        test_namespace: str,
        operator_namespace: str,
        shared_operator,
        keycloak_admin_client,
    ) -> None:
        """Test updating required actions that already exist in realm.

        This specifically tests the update path when actions already exist:
        - Create realm without required actions config
        - Verify default actions exist
        - Update realm to modify those existing actions
        """
        suffix = uuid.uuid4().hex[:8]
        realm_name = f"update-actions-{suffix}"
        namespace = test_namespace

        from keycloak_operator.models.realm import (
            KeycloakRealmSpec,
            OperatorRef,
            RequiredActionProvider,
        )

        # First create realm without required action configs
        realm_spec_v1 = KeycloakRealmSpec(
            operator_ref=OperatorRef(namespace=operator_namespace),
            realm_name=realm_name,
            display_name="Update Actions Test",
            client_authorization_grants=[namespace],
            # No required_actions - use defaults
        )

        realm_manifest = {
            "apiVersion": "vriesdemichael.github.io/v1",
            "kind": "KeycloakRealm",
            "metadata": {"name": realm_name, "namespace": namespace},
            "spec": realm_spec_v1.model_dump(by_alias=True, exclude_unset=True),
        }

        try:
            await k8s_custom_objects.create_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                body=realm_manifest,
            )

            await wait_for_resource_ready(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify default actions exist
            initial_actions = await keycloak_admin_client.get_required_actions(
                realm_name, namespace
            )
            initial_map = {a.alias: a for a in initial_actions}

            # TERMS_AND_CONDITIONS is typically disabled by default
            terms = initial_map.get("TERMS_AND_CONDITIONS")
            initial_terms_enabled = terms.enabled if terms else False
            logger.info(
                f"Initial TERMS_AND_CONDITIONS enabled: {initial_terms_enabled}"
            )

            # Now update realm to modify the TERMS_AND_CONDITIONS action
            realm_spec_v2 = KeycloakRealmSpec(
                operator_ref=OperatorRef(namespace=operator_namespace),
                realm_name=realm_name,
                display_name="Update Actions Test - Updated",
                client_authorization_grants=[namespace],
                required_actions=[
                    RequiredActionProvider(
                        alias="TERMS_AND_CONDITIONS",
                        name="Terms and Conditions",
                        enabled=True,  # Enable it
                        default_action=True,  # Make it default
                        priority=50,
                    ),
                ],
            )

            updated_manifest = {
                "apiVersion": "vriesdemichael.github.io/v1",
                "kind": "KeycloakRealm",
                "metadata": {"name": realm_name, "namespace": namespace},
                "spec": realm_spec_v2.model_dump(by_alias=True, exclude_unset=True),
            }

            # Get generation before patching
            resource = await k8s_custom_objects.get_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
            current_generation = resource["metadata"]["generation"]

            await k8s_custom_objects.patch_namespaced_custom_object(
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                body=updated_manifest,
            )

            # Wait for reconciliation
            await wait_for_reconciliation_complete(
                k8s_custom_objects=k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
                min_generation=current_generation + 1,
                timeout=120,
                operator_namespace=operator_namespace,
            )

            # Verify action was updated
            updated_actions = await keycloak_admin_client.get_required_actions(
                realm_name, namespace
            )
            updated_map = {a.alias: a for a in updated_actions}

            updated_terms = updated_map.get("TERMS_AND_CONDITIONS")
            assert updated_terms is not None, "TERMS_AND_CONDITIONS should exist"
            assert updated_terms.enabled is True, "Should be enabled now"
            assert updated_terms.default_action is True, "Should be default action"

            logger.info("✓ Successfully updated existing required action")

        finally:
            await _cleanup_resource(
                k8s_custom_objects,
                group="vriesdemichael.github.io",
                version="v1",
                namespace=namespace,
                plural="keycloakrealms",
                name=realm_name,
            )
