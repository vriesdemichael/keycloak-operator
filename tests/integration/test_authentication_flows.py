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

from .wait_helpers import wait_for_resource_deleted, wait_for_resource_ready

logger = logging.getLogger(__name__)


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
            assert (
                len(executions) >= 2
            ), f"Flow should have at least 2 executions, got {len(executions)}"

            # Check that expected authenticators are present
            authenticator_ids = [ex.provider_id for ex in executions if ex.provider_id]
            assert (
                "auth-cookie" in authenticator_ids
            ), "auth-cookie should be in flow executions"
            assert (
                "identity-provider-redirector" in authenticator_ids
            ), "identity-provider-redirector should be in flow executions"

            logger.info(
                f"✓ Flow has {len(executions)} executions with correct authenticators"
            )

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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
            assert (
                flow.built_in is False
            ), "Copied flow should not be marked as built-in"

            # Verify the copied flow has executions (inherited from browser flow)
            executions = await keycloak_admin_client.get_flow_executions(
                realm_name, new_flow_alias, namespace
            )
            assert (
                len(executions) > 0
            ), "Copied flow should have executions from browser flow"

            logger.info(
                f"✓ Successfully copied flow '{new_flow_alias}' with "
                f"{len(executions)} executions"
            )

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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
            # Cleanup
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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

            # Give a moment for required actions to be configured
            await asyncio.sleep(2)

            # Verify required actions are configured
            actions = await keycloak_admin_client.get_required_actions(
                realm_name, namespace
            )

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
            assert (
                verify_email.default_action is True
            ), "VERIFY_EMAIL should be a default action"

            # Check UPDATE_PASSWORD
            update_pwd = action_map.get("UPDATE_PASSWORD")
            assert update_pwd is not None, "UPDATE_PASSWORD should exist"
            assert update_pwd.enabled is True, "UPDATE_PASSWORD should be enabled"

            logger.info("✓ Successfully verified required actions in realm")

        finally:
            # Cleanup
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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

            # Give Keycloak a moment to cleanup
            await asyncio.sleep(3)

            # Verify realm (and thus flows) are deleted from Keycloak
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert (
                realm_repr is None
            ), f"Realm {realm_name} should be deleted from Keycloak"

            logger.info("✓ Realm and flows successfully cleaned up")

        finally:
            # Cleanup (in case test failed before deletion)
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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

            # Verify realm and bindings
            realm_repr = await keycloak_admin_client.get_realm(realm_name, namespace)
            assert realm_repr is not None, f"Realm {realm_name} should exist"

            # Check browser flow binding
            assert realm_repr.browser_flow == browser_flow_alias, (
                f"browserFlow should be '{browser_flow_alias}', "
                f"got '{realm_repr.browser_flow}'"
            )

            # Check direct grant flow binding
            assert realm_repr.direct_grant_flow == direct_grant_alias, (
                f"directGrantFlow should be '{direct_grant_alias}', "
                f"got '{realm_repr.direct_grant_flow}'"
            )

            logger.info("✓ Multiple flow bindings correctly applied")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
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
            await asyncio.sleep(2)

            # Verify required actions
            actions = await keycloak_admin_client.get_required_actions(
                realm_name, namespace
            )
            action_map = {action.alias: action for action in actions}

            # CONFIGURE_TOTP should be a default action
            totp = action_map.get("CONFIGURE_TOTP")
            assert totp is not None, "CONFIGURE_TOTP should exist"
            assert (
                totp.default_action is True
            ), "CONFIGURE_TOTP should be a default action"

            # VERIFY_EMAIL should NOT be a default action
            verify_email = action_map.get("VERIFY_EMAIL")
            assert verify_email is not None, "VERIFY_EMAIL should exist"
            assert (
                verify_email.default_action is False
            ), "VERIFY_EMAIL should NOT be a default action"

            logger.info("✓ defaultAction flags correctly applied")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )

    @pytest.mark.skip(
        reason="Update handler for authentication flows needs to be implemented. "
        "Issue: update handler uses sync configure_authentication_flow() instead "
        "of the new async methods. Works for initial creation."
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

            assert flow is not None, f"Flow {flow_alias} should exist after update"
            assert flow.alias == flow_alias

            logger.info("✓ Flow successfully added via realm update")

        finally:
            with contextlib.suppress(ApiException):
                await k8s_custom_objects.delete_namespaced_custom_object(
                    group="vriesdemichael.github.io",
                    version="v1",
                    namespace=namespace,
                    plural="keycloakrealms",
                    name=realm_name,
                )
