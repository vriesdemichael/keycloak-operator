"""
Leader election monitoring and metrics collection.

This module provides monitoring for Kopf's leader election functionality,
collecting metrics about leadership status, changes, and lease renewals.
"""

import logging
import platform

import kopf
from kubernetes.client.rest import ApiException

from keycloak_operator.settings import settings

from .metrics import metrics_collector

logger = logging.getLogger(__name__)


class LeaderElectionMonitor:
    """Monitors leader election status and emits metrics."""

    def __init__(self):
        """Initialize the leader election monitor."""
        self.instance_id = self._get_instance_id()
        self.namespace = settings.pod_namespace
        self.is_leader = False
        self.previous_leader: str | None = None

        logger.info(
            f"Leader election monitor initialized for instance: {self.instance_id}"
        )

    def _get_instance_id(self) -> str:
        """
        Generate a unique instance ID for this operator pod.

        Returns:
            Unique identifier for this operator instance
        """
        # Try to get pod name from settings (set via downward API)
        if settings.pod_name:
            return settings.pod_name

        # Fallback to hostname
        hostname = platform.node()
        if hostname:
            return hostname

        # Final fallback - generate based on process info
        import uuid

        return f"operator-{uuid.uuid4().hex[:8]}"

    def on_leadership_acquired(self):
        """Called when this instance becomes the leader."""
        logger.info(f"Leadership acquired by instance: {self.instance_id}")

        # Record leadership change if we know the previous leader
        if self.previous_leader and self.previous_leader != self.instance_id:
            metrics_collector.record_leader_election_change(
                previous_leader=self.previous_leader,
                new_leader=self.instance_id,
                namespace=self.namespace,
            )

        # Update leadership status
        self.is_leader = True
        self.previous_leader = self.instance_id
        metrics_collector.update_leader_election_status(
            instance_id=self.instance_id, namespace=self.namespace, is_leader=True
        )

    def on_leadership_lost(self):
        """Called when this instance loses leadership."""
        logger.info(f"Leadership lost by instance: {self.instance_id}")

        # Update leadership status
        self.is_leader = False
        metrics_collector.update_leader_election_status(
            instance_id=self.instance_id, namespace=self.namespace, is_leader=False
        )

    async def check_leadership_status(self) -> bool:
        """
        Check current leadership status and update metrics.

        Returns:
            True if this instance is currently the leader
        """
        try:
            # Use kopf's peering mechanism to check leadership

            # Get current lease information
            # Note: This is a simplified check - in practice, you might want to
            # query the Kubernetes API directly for the lease

            # For now, we'll check if we can perform leader-only operations
            # This is a practical way to determine leadership status
            current_leader = await self._get_current_leader()

            was_leader = self.is_leader
            self.is_leader = current_leader == self.instance_id

            # Update metrics
            metrics_collector.update_leader_election_status(
                instance_id=self.instance_id,
                namespace=self.namespace,
                is_leader=self.is_leader,
            )

            # Track leadership changes
            if was_leader and not self.is_leader:
                self.on_leadership_lost()
            elif not was_leader and self.is_leader:
                self.on_leadership_acquired()

            return self.is_leader

        except Exception as e:
            logger.error(f"Error checking leadership status: {e}")
            return False

    async def _get_current_leader(self) -> str | None:
        """
        Get the current leader from the Kubernetes lease.

        Returns:
            Current leader instance ID, or None if no leader
        """
        try:
            # Import kubernetes client
            from kubernetes import client, config

            # Load config
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()

            # Get coordination API
            coordination_v1 = client.CoordinationV1Api()

            # Get the lease for this operator
            lease_name = "keycloak-operator"  # Should match peering.name in operator.py

            try:
                lease = coordination_v1.read_namespaced_lease(
                    name=lease_name, namespace=self.namespace
                )

                if lease.spec and lease.spec.holder_identity:
                    return lease.spec.holder_identity

            except ApiException as e:
                if e.status == 404:
                    # Lease doesn't exist yet - no leader
                    logger.debug("Leader election lease not found - no current leader")
                    return None
                else:
                    raise

        except Exception as e:
            logger.error(f"Error getting current leader from lease: {e}")

        return None

    def record_lease_renewal(self, success: bool, duration: float):
        """
        Record a lease renewal attempt.

        Args:
            success: Whether the renewal succeeded
            duration: Time taken for the renewal
        """
        metrics_collector.record_lease_renewal(
            instance_id=self.instance_id,
            namespace=self.namespace,
            success=success,
            duration=duration,
        )

        if success:
            logger.debug(f"Lease renewed successfully in {duration:.3f}s")
        else:
            logger.warning(f"Lease renewal failed after {duration:.3f}s")


# Global monitor instance
_leader_election_monitor: LeaderElectionMonitor | None = None


def get_leader_election_monitor() -> LeaderElectionMonitor:
    """Get or create the global leader election monitor instance."""
    global _leader_election_monitor

    if _leader_election_monitor is None:
        _leader_election_monitor = LeaderElectionMonitor()

    return _leader_election_monitor


# Kopf event handlers for leader election
@kopf.on.event("coordination.k8s.io", "v1", "leases")
async def on_lease_event(event, name, namespace, **kwargs):
    """Monitor lease events for leader election changes."""
    monitor = get_leader_election_monitor()

    # Only monitor our operator's lease
    if name == "keycloak-operator" and namespace == monitor.namespace:
        logger.debug(f"Lease event: {event['type']} for {name} in {namespace}")

        # Check leadership status after lease events
        await monitor.check_leadership_status()


# Periodic leadership status check via lease monitoring (no pod watching needed)
# Leadership is determined by the lease owner, which is already monitored above
