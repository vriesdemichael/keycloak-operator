"""Unit tests for Helm chart monitoring resources."""

import json
import subprocess

import pytest
import yaml


def helm_template(chart_path: str, values: dict | None = None) -> list[dict]:
    """Render Helm chart and return parsed YAML documents."""
    cmd = ["helm", "template", "test", chart_path]
    
    if values:
        # Convert values dict to --set arguments
        for key, value in values.items():
            if isinstance(value, bool):
                value_str = str(value).lower()
            else:
                value_str = str(value)
            cmd.extend(["--set", f"{key}={value_str}"])
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )
    
    # Parse YAML documents
    docs = list(yaml.safe_load_all(result.stdout))
    return [doc for doc in docs if doc is not None]


class TestMonitoringResources:
    """Test Helm chart monitoring resource rendering."""

    @pytest.fixture
    def chart_path(self):
        """Path to the Helm chart."""
        return "charts/keycloak-operator"

    def test_monitoring_disabled_by_default(self, chart_path):
        """Monitoring resources should not be created when disabled."""
        docs = helm_template(chart_path)
        
        # Check no ServiceMonitor
        service_monitors = [
            doc for doc in docs 
            if doc.get("kind") == "ServiceMonitor"
        ]
        assert len(service_monitors) == 0, "ServiceMonitor should not exist when monitoring disabled"
        
        # Check no PrometheusRule
        prometheus_rules = [
            doc for doc in docs 
            if doc.get("kind") == "PrometheusRule"
        ]
        assert len(prometheus_rules) == 0, "PrometheusRule should not exist when monitoring disabled"
        
        # Check no Grafana dashboard ConfigMap
        dashboards = [
            doc for doc in docs 
            if doc.get("kind") == "ConfigMap" 
            and "dashboard" in doc.get("metadata", {}).get("name", "")
        ]
        assert len(dashboards) == 0, "Dashboard ConfigMap should not exist when monitoring disabled"

    def test_servicemonitor_created_when_enabled(self, chart_path):
        """ServiceMonitor should be created when monitoring is enabled."""
        docs = helm_template(chart_path, {"monitoring.enabled": True})
        
        service_monitors = [
            doc for doc in docs 
            if doc.get("kind") == "ServiceMonitor"
        ]
        
        assert len(service_monitors) == 1, "Should create exactly one ServiceMonitor"
        
        sm = service_monitors[0]
        assert sm["apiVersion"] == "monitoring.coreos.com/v1"
        assert sm["metadata"]["name"] == "test-keycloak-operator"
        assert sm["metadata"]["namespace"] == "keycloak-system"
        
        # Check endpoints configuration
        endpoints = sm["spec"]["endpoints"]
        assert len(endpoints) == 1
        assert endpoints[0]["port"] == "metrics"
        assert endpoints[0]["path"] == "/metrics"
        assert endpoints[0]["interval"] == "30s"
        assert endpoints[0]["scrapeTimeout"] == "10s"

    def test_servicemonitor_custom_namespace(self, chart_path):
        """ServiceMonitor should use custom namespace when specified."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.namespace": "monitoring",
        })
        
        service_monitors = [
            doc for doc in docs 
            if doc.get("kind") == "ServiceMonitor"
        ]
        
        assert len(service_monitors) == 1
        assert service_monitors[0]["metadata"]["namespace"] == "monitoring"

    def test_prometheusrule_created_when_enabled(self, chart_path):
        """PrometheusRule should be created when enabled."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.prometheusRules.enabled": True,
        })
        
        prometheus_rules = [
            doc for doc in docs 
            if doc.get("kind") == "PrometheusRule"
        ]
        
        assert len(prometheus_rules) == 1, "Should create exactly one PrometheusRule"
        
        pr = prometheus_rules[0]
        assert pr["apiVersion"] == "monitoring.coreos.com/v1"
        assert pr["metadata"]["name"] == "test-keycloak-operator"
        
        # Check alert rules exist
        groups = pr["spec"]["groups"]
        assert len(groups) == 1
        assert groups[0]["name"] == "keycloak-operator.rules"
        assert groups[0]["interval"] == "30s"
        
        rules = groups[0]["rules"]
        assert len(rules) > 0, "Should have alert rules"
        
        # Check expected alerts exist
        alert_names = {rule["alert"] for rule in rules}
        expected_alerts = {
            "KeycloakOperatorHighFailureRate",
            "KeycloakOperatorAllInstancesFailed",
            "KeycloakOperatorCircuitBreakerOpen",
            "KeycloakOperatorCrashlooping",
            "KeycloakOperatorSlowReconciliation",
            "KeycloakOperatorNoActivity",
            "KeycloakOperatorHighMemory",
        }
        
        assert expected_alerts.issubset(alert_names), f"Missing expected alerts: {expected_alerts - alert_names}"

    def test_prometheusrule_alert_structure(self, chart_path):
        """PrometheusRule alerts should have proper structure."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.prometheusRules.enabled": True,
        })
        
        prometheus_rules = [
            doc for doc in docs 
            if doc.get("kind") == "PrometheusRule"
        ]
        
        rules = prometheus_rules[0]["spec"]["groups"][0]["rules"]
        
        for rule in rules:
            # Every rule should have these fields
            assert "alert" in rule, f"Rule missing 'alert' field: {rule}"
            assert "expr" in rule, f"Rule missing 'expr' field: {rule}"
            assert "for" in rule, f"Rule missing 'for' field: {rule}"
            assert "labels" in rule, f"Rule missing 'labels' field: {rule}"
            assert "annotations" in rule, f"Rule missing 'annotations' field: {rule}"
            
            # Check labels
            assert "severity" in rule["labels"], f"Rule missing 'severity' label: {rule}"
            assert "component" in rule["labels"], f"Rule missing 'component' label: {rule}"
            assert rule["labels"]["component"] == "keycloak-operator"
            
            # Check annotations
            assert "summary" in rule["annotations"], f"Rule missing 'summary' annotation: {rule}"
            assert "description" in rule["annotations"], f"Rule missing 'description' annotation: {rule}"
            assert "runbook_url" in rule["annotations"], f"Rule missing 'runbook_url' annotation: {rule}"

    def test_prometheusrule_custom_threshold(self, chart_path):
        """PrometheusRule should use custom threshold when specified."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.prometheusRules.enabled": True,
            "monitoring.prometheusRules.slowReconciliationThreshold": 60,
        })
        
        prometheus_rules = [
            doc for doc in docs 
            if doc.get("kind") == "PrometheusRule"
        ]
        
        rules = prometheus_rules[0]["spec"]["groups"][0]["rules"]
        
        # Find the slow reconciliation rule
        slow_recon_rule = next(
            (r for r in rules if r["alert"] == "KeycloakOperatorSlowReconciliation"),
            None
        )
        
        assert slow_recon_rule is not None
        # The expression should reference the threshold (60 seconds)
        assert "60" in slow_recon_rule["expr"]

    def test_grafana_dashboard_created_when_enabled(self, chart_path):
        """Grafana dashboard ConfigMap should be created when enabled."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.grafanaDashboard.enabled": True,
        })
        
        dashboards = [
            doc for doc in docs 
            if doc.get("kind") == "ConfigMap" 
            and "dashboard" in doc.get("metadata", {}).get("name", "")
        ]
        
        assert len(dashboards) == 1, "Should create exactly one dashboard ConfigMap"
        
        cm = dashboards[0]
        assert cm["metadata"]["name"] == "test-keycloak-operator-dashboard"
        assert cm["metadata"]["namespace"] == "keycloak-system"
        
        # Check dashboard data exists
        assert "keycloak-operator-dashboard.json" in cm["data"]
        
        # Parse dashboard JSON
        dashboard_json = cm["data"]["keycloak-operator-dashboard.json"]
        dashboard = json.loads(dashboard_json)
        
        # Check dashboard structure
        assert dashboard["title"] == "Keycloak Operator"
        assert "panels" in dashboard
        assert len(dashboard["panels"]) > 0, "Dashboard should have panels"
        
        # Check some expected panels exist
        panel_titles = {panel["title"] for panel in dashboard["panels"]}
        expected_panels = {
            "Resource Status by Type",
            "Reconciliation Success Rate (5m)",
            "Reconciliation Duration (p50/p95/p99)",
            "Active Reconciliations",
            "Operator Memory Usage",
            "Operator CPU Usage",
        }
        
        assert expected_panels.issubset(panel_titles), f"Missing expected panels: {expected_panels - panel_titles}"

    def test_grafana_dashboard_has_metrics_queries(self, chart_path):
        """Grafana dashboard panels should have proper Prometheus queries."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.grafanaDashboard.enabled": True,
        })
        
        dashboards = [
            doc for doc in docs 
            if doc.get("kind") == "ConfigMap" 
            and "dashboard" in doc.get("metadata", {}).get("name", "")
        ]
        
        dashboard_json = dashboards[0]["data"]["keycloak-operator-dashboard.json"]
        dashboard = json.loads(dashboard_json)
        
        # Check panels have Prometheus queries
        for panel in dashboard["panels"]:
            if "targets" in panel:
                for target in panel["targets"]:
                    assert "expr" in target, f"Panel '{panel['title']}' missing Prometheus query"
                    expr = target["expr"]
                    # Check query uses our metrics
                    metric_prefixes = [
                        "keycloak_operator_",
                        "kopf_reconciliation_",
                        "container_memory_",
                        "container_cpu_",
                        "kube_pod_",
                    ]
                    assert any(prefix in expr for prefix in metric_prefixes), \
                        f"Panel '{panel['title']}' query doesn't use expected metrics: {expr}"

    def test_grafana_dashboard_custom_labels(self, chart_path):
        """Grafana dashboard should support custom labels."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.grafanaDashboard.enabled": True,
            "monitoring.grafanaDashboard.labels.grafana_dashboard": "1",
        })
        
        dashboards = [
            doc for doc in docs 
            if doc.get("kind") == "ConfigMap" 
            and "dashboard" in doc.get("metadata", {}).get("name", "")
        ]
        
        cm = dashboards[0]
        # YAML parser converts "1" to int, so check for both
        assert cm["metadata"]["labels"]["grafana_dashboard"] in ("1", 1)

    def test_all_monitoring_resources_together(self, chart_path):
        """All monitoring resources should work together when enabled."""
        docs = helm_template(chart_path, {
            "monitoring.enabled": True,
            "monitoring.prometheusRules.enabled": True,
            "monitoring.grafanaDashboard.enabled": True,
        })
        
        # Count monitoring resources
        service_monitors = [d for d in docs if d.get("kind") == "ServiceMonitor"]
        prometheus_rules = [d for d in docs if d.get("kind") == "PrometheusRule"]
        dashboards = [
            d for d in docs 
            if d.get("kind") == "ConfigMap" and "dashboard" in d.get("metadata", {}).get("name", "")
        ]
        
        assert len(service_monitors) == 1, "Should have ServiceMonitor"
        assert len(prometheus_rules) == 1, "Should have PrometheusRule"
        assert len(dashboards) == 1, "Should have dashboard ConfigMap"
        
        # Verify they all use the same namespace by default
        assert service_monitors[0]["metadata"]["namespace"] == "keycloak-system"
        assert prometheus_rules[0]["metadata"]["namespace"] == "keycloak-system"
        assert dashboards[0]["metadata"]["namespace"] == "keycloak-system"
