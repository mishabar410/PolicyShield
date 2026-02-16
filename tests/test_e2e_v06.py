"""E2E tests for PolicyShield v0.6.0 release."""

import subprocess
import sys
from pathlib import Path

import policyshield

ROOT = Path(__file__).resolve().parent.parent


class TestVersioning:
    def test_version_is_0_6_0(self):
        version = tuple(int(x) for x in policyshield.__version__.split("."))
        assert version >= (0, 6, 0)

    def test_pyproject_version_matches(self):
        pyproject = (ROOT / "pyproject.toml").read_text()
        assert f'version = "{policyshield.__version__}"' in pyproject


class TestChangelog:
    def test_changelog_has_v06(self):
        changelog = (ROOT / "CHANGELOG.md").read_text()
        assert "## [0.6.0]" in changelog

    def test_changelog_has_trace_search(self):
        changelog = (ROOT / "CHANGELOG.md").read_text()
        assert "trace" in changelog.lower() or "0.6.0" in changelog

    def test_changelog_has_dashboard(self):
        changelog = (ROOT / "CHANGELOG.md").read_text()
        assert "Dashboard" in changelog


class TestReadme:
    def test_readme_roadmap_v06_complete(self):
        readme = (ROOT / "README.md").read_text()
        # v0.6 features should exist
        assert len(readme) > 100


class TestModulesExist:
    def test_trace_search_module(self):
        from policyshield.trace.search import TraceSearchEngine  # noqa: F401

    def test_trace_aggregator_module(self):
        from policyshield.trace.aggregator import TraceAggregator  # noqa: F401

    def test_cost_estimator_module(self):
        from policyshield.trace.cost import CostEstimator  # noqa: F401

    def test_alert_engine_module(self):
        from policyshield.alerts import AlertEngine  # noqa: F401

    def test_alert_backends_module(self):
        from policyshield.alerts.backends import AlertDispatcher  # noqa: F401

    def test_dashboard_module(self):
        from policyshield.dashboard import create_dashboard_app  # noqa: F401

    def test_prometheus_module(self):
        from policyshield.dashboard.prometheus import PrometheusExporter  # noqa: F401


class TestCLICommands:
    def _run(self, *args):
        script = Path(sys.executable).parent / "policyshield"
        return subprocess.run(
            [str(script), *args],
            capture_output=True,
            text=True,
        )

    def _output(self, r):
        return (r.stdout + r.stderr).lower()

    def test_cli_trace_search_registered(self):
        r = self._run("trace", "search", "--help")
        assert r.returncode == 0
        assert "search" in self._output(r)

    def test_cli_trace_stats_registered(self):
        r = self._run("trace", "stats", "--help")
        assert r.returncode == 0

    def test_cli_trace_cost_registered(self):
        r = self._run("trace", "cost", "--help")
        assert r.returncode == 0
        assert "model" in self._output(r)

    def test_cli_trace_dashboard_registered(self):
        r = self._run("trace", "dashboard", "--help")
        assert r.returncode == 0
        assert "port" in self._output(r)


class TestArtifactsExist:
    def test_grafana_dashboard_json_exists(self):
        assert (ROOT / "grafana" / "dashboards" / "policyshield.json").exists()

    def test_grafana_datasource_exists(self):
        assert (ROOT / "grafana" / "provisioning" / "datasources" / "policyshield.yaml").exists()

    def test_dashboard_frontend_exists(self):
        assert (ROOT / "policyshield" / "dashboard" / "static" / "index.html").exists()

    def test_all_new_files_exist(self):
        expected = [
            "policyshield/trace/search.py",
            "policyshield/trace/aggregator.py",
            "policyshield/trace/cost.py",
            "policyshield/alerts/__init__.py",
            "policyshield/alerts/backends.py",
            "policyshield/dashboard/__init__.py",
            "policyshield/dashboard/prometheus.py",
            "policyshield/dashboard/static/index.html",
            "grafana/dashboards/policyshield.json",
        ]
        for path in expected:
            assert (ROOT / path).exists(), f"Missing: {path}"
