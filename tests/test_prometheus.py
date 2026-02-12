"""Tests for Prometheus exporter."""

import json

from policyshield.dashboard.prometheus import PrometheusExporter, add_prometheus_endpoint


def _write_traces(trace_dir, records):
    trace_dir.mkdir(parents=True, exist_ok=True)
    with open(trace_dir / "trace.jsonl", "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _sample_records():
    return [
        {"timestamp": "2025-01-01T12:00:00", "tool": "exec", "verdict": "BLOCK", "session_id": "s1"},
        {"timestamp": "2025-01-01T12:01:00", "tool": "exec", "verdict": "ALLOW", "session_id": "s1"},
        {"timestamp": "2025-01-01T12:02:00", "tool": "read_file", "verdict": "ALLOW", "session_id": "s1"},
        {"timestamp": "2025-01-01T12:03:00", "tool": "web_fetch", "verdict": "BLOCK", "session_id": "s1", "pii_types": ["EMAIL"]},
    ]


class TestCollectMetrics:
    def test_collect_basic(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d)
        metrics = exporter.collect_metrics()
        assert metrics["policyshield_verdicts_total"] == 4
        assert metrics["policyshield_verdicts_allow"] == 2
        assert metrics["policyshield_verdicts_block"] == 2

    def test_block_rate(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d)
        metrics = exporter.collect_metrics()
        assert abs(metrics["policyshield_block_rate"] - 0.5) < 0.01

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "traces"
        d.mkdir()
        exporter = PrometheusExporter(d)
        metrics = exporter.collect_metrics()
        assert metrics.get("policyshield_verdicts_total", 0) == 0

    def test_nonexistent_dir(self, tmp_path):
        exporter = PrometheusExporter(tmp_path / "nope")
        assert exporter.collect_metrics() == {}


class TestCustomNamespace:
    def test_namespace(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d, namespace="myapp")
        metrics = exporter.collect_metrics()
        assert "myapp_verdicts_total" in metrics


class TestFormatPrometheus:
    def test_format(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d)
        text = exporter.format_prometheus()
        assert "policyshield_verdicts_total 4" in text
        assert "policyshield_block_rate" in text

    def test_format_empty(self, tmp_path):
        exporter = PrometheusExporter(tmp_path / "nope")
        text = exporter.format_prometheus()
        assert text == ""


class TestToolMetrics:
    def test_per_tool(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d)
        metrics = exporter.collect_metrics()
        # Should have tool-level metrics with labels
        tool_keys = [k for k in metrics if "tool_calls" in k]
        assert len(tool_keys) > 0


class TestPIIMetrics:
    def test_pii_heatmap(self, tmp_path):
        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        exporter = PrometheusExporter(d)
        metrics = exporter.collect_metrics()
        pii_keys = [k for k in metrics if "pii_detections" in k]
        assert len(pii_keys) >= 1


class TestPrometheusEndpoint:
    def test_endpoint(self, tmp_path):
        from starlette.testclient import TestClient

        from policyshield.dashboard import create_dashboard_app

        d = tmp_path / "traces"
        _write_traces(d, _sample_records())
        app = create_dashboard_app(d)
        add_prometheus_endpoint(app, d)
        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "policyshield_verdicts_total" in resp.text
