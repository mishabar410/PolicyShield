"""Prometheus metrics exporter for PolicyShield."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PrometheusExporter:
    """Exports PolicyShield metrics in Prometheus format."""

    def __init__(self, trace_dir: str | Path = "./traces", namespace: str = "policyshield") -> None:
        self._trace_dir = Path(trace_dir)
        self._namespace = namespace

    def collect_metrics(self) -> dict:
        """Collect current metrics from traces."""
        from policyshield.trace.aggregator import TraceAggregator

        if not self._trace_dir.exists():
            return {}

        agg = TraceAggregator(self._trace_dir)
        result = agg.aggregate()

        metrics: dict = {}
        vb = result.verdict_breakdown

        # Verdict counters
        metrics[f"{self._namespace}_verdicts_total"] = vb.total
        metrics[f"{self._namespace}_verdicts_allow"] = vb.allow
        metrics[f"{self._namespace}_verdicts_block"] = vb.block
        metrics[f"{self._namespace}_verdicts_redact"] = vb.redact
        metrics[f"{self._namespace}_verdicts_approve"] = vb.approve

        # Block rate
        if vb.total > 0:
            metrics[f"{self._namespace}_block_rate"] = vb.block / vb.total
        else:
            metrics[f"{self._namespace}_block_rate"] = 0.0

        # Per-tool stats
        for ts in result.top_tools:
            metrics[f"{self._namespace}_tool_calls{{{self._label('tool', ts.tool)}}}"] = ts.call_count
            metrics[f"{self._namespace}_tool_blocks{{{self._label('tool', ts.tool)}}}"] = ts.block_count

        # PII counts
        for entry in result.pii_heatmap:
            key = f"{self._namespace}_pii_detections{{{self._label('type', entry.pii_type)},{self._label('tool', entry.tool)}}}"
            metrics[key] = entry.count

        return metrics

    def format_prometheus(self) -> str:
        """Format metrics as Prometheus text exposition."""
        metrics = self.collect_metrics()
        lines = []
        for name, value in metrics.items():
            # Metrics with labels already have {} in name
            if isinstance(value, float):
                lines.append(f"{name} {value:.6f}")
            else:
                lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n" if lines else ""

    @staticmethod
    def _label(key: str, value: str) -> str:
        # Escape per Prometheus exposition format: \ → \\, " → \", \n → \\n
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'{key}="{escaped}"'


def add_prometheus_endpoint(app, trace_dir: str | Path = "./traces") -> None:
    """Add /metrics endpoint to a FastAPI app."""
    try:
        from fastapi.responses import PlainTextResponse
    except ImportError:
        raise ImportError("Prometheus endpoint requires FastAPI. Install with: pip install policyshield[dashboard]")

    exporter = PrometheusExporter(trace_dir)

    @app.get("/metrics", response_class=PlainTextResponse)
    def prometheus_metrics():
        return exporter.format_prometheus()
