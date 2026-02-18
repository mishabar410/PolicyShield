"""Simple metrics collector for Prometheus-format /metrics endpoint."""

from __future__ import annotations

import threading
from collections import Counter


class MetricsCollector:
    """Lightweight metrics collector without external dependencies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._request_count = 0
        self._verdict_counts: Counter = Counter()
        self._latency_sum = 0.0
        self._latency_count = 0

    def record(self, verdict: str, latency_ms: float) -> None:
        with self._lock:
            self._request_count += 1
            self._verdict_counts[verdict] += 1
            self._latency_sum += latency_ms
            self._latency_count += 1

    def to_prometheus(self) -> str:
        with self._lock:
            avg = self._latency_sum / max(self._latency_count, 1)
            lines = [
                "# HELP policyshield_requests_total Total check requests",
                "# TYPE policyshield_requests_total counter",
                f"policyshield_requests_total {self._request_count}",
                "# HELP policyshield_latency_ms_avg Average latency in ms",
                "# TYPE policyshield_latency_ms_avg gauge",
                f"policyshield_latency_ms_avg {avg:.2f}",
            ]
            for verdict, count in self._verdict_counts.items():
                lines.append(f'policyshield_verdicts_total{{verdict="{verdict}"}} {count}')
            return "\n".join(lines) + "\n"
