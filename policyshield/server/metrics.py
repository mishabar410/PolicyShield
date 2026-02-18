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
        # Approval metrics
        self._approval_submitted = 0
        self._approval_approved = 0
        self._approval_denied = 0
        self._approval_timeout = 0
        self._approval_response_times: list[float] = []
        self._max_response_times = 1000  # Rolling window

    def record(self, verdict: str, latency_ms: float) -> None:
        with self._lock:
            self._request_count += 1
            self._verdict_counts[verdict] += 1
            self._latency_sum += latency_ms
            self._latency_count += 1

    def record_approval_submitted(self) -> None:
        with self._lock:
            self._approval_submitted += 1

    def record_approval_resolved(self, *, approved: bool, response_time_ms: float) -> None:
        with self._lock:
            if approved:
                self._approval_approved += 1
            else:
                self._approval_denied += 1
            self._approval_response_times.append(response_time_ms)
            if len(self._approval_response_times) > self._max_response_times:
                self._approval_response_times = self._approval_response_times[-self._max_response_times :]

    def record_approval_timeout(self) -> None:
        with self._lock:
            self._approval_timeout += 1

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
            # Approval metrics
            lines.append(f"policyshield_approvals_submitted_total {self._approval_submitted}")
            lines.append(f"policyshield_approvals_approved_total {self._approval_approved}")
            lines.append(f"policyshield_approvals_denied_total {self._approval_denied}")
            lines.append(f"policyshield_approvals_timeout_total {self._approval_timeout}")
            if self._approval_response_times:
                avg_ms = sum(self._approval_response_times) / len(self._approval_response_times)
                lines.append(f"policyshield_approval_response_time_avg_ms {avg_ms:.1f}")
            return "\n".join(lines) + "\n"
