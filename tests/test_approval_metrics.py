"""Tests for approval Prometheus metrics."""

from __future__ import annotations

from policyshield.server.metrics import MetricsCollector


class TestApprovalMetrics:
    def test_metrics_count_submissions(self):
        mc = MetricsCollector()
        mc.record_approval_submitted()
        mc.record_approval_submitted()
        output = mc.to_prometheus()
        assert "policyshield_approvals_submitted_total 2" in output

    def test_metrics_count_resolved(self):
        mc = MetricsCollector()
        mc.record_approval_resolved(approved=True, response_time_ms=150.0)
        mc.record_approval_resolved(approved=False, response_time_ms=300.0)
        output = mc.to_prometheus()
        assert "policyshield_approvals_approved_total 1" in output
        assert "policyshield_approvals_denied_total 1" in output
        assert "policyshield_approval_response_time_avg_ms 225.0" in output

    def test_metrics_timeout(self):
        mc = MetricsCollector()
        mc.record_approval_timeout()
        output = mc.to_prometheus()
        assert "policyshield_approvals_timeout_total 1" in output

    def test_no_avg_when_no_responses(self):
        mc = MetricsCollector()
        output = mc.to_prometheus()
        assert "policyshield_approval_response_time_avg_ms" not in output

    def test_rolling_window_capped(self):
        mc = MetricsCollector()
        mc._max_response_times = 5
        for i in range(10):
            mc.record_approval_resolved(approved=True, response_time_ms=float(i))
        assert len(mc._approval_response_times) == 5
