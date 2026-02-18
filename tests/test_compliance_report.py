"""Tests for compliance report generation."""

from __future__ import annotations

from policyshield.reporting.compliance import ComplianceReport, generate_report, render_html


class TestComplianceReport:
    def test_report_generation(self, tmp_path):
        traces = tmp_path / "traces"
        traces.mkdir()
        (traces / "trace_test.jsonl").write_text(
            '{"tool": "exec", "verdict": "BLOCK", "rule_id": "r1", "session_id": "s1"}\n'
            '{"tool": "read", "verdict": "ALLOW", "session_id": "s1"}\n'
        )
        report = generate_report(traces)
        assert report.total_checks == 2
        assert report.verdicts["BLOCK"] == 1
        assert report.sessions_analyzed == 1

    def test_html_rendering(self):
        report = ComplianceReport(
            period_start="2025-01-01",
            period_end="2025-01-31",
            total_checks=100,
            verdicts={"ALLOW": 90, "BLOCK": 10},
        )
        html = render_html(report)
        assert "PolicyShield Compliance Report" in html
        assert "100" in html

    def test_empty_traces(self, tmp_path):
        traces = tmp_path / "traces"
        traces.mkdir()
        report = generate_report(traces)
        assert report.total_checks == 0

    def test_pii_detection_count(self, tmp_path):
        traces = tmp_path / "traces"
        traces.mkdir()
        (traces / "trace_test.jsonl").write_text(
            '{"tool": "read", "verdict": "ALLOW", "pii_detected": true, "session_id": "s1"}\n'
        )
        report = generate_report(traces)
        assert report.pii_detections == 1
