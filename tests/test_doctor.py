"""Tests for policyshield doctor."""

import tempfile
from pathlib import Path

import yaml

from policyshield.cli.doctor import Check, DoctorReport, format_report, run_doctor


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data))


class TestDoctor:
    def test_perfect_score(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            _write_yaml(td / "policyshield.yaml", {
                "mode": "ENFORCE",
                "fail_open": False,
                "trace": {"enabled": True},
                "sanitizer": {
                    "builtin_detectors": [
                        "path_traversal", "shell_injection",
                        "sql_injection", "ssrf", "url_schemes",
                    ],
                },
            })
            _write_yaml(td / "policies" / "rules.yaml", {
                "default_verdict": "block",
                "rules": [
                    {"id": "r1", "when": {"tool": "exec"}, "then": "block"},
                    {"id": "r2", "when": {"tool": "send"}, "then": "redact"},
                    {"id": "r3", "when": {"tool": "write"}, "then": "approve"},
                    {"id": "r4", "when": {"tool": "web", "session": {"tool_count.web": {"gt": 10}}}, "then": "block"},
                ],
            })
            report = run_doctor(
                config_path=td / "policyshield.yaml",
                rules_path=td / "policies" / "rules.yaml",
            )
            assert report.grade == "A"
            assert report.score == report.max_score

    def test_minimal_preset_low_score(self):
        """Minimal preset should score poorly — missing many protections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            _write_yaml(td / "policyshield.yaml", {
                "mode": "ENFORCE", "fail_open": True,
            })
            _write_yaml(td / "policies" / "rules.yaml", {
                "rules": [
                    {"id": "r1", "when": {"tool": "read_file"}, "then": "allow"},
                ],
            })
            report = run_doctor(
                config_path=td / "policyshield.yaml",
                rules_path=td / "policies" / "rules.yaml",
            )
            assert report.grade in ("D", "F")

    def test_missing_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            report = run_doctor(
                config_path=td / "nonexistent.yaml",
                rules_path=td / "nonexistent.yaml",
            )
            assert report.score == 0
            assert report.grade == "F"

    def test_format_report(self):
        report = DoctorReport()
        report.add(Check("Test", True, 10, "✓ OK"))
        report.add(Check("Test2", False, 10, "✗ Bad", "Fix it"))
        report.finalize()
        output = format_report(report)
        assert "Score: 10/20" in output
        assert "Fix it" in output

    def test_grade_boundaries(self):
        """Test all grade boundaries."""
        report = DoctorReport()
        # Score 90% → A
        for i in range(9):
            report.add(Check(f"t{i}", True, 10, "ok"))
        report.add(Check("t9", False, 10, "bad"))
        report.finalize()
        assert report.grade == "A"
