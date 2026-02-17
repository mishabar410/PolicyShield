"""Extended tests for policyshield doctor — full coverage."""

import tempfile
from pathlib import Path

import yaml

from policyshield.cli.doctor import Check, DoctorReport, format_report, run_doctor


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data))


def _base_config() -> dict:
    return {
        "mode": "ENFORCE",
        "fail_open": False,
        "trace": {"enabled": True},
        "sanitizer": {
            "builtin_detectors": [
                "path_traversal",
                "shell_injection",
                "sql_injection",
                "ssrf",
                "url_schemes",
            ],
        },
    }


def _base_rules() -> dict:
    return {
        "default_verdict": "block",
        "rules": [
            {"id": "r1", "when": {"tool": "exec"}, "then": "block"},
            {"id": "r2", "when": {"tool": "send"}, "then": "redact"},
            {"id": "r3", "when": {"tool": "write"}, "then": "approve"},
            {"id": "r4", "when": {"tool": "web", "session": {"tool_count.web": {"gt": 10}}}, "then": "block"},
        ],
    }


class TestDoctor:
    def test_perfect_score(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            _write_yaml(td / "policyshield.yaml", _base_config())
            _write_yaml(td / "policies" / "rules.yaml", _base_rules())
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
            _write_yaml(
                td / "policyshield.yaml",
                {
                    "mode": "ENFORCE",
                    "fail_open": True,
                },
            )
            _write_yaml(
                td / "policies" / "rules.yaml",
                {
                    "rules": [
                        {"id": "r1", "when": {"tool": "read_file"}, "then": "allow"},
                    ],
                },
            )
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


class TestDoctorChecksIsolated:
    """Test each check individually."""

    def test_config_exists_pass(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {"mode": "ENFORCE"})
            _write_yaml(td / "rules.yaml", {"rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            config_check = next(c for c in report.checks if c.name == "Config file")
            assert config_check.passed

    def test_config_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "cfg.yaml").write_text(": invalid: yaml: [")
            _write_yaml(td / "rules.yaml", {"rules": []})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            config_check = next(c for c in report.checks if c.name == "Config file")
            assert not config_check.passed

    def test_rules_empty(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {})
            _write_yaml(td / "rules.yaml", {"rules": []})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            rules_check = next(c for c in report.checks if c.name == "Rules file")
            assert not rules_check.passed

    def test_default_verdict_block(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {})
            _write_yaml(
                td / "rules.yaml",
                {"default_verdict": "block", "rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]},
            )
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            verdict_check = next(c for c in report.checks if c.name == "Default verdict")
            assert verdict_check.passed

    def test_default_verdict_allow(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {})
            _write_yaml(
                td / "rules.yaml",
                {"default_verdict": "allow", "rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]},
            )
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            verdict_check = next(c for c in report.checks if c.name == "Default verdict")
            assert not verdict_check.passed

    def test_partial_detectors(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(
                td / "cfg.yaml",
                {
                    "sanitizer": {"builtin_detectors": ["path_traversal", "ssrf"]},
                },
            )
            _write_yaml(td / "rules.yaml", {"rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            det_check = next(c for c in report.checks if c.name == "Builtin detectors")
            assert not det_check.passed
            assert "2/5" in det_check.message

    def test_exec_protection_list_tools(self):
        """Exec block with list of tools should pass."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {})
            _write_yaml(
                td / "rules.yaml",
                {
                    "rules": [{"id": "r", "when": {"tool": ["exec", "shell"]}, "then": "block"}],
                },
            )
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            exec_check = next(c for c in report.checks if c.name == "Exec protection")
            assert exec_check.passed


class TestGradeBoundaries:
    def _grade(self, score: int, max_score: int) -> str:
        report = DoctorReport()
        report.score = score
        report.max_score = max_score
        report.finalize()
        return report.grade

    def test_grade_a(self):
        assert self._grade(90, 100) == "A"
        assert self._grade(100, 100) == "A"

    def test_grade_b(self):
        assert self._grade(75, 100) == "B"
        assert self._grade(89, 100) == "B"

    def test_grade_c(self):
        assert self._grade(50, 100) == "C"
        assert self._grade(74, 100) == "C"

    def test_grade_d(self):
        assert self._grade(25, 100) == "D"
        assert self._grade(49, 100) == "D"

    def test_grade_f(self):
        assert self._grade(0, 100) == "F"
        assert self._grade(24, 100) == "F"

    def test_empty_max_score(self):
        """Edge case: max_score=0."""
        report = DoctorReport()
        report.finalize()
        assert report.grade == "F"  # 0/0 → 0%


class TestFormatReport:
    def test_includes_all_checks(self):
        report = DoctorReport()
        report.add(Check("A", True, 10, "✓ OK"))
        report.add(Check("B", False, 10, "✗ Bad", "Fix B"))
        report.finalize()
        output = format_report(report)
        assert "✓ OK" in output
        assert "✗ Bad" in output
        assert "Fix B" in output

    def test_includes_grade(self):
        report = DoctorReport()
        report.add(Check("A", True, 10, "✓ OK"))
        report.finalize()
        output = format_report(report)
        assert "Grade: A" in output

    def test_includes_score(self):
        report = DoctorReport()
        report.add(Check("A", True, 10, "✓ OK"))
        report.add(Check("B", True, 5, "✓ Also OK"))
        report.finalize()
        output = format_report(report)
        assert "15/15" in output
