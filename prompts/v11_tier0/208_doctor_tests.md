# Prompt 208 — Doctor Tests (полное покрытие)

## Цель

Расширить тестовое покрытие `policyshield doctor` — граничные случаи, scoring corner cases, проверка каждого check по отдельности.

## Контекст

- Промпт 207 создал doctor с базовыми тестами
- Нужно покрыть:
  - Каждый из 10 checks изолированно (passed + failed)
  - Partial detector configs
  - Malformed YAML
  - Empty rules
  - JSON output format
  - Grade boundaries (A=90%, B=75%, C=50%, D=25%)

## Что сделать

### 1. Расширить `tests/test_doctor.py`

```python
"""Extended tests for policyshield doctor — full coverage."""

import json
import tempfile
from pathlib import Path

import yaml
import pytest

from policyshield.cli.doctor import run_doctor, format_report, DoctorReport, Check


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
                "path_traversal", "shell_injection",
                "sql_injection", "ssrf", "url_schemes",
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
            _write_yaml(td / "rules.yaml", {"default_verdict": "block", "rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            verdict_check = next(c for c in report.checks if c.name == "Default verdict")
            assert verdict_check.passed

    def test_default_verdict_allow(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {})
            _write_yaml(td / "rules.yaml", {"default_verdict": "allow", "rules": [{"id": "r", "when": {"tool": "x"}, "then": "allow"}]})
            report = run_doctor(config_path=td / "cfg.yaml", rules_path=td / "rules.yaml")
            verdict_check = next(c for c in report.checks if c.name == "Default verdict")
            assert not verdict_check.passed

    def test_partial_detectors(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            _write_yaml(td / "cfg.yaml", {
                "sanitizer": {"builtin_detectors": ["path_traversal", "ssrf"]},
            })
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
            _write_yaml(td / "rules.yaml", {
                "rules": [{"id": "r", "when": {"tool": ["exec", "shell"]}, "then": "block"}],
            })
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
```

## Самопроверка

```bash
pytest tests/test_doctor.py -v --tb=short
pytest tests/ -q
```

## Коммит

```
test(doctor): add full coverage for doctor checks and grading

- Isolated tests for each of 10 checks (pass + fail cases)
- Partial detector config handling
- Malformed YAML and empty rules
- Grade boundary tests (A/B/C/D/F)
- Format report output validation
```
