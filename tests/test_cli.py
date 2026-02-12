"""Tests for CLI."""

import json

import pytest

from policyshield.cli.main import app


@pytest.fixture
def valid_yaml(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("""\
shield_name: test-shield
version: 1
rules:
  - id: block-exec
    description: Block exec
    when:
      tool: exec
    then: BLOCK
    severity: HIGH
  - id: allow-read
    when:
      tool: read_file
    then: ALLOW
    enabled: false
""")
    return str(f)


@pytest.fixture
def trace_file(tmp_path):
    f = tmp_path / "trace.jsonl"
    entries = [
        {
            "timestamp": "2024-01-01T00:00:00",
            "session_id": "s1",
            "tool": "exec",
            "verdict": "BLOCK",
            "rule_id": "r1",
            "latency_ms": 1.5,
        },
        {"timestamp": "2024-01-01T00:00:01", "session_id": "s1", "tool": "read", "verdict": "ALLOW", "latency_ms": 0.5},
        {
            "timestamp": "2024-01-01T00:00:02",
            "session_id": "s2",
            "tool": "write",
            "verdict": "REDACT",
            "rule_id": "r2",
            "pii_types": ["EMAIL"],
            "latency_ms": 2.0,
        },
    ]
    with open(f, "w") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    return str(f)


class TestValidateCommand:
    def test_validate_success(self, valid_yaml, capsys):
        exit_code = app(["validate", valid_yaml])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Valid" in captured.out
        assert "block-exec" in captured.out

    def test_validate_nonexistent(self, capsys):
        exit_code = app(["validate", "/nonexistent/rules.yaml"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error" in captured.err

    def test_validate_invalid_yaml(self, tmp_path, capsys):
        f = tmp_path / "bad.yaml"
        f.write_text("rules: not-a-list\n")
        exit_code = app(["validate", str(f)])
        assert exit_code == 1


class TestTraceShowCommand:
    def test_show_all(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "3 entries shown" in captured.out

    def test_show_filter_verdict(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file, "--verdict", "BLOCK"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "1 entries shown" in captured.out

    def test_show_filter_tool(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file, "--tool", "exec"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "exec" in captured.out

    def test_show_filter_session(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file, "--session", "s2"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "1 entries shown" in captured.out

    def test_show_limit(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file, "-n", "1"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "1 entries shown" in captured.out

    def test_show_nonexistent(self, capsys):
        exit_code = app(["trace", "show", "/nonexistent.jsonl"])
        assert exit_code == 1

    def test_show_pii_info(self, trace_file, capsys):
        exit_code = app(["trace", "show", trace_file, "--verdict", "REDACT"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "EMAIL" in captured.out


class TestTraceViolationsCommand:
    def test_violations_only(self, trace_file, capsys):
        exit_code = app(["trace", "violations", trace_file])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "ALLOW" not in captured.out.split("entries")[0]  # ALLOW entries excluded
        assert "2 entries shown" in captured.out


class TestCLIGeneral:
    def test_no_command(self, capsys):
        exit_code = app([])
        assert exit_code == 1

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            app(["--version"])
        assert exc_info.value.code == 0
