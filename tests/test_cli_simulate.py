"""Tests for policyshield simulate CLI command."""

from __future__ import annotations

from policyshield.cli.main import app


class TestSimulateCLI:
    def test_simulate_shows_change(self, tmp_path):
        """Simulate should show verdict change when new rule blocks a tool."""
        base = tmp_path / "base.yaml"
        base.write_text("shield_name: test\nversion: 1\nrules:\n  - id: allow-all\n    tool: '.*'\n    then: ALLOW\n")
        new = tmp_path / "new.yaml"
        new.write_text("shield_name: test\nversion: 1\nrules:\n  - id: block-exec\n    tool: exec\n    then: BLOCK\n")

        import io
        import sys

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            result = app(
                [
                    "simulate",
                    "--rules",
                    str(base),
                    "--new-rule",
                    str(new),
                    "--tool",
                    "exec",
                    "--args",
                    "{}",
                ]
            )
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert result == 0
        assert "CHANGE" in output or "BLOCK" in output

    def test_simulate_no_change(self, tmp_path):
        """Simulate should indicate no change when new rule doesn't affect verdict."""
        base = tmp_path / "base.yaml"
        base.write_text("shield_name: test\nversion: 1\nrules:\n  - id: block-exec\n    tool: exec\n    then: BLOCK\n")
        new = tmp_path / "new.yaml"
        new.write_text("shield_name: test\nversion: 1\nrules:\n  - id: allow-read\n    tool: read\n    then: ALLOW\n")

        import io
        import sys

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            result = app(
                [
                    "simulate",
                    "--rules",
                    str(base),
                    "--new-rule",
                    str(new),
                    "--tool",
                    "exec",
                    "--args",
                    "{}",
                ]
            )
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert result == 0
        assert "No change" in output

    def test_simulate_invalid_json(self, tmp_path):
        """Simulate should exit 1 on invalid JSON args."""
        base = tmp_path / "base.yaml"
        base.write_text("shield_name: test\nversion: 1\nrules: []\n")
        new = tmp_path / "new.yaml"
        new.write_text("shield_name: test\nversion: 1\nrules: []\n")

        result = app(
            [
                "simulate",
                "--rules",
                str(base),
                "--new-rule",
                str(new),
                "--tool",
                "test",
                "--args",
                "{invalid}",
            ]
        )
        assert result == 1

    def test_simulate_invalid_rules(self, tmp_path):
        """Simulate should exit 1 on invalid rules file."""
        base = tmp_path / "nonexistent.yaml"
        new = tmp_path / "new.yaml"
        new.write_text("shield_name: test\nversion: 1\nrules: []\n")

        result = app(
            [
                "simulate",
                "--rules",
                str(base),
                "--new-rule",
                str(new),
                "--tool",
                "test",
            ]
        )
        assert result == 1
