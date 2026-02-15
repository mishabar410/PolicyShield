"""Tests for playground CLI command."""

import json

import pytest

from policyshield.cli.main import app
from policyshield.cli.playground import _parse_args, run_single_check


@pytest.fixture
def rules_yaml(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("""\
shield_name: playground-test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
    message: "exec blocked"
  - id: allow-read
    when:
      tool: read_file
    then: ALLOW
  - id: redact-email
    when:
      tool: send_email
    then: REDACT
    message: "PII redacted"
""")
    return str(f)


class TestSingleCheck:
    def test_allow_verdict(self, rules_yaml, capsys):
        code = run_single_check(rules_yaml, "read_file", '{"path": "/tmp/x"}')
        assert code == 0
        out = capsys.readouterr().out
        assert "ALLOW" in out

    def test_block_verdict(self, rules_yaml, capsys):
        code = run_single_check(rules_yaml, "exec", '{"command": "rm -rf /"}')
        assert code == 1
        out = capsys.readouterr().out
        assert "BLOCK" in out
        assert "exec blocked" in out

    def test_redact_verdict(self, rules_yaml, capsys):
        code = run_single_check(rules_yaml, "send_email", '{"to": "test@example.com"}')
        # REDACT is non-ALLOW → exit code 1
        captured = capsys.readouterr().out
        assert "REDACT" in captured

    def test_default_verdict(self, rules_yaml, capsys):
        """Unmatched tool gets default verdict (ALLOW)."""
        code = run_single_check(rules_yaml, "unknown_tool")
        assert code == 0

    def test_invalid_json_args(self, rules_yaml, capsys):
        code = run_single_check(rules_yaml, "exec", "not-json")
        assert code == 2
        assert "Invalid JSON" in capsys.readouterr().err

    def test_missing_rules_file(self, capsys):
        code = run_single_check("/nonexistent/rules.yaml", "exec")
        assert code == 2
        assert "not found" in capsys.readouterr().err


class TestPlaygroundCLI:
    def test_playground_missing_rules(self, capsys):
        with pytest.raises(SystemExit):
            app(["playground"])

    def test_playground_single_check_via_cli(self, rules_yaml, capsys):
        code = app(["playground", "--rules", rules_yaml, "--tool", "exec", "--args", '{"cmd": "ls"}'])
        assert code == 1  # BLOCK
        assert "BLOCK" in capsys.readouterr().out

    def test_playground_single_check_allow(self, rules_yaml, capsys):
        code = app(["playground", "--rules", rules_yaml, "--tool", "read_file"])
        assert code == 0
        assert "ALLOW" in capsys.readouterr().out

    def test_playground_nonexistent_rules(self, capsys):
        code = app(["playground", "--rules", "/nonexistent.yaml", "--tool", "exec"])
        assert code == 2


class TestParseArgs:
    def test_simple_key_value(self):
        assert _parse_args("key=value") == ["key=value"]

    def test_multiple_key_value(self):
        assert _parse_args("a=1 b=2") == ["a=1", "b=2"]

    def test_quoted_value(self):
        result = _parse_args('msg="hello world"')
        assert result == ["msg=hello world"]

    def test_empty(self):
        assert _parse_args("") == []

    def test_single_word(self):
        assert _parse_args("something") == ["something"]


class TestPlaygroundREPL:
    def test_interactive_quit(self, rules_yaml, monkeypatch, capsys):
        """Interactive mode exits on :quit."""
        from policyshield.cli.playground import cmd_playground

        inputs = iter([":quit"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        code = cmd_playground(rules_yaml)
        assert code == 0
        out = capsys.readouterr().out
        assert "Playground" in out
        assert "3 rules" in out

    def test_interactive_check(self, rules_yaml, monkeypatch, capsys):
        """Interactive mode processes tool calls."""
        from policyshield.cli.playground import cmd_playground

        inputs = iter(["exec command=ls", ":q"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        code = cmd_playground(rules_yaml)
        assert code == 0
        out = capsys.readouterr().out
        assert "BLOCK" in out

    def test_interactive_rules(self, rules_yaml, monkeypatch, capsys):
        """:rules shows loaded rules."""
        from policyshield.cli.playground import cmd_playground

        inputs = iter([":rules", ":q"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        code = cmd_playground(rules_yaml)
        assert code == 0
        out = capsys.readouterr().out
        assert "block-exec" in out

    def test_interactive_help(self, rules_yaml, monkeypatch, capsys):
        """:help shows usage."""
        from policyshield.cli.playground import cmd_playground

        inputs = iter([":help", ":q"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))
        code = cmd_playground(rules_yaml)
        assert code == 0
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_interactive_eof(self, rules_yaml, monkeypatch, capsys):
        """EOF (Ctrl+D) exits gracefully."""
        from policyshield.cli.playground import cmd_playground

        def raise_eof(_):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        code = cmd_playground(rules_yaml)
        assert code == 0
