"""CLI tests for `policyshield diff` (Prompt 06)."""

from __future__ import annotations

import json
import textwrap

from policyshield.cli.main import app


def _write_rules(path, content):
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def test_cli_diff_no_changes(tmp_path):
    rules = textwrap.dedent("""\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "block rm"
        when:
          tool: exec
          args.command__contains: "rm"
        then: BLOCK
        severity: HIGH
    """)
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    _write_rules(old, rules)
    _write_rules(new, rules)

    rc = app(["diff", str(old), str(new)])
    assert rc == 0


def test_cli_diff_changes(tmp_path, capsys):
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    _write_rules(
        old,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "block rm"
        when:
          tool: exec
        then: BLOCK
        severity: HIGH
    """,
    )
    _write_rules(
        new,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "block rm"
        when:
          tool: exec
        then: ALLOW
        severity: LOW
    """,
    )

    rc = app(["diff", str(old), str(new)])
    assert rc == 0  # no --exit-code
    out = capsys.readouterr().out
    assert "MODIFIED" in out


def test_cli_diff_json(tmp_path, capsys):
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    _write_rules(
        old,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "d"
        when:
          tool: exec
        then: BLOCK
        severity: HIGH
    """,
    )
    _write_rules(
        new,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r2
        description: "new"
        when:
          tool: exec
        then: ALLOW
        severity: LOW
    """,
    )

    rc = app(["diff", str(old), str(new), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "added" in data
    assert "removed" in data


def test_cli_diff_exit_code(tmp_path):
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    _write_rules(
        old,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "d"
        when:
          tool: exec
        then: BLOCK
        severity: HIGH
    """,
    )
    _write_rules(
        new,
        """\
    shield_name: test
    version: 1
    rules:
      - id: r1
        description: "d"
        when:
          tool: exec
        then: ALLOW
        severity: HIGH
    """,
    )

    rc = app(["diff", str(old), str(new), "--exit-code"])
    assert rc == 1
