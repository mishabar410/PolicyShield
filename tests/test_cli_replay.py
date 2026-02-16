import json

from policyshield.cli.main import app


def _setup_replay(tmp_path):
    """Create trace file and rules file for testing."""
    traces = tmp_path / "traces"
    traces.mkdir()
    trace_file = traces / "test.jsonl"
    with open(trace_file, "w") as f:
        f.write(json.dumps({"timestamp": "2026-01-01T00:00:00+00:00", "session_id": "s1", "tool": "read_file", "verdict": "allow"}) + "\n")
        f.write(json.dumps({"timestamp": "2026-01-01T00:01:00+00:00", "session_id": "s1", "tool": "delete_file", "verdict": "allow"}) + "\n")

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("""
version: "1"
default_verdict: allow
rules:
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "Deletion blocked"
""")
    return traces, rules_file


def test_replay_table_output(tmp_path, capsys):
    traces, rules = _setup_replay(tmp_path)
    exit_code = app(["replay", str(traces), "--rules", str(rules)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "delete_file" in output
    assert "tightened" in output.lower() or "↑" in output


def test_replay_json_output(tmp_path, capsys):
    traces, rules = _setup_replay(tmp_path)
    exit_code = app(["replay", str(traces), "--rules", str(rules), "--format", "json"])
    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["tightened"] == 1


def test_replay_only_changed(tmp_path, capsys):
    traces, rules = _setup_replay(tmp_path)
    app(["replay", str(traces), "--rules", str(rules), "--only-changed", "--format", "json"])
    output = json.loads(capsys.readouterr().out)
    assert len(output["results"]) == 1
    assert output["results"][0]["tool"] == "delete_file"
