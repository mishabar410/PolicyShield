# Prompt 103 — CLI replay command

## Цель

Добавить CLI-команду `policyshield replay` — прогоняет трейсы через новые правила и выводит diff в терминал.

## Контекст

- `TraceLoader` (промпт 101) загружает трейсы
- `ReplayEngine` (промпт 102) выдаёт `ReplayResult` с old/new вердиктами
- CLI уже использует `argparse` в `cli/main.py`
- Нужен красивый форматированный вывод: таблица изменений + summary

## Что сделать

### 1. Добавить subcommand `replay` в `policyshield/cli/main.py`

В `_build_parser()` добавить:

```python
sp_replay = subparsers.add_parser("replay", help="Replay traces against different rules")
sp_replay.add_argument("traces", help="Path to JSONL trace file or directory")
sp_replay.add_argument("--rules", required=True, help="Path to new rules YAML")
sp_replay.add_argument("--session", default=None, help="Filter by session ID")
sp_replay.add_argument("--tool", default=None, help="Filter by tool name")
sp_replay.add_argument("--only-changed", action="store_true", help="Show only changed verdicts")
sp_replay.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
sp_replay.set_defaults(func=_cmd_replay)
```

### 2. Реализовать `_cmd_replay(args)`

```python
def _cmd_replay(args) -> int:
    """Replay historical traces against new rules."""
    from policyshield.replay.loader import TraceLoader
    from policyshield.replay.engine import ReplayEngine, ChangeType

    # Load traces
    loader = TraceLoader.from_path(args.traces)
    entries = loader.load(session_id=args.session, tool=args.tool)

    if not entries:
        print("No trace entries found.")
        return 1

    # Replay
    engine = ReplayEngine.from_file(args.rules)
    results = engine.replay_all(entries)
    summary = engine.summary(results)

    if args.only_changed:
        results = [r for r in results if r.changed]

    if args.format == "json":
        import json
        output = {
            "summary": summary,
            "results": [
                {
                    "tool": r.entry.tool,
                    "session_id": r.entry.session_id,
                    "old_verdict": r.old_verdict,
                    "new_verdict": r.new_verdict,
                    "change": r.change_type.value,
                    "rule_id": r.new_rule_id,
                }
                for r in results
            ],
        }
        print(json.dumps(output, indent=2))
        return 0

    # Table format
    _CHANGE_SYMBOLS = {
        ChangeType.UNCHANGED: "  ",
        ChangeType.RELAXED: "↓ ",
        ChangeType.TIGHTENED: "↑ ",
        ChangeType.MODIFIED: "~ ",
    }
    _CHANGE_COLORS = {
        ChangeType.UNCHANGED: "",
        ChangeType.RELAXED: "\033[32m",    # green
        ChangeType.TIGHTENED: "\033[31m",  # red
        ChangeType.MODIFIED: "\033[33m",   # yellow
    }
    RESET = "\033[0m"

    print(f"\n{'Tool':<30} {'Old':<10} {'New':<10} {'Change':<12} {'Rule'}")
    print("─" * 80)

    for r in results:
        symbol = _CHANGE_SYMBOLS[r.change_type]
        color = _CHANGE_COLORS[r.change_type]
        rule = r.new_rule_id or "(default)"
        print(f"{color}{r.entry.tool:<30} {r.old_verdict:<10} {r.new_verdict:<10} {symbol}{r.change_type.value:<10} {rule}{RESET}")

    print("─" * 80)
    print(f"\nTotal: {summary['total']}  |  "
          f"Unchanged: {summary['unchanged']}  |  "
          f"\033[31m↑ Tightened: {summary['tightened']}\033[0m  |  "
          f"\033[32m↓ Relaxed: {summary['relaxed']}\033[0m")

    if summary["tightened"] > 0:
        print(f"\n⚠️  {summary['tightened']} tool call(s) would be MORE restricted with new rules.")

    return 0
```

### 3. Тесты

#### `tests/test_cli_replay.py`

```python
import json
import tempfile
from pathlib import Path

from policyshield.cli.main import main as cli_main


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
    exit_code = cli_main(["replay", str(traces), "--rules", str(rules)])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "delete_file" in output
    assert "tightened" in output.lower() or "↑" in output


def test_replay_json_output(tmp_path, capsys):
    traces, rules = _setup_replay(tmp_path)
    exit_code = cli_main(["replay", str(traces), "--rules", str(rules), "--format", "json"])
    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["tightened"] == 1


def test_replay_only_changed(tmp_path, capsys):
    traces, rules = _setup_replay(tmp_path)
    exit_code = cli_main(["replay", str(traces), "--rules", str(rules), "--only-changed", "--format", "json"])
    output = json.loads(capsys.readouterr().out)
    assert len(output["results"]) == 1
    assert output["results"][0]["tool"] == "delete_file"
```

## Самопроверка

```bash
pytest tests/test_cli_replay.py -v
pytest tests/ -q

# Ручная проверка
policyshield replay traces/ --rules new_rules.yaml
policyshield replay traces/ --rules new_rules.yaml --only-changed
policyshield replay traces/ --rules new_rules.yaml --format json
```

## Коммит

```
feat(cli): add `policyshield replay` command

- Replay historical traces against new rules
- Table output with color-coded verdict changes (↑ tightened, ↓ relaxed)
- JSON output for CI integration
- Filter by --session, --tool, --only-changed
- Summary: total, unchanged, tightened, relaxed counts
```
