# Prompt 353 — CLI `policyshield check --dry-run`

## Цель

Добавить `--dry-run` режим в CLI: показать verdict без реального воздействия.

## Контекст

- Разработчики хотят тестировать правила локально до деплоя
- Нужно: `policyshield check --tool send_email --args '{"to":"test@example.com"}' --dry-run`

## Что сделать

```python
# cli/commands/check.py (новый файл или обновить существующий CLI)
import click
import json

@click.command()
@click.option("--tool", required=True, help="Tool name to check")
@click.option("--args", default="{}", help="JSON args")
@click.option("--dry-run", is_flag=True, help="Show verdict without side effects")
@click.option("--rules", default=None, help="Path to rules YAML")
def check(tool, args, dry_run, rules):
    """Check a tool call against rules."""
    from policyshield.shield.sync_engine import ShieldEngine
    parsed_args = json.loads(args)
    engine = ShieldEngine(rules=rules or "rules.yaml")
    result = engine.check(tool, parsed_args)

    output = {
        "tool": tool,
        "verdict": result.verdict.value,
        "message": result.message,
        "rule_id": result.rule_id,
    }
    if dry_run:
        output["mode"] = "dry-run"

    click.echo(json.dumps(output, indent=2))
```

## Тесты

```python
class TestDryRunCLI:
    def test_dry_run_shows_verdict(self, cli_runner, tmp_rules):
        result = cli_runner.invoke(check, ["--tool", "test", "--dry-run", "--rules", str(tmp_rules)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "verdict" in data
        assert data["mode"] == "dry-run"
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestDryRunCLI -v
pytest tests/ -q
```

## Коммит

```
feat(cli): add `policyshield check --dry-run` for local rule testing
```
