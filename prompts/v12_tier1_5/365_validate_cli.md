# Prompt 365 — CLI `policyshield validate`

## Цель

Добавить CLI-команду для валидации YAML правил без запуска сервера.

## Контекст

- Сейчас ошибки в правилах обнаруживаются только при `serve` → слишком поздно
- Нужно: `policyshield validate rules.yaml` → проверить синтаксис, семантику, паттерны regex

## Что сделать

```python
# cli/commands/validate.py
import click
import yaml
import re
import sys

@click.command()
@click.argument("rules_path")
def validate(rules_path):
    """Validate a rules YAML file."""
    errors = []
    warnings = []

    # 1. YAML parse
    try:
        with open(rules_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        click.echo(f"❌ YAML parse error: {e}", err=True)
        sys.exit(1)

    if not isinstance(data, dict) or "rules" not in data:
        click.echo("❌ Missing 'rules' key in YAML", err=True)
        sys.exit(1)

    # 2. Validate each rule
    for i, rule in enumerate(data["rules"]):
        rule_id = rule.get("id", f"rule[{i}]")
        if not rule.get("tool_name"):
            errors.append(f"{rule_id}: missing 'tool_name'")
        if not rule.get("verdict"):
            errors.append(f"{rule_id}: missing 'verdict'")
        elif rule["verdict"] not in ("ALLOW", "BLOCK", "APPROVE", "REDACT"):
            errors.append(f"{rule_id}: invalid verdict '{rule['verdict']}'")
        # Validate regex patterns
        for field in ("args_pattern", "pattern"):
            pat = rule.get(field)
            if pat:
                try:
                    re.compile(pat)
                except re.error as e:
                    errors.append(f"{rule_id}: invalid regex in {field}: {e}")

    # 3. Report
    if errors:
        for e in errors:
            click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    else:
        click.echo(f"✅ {len(data['rules'])} rules validated successfully")
```

## Тесты

```python
class TestValidateCLI:
    def test_valid_rules_pass(self, cli_runner, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("rules:\\n  - id: r1\\n    tool_name: test\\n    verdict: BLOCK")
        result = cli_runner.invoke(validate, [str(rules)])
        assert result.exit_code == 0
        assert "validated" in result.output

    def test_invalid_verdict_fails(self, cli_runner, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("rules:\\n  - id: r1\\n    tool_name: test\\n    verdict: DESTROY")
        result = cli_runner.invoke(validate, [str(rules)])
        assert result.exit_code == 1

    def test_invalid_regex_detected(self, cli_runner, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text("rules:\\n  - id: r1\\n    tool_name: test\\n    verdict: BLOCK\\n    args_pattern: '[invalid'")
        result = cli_runner.invoke(validate, [str(rules)])
        assert result.exit_code == 1
```

## Коммит

```
feat(cli): add `policyshield validate` for offline rule validation
```
