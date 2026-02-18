# Prompt 211 — CLI `generate-rules`

## Цель

Добавить CLI команду `policyshield generate-rules --from-openclaw` — получает тулы из OpenClaw, генерирует правила, записывает в файл.

## Контекст

- Промпт 209: `fetch_tool_names()` (HTTP client)
- Промпт 210: `generate_rules()` → `rules_to_yaml()` (классификация + генерация)
- Нужно всё соединить в CLI:
  ```bash
  policyshield generate-rules --from-openclaw --url http://localhost:3000 --output policies/rules.yaml
  ```
- Альтернатива: `--tools exec,read_file,write_file` — список тулов напрямую (без OpenClaw)
- Вывод: сколько правил, сколько block/approve/allow, куда сохранено
- Если файл уже существует — спросить подтверждение (или `--force`)

## Что сделать

### 1. Добавить subparser в `policyshield/cli/main.py`

```python
# --- generate-rules subparser ---
genrules_parser = subparsers.add_parser(
    "generate-rules",
    help="Auto-generate rules from tool list or OpenClaw",
)
genrules_parser.add_argument(
    "--from-openclaw", action="store_true",
    help="Fetch tools from running OpenClaw instance",
)
genrules_parser.add_argument(
    "--url", type=str, default="http://localhost:3000",
    help="OpenClaw URL (default: http://localhost:3000)",
)
genrules_parser.add_argument(
    "--tools", type=str, default=None,
    help="Comma-separated tool names (alternative to --from-openclaw)",
)
genrules_parser.add_argument(
    "--output", "-o", type=str, default="policies/rules.yaml",
    help="Output file path",
)
genrules_parser.add_argument(
    "--include-safe", action="store_true",
    help="Include explicit ALLOW rules for safe tools",
)
genrules_parser.add_argument(
    "--default-verdict", type=str, default="block",
    help="Default verdict for unmatched tools (default: block)",
)
genrules_parser.add_argument(
    "--force", action="store_true",
    help="Overwrite output file without asking",
)
genrules_parser.set_defaults(func=_cmd_generate_rules)
```

### 2. Implement `_cmd_generate_rules`

```python
def _cmd_generate_rules(args: argparse.Namespace) -> None:
    """Generate rules from tool list or OpenClaw."""
    from policyshield.ai.auto_rules import generate_rules, rules_to_yaml

    # Get tool names
    if args.from_openclaw:
        from policyshield.integrations.openclaw_client import (
            fetch_tool_names,
            OpenClawConnectionError,
        )
        try:
            print(f"Fetching tools from {args.url}...")
            tool_names = fetch_tool_names(args.url)
            print(f"  Found {len(tool_names)} tools")
        except OpenClawConnectionError as e:
            print(f"✗ {e}")
            raise SystemExit(1)
    elif args.tools:
        tool_names = [t.strip() for t in args.tools.split(",") if t.strip()]
        print(f"Using {len(tool_names)} provided tool names")
    else:
        print("✗ Specify --from-openclaw or --tools")
        print("  Example: policyshield generate-rules --tools exec,read_file,write_file")
        raise SystemExit(1)

    if not tool_names:
        print("✗ No tools found")
        raise SystemExit(1)

    # Generate rules
    rules = generate_rules(
        tool_names,
        include_safe=args.include_safe,
        default_verdict=args.default_verdict,
    )

    if not rules:
        print("⚠ No rules generated (all tools classified as safe)")
        print("  Use --include-safe to generate explicit ALLOW rules for safe tools")
        return

    # Summary
    verdicts = {}
    for r in rules:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1
    print(f"\nGenerated {len(rules)} rules:")
    for v, count in sorted(verdicts.items()):
        print(f"  {v.upper()}: {count}")

    # Output
    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        try:
            confirm = input(f"\n{output_path} already exists. Overwrite? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                return
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_str = rules_to_yaml(
        rules,
        shield_name=f"auto-{args.default_verdict}-policy",
        default_verdict=args.default_verdict,
    )
    output_path.write_text(yaml_str, encoding="utf-8")
    print(f"\n✓ Rules written to {output_path}")
    print(f"  Next: policyshield validate {output_path}")
```

### 3. Тесты

#### `tests/test_cli_generate_rules.py`

```python
"""Tests for CLI generate-rules command."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml
import pytest


class TestGenerateRulesCLI:
    def test_from_tools_flag(self):
        """--tools generates rules to file."""
        from policyshield.cli.main import _cmd_generate_rules
        import argparse

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="exec,write_file,delete_file,read_file",
                output=str(output),
                include_safe=False,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            assert output.exists()
            data = yaml.safe_load(output.read_text())
            assert len(data["rules"]) >= 2  # exec=block, write=approve, delete=block
            assert data["default_verdict"] == "block"

    def test_include_safe(self):
        """--include-safe includes safe tool rules."""
        from policyshield.cli.main import _cmd_generate_rules
        import argparse

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="log_message,exec",
                output=str(output),
                include_safe=True,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            data = yaml.safe_load(output.read_text())
            names = [r["when"]["tool"] for r in data["rules"]]
            assert "log_message" in names

    def test_no_tools_no_openclaw(self):
        """Must specify --from-openclaw or --tools."""
        from policyshield.cli.main import _cmd_generate_rules
        import argparse

        args = argparse.Namespace(
            from_openclaw=False,
            url="http://localhost:3000",
            tools=None,
            output="/dev/null",
            include_safe=False,
            default_verdict="block",
            force=True,
        )
        with pytest.raises(SystemExit):
            _cmd_generate_rules(args)

    def test_makedirs(self):
        """Output directory is created if needed."""
        from policyshield.cli.main import _cmd_generate_rules
        import argparse

        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "deep" / "nested" / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="exec",
                output=str(output),
                include_safe=False,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            assert output.exists()
```

## Самопроверка

```bash
pytest tests/test_cli_generate_rules.py -v
pytest tests/ -q
```

## Коммит

```
feat(cli): add generate-rules command for auto-rule generation

- policyshield generate-rules --from-openclaw --url <URL>
- policyshield generate-rules --tools exec,read_file,write_file
- Outputs classified YAML rules with summary stats
- --include-safe, --default-verdict, --force flags
- Auto-creates output directory
```
