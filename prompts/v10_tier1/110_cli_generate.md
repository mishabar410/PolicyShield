# Prompt 110 — CLI `generate` command

## Цель

Добавить CLI-команду `policyshield generate` — интерактивная генерация YAML-правил через LLM по текстовому описанию.

## Контекст

- `generate_rules()` из промпта 109 — async генерация YAML через LLM
- `recommend_rules()` из промпта 108 — рекомендации без LLM (offline fallback)
- CLI уже использует `argparse` в `cli/main.py`
- Два режима: `--ai` (через LLM) и `--template` (офлайн, по шаблонам)
- Результат: готовый YAML записывается в файл или stdout

## Что сделать

### 1. Добавить subcommand `generate` в `policyshield/cli/main.py`

```python
sp_gen = subparsers.add_parser("generate", help="Generate rules from description")
sp_gen.add_argument("description", nargs="?", help="Natural language description of rules")
sp_gen.add_argument("--tools", nargs="+", help="List of tool names for context")
sp_gen.add_argument("--output", "-o", default=None, help="Output YAML file (default: stdout)")
sp_gen.add_argument("--provider", choices=["openai", "anthropic"], default="openai", help="LLM provider")
sp_gen.add_argument("--model", default=None, help="Specific LLM model")
sp_gen.add_argument("--template", action="store_true",
                     help="Use offline template mode (no LLM). Requires --tools")
sp_gen.add_argument("--interactive", "-i", action="store_true",
                     help="Interactive mode: ask follow-up questions")
sp_gen.set_defaults(func=_cmd_generate)
```

### 2. Реализовать `_cmd_generate(args)`

```python
def _cmd_generate(args) -> int:
    """Generate PolicyShield rules."""
    import asyncio

    # Template mode (offline, no LLM)
    if args.template:
        return _generate_template(args)

    # AI mode (requires LLM)
    if not args.description:
        print("Error: description is required for AI generation.")
        print("Usage: policyshield generate 'Block all file deletions' --tools delete_file read_file")
        return 1

    return asyncio.run(_generate_ai(args))


def _generate_template(args) -> int:
    """Generate rules from templates (offline mode)."""
    from policyshield.ai.templates import recommend_rules

    if not args.tools:
        print("Error: --tools is required for template mode.")
        print("Usage: policyshield generate --template --tools delete_file send_email -o rules.yaml")
        return 1

    recs = recommend_rules(args.tools)
    if not recs:
        print("No rule recommendations for the given tools (all classified as safe).")
        return 0

    # Build YAML
    lines = ['version: "1"', 'default_verdict: allow', '', 'rules:']
    for rec in recs:
        lines.append(f"  # {rec.tool_name} ({rec.danger_level.value})")
        for yaml_line in rec.yaml_snippet.split("\n"):
            lines.append(f"  {yaml_line}")
        lines.append("")

    yaml_text = "\n".join(lines)

    return _output_yaml(yaml_text, args.output, recs=recs)


async def _generate_ai(args) -> int:
    """Generate rules using LLM."""
    from policyshield.ai.generator import generate_rules

    print(f"🧠 Generating rules with {args.provider}...")
    if args.tools:
        print(f"   Tools: {', '.join(args.tools)}")

    try:
        result = await generate_rules(
            args.description,
            tool_names=args.tools,
            provider=args.provider,
            model=args.model,
        )
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1

    if not result.validation_ok:
        print(f"⚠️  Generated YAML has validation errors: {result.validation_error}")
        print("─" * 60)
        print(result.yaml_text)
        print("─" * 60)
        print("\nYou can save this YAML and fix it manually with: policyshield lint <file>")

        if args.output:
            _write_file(args.output, result.yaml_text)
            print(f"\nSaved (with warnings) to: {args.output}")
        return 1

    return _output_yaml(result.yaml_text, args.output, model=result.model)


def _output_yaml(yaml_text: str, output_path: str | None, **info) -> int:
    """Output YAML to file or stdout."""
    if output_path:
        _write_file(output_path, yaml_text)
        print(f"✅ Rules saved to: {output_path}")
        if info.get("model"):
            print(f"   Model: {info['model']}")
        if info.get("recs"):
            print(f"   Generated {len(info['recs'])} rule(s) from templates")
    else:
        print(yaml_text)

    # Validate output
    from policyshield.core.parser import parse_rules_from_string
    rule_set = parse_rules_from_string(yaml_text)
    print(f"\n✅ Valid: {len(rule_set.rules)} rule(s) parsed successfully")
    return 0


def _write_file(path: str, content: str) -> None:
    from pathlib import Path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")
```

### 3. Добавить `policyshield[ai]` extra в `pyproject.toml`

```toml
[project.optional-dependencies]
ai = ["openai>=1.0", "anthropic>=0.20"]
```

### 4. Тесты

#### `tests/test_cli_generate.py`

```python
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from policyshield.cli.main import main as cli_main


def test_generate_template_mode(tmp_path, capsys):
    output_file = tmp_path / "generated.yaml"
    exit_code = cli_main([
        "generate", "--template",
        "--tools", "delete_file", "send_email", "read_file",
        "-o", str(output_file),
    ])
    assert exit_code == 0
    content = output_file.read_text()
    assert "delete_file" in content
    assert "send_email" in content
    output = capsys.readouterr().out
    assert "saved" in output.lower() or "✅" in output


def test_generate_template_no_tools(capsys):
    exit_code = cli_main(["generate", "--template"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "--tools" in output


def test_generate_template_safe_tools(capsys):
    exit_code = cli_main([
        "generate", "--template",
        "--tools", "log_event", "format_text",
    ])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "safe" in output.lower() or "No rule" in output


def test_generate_ai_no_description(capsys):
    exit_code = cli_main(["generate"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "description" in output.lower()


def test_generate_template_to_stdout(capsys):
    exit_code = cli_main([
        "generate", "--template",
        "--tools", "delete_file",
    ])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "version:" in output
    assert "delete_file" in output


@pytest.mark.asyncio
async def test_generate_ai_mode(tmp_path, capsys):
    """Test AI generation with mocked LLM."""
    mock_yaml = """version: "1"
default_verdict: allow
rules:
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "Blocked by AI"
"""
    output_file = tmp_path / "ai_rules.yaml"

    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock:
        mock.return_value = f"```yaml\n{mock_yaml}```"
        exit_code = cli_main([
            "generate", "Block all file deletions",
            "--tools", "delete_file",
            "-o", str(output_file),
        ])
        assert exit_code == 0
        content = output_file.read_text()
        assert "delete_file" in content
```

## Самопроверка

```bash
pytest tests/test_cli_generate.py -v
pytest tests/ -q

# Ручная проверка (template mode, без LLM)
policyshield generate --template --tools delete_file send_email exec_command read_file
policyshield generate --template --tools delete_file -o /tmp/rules.yaml
policyshield lint /tmp/rules.yaml

# AI mode (нужен API key)
OPENAI_API_KEY=... policyshield generate "Block dangerous tools, allow reads" --tools delete_file read_file send_email
```

## Коммит

```
feat(cli): add `policyshield generate` command

- Template mode (--template): offline rule generation from tool names
- AI mode: LLM-based generation with OpenAI/Anthropic
- Output to file (-o) or stdout
- Auto-validation of generated YAML
- Add `ai` extra dependency group in pyproject.toml
- Tool danger classification in prompt context
```
