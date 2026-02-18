# Prompt 109 — LLM Rule Generator

## Цель

Создать `policyshield/ai/generator.py` — генератор YAML-правил через LLM API. На вход: описание на естественном языке + (опционально) список тулов. На выход: валидный YAML-конфиг PolicyShield.

## Контекст

- Шаблоны и классификатор тулов из промпта 108 используются как few-shot context
- Поддержка двух LLM провайдеров: OpenAI и Anthropic (через env var)
- LLM получает system prompt со структурой YAML + примерами
- Ответ LLM → валидация через `parse_rules_from_string()` → финальный YAML
- Если валидация не прошла → retry с ошибкой для LLM (max 2 retry)

## Что сделать

### 1. Создать `policyshield/ai/generator.py`

```python
"""LLM-based YAML rule generator for PolicyShield."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from policyshield.ai.templates import (
    RULE_TEMPLATES,
    classify_tools,
    recommend_rules,
)


SYSTEM_PROMPT = """You are PolicyShield Rule Writer — an expert at writing security policies for AI agents.

PolicyShield uses YAML rules to control which tool calls an AI agent can make.

## YAML Format

```yaml
version: "1"
default_verdict: allow  # or block

rules:
  - id: unique-rule-id
    when:
      tool: "tool_name"       # exact name or regex
      args:                    # optional argument matchers
        - key: "param_name"
          pattern: "regex_pattern"
      sender: "agent_name"    # optional
      chain:                  # optional temporal conditions
        - tool: "previous_tool"
          within_seconds: 60
    then: allow|block|redact|approve
    severity: low|medium|high|critical
    message: "Human-readable explanation"
    enabled: true
```

## Verdicts
- **allow**: permit the tool call
- **block**: deny the tool call
- **redact**: allow but remove PII from arguments
- **approve**: pause and require human approval

## Examples

{examples}

## Instructions
- Generate ONLY valid YAML
- Each rule must have a unique `id`
- Use descriptive messages
- Default to `block` for unknown/dangerous tools
- Output ONLY the YAML, no explanation
"""


@dataclass
class GenerateResult:
    """Result of rule generation."""
    yaml_text: str
    model: str
    prompt_used: str
    validation_ok: bool
    validation_error: str | None = None


def _build_examples(tool_names: list[str] | None) -> str:
    """Build few-shot examples from templates and recommendations."""
    examples = []

    # Add template examples
    for key in ["block_dangerous", "approve_critical", "redact_pii"]:
        examples.append(RULE_TEMPLATES[key].format(
            tool_name="example_tool",
        ))

    # Add chain template
    examples.append(RULE_TEMPLATES["chain_anti_exfil"].format(
        outgoing_tool="send_email",
        sensitive_tool="read_database",
    ))

    # Add recommendations for user's tools
    if tool_names:
        recs = recommend_rules(tool_names)
        for rec in recs[:3]:
            examples.append(f"# Recommended for '{rec.tool_name}' ({rec.danger_level.value}):")
            examples.append(rec.yaml_snippet)

    return "\n\n".join(examples)


def _extract_yaml(text: str) -> str:
    """Extract YAML from LLM response (may be wrapped in ```yaml ... ```)."""
    # Try to extract from code blocks
    match = re.search(r"```(?:yaml)?\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _validate_yaml(yaml_text: str) -> tuple[bool, str | None]:
    """Validate generated YAML against PolicyShield parser."""
    try:
        from policyshield.core.parser import parse_rules_from_string
        rule_set = parse_rules_from_string(yaml_text)
        if not rule_set.rules:
            return False, "No rules found in generated YAML"
        return True, None
    except Exception as e:
        return False, str(e)


async def generate_rules(
    description: str,
    *,
    tool_names: list[str] | None = None,
    provider: str = "openai",
    model: str | None = None,
    max_retries: int = 2,
) -> GenerateResult:
    """Generate PolicyShield YAML rules from a natural language description.

    Args:
        description: Natural language description of desired rules.
        tool_names: Optional list of tool names for context and recommendations.
        provider: LLM provider ('openai' or 'anthropic').
        model: Specific model name. Defaults per provider.
        max_retries: Max retry attempts on validation failure.

    Returns:
        GenerateResult with generated YAML.

    Raises:
        ValueError: If provider is not supported.
        RuntimeError: If LLM call fails after retries.
    """
    examples = _build_examples(tool_names)
    system = SYSTEM_PROMPT.format(examples=examples)

    user_msg = f"Generate PolicyShield YAML rules for:\n\n{description}"
    if tool_names:
        classifications = classify_tools(tool_names)
        tool_info = "\n".join(f"  - {name}: {level.value}" for name, level in classifications.items())
        user_msg += f"\n\nAvailable tools and their danger levels:\n{tool_info}"

    # Select provider
    if provider == "openai":
        llm_call = _call_openai
        model = model or "gpt-4o"
    elif provider == "anthropic":
        llm_call = _call_anthropic
        model = model or "claude-sonnet-4-20250514"
    else:
        raise ValueError(f"Unsupported provider: {provider}. Use 'openai' or 'anthropic'.")

    last_error: str | None = None
    for attempt in range(1 + max_retries):
        prompt = user_msg
        if last_error:
            prompt += f"\n\n⚠️ Previous attempt had a validation error:\n{last_error}\nPlease fix the YAML."

        raw_response = await llm_call(system, prompt, model)
        yaml_text = _extract_yaml(raw_response)

        ok, error = _validate_yaml(yaml_text)
        if ok:
            return GenerateResult(
                yaml_text=yaml_text,
                model=model,
                prompt_used=prompt,
                validation_ok=True,
            )
        last_error = error

    return GenerateResult(
        yaml_text=yaml_text,
        model=model,
        prompt_used=user_msg,
        validation_ok=False,
        validation_error=last_error,
    )


async def _call_openai(system: str, user: str, model: str) -> str:
    """Call OpenAI API."""
    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("openai package is required. Install with: pip install openai")

    client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.3,
        max_tokens=2000,
    )
    return response.choices[0].message.content or ""


async def _call_anthropic(system: str, user: str, model: str) -> str:
    """Call Anthropic API."""
    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        raise RuntimeError("anthropic package is required. Install with: pip install anthropic")

    client = AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    response = await client.messages.create(
        model=model,
        max_tokens=2000,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return response.content[0].text
```

### 2. Тесты

#### `tests/test_rule_generator.py`

```python
import pytest
from unittest.mock import AsyncMock, patch
from policyshield.ai.generator import (
    generate_rules,
    _extract_yaml,
    _validate_yaml,
    _build_examples,
)


def test_extract_yaml_from_code_block():
    text = """Here is the YAML:
```yaml
version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: read_file
    then: allow
```
"""
    result = _extract_yaml(text)
    assert result.startswith("version:")
    assert "rules:" in result


def test_extract_yaml_plain():
    text = 'version: "1"\ndefault_verdict: allow\nrules: []'
    result = _extract_yaml(text)
    assert result == text


def test_validate_yaml_valid():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: read_file
    then: allow
"""
    ok, error = _validate_yaml(yaml_text)
    assert ok
    assert error is None


def test_validate_yaml_invalid():
    ok, error = _validate_yaml("not: valid: yaml: {{{}}")
    assert not ok
    assert error is not None


def test_validate_yaml_no_rules():
    yaml_text = """
version: "1"
default_verdict: allow
rules: []
"""
    ok, error = _validate_yaml(yaml_text)
    assert not ok
    assert "No rules" in error


def test_build_examples_with_tools():
    examples = _build_examples(["delete_file", "read_file"])
    assert "delete_file" in examples or "Recommended" in examples


def test_build_examples_without_tools():
    examples = _build_examples(None)
    assert "example_tool" in examples


@pytest.mark.asyncio
async def test_generate_rules_openai():
    mock_yaml = """version: "1"
default_verdict: allow
rules:
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "Delete blocked"
"""
    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = f"```yaml\n{mock_yaml}```"
        result = await generate_rules("Block all file deletions", provider="openai")
        assert result.validation_ok
        assert "delete" in result.yaml_text.lower()


@pytest.mark.asyncio
async def test_generate_rules_retry_on_invalid():
    """Test retry logic when first response is invalid."""
    bad_yaml = "not valid yaml {{{"
    good_yaml = """version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: test
    then: allow
"""
    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = [bad_yaml, good_yaml]
        result = await generate_rules("Test rules", provider="openai")
        assert result.validation_ok
        assert mock_call.call_count == 2  # Retried once


@pytest.mark.asyncio
async def test_generate_rules_unsupported_provider():
    with pytest.raises(ValueError, match="Unsupported"):
        await generate_rules("Test", provider="unknown")
```

## Самопроверка

```bash
pytest tests/test_rule_generator.py -v
pytest tests/ -q
```

## Коммит

```
feat(ai): add LLM-based YAML rule generator

- System prompt with PolicyShield YAML format and few-shot examples
- OpenAI and Anthropic provider support (async)
- Auto-validation: parse generated YAML through PolicyShield parser
- Retry logic: re-prompt LLM with validation error (max 2 retries)
- Tool classification context injected into prompt
- _extract_yaml: handles code blocks and plain text
```
