"""LLM-based YAML rule generator for PolicyShield."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from policyshield.ai.templates import (
    RULE_TEMPLATES,
    classify_tools,
    recommend_rules,
)


SYSTEM_PROMPT = """\
You are PolicyShield Rule Writer — an expert at writing security policies for AI agents.

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
        examples.append(
            RULE_TEMPLATES[key].format(
                tool_name="example_tool",
            )
        )

    # Add chain template
    examples.append(
        RULE_TEMPLATES["chain_anti_exfil"].format(
            outgoing_tool="send_email",
            sensitive_tool="read_database",
        )
    )

    # Add recommendations for user's tools
    if tool_names:
        recs = recommend_rules(tool_names)
        for rec in recs[:3]:
            examples.append(f"# Recommended for '{rec.tool_name}' ({rec.danger_level.value}):")
            examples.append(rec.yaml_snippet)

    return "\n\n".join(examples)


def _extract_yaml(text: str) -> str:
    """Extract YAML from LLM response (may be wrapped in ```yaml ... ```)."""
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

    yaml_text = ""
    last_error: str | None = None
    for _attempt in range(1 + max_retries):
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
