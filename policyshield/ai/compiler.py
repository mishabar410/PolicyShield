"""Natural Language → Policy YAML compiler.

Converts human-readable policy descriptions into valid PolicyShield YAML rules
using an LLM.  Includes a validation loop that re-prompts on parse errors.

Usage::

    compiler = PolicyCompiler(api_key="sk-...")
    yaml_text = await compiler.compile("Block all file deletions in production")
    # → valid YAML for PolicyShield rules

Or via CLI::

    policyshield compile "Block all file deletions in production" -o rules/custom.yaml
"""

from __future__ import annotations

import logging
import os

import yaml

logger = logging.getLogger("policyshield")


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a PolicyShield rule compiler.  Convert natural language descriptions
into valid PolicyShield YAML rules.

PolicyShield rule format:

```yaml
shield_name: <name>
version: 1

rules:
  - id: <unique-id>
    when:
      tool: <tool-pattern>           # glob pattern, e.g. "file.*"
      args:                           # optional argument conditions
        key: value
        key: "!value"                 # negation
      context:                        # optional context conditions
        user_role: admin
        environment: production
        time_of_day: "09:00-18:00"
    then: BLOCK | ALLOW | REDACT | APPROVE
    message: "Human-readable explanation"
    severity: CRITICAL | HIGH | MEDIUM | LOW
    priority: <int, higher = more specific>
```

Output ONLY valid YAML, no markdown fences, no commentary.
"""


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------


class CompileResult:
    """Result of a compilation attempt."""

    def __init__(
        self,
        yaml_text: str = "",
        is_valid: bool = False,
        errors: list[str] | None = None,
        attempts: int = 0,
    ):
        self.yaml_text = yaml_text
        self.is_valid = is_valid
        self.errors = errors or []
        self.attempts = attempts


class PolicyCompiler:
    """LLM-powered natural language → PolicyShield YAML compiler.

    Args:
        api_key: OpenAI API key (or set ``OPENAI_API_KEY`` env var).
        model: LLM model to use.
        base_url: API base URL.
        max_retries: Max validation-loop retries.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        max_retries: int = 2,
    ) -> None:
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._model = model
        self._base_url = base_url
        self._max_retries = max_retries

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def compile(self, description: str) -> CompileResult:
        """Compile a natural language description to PolicyShield YAML.

        Returns a :class:`CompileResult` with the YAML text, validation status,
        and any errors encountered.
        """
        errors: list[str] = []
        for attempt in range(1, self._max_retries + 1):
            try:
                yaml_text = await self._call_llm(description, errors)
            except Exception as e:
                logger.error("Compiler LLM call failed: %s", e)
                return CompileResult(
                    yaml_text="",
                    is_valid=False,
                    errors=[f"LLM call failed: {e}"],
                    attempts=attempt,
                )

            validation_errors = self._validate(yaml_text)
            if not validation_errors:
                return CompileResult(
                    yaml_text=yaml_text,
                    is_valid=True,
                    attempts=attempt,
                )

            errors = validation_errors
            logger.info(
                "Compilation attempt %d/%d had %d errors, retrying",
                attempt,
                self._max_retries,
                len(errors),
            )

        return CompileResult(
            yaml_text=yaml_text if "yaml_text" in dir() else "",  # type: ignore
            is_valid=False,
            errors=errors,
            attempts=self._max_retries,
        )

    def compile_sync(self, description: str) -> CompileResult:
        """Synchronous wrapper for :meth:`compile`."""
        import asyncio

        return asyncio.run(self.compile(description))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, yaml_text: str) -> list[str]:
        """Validate generated YAML against PolicyShield schema.

        Returns list of error messages (empty = valid).
        """
        errors: list[str] = []

        # Parse YAML
        try:
            data = yaml.safe_load(yaml_text)
        except yaml.YAMLError as e:
            return [f"YAML parse error: {e}"]

        if not isinstance(data, dict):
            return ["Root must be a YAML mapping"]

        # Check required fields
        if "rules" not in data:
            errors.append("Missing 'rules' key")
        elif not isinstance(data["rules"], list):
            errors.append("'rules' must be a list")
        else:
            for i, rule in enumerate(data["rules"]):
                if not isinstance(rule, dict):
                    errors.append(f"Rule {i}: must be a mapping")
                    continue
                if "id" not in rule:
                    errors.append(f"Rule {i}: missing 'id'")
                if "when" not in rule:
                    errors.append(f"Rule {i}: missing 'when'")
                if "then" not in rule:
                    errors.append(f"Rule {i}: missing 'then'")
                elif rule["then"] not in ("BLOCK", "ALLOW", "REDACT", "APPROVE"):
                    errors.append(f"Rule {i}: invalid 'then' value: {rule['then']}")

        return errors

    # ------------------------------------------------------------------
    # LLM interaction
    # ------------------------------------------------------------------

    async def _call_llm(self, description: str, errors: list[str]) -> str:
        import httpx

        user_msg = f"Convert to PolicyShield YAML rules:\n\n{description}"
        if errors:
            user_msg += "\n\nPrevious attempt had errors:\n" + "\n".join(f"- {e}" for e in errors)
            user_msg += "\n\nFix these errors and output corrected YAML."

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self._model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.2,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        raw = data["choices"][0]["message"]["content"]

        # Strip markdown fences if present
        if raw.strip().startswith("```"):
            lines = raw.strip().split("\n")
            raw = "\n".join(lines[1:-1])

        return raw.strip()
